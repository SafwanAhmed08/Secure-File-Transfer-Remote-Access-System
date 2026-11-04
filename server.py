"""Single local backend for Relay's browser and terminal clients.

Run `python3 server.py` to serve HTTPS on 127.0.0.1:8443. Both clients call
this API, so authentication, file access rules, limits and activity records
have one implementation. Importing this module never starts sockets or writes
account data. auth.py/database.py remain reusable password/storage helpers.
This standard-library server is for local development, not internet deployment.
"""

import argparse
from collections import defaultdict, deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, urlsplit

import auth
import database
from tls_transport import create_server_context

PROJECT_ROOT = Path(__file__).resolve().parent
WEB_ROOT = PROJECT_ROOT / "web"
MAX_UPLOAD = 100 * 1024 * 1024
USER_QUOTA = 1024 * 1024 * 1024
SESSION_SECONDS = 8 * 60 * 60
TEXT_EXTENSIONS = {".txt", ".md", ".json", ".csv", ".log", ".py", ".js", ".css", ".html", ".xml", ".yaml", ".yml"}
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}


def normalise_public_origin(value):
    """Accept one explicit HTTPS origin, never a wildcard or arbitrary URL path."""
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment or parsed.port not in {None, 443}
            or any(char.isspace() for char in value) or "\\" in value
            or "*" in parsed.netloc):
        raise ValueError("Public origin must be one HTTPS URL, e.g. https://name.trycloudflare.com")
    if ":" in parsed.hostname:
        raise ValueError("Use a public DNS hostname for the tunnel origin.")
    return "https://" + parsed.hostname.lower()


class ApiError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status


class Application:
    def __init__(self, data_dir=PROJECT_ROOT, secure=True):
        # Default to this repository. Tests supply temporary data folders; no
        # path is inserted into sys.path and no second backend is imported.
        self.project = Path(data_dir).resolve()
        self.auth = auth
        self.database = database
        self.db_path = self.project / "users.db"
        self.storage = self.project / "server_uploads"
        self.storage.mkdir(exist_ok=True)
        self.secure = secure
        self.started = time.time()
        self.lock = threading.RLock()
        self.file_lock = threading.RLock()
        self.user_file_locks = {}
        # Tokens live only on the server and in an HttpOnly cookie, never in
        # localStorage. Restarting the web server invalidates all web sessions.
        self.sessions = {}
        self.attempts = defaultdict(deque)
        self.auth.initialise_database(self.db_path)
        with self.db() as db:
            # Separate tables preserve the existing users schema. No account
            # becomes an administrator automatically or by clicking a UI switch.
            db.execute("CREATE TABLE IF NOT EXISTS web_admins (username TEXT PRIMARY KEY)")
            db.execute("""CREATE TABLE IF NOT EXISTS web_events (
                id INTEGER PRIMARY KEY, username TEXT NOT NULL,
                action TEXT NOT NULL, filename TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL
            )""")
        # Unknown usernames still perform a password derivation to reduce simple
        # account enumeration by timing. This value is not a usable account.
        self.dummy_hash = self.auth.hash_password(secrets.token_urlsafe(32))
        
    def file_lock_for(self, username):
        # Protect creation so two requests get the same lock for this account.
        with self.lock:
            if username not in self.user_file_locks:
                self.user_file_locks[username] = threading.RLock()

            return self.user_file_locks[username]
        
    def db(self):
        # A new connection per operation avoids sharing connections across HTTP
        # threads. Callers use `with app.db()` for commit/rollback; the wrapper
        # also closes the handle (sqlite3's own context manager does not).
        class Connection:
            def __enter__(inner):
                inner.connection = sqlite3.connect(self.db_path, timeout=5)
                inner.connection.row_factory = sqlite3.Row
                return inner.connection
            def __exit__(inner, kind, value, trace):
                try:
                    if kind is None:
                        inner.connection.commit()
                    else:
                        inner.connection.rollback()
                finally:
                    inner.connection.close()
        return Connection()

    def is_admin(self, username):
        with self.db() as db:
            return db.execute("SELECT 1 FROM web_admins WHERE username = ?", (username,)).fetchone() is not None

    def grant_admin(self, username):
        with self.db() as db:
            if not db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise ValueError("That username does not exist. Create it with auth.py first.")
            db.execute("INSERT OR IGNORE INTO web_admins (username) VALUES (?)", (username,))

    def event(self, username, action, filename="", size=0):
        with self.db() as db:
            db.execute("INSERT INTO web_events (username, action, filename, size, created_at) VALUES (?, ?, ?, ?, ?)",
                       (username, action, filename, size, time.time()))
            # Keep this local audit log bounded; this is not a compliance archive.
            db.execute("DELETE FROM web_events WHERE id <= (SELECT COALESCE(MAX(id), 0) - 5000 FROM web_events)")

    def login(self, username, password, remote, client="browser"):
        now = time.time()
        with self.lock:
            attempts = self.attempts[remote]
            while attempts and attempts[0] < now - 600:
                attempts.popleft()
            if len(attempts) >= 10:
                raise ApiError("Too many sign-in attempts. Try again in 10 minutes.", 429)
            attempts.append(now)
        valid_name = isinstance(username, str) and self.auth.USERNAME_PATTERN.fullmatch(username)
        stored = self.database.get_password_hash(username, self.db_path) if valid_name else None
        valid = self.auth.verify_password(password, stored or self.dummy_hash)
        if not valid or stored is None:
            raise ApiError("Username or password is incorrect.", 401)
        token = secrets.token_urlsafe(32)
        session = {"username": username, "csrf": secrets.token_urlsafe(32), "expires": now + SESSION_SECONDS,
                   "created": now, "last_seen": now, "client": client}
        with self.lock:
            self.attempts.pop(remote, None)
            self.prune_sessions(now)
            self.sessions[self.token_key(token)] = session
        self.event(username, "signed_in")
        return token, session

    @staticmethod
    def token_key(token):
        # Storing only a digest means accidental inspection of the session map
        # does not reveal bearer tokens that could be pasted into a browser.
        return hashlib.sha256(token.encode()).hexdigest()

    def prune_sessions(self, now=None):
        now = now or time.time()
        for key in list(self.sessions):
            if self.sessions[key]["expires"] <= now:
                del self.sessions[key]

    def session(self, token):
        with self.lock:
            self.prune_sessions()
            session = self.sessions.get(self.token_key(token))
            if session:
                session["last_seen"] = time.time()
            return session

    def user_folder(self, username):
        if not self.auth.USERNAME_PATTERN.fullmatch(username):
            raise ApiError("Invalid account.", 400)
        folder = self.storage / f"client_{username}"
        # A symlink could bypass the intended per-user directory boundary.
        if folder.is_symlink():
            raise ApiError("This storage folder is unavailable.", 409)
        folder.mkdir(exist_ok=True)
        return folder

    def file_path(self, username, name):
        # This app intentionally supports flat folders, matching the CLI. Reject
        # traversal, absolute paths, control characters and symlinked files.
        if (not name or len(name.encode("utf-8")) > 240 or name in {".", ".."}
                or name.startswith(".upload-")
                or "/" in name or "\\" in name or any(ord(char) < 32 for char in name)):
            raise ApiError("Choose a valid filename without path separators.")
        path = self.user_folder(username) / name
        if path.is_symlink():
            raise ApiError("Symbolic links are not accessible.", 403)
        return path

    @staticmethod
    def file_type(name):
        ext = Path(name).suffix.lower()
        if ext in IMAGE_TYPES:
            return "image"
        if ext in {".mp4", ".mov", ".mp3", ".wav", ".webm", ".m4a"}:
            return "media"
        if ext in TEXT_EXTENSIONS or ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
            return "document"
        return "other"

    def files(self, username):
        result = []
        for path in self.user_folder(username).iterdir():
            if path.is_file() and not path.is_symlink() and not path.name.startswith(".upload-"):
                info = path.stat()
                result.append({"name": path.name, "size": info.st_size, "modified": info.st_mtime,
                               "type": self.file_type(path.name), "extension": path.suffix.lower().lstrip(".")})
        return sorted(result, key=lambda row: row["modified"], reverse=True)

    def events(self, username=None, limit=100):
        with self.db() as db:
            if username is None:
                rows = db.execute("SELECT * FROM web_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM web_events WHERE username = ? ORDER BY id DESC LIMIT ?", (username, limit)).fetchall()
        return [dict(row) for row in rows]


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, address, app, public_origin=None):
        self.public_origin = normalise_public_origin(public_origin) if public_origin else None
        if self.public_origin and not app.secure:
            raise ValueError("Tunnel mode requires local HTTPS; do not combine it with --http.")
        self.app = app
        self.tls_context = None
        super().__init__(address, Handler)
        self.allowed_hosts = {"localhost", "127.0.0.1", "::1", address[0]}
        if self.public_origin:
            self.allowed_hosts.add(urlsplit(self.public_origin).hostname)

    def process_request_thread(self, request, client_address):
        # Handshake in a worker, not in the accept loop. A stalled TLS client
        # therefore cannot prevent another browser from connecting.
        if self.tls_context is not None:
            try:
                request.settimeout(5)
                request = self.tls_context.wrap_socket(request, server_side=True)
            except OSError:
                request.close()
                return
        super().process_request_thread(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = "RelayLocal/1.0"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    @property
    def app(self):
        return self.server.app

    def log_message(self, format, *args):
        # Avoid printing query strings, filenames or session material in logs.
        if args and str(args[0]).startswith('"'):
            return

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")

    def respond(self, data, status=200, headers=None):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.security_headers()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def guard_request(self):
        # Restrict Host to prevent a hostile DNS name rebinding to this local
        # service. No CORS headers are provided; all UI requests are same-origin.
        authority = self.headers.get("Host", "").lower()
        host = urlsplit("//" + authority).hostname
        if host not in self.server.allowed_hosts:
            raise ApiError("This hostname is not allowed.", 403)
        # Allow only the configured public authority, not a suffix wildcard or
        # an arbitrary port. Forwarded-Host/Proto headers never expand trust.
        public = self.server.public_origin
        if public and host == urlsplit(public).hostname and "https://" + authority != public:
            raise ApiError("This public hostname/port is not allowed.", 403)
        if self.command not in {"GET", "HEAD"}:
            origin = self.headers.get("Origin")
            expected = ("https" if self.app.secure else "http") + "://" + authority
            if origin and origin != expected:
                raise ApiError("Cross-origin requests are not allowed.", 403)

    def current_session(self, mutate=False, admin=False):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
            token = jar["relay_session"].value if "relay_session" in jar else ""
        except cookies.CookieError:
            token = ""
        session = self.app.session(token)
        if not session:
            raise ApiError("Sign in to continue.", 401)
        if mutate and not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise ApiError("Session check failed. Refresh the page and try again.", 403)
        if admin and not self.app.is_admin(session["username"]):
            raise ApiError("Administrator access is required.", 403)
        return session, token

    def read_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError("A JSON request is required.", 415)
        length = self.body_length(16384)
        try:
            result = json.loads(self.rfile.read(length))
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, UnicodeDecodeError):
            raise ApiError("Invalid request data.") from None

    def body_length(self, maximum):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise ApiError("A valid content length is required.", 411)
        if length < 0:
            raise ApiError("A content length is required.", 411)
        if length > maximum:
            self.close_connection = True
            raise ApiError("The file exceeds the 100 MB upload limit." if maximum == MAX_UPLOAD else "Request is too large.", 413)
        return length

    def dispatch(self):
        try:
            self.guard_request()
            parsed = urlsplit(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if not path.startswith("/api/"):
                if self.command != "GET":
                    raise ApiError("Method not allowed.", 405)
                return self.static(path)
            return self.api(path, query)
        except ApiError as error:
            # Close on rejected bodies, so unread bytes cannot become another
            # HTTP request on the keep-alive connection.
            if self.command != "GET":
                self.close_connection = True
            self.respond({"error": error.message}, error.status)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except (OSError, sqlite3.Error, ValueError):
            self.close_connection = True
            self.respond({"error": "The request could not be completed. Check the local server."}, 500)

    do_GET = dispatch
    do_POST = dispatch
    do_DELETE = dispatch

    def static(self, path):
        # Never serve auth.py, database files, private keys or arbitrary paths.
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/assets/styles.css": ("styles.css", "text/css; charset=utf-8")}
        if path not in assets:
            raise ApiError("Page not found.", 404)
        name, content_type = assets[path]
        payload = (WEB_ROOT / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def api(self, path, query):
        method = self.command
        if path == "/api/login" and method == "POST":
            data = self.read_json()
            username, password = data.get("username", ""), data.get("password", "")
            if not isinstance(username, str) or not isinstance(password, str) or len(password) > 4096:
                raise ApiError("Invalid sign-in details.")
            client = "terminal" if data.get("client") == "terminal" else "browser"
            token, session = self.app.login(username, password, self.client_address[0], client)
            cookie = f"relay_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
            if self.app.secure:
                cookie += "; Secure"
            return self.respond(self.session_payload(session), headers={"Set-Cookie": cookie})

        session, token = self.current_session(mutate=method != "GET", admin=path.startswith("/api/admin/"))
        username = session["username"]
        if path == "/api/session" and method == "GET":
            return self.respond(self.session_payload(session))
        if path == "/api/logout" and method == "POST":
            with self.app.lock:
                self.app.sessions.pop(self.app.token_key(token), None)
            return self.respond({"ok": True}, headers={"Set-Cookie": "relay_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if self.app.secure else "")})
        if path == "/api/files" and method == "GET":
            files = self.app.files(username)
            return self.respond({"files": files, "used": sum(item["size"] for item in files), "quota": USER_QUOTA})
        if path == "/api/files" and method == "POST":
            return self.upload(username, query.get("name", [""])[0])
        if path == "/api/files" and method == "DELETE":
            name = query.get("name", [""])[0]
            file_path = self.app.file_path(username, name)
            with self.app.file_lock_for(username):
                if not file_path.is_file():
                    raise ApiError("File not found.", 404)
                file_path.unlink()
            self.app.event(username, "deleted", name)
            return self.respond({"ok": True})
        if path in {"/api/download", "/api/preview"} and method == "GET":
            return self.download(username, query.get("name", [""])[0], preview=path.endswith("preview"))
        if path == "/api/activity" and method == "GET":
            return self.respond({"events": self.app.events(username)})
        if path == "/api/password" and method == "POST":
            data = self.read_json()
            old, new = data.get("current", ""), data.get("password", "")
            if not isinstance(old, str) or not isinstance(new, str) or not new or len(new) > 4096:
                raise ApiError("Enter a valid new password.")
            if not self.app.auth.authenticate_user(username, old, self.app.db_path):
                raise ApiError("Your current password is incorrect.", 400)
            self.app.auth.set_password(username, new, self.app.db_path)
            with self.app.lock:
                key = self.app.token_key(token)
                for other in list(self.app.sessions):
                    if other != key and self.app.sessions[other]["username"] == username:
                        del self.app.sessions[other]
            self.app.event(username, "password_changed")
            return self.respond({"ok": True})
        if path == "/api/admin/status" and method == "GET":
            return self.admin_status()
        if path == "/api/admin/users" and method == "POST":
            data = self.read_json()
            name, password = data.get("username", ""), data.get("password", "")
            if not isinstance(name, str) or not isinstance(password, str) or not password or len(password) > 4096:
                raise ApiError("Enter a valid username and password.")
            with self.app.db() as db:
                exists = db.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone()
            # Explicit create/reset intent prevents an accidental username clash
            # from silently resetting someone else's password.
            if bool(exists) != bool(data.get("reset")):
                raise ApiError("That account already exists." if exists else "Account not found.", 409)
            try:
                self.app.auth.set_password(name, password, self.app.db_path)
            except ValueError as error:
                raise ApiError(str(error)) from None
            with self.app.lock:
                for key in list(self.app.sessions):
                    if self.app.sessions[key]["username"] == name:
                        del self.app.sessions[key]
            self.app.event(username, "account_password_reset" if exists else "account_created", name)
            return self.respond({"ok": True})
        if path == "/api/admin/revoke" and method == "POST":
            data = self.read_json()
            session_id = data.get("id", "")
            # Session IDs shown in the dashboard are digests, not usable cookies.
            if session_id == self.app.token_key(token):
                raise ApiError("Use Sign out to end your current session.")
            with self.app.lock:
                self.app.sessions.pop(session_id, None)
            self.app.event(username, "session_ended")
            return self.respond({"ok": True})
        raise ApiError("Endpoint not found.", 404)

    def session_payload(self, session):
        return {"username": session["username"], "admin": self.app.is_admin(session["username"]),
                "csrf": session["csrf"], "secure": self.app.secure,
                "expires": session["expires"], "max_upload": MAX_UPLOAD}

    def upload(self, username, name):
        length = self.body_length(MAX_UPLOAD)
        destination = self.app.file_path(username, name)
        # The raw file body avoids a multipart parser and streams to disk instead
        # of buffering a whole 100 MB file in memory. A temporary file prevents
        # incomplete uploads appearing in the user's browser listing.
        with self.app.file_lock_for(username):
            if destination.exists():
                raise ApiError("A file with that name already exists. Rename it before uploading.", 409)
            if sum(item["size"] for item in self.app.files(username)) + length > USER_QUOTA:
                raise ApiError("This upload would exceed your 1 GB web storage allowance.", 413)
            descriptor, temporary = tempfile.mkstemp(prefix=".upload-", dir=destination.parent)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            raise ApiError("Upload interrupted. Please try again.")
                        output.write(chunk)
                        remaining -= len(chunk)
                # Hard linking publishes without overwriting a file another upload may
                # have created while this request was streaming.
                try:
                    os.link(temporary, destination)
                except FileExistsError:
                    raise ApiError("A file with that name already exists.", 409) from None
            finally:
                Path(temporary).unlink(missing_ok=True)
        self.app.event(username, "uploaded", name, length)
        return self.respond({"ok": True}, 201)

    def download(self, username, name, preview=False):
        path = self.app.file_path(username, name)
        if not path.is_file():
            raise ApiError("File not found.", 404)
        ext = path.suffix.lower()
        if preview and ext in TEXT_EXTENSIONS:
            with path.open("rb") as file:
                content = file.read(256 * 1024 + 1)
            return self.respond({"kind": "text", "text": content[:256 * 1024].decode("utf-8", errors="replace"),
                                 "truncated": len(content) > 256 * 1024})
        if preview and ext not in IMAGE_TYPES:
            return self.respond({"kind": "unsupported", "message": "Download this file to open it on your device."})
        info = path.stat()
        self.send_response(200)
        self.send_header("Content-Length", str(info.st_size))
        self.send_header("Content-Type", IMAGE_TYPES[ext] if preview else "application/octet-stream")
        self.send_header("Content-Disposition", ("inline" if preview else "attachment") + "; filename*=UTF-8''" + quote(name, safe=""))
        self.security_headers()
        self.end_headers()
        with path.open("rb") as file:
            shutil.copyfileobj(file, self.wfile, length=65536)
        if not preview:
            self.app.event(username, "downloaded", name, info.st_size)

    def admin_status(self):
        with self.app.db() as db:
            users = db.execute("SELECT u.username, CASE WHEN a.username IS NULL THEN 0 ELSE 1 END AS admin FROM users u LEFT JOIN web_admins a ON u.username = a.username ORDER BY u.username").fetchall()
        rows = []
        for user in users:
            files = self.app.files(user["username"])
            rows.append({"username": user["username"], "admin": bool(user["admin"]),
                         "files": len(files), "used": sum(item["size"] for item in files)})
        with self.app.lock:
            self.app.prune_sessions()
            sessions = [{"id": key, "username": value["username"], "created": value["created"],
                         "last_seen": value["last_seen"], "client": value["client"]} for key, value in self.app.sessions.items()]
        return self.respond({"users": rows, "sessions": sessions, "events": self.app.events(),
                             "uptime": int(time.time() - self.app.started), "secure": self.app.secure,
                             "disk_free": shutil.disk_usage(self.app.storage).free,
                             "max_upload": MAX_UPLOAD, "quota": USER_QUOTA,
                             "files": sum(row["files"] for row in rows), "used": sum(row["used"] for row in rows)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--http", action="store_true", help="Loopback-only HTTP for local UI development")
    parser.add_argument("--public-origin", help="One trusted tunnel HTTPS origin; local HTTPS is still required")
    parser.add_argument("--grant-admin", metavar="USERNAME", help="Grant an existing user web-admin access, then exit")
    args = parser.parse_args()
    if args.http and args.host not in {"127.0.0.1", "localhost"}:
        parser.error("HTTP preview must stay on loopback. Use HTTPS for other devices.")
    try:
        public_origin = normalise_public_origin(args.public_origin) if args.public_origin else None
        if public_origin and (args.http or args.host not in {"127.0.0.1", "localhost"}):
            raise ValueError("Tunnel mode must use HTTPS on loopback, without --http or a LAN bind.")
        app = Application(secure=not args.http)
        if args.grant_admin:
            app.grant_admin(args.grant_admin)
            print("Administrator access granted.")
            return
        # Validate the certificate/key before opening the listening socket.
        # HTTPS uses the same documented context settings as the CLI client.
        context = None if args.http else create_server_context(
            app.project / "certs/server.crt", app.project / "certs/server.key"
        )
        server = WebServer((args.host, args.port), app, public_origin=public_origin)
        server.tls_context = context
        print(f"Relay is ready: {'http' if args.http else 'https'}://{args.host}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    except (OSError, ValueError, sqlite3.Error, ImportError) as error:
        parser.exit(1, f"Cannot start Relay: {error}\n")


if __name__ == "__main__":
    main()
