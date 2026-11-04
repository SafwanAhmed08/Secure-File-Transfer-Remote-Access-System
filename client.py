"""Optional terminal interface to the SAME API used by the browser.

Start `python3 server.py`, then run `python3 client.py`. This client performs no
server-side file operations and never reads users.db. All permissions, hashing,
limits and activity recording are handled by server.py through verified HTTPS.
"""

import argparse
import getpass
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, HTTPSHandler, Request

from tls_transport import CERT_FILE, create_client_context


class ClientError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class RelayClient:
    def __init__(self, base_url="https://127.0.0.1:8443", cert_file=CERT_FILE):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("The terminal client requires an HTTPS server URL.")
        self.base_url = base_url.rstrip("/")
        # Certificate trust and hostname checks stay enabled. CookieJar keeps the
        # issued session cookie for this process, not on disk or in command history.
        self.opener = build_opener(
            HTTPCookieProcessor(CookieJar()),
            HTTPSHandler(context=create_client_context(cert_file)),
        )
        self.csrf = None
        self.username = None

    def request(self, path, method="GET", data=None, body=None, headers=None):
        headers = dict(headers or {})
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if method != "GET" and self.csrf:
            # Same mutation protection used by web/app.js; terminal clients do
            # not get a privileged bypass of the browser's API permissions.
            headers["X-CSRF-Token"] = self.csrf
        request = Request(self.base_url + "/api/" + path, data=body,
                          headers=headers, method=method)
        try:
            return self.opener.open(request, timeout=30)
        except HTTPError as error:
            try:
                message = json.loads(error.read()).get("error", "Request failed.")
            except (ValueError, UnicodeDecodeError):
                message = f"Server returned HTTP {error.code}."
            finally:
                error.close()
            raise ClientError(message, error.code) from None
        except (URLError, OSError) as error:
            raise ClientError(f"Cannot reach the secure server: {error}") from None

    def api(self, path, method="GET", data=None):
        with self.request(path, method, data=data) as response:
            return json.load(response)

    def login(self, username, password):
        session = self.api("login", "POST", {"username": username, "password": password,
                                              "client": "terminal"})
        self.csrf, self.username = session["csrf"], session["username"]
        return session

    def logout(self):
        result = self.api("logout", "POST")
        self.csrf = self.username = None
        return result

    def list_files(self):
        return self.api("files")["files"]

    def upload(self, file_path):
        file_path = Path(file_path).expanduser()
        # Sending the known byte length lets the server stream exactly this
        # file. Literal EOF bytes are ordinary data, not protocol terminators.
        with file_path.open("rb") as body:
            size = os.fstat(body.fileno()).st_size
            with self.request("files?name=" + quote(file_path.name, safe=""), "POST", body=body,
                              headers={"Content-Type": "application/octet-stream",
                                       "Content-Length": str(size)}) as response:
                return json.load(response)

    def download(self, name, destination):
        destination = Path(destination).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ClientError("The destination already exists. Choose another filename.")
        temporary_path = None
        try:
            with self.request("download?name=" + quote(name, safe="")) as response:
                # Publish only after the declared response body has arrived.
                expected = int(response.headers["Content-Length"])
                with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
                    temporary_path = Path(temporary.name)
                    shutil.copyfileobj(response, temporary, length=65536)
                    if temporary.tell() != expected:
                        raise ClientError("Download interrupted; incomplete data was discarded.")
            os.link(temporary_path, destination)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
        return destination

    def delete(self, name):
        return self.api("files?name=" + quote(name, safe=""), "DELETE")

    def preview(self, name):
        with self.request("preview?name=" + quote(name, safe="")) as response:
            if response.headers.get_content_type().startswith("image/"):
                return "Image preview is available in the browser interface."
            data = json.load(response)
            text = data.get("text", data.get("message", "Preview is unavailable."))
            return text + ("\n[Preview truncated]" if data.get("truncated") else "")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:8443")
    parser.add_argument("--cert", type=Path, default=CERT_FILE,
                        help="Trusted public server certificate; never the private key")
    args = parser.parse_args()
    client = None
    try:
        client = RelayClient(args.url, args.cert)
        while True:
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            try:
                client.login(username, password)
                break
            except ClientError as error:
                print(error)
                if error.status != 401:
                    return
        print("Signed in to the same server used by the browser.")
        while True:
            print("\n1 Upload  2 List files  3 Download  4 Delete  5 Preview  6 Sign out")
            option = input("Choose an option: ").strip()
            try:
                if option == "1":
                    client.upload(input("File path: ").strip())
                    print("File uploaded.")
                elif option == "2":
                    files = client.list_files()
                    for file in files:
                        print(f"{file['name']} ({file['size']} bytes)")
                    if not files:
                        print("No files yet.")
                elif option == "3":
                    name = input("Server filename: ").strip()
                    default = Path("fromserver") / client.username / Path(name).name
                    destination = input(f"Save as [{default}]: ").strip() or default
                    print(f"Saved to {client.download(name, destination)}")
                elif option == "4":
                    name = input("Server filename: ").strip()
                    if input("Permanently delete this file? Type yes: ").strip() == "yes":
                        client.delete(name)
                        print("File deleted.")
                elif option == "5":
                    print(client.preview(input("Server filename: ").strip()))
                elif option == "6":
                    return
                else:
                    print("Choose a number from 1 to 6.")
            except (ClientError, OSError) as error:
                print(error)
                if isinstance(error, ClientError) and error.status == 401:
                    return  # Re-run to sign in after session expiry/revocation.
    except (ClientError, OSError, ValueError, ssl.SSLError) as error:
        print(error)
    except (EOFError, KeyboardInterrupt):
        print("\nClosing client.")
    finally:
        if client is not None and client.csrf:
            try:
                client.logout()
            except ClientError:
                pass


if __name__ == "__main__":
    main()
