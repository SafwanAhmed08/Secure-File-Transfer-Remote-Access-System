# Secure File Transfer & Remote Access System

A local file server with a browser interface and an optional terminal client.
**`server.py` is the only backend.** Both clients use its HTTPS API for the same
authentication, file operations, permissions, limits and activity records.

## Run the application

From this repository:

```sh
python3 server.py
```

Open **https://127.0.0.1:8443** and use your existing username and password.
Stop the server with Ctrl+C. You do not need `client.py` for the website.

The localhost development certificate is self-signed, so your browser must trust
it before using HTTPS. Review/trust your own certificate yourself. For UI work
without configuring browser trust, use loopback-only development mode:

```sh
python3 server.py --http --port 8080
```

Then open **http://127.0.0.1:8080**. This mode is unencrypted and cannot bind to
another device's address. The terminal client requires HTTPS.

## First-time setup only

Skip these steps if accounts and certificates already exist:

```sh
# Generate a local development certificate/key; existing keys are never replaced.
python3 setup_tls.py

# Create an account. Running this for an existing username resets its password.
python3 auth.py set-password alice
```

Passwords are entered through hidden prompts and stored as salted
PBKDF2-HMAC-SHA256 hashes in `users.db`. The old plaintext credential file is not
used. Database and upload directories are resolved relative to this repository.
Existing accounts, hashes, administrator grants and uploaded files are preserved.

## Server dashboard

No user is automatically an administrator. Grant access when ready:

```sh
python3 server.py --grant-admin YOUR_USERNAME
```

Refresh the browser page to see the **My workspace / Server** switch. Every admin
API request checks the role on the server; switching frontend views cannot grant
permissions. The dashboard shows actual storage/account/session statistics,
account creation and password reset, session revocation, and recent activity.
Sessions and audit events cover browser **and terminal** API clients.

## Optional terminal interface

With the same HTTPS server running:

```sh
python3 client.py
```

It offers upload, list, download, delete, preview and sign out. It does not read
`users.db` or manage server-side files directly. It calls the exact same API as
the browser, including CSRF/session protection and file limits. The server's
certificate is verified against `certs/server.crt`; its private key is never used
by the client. Use `--url` and `--cert` for another trusted HTTPS server.

## One backend, one implementation

```text
Browser: web/index.html + styles.css + app.js ─┐
                                            ├─ HTTPS :8443 ─ server.py
Optional terminal: client.py ────────────────┘                  │
                                                              ├─ auth.py
                                                              ├─ database.py → users.db
                                                              └─ server_uploads/client_USERNAME/
```

`server.py` owns HTTP routing, sessions, user/admin authorisation, upload streaming,
listing, previews, downloads, deletion, limits and audit records. `auth.py` and
`database.py` are shared helper modules, not independent servers. Importing the
server does not start listeners, register signal handlers or modify account data.

The old custom TCP/EOF protocol has been replaced by HTTP requests with explicit
body lengths. Files containing `EOF` bytes transfer normally. There are no
separate shutdown connections or duplicate file-operation implementations.

## Browser features

- Responsive client workspace and administrator dashboard.
- Multi-file selection and drag/drop uploads with progress.
- File search, type filters, sorting, list/grid views, and confirmed deletion.
- Safe text/image previews and downloads for other file types.
- Account settings, activity, user management and client session revocation.

All files stay on your local server. No external JavaScript, fonts, analytics or
hosted storage is used. The server is a Python standard-library development
server; internet deployment needs a production stack and deployment hardening.

## Security and limits

- HTTPS defaults to TLS 1.2 or newer. `certs/server.key` stays private and untracked.
- Password hashes use PBKDF2-HMAC-SHA256, 600,000 iterations, and a random 16-byte salt.
- Sessions expire after 8 hours and live in memory; restart signs clients out.
- HTTPS cookies are Secure, HttpOnly and SameSite=Strict. Mutations need a CSRF token.
- Filename/path validation and per-user folders restrict file access.
- Uploads are limited to 100 MB per file and 1 GB per account for **both** clients.
- Duplicate filenames never overwrite existing server files.
- Login attempts are rate-limited; static serving never exposes source, keys or the DB.
- API password resets revoke affected sessions. Password changes through the local
  `auth.py` command do not revoke already-issued sessions.
- Audit history is bounded to 5,000 events. Disk files are not encrypted at rest.

For another device, use HTTPS with a device-trusted certificate covering the Mac's
actual LAN IP/name and bind using `--host YOUR_LAN_IP`. The localhost certificate
alone does not configure Android/LAN access.

## Tests and learning guide

```sh
python3 -B -m unittest discover -s tests -v
node --check web/app.js
```

Tests use disposable accounts, files, keys and ports. They cover password storage,
verified TLS, both API clients, binary transfers, ownership boundaries, admin
permissions, CSRF, expiry, rate limits and file validation. No real user data is
changed. Read [WEB_INTERFACE.md](WEB_INTERFACE.md) for the code walkthrough.


## Temporary phone access through Cloudflare Tunnel

This is an opt-in development tunnel, not a permanent deployment. Keep the app
bound to loopback. Both phone-to-Cloudflare and Cloudflare-to-this-server use TLS;
cloudflared explicitly trusts the local certificate. Nothing disables TLS checks.

Install the connector on the Mac once:

```sh
brew install cloudflared
```

From this repository, start the connector in one terminal:

```sh
cloudflared tunnel --url https://127.0.0.1:8443 --origin-ca-pool certs/server.crt
```

It prints a temporary `https://...trycloudflare.com` URL. The origin may report
connection refused until the app starts. In a second terminal, use that exact URL:

```sh
python3 server.py --public-origin https://YOUR-EXACT-URL.trycloudflare.com
```

Open the printed public URL on your phone and sign in. No phone certificate
installation or same-Wi-Fi requirement is needed. The server permits only the
explicit public hostname, keeps Origin and CSRF checks, and still issues Secure
cookies. Do not use `--http`, `--no-tls-verify`, wildcard hosts or router port forwarding.

The tunnel exposes the app's login page to the internet, and Cloudflare carries
its traffic. Use test data for this development server. Anyone with the link can
reach the login page; file access still requires an account. Both the Mac and
both processes must stay running. Ctrl+C stops them. Quick Tunnel URLs are
for testing, change between runs, and stop working when the connector exits.
Use a named tunnel/custom domain for a stable deployment.

If a new tunnel URL is generated, restart `server.py` with the new exact origin.
If you replaced the self-signed certificate with a CA-signed one, point
`--origin-ca-pool` at its issuer's public CA bundle instead. Never share a private key.

References: [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
and [HTTPS origin settings](https://developers.cloudflare.com/tunnel/troubleshooting/).
