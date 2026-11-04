# Code walkthrough: one server for both clients

Start **`python3 server.py`**, then open **https://127.0.0.1:8443**. For local
HTTP development only, use `python3 server.py --http --port 8080` and open
http://127.0.0.1:8080. Existing accounts and files remain in this repository.

## Request flow

```text
Browser JavaScript or terminal client
           ↓ HTTPS request
server.py → Handler → Application
           ↓
auth.py / database.py / user file folder
           ↓
HTTP response (JSON, image, or downloaded bytes)
```

There is one backend and no browser-to-terminal-server bridge. Both clients call
one implementation of each operation. A bug fix to deletion or access checking
in `server.py` therefore applies to both interfaces.

## Read in this order

1. **`auth.py`** — salts, password derivation, hash verification, and account setup.
   Password hashing protects stored credentials; HTTPS protects traffic.
2. **`database.py`** — the users table, parameterised lookups and password upserts.
3. **`server.py` → `Application`** — sessions, administrator roles, event storage,
   file names/ownership and account boundaries. Defaults use this project folder;
   tests pass a disposable data directory instead.
4. **`server.py` → `Handler`** — routes, request parsing, status codes, CSRF checks,
   JSON responses, streaming upload/download, previews and admin operations.
5. **`web/app.js`** — browser state, API calls, progress updates and rendering.
   Browser code cannot decide who is an administrator; the backend checks this.
6. **`client.py` → `RelayClient`** — the same requests from Python, using a cookie
   jar and CSRF token. It never compares passwords or accesses server-side files.
7. **`tls_transport.py` / `setup_tls.py`** — contexts, trusted server certificates,
   identity checks and creation of local-development certificate/key pairs.

The HTML and CSS stay in `web/` because they are frontend assets. `auth.py` and
`database.py` remain small utility modules. None of these is a second backend.
`web_server.py` has been removed.

## Important API routes

| Request | Operation |
| --- | --- |
| `POST /api/login` | Verify credentials; create a session cookie and CSRF token |
| `GET /api/session` | Check the current identity and role |
| `GET /api/files` | List the current user's files |
| `POST /api/files?name=...` | Stream a file into that user's folder |
| `DELETE /api/files?name=...` | Validate ownership/path and delete a file |
| `GET /api/download?name=...` | Stream a file to the authenticated client |
| `GET /api/preview?name=...` | Return safe text/image previews |
| `POST /api/password` | Change a password and revoke other sessions |
| `GET /api/admin/status` | Fetch administrator-only statistics, sessions and events |
| `POST /api/admin/users` | Create a client account or explicitly reset its password |
| `POST /api/admin/revoke` | End another client session |
| `POST /api/logout` | Revoke the current session |

Mutating requests require a CSRF token, except login which enforces origin and
request-type rules. API handlers also authenticate the cookie and enforce the
role; hiding an admin button is not an access-control mechanism.

## Administrator setup

```sh
python3 server.py --grant-admin YOUR_USERNAME
```

This grants a role to an existing account and exits. It does not start a second
server. Reload the browser to reveal the Server view. New accounts created from
that dashboard are client accounts; administrator grants require this local command.

The persisted `web_admins` and `web_events` table names are retained for backwards
compatibility. They are used by the one server and include terminal API activity.
No account migration or password reset is required for this consolidation.

## TLS and local development

HTTPS uses the existing certificate/key. The self-signed development certificate
requires browser trust; review it yourself rather than ignoring unexpected warnings.
The terminal client verifies the public certificate directly. Never copy the
private key to a client. HTTP preview is restricted to loopback and is labelled
unencrypted; it is not supported by the terminal client.

For another device on Wi-Fi, configure a trusted certificate with the correct
LAN hostname/IP and use `--host YOUR_LAN_IP`. Ports 9999/10000 and the old EOF
protocol are no longer used; both real clients share port 8443 by default.

## Tests

- `tests/test_auth.py`: salts, hashes, account updates, uniqueness and SQLite threads.
- `tests/test_tls.py`: real TLS verification and the terminal client talking to
  the actual server entry point over HTTPS, including binary upload/download.
- `tests/test_web.py`: the same HTTP API for browser use, including isolation,
  admin permissions, sessions, expiry, CSRF, limits and secure cookies.

Run `python3 -B -m unittest discover -s tests -v`. Tests use temporary data and do
not start persistent application/preview servers.


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
