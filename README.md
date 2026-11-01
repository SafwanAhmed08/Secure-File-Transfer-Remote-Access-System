# Distributed File Orchestration and Synchronization: Multi-Node Data-Transfer-Framework for Linux

## System Architecture Overview

### 1. Network Communication Model
- Protocol: Custom TCP communication over verified TLS (minimum TLS 1.2)
- Host: Localhost (127.0.0.1)
- Primary Port: 9999
- Termination Port: 10000
- Buffer Size: 128 KB

### 2. Authentication Mechanism
- Credential Storage: SQLite (`users.db`), containing salted PBKDF2-HMAC-SHA256 password hashes
- Authentication Flow:
  1. Client sends username/password
  2. Server looks up the user in SQLite and verifies the stored password hash
  3. Successful login generates user-specific session
  4. Failed attempts trigger re-authentication

### 3. User Session Management
- User-specific directory creation: `client_{username}`
- Isolated file storage per user
- Concurrent user support via threading

## System Components

### Core Modules
1. **Authentication Module**
   - User credential verification
   - Session initialization
   - Access control

2. **File Management Module**
   - Upload/download capabilities
   - File listing
   - File preview
   - File deletion

3. **Communication Handler**
   - Socket management
   - Client-server interaction
   - Graceful termination protocols

## Security Considerations and Future Enhancements

### Recommended Security Upgrades
1. **Authentication Improvements**
   - Salted password hashing implemented; add login rate limiting
   - Add multi-factor authentication
   - Create role-based access control

2. **Communication Security**
   - TLS implemented on both connections with client-side server certificate verification
   - Implement certificate-based authentication
   - Add secure key exchange mechanism

3. **Logging and Auditing**
- Objective: Track client activity and detect suspicious behavior.
- Include system-level alerts for failed uploads/downloads or unauthorized access attempts.


### Proposed Encryption Strategy
- Implement asymmetric key encryption for initial handshake
- Use AES-256 for subsequent symmetric encryption
- Rotate encryption keys periodically

## System Limitations and Constraints
- Single-host deployment
- Local development certificate requires explicit trust and expires after 30 days
- No advanced access control
- Limited file type support

## Performance Optimization Strategies
- Implement connection pooling
- Add concurrent file transfer capabilities
- Optimize buffer management
- Introduce transfer resumption mechanism

## Compliance and Standards
- POSIX file system compatibility
- Linux kernel socket programming standards
- Basic OWASP security recommendations

## Deployment Guidelines
1. Create an account with `python3 auth.py set-password USERNAME`
2. Set appropriate file permissions
3. Configure firewall rules
4. Enable logging mechanisms

## Potential Extension Points
- Cloud storage integration
- Distributed file synchronization
- Advanced metadata management
- Machine-to-machine transfer protocols

## Recommended Technology Stack
- Python 3.8+
- Socket Programming
- Threading
- SSL/cryptography libraries
- Logging frameworks

## Error Handling and Resilience
- Graceful connection termination
- Comprehensive exception management
- Client-side and server-side timeout mechanisms

## Monitoring and Observability
- System health checks
- Performance metrics collection
- Real-time activity tracking

## License and Usage
- Open-source
- Community-driven development model

## Contribution Guidelines
1. Write comprehensive unit tests
2. Document all new features
3. Maintain backward compatibility



## SQLite accounts: running and understanding the code

Only Python's standard library is required. The old `id_passwd.txt` is no longer
read or written. Existing text-file accounts are not imported; create fresh
accounts. Existing SQLite accounts are preserved.

```sh
# Optional: create an empty database and users table.
python3 database.py

# Create an account, or replace the password for an existing username.
# Passwords are entered at hidden prompts, not included in the command.
python3 auth.py set-password alice

# Once per local checkout: generate the development certificate.
python3 setup_tls.py

# In separate terminals:
python3 server.py
python3 client.py
```

`set-password` and the server both initialise the schema automatically, so running
`database.py` separately is optional. Database creation never makes a default user.
The database path is anchored to `database.py`; running from another working
folder uses the same account store. Keep `users.db` and related journal files out
of Git. The file is restricted to owner access on macOS/Linux. Real passwords
previously committed to Git should be changed; ignoring a file does not remove
its history.

### Read the implementation in this order

1. **`auth.hash_password`** derives a PBKDF2-HMAC-SHA256 hash with 600,000
   iterations and a fresh 16-byte random salt. The stored string includes the
   algorithm, iteration count, salt, and digest. Hashing does not encrypt a password.
2. **`database.initialise_database`** defines a users table. `UNIQUE` enforces
   distinct usernames and creates an index; `NOT NULL` does not reject empty
   strings, so `auth.py` validates usernames and rejects empty passwords.
3. **`auth.set_password`** hashes first, then saves through a database upsert.
   A reset updates one row without changing its user ID or rewriting every account.
4. **`database.get_password_hash`** looks up one user using a `?` parameter.
   Parameters separate user input from SQL syntax and prevent SQL injection.
5. **`auth.authenticate_user`** retrieves that hash and verifies it with the
   original salt and a constant-time digest comparison. Missing users, invalid
   hashes, and incorrect passwords are rejected. No plaintext fallback exists.
6. **`server.validate_user`** retries login in a loop. `on_user` checks its boolean
   result before opening the file menu. There is one authentication handler.

Each database operation owns its connection, so client threads do not share a
SQLite connection. Transactions commit successful updates and roll back failed
updates. Connections are explicitly closed afterward. SQLite supports one writer
at a time; connections wait up to five seconds for a write lock. Password hashing
happens before the write transaction to keep that lock short. Password resets are
seen by subsequent login attempts; they do not revoke already logged-in sessions.

Run the regression tests:

```sh
python3 -B -m unittest discover -s tests -v
```

The tests use temporary databases, never real account data. They cover hashing,
account creation/reset, uniqueness, SQL parameter handling, threaded lookups,
and the rule that failed authentication cannot enter the file menu.

### Remaining security work

Both TCP connections now require TLS, including the shutdown notification port.
Message framing, login rate limiting, secure pairing of simultaneous clients'
two connections, and validation of file-operation paths remain separate
improvements. TLS protects bytes in transit; it does not fix these application
protocol or authorisation issues.


## TLS: setup and learning guide

```sh
# Generate a local certificate/key (already generated when TLS was installed).
python3 setup_tls.py

# Start in separate terminals. Existing SQLite accounts still work.
python3 server.py
python3 client.py
```

No new Python packages are needed. Certificate creation uses the installed
`openssl` command. `setup_tls.py` refuses to overwrite an existing certificate or
key. The generated certificate is valid for 30 days and covers `localhost`,
`127.0.0.1`, and `::1`; the application's default connections still use IPv4
`127.0.0.1` on ports 9999 and 10000. Expired certificates are rejected.

- **`certs/server.key`** is the private key, readable only by its owner on
  macOS/Linux. Keep it on the server and never commit or distribute it.
- **`certs/server.crt`** is the public certificate. The client explicitly trusts
  this file and verifies that the hostname/IP it connects to appears in its
  Subject Alternative Names. Install it on a client through a trusted channel.
- Both artifacts are ignored by Git. Copy only `server.crt` to a different
  client's `certs/` folder; it does not need `server.key` or account database files.

For certificate renewal, stop the server, deliberately move the old certificate
and key to a private location, rerun `setup_tls.py`, and replace trusted copies
on clients. Changing HOST to another IP/name requires a certificate with that
IP/name in its SAN. Do not disable verification to bypass an error. For deployment,
use an appropriate CA-issued certificate and trust configuration instead of this
localhost development certificate. Trust is configured per application; nothing
is installed into the operating system's trust store.

### What the code does

1. `create_server_context()` loads the certificate and private key. A minimum
   TLS version of 1.2 allows negotiation of TLS 1.3 on supported installations.
2. `create_client_context()` loads the trusted certificate. Certificate and
   hostname verification remain enabled; no insecure/plaintext fallback exists.
3. `connect_tls()` connects TCP, then completes a verified TLS handshake before
   returning the socket. No username, password or file data is sent before that.
4. The server accepts a TCP socket and wraps it with TLS before accepting and
   securing the notification socket. That ordering avoids a startup deadlock.
5. Handshakes and the wait for the second connection have a five-second timeout.
   After a handshake, sockets return to blocking mode so typing a password or
   selecting a file is not subject to that short timeout.
6. Application `sendall()` and `recv()` calls then pass through the TLS socket:
   the TLS library handles encryption, integrity checks and session keys.
   SQLite password hashing and username/password login remain separate.

This uses server-authenticated TLS, not mutual TLS: the client verifies the
server certificate, and the server authenticates users through their passwords.
See [Python's ssl documentation](https://docs.python.org/3/library/ssl.html).

The upload EOF marker was also corrected to match the receiver exactly; the
previous `.EOF` marker appended an extra dot to uploaded files. The legacy EOF
protocol still needs length-based framing for arbitrary binary contents and
unpredictable TCP/TLS read boundaries.

Run `python3 -B -m unittest discover -s tests -v` for authentication and TLS tests.
TLS tests use temporary keys/certificates and account data. They exercise trusted
connections, untrusted/wrong-host rejection, plaintext rejection, bounded
handshakes, both application channels, and encrypted upload/download behavior.
