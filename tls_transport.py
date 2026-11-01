"""TLS configuration shared by the client and server.

TLS encrypts traffic and authenticates the server certificate. Username/password
login remains a separate application step; this is not mutual/client-certificate TLS.
"""

from pathlib import Path
import socket
import ssl


CERT_DIRECTORY = Path(__file__).resolve().with_name("certs")
CERT_FILE = CERT_DIRECTORY / "server.crt"
KEY_FILE = CERT_DIRECTORY / "server.key"
HANDSHAKE_TIMEOUT = 5


def create_server_context(cert_file=CERT_FILE, key_file=KEY_FILE):
    """Load the server's public certificate and matching private key."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Negotiate TLS 1.3 when supported; never accept TLS versions below 1.2.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def create_client_context(cert_file=CERT_FILE):
    """Trust the local development certificate and verify the requested host."""
    # cafile explicitly trusts this development certificate. A different server
    # certificate is rejected. Keep hostname verification and CERT_REQUIRED on;
    # disabling either would allow an impostor to receive the user's password.
    context = ssl.create_default_context(cafile=str(cert_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Require Subject Alternative Names rather than the legacy Common Name.
    context.hostname_checks_common_name = False
    return context


def wrap_server_connection(connection, context, timeout=HANDSHAKE_TIMEOUT):
    """Finish TLS before passing an accepted connection to application code."""
    connection.settimeout(timeout)
    try:
        secure = context.wrap_socket(connection, server_side=True)
    except BaseException:
        # Includes a failed TLS handshake or Ctrl+C during the handshake.
        connection.close()
        raise
    # The timeout limits handshakes, not how long users may spend typing.
    secure.settimeout(None)
    return secure


def connect_tls(host, port, context, timeout=HANDSHAKE_TIMEOUT):
    """Connect and verify TLS before returning a socket that can carry secrets."""
    connection = socket.create_connection((host, port), timeout=timeout)
    try:
        # server_hostname enables identity verification, including IP SAN checks
        # when host is 127.0.0.1. Connecting by a different name requires a cert
        # whose SAN includes that name; never bypass verification to work around it.
        secure = context.wrap_socket(connection, server_hostname=host)
    except BaseException:
        connection.close()
        raise
    secure.settimeout(None)
    return secure
