"""Create a local-development certificate using the installed OpenSSL command.

This certificate is for localhost testing only. The client must receive a trusted
copy of server.crt. Never copy server.key to clients or commit it to Git.
"""

import argparse
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile

from tls_transport import CERT_DIRECTORY, create_server_context


# Subject Alternative Names are what the client verifies. IP and DNS names are
# different SAN types, so include both the default loopback IP and localhost.
# The key-usage extensions describe a TLS server certificate, not a signing CA.
CERT_CONFIG = """
[req]
prompt = no
distinguished_name = subject
x509_extensions = server_extensions
[subject]
CN = localhost
[server_extensions]
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def generate_certificate(directory=CERT_DIRECTORY, days=30):
    """Generate a matching key/certificate without overwriting existing trust."""
    if shutil.which("openssl") is None:
        raise ValueError("OpenSSL is required to generate the development certificate.")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    certificate, key = directory / "server.crt", directory / "server.key"
    if certificate.exists() or key.exists():
        raise ValueError("Certificate/key already exists. Existing files were not replaced.")

    # Generate and validate privately before publishing either output file.
    with tempfile.TemporaryDirectory(prefix=".tls-", dir=directory) as temporary:
        temporary = Path(temporary)
        config = temporary / "openssl.cnf"
        config.write_text(CERT_CONFIG)
        temp_cert, temp_key = temporary / "server.crt", temporary / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
            "-nodes", "-days", str(days), "-config", str(config),
            "-keyout", str(temp_key), "-out", str(temp_cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        create_server_context(temp_cert, temp_key)

        created = []
        try:
            for source, destination, mode in (
                (temp_key, key, 0o600), (temp_cert, certificate, 0o644)
            ):
                # O_EXCL refuses to replace an existing file, even if another
                # setup process created one after the earlier existence check.
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                created.append(destination)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(source.read_bytes())
        except BaseException:
            # Remove only outputs created by this attempt, never an existing key.
            for destination in created:
                destination.unlink()
            raise
    return certificate, key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=CERT_DIRECTORY)
    args = parser.parse_args()
    try:
        certificate, _ = generate_certificate(args.directory)
        print(f"Development certificate ready: {certificate}")
        print("Valid for 30 days. Keep server.key private; clients trust server.crt.")
    except (OSError, ValueError, ssl.SSLError, subprocess.CalledProcessError) as error:
        # Do not print key material or OpenSSL's captured output.
        parser.exit(1, f"TLS setup failed: {error}\n")


if __name__ == "__main__":
    main()
