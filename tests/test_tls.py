"""Real TLS handshakes and application tests using disposable local fixtures."""

import hashlib
import os
from pathlib import Path
import queue
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import auth
from setup_tls import generate_certificate
from tls_transport import (
    connect_tls, create_client_context, create_server_context, wrap_server_connection,
)


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError("Connection closed before the expected bytes arrived.")
        data += chunk
    return data


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.folder.cleanup)
        cls.root = Path(cls.folder.name)
        cls.cert, cls.key = generate_certificate(cls.root / "trusted")
        cls.other_cert, _ = generate_certificate(cls.root / "untrusted")

    def serve_once(self, timeout=1):
        context = create_server_context(self.cert, self.key)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        errors, versions = [], []
        def server():
            try:
                connection, _ = listener.accept()
                with wrap_server_connection(connection, context, timeout=timeout) as secure:
                    versions.append(secure.version())
                    secure.settimeout(3)
                    secure.sendall(b"ready")
                    payload = receive_exact(secure, 7)
                    secure.sendall(payload)
            except (OSError, ssl.SSLError) as error:
                errors.append(error)
            finally:
                listener.close()
        worker = threading.Thread(target=server)
        worker.start()
        self.addCleanup(lambda: worker.join(4))
        return listener.getsockname()[1], errors, versions, worker

    def test_verified_connection_encrypts_and_roundtrips_binary_data(self):
        port, errors, versions, worker = self.serve_once()
        with connect_tls("127.0.0.1", port, create_client_context(self.cert)) as secure:
            secure.settimeout(3)
            self.assertEqual(receive_exact(secure, 5), b"ready")
            self.assertTrue(secure.cipher())
            self.assertIn(secure.version(), ("TLSv1.2", "TLSv1.3"))
            secure.sendall(b"\x00\xffhello")
            self.assertEqual(receive_exact(secure, 7), b"\x00\xffhello")
        worker.join(3)
        self.assertEqual(errors, [])
        self.assertTrue(versions)

    def test_localhost_dns_name_is_also_verified(self):
        port, errors, _, worker = self.serve_once()
        with connect_tls("localhost", port, create_client_context(self.cert)) as secure:
            secure.settimeout(3)
            self.assertEqual(receive_exact(secure, 5), b"ready")
            secure.sendall(b"testing")
            self.assertEqual(receive_exact(secure, 7), b"testing")
        worker.join(3)
        self.assertEqual(errors, [])

    def test_untrusted_certificate_is_rejected(self):
        port, errors, _, worker = self.serve_once()
        with self.assertRaises(ssl.SSLCertVerificationError):
            connect_tls("127.0.0.1", port, create_client_context(self.other_cert))
        worker.join(3)
        self.assertTrue(errors)

    def test_wrong_hostname_is_rejected(self):
        port, errors, _, worker = self.serve_once()
        raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                create_client_context(self.cert).wrap_socket(raw, server_hostname="wrong.example")
        finally:
            raw.close()
        worker.join(3)
        self.assertTrue(errors)

    def test_plaintext_is_rejected_before_application_data(self):
        port, errors, versions, worker = self.serve_once()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
            worker.join(3)
        self.assertTrue(errors)
        self.assertEqual(versions, [])

    def test_stalled_handshake_has_a_timeout(self):
        port, errors, versions, worker = self.serve_once(timeout=0.1)
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertTrue(any(isinstance(error, TimeoutError) for error in errors))
        self.assertEqual(versions, [])

    def test_secure_context_settings_and_missing_certificates(self):
        client = create_client_context(self.cert)
        server = create_server_context(self.cert, self.key)
        self.assertTrue(client.check_hostname)
        self.assertEqual(client.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(client.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertGreaterEqual(server.minimum_version, ssl.TLSVersion.TLSv1_2)
        with self.assertRaises(FileNotFoundError):
            create_client_context(self.root / "missing.crt")
        with self.assertRaises(FileNotFoundError):
            create_server_context(self.cert, self.root / "missing.key")

    def test_setup_never_replaces_existing_key_or_certificate(self):
        before = hashlib.sha256(self.key.read_bytes()).digest()
        with self.assertRaises(ValueError):
            generate_certificate(self.cert.parent)
        self.assertEqual(hashlib.sha256(self.key.read_bytes()).digest(), before)
        if os.name == "posix":
            self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)


class ApplicationTLSTests(unittest.TestCase):
    def test_one_server_for_terminal_and_browser_api(self):
        from client import RelayClient, ClientError
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("server.py", "auth.py", "database.py", "tls_transport.py"):
                shutil.copyfile(source / name, root / name)
            shutil.copytree(source / "web", root / "web")
            cert, _ = generate_certificate(root / "certs")
            auth.set_password("tls_test", "disposable-password", root / "users.db")
            # Only one ephemeral listening port is needed for both interfaces.
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                port = reserved.getsockname()[1]
            process = subprocess.Popen(
                [sys.executable, "-u", "-B", "server.py", "--port", str(port)],
                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            output = queue.Queue()
            def collect():
                for line in process.stdout:
                    output.put(line)
            reader = threading.Thread(target=collect, daemon=True)
            reader.start()
            client = RelayClient(f"https://127.0.0.1:{port}", cert)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    line = output.get(timeout=max(0.01, deadline - time.monotonic()))
                    if "Relay is ready" in line:
                        break
                else:
                    self.fail("Single server entry point did not start.")
                with self.assertRaises(ClientError) as rejected:
                    client.login("tls_test", "wrong")
                self.assertEqual(rejected.exception.status, 401)
                session = client.login("tls_test", "disposable-password")
                self.assertTrue(session["secure"])
                self.assertFalse(session["admin"])

                # The browser UI is served by the same HTTPS listener. Use the
                # verified terminal client's transport to fetch its static page.
                from urllib.request import Request
                with client.opener.open(Request(client.base_url + "/"), timeout=3) as page:
                    self.assertIn(b"Relay", page.read())

                payload = bytes(range(256)) * 8 + b"EOF.EOF\x00"
                upload = root / "binary.dat"
                upload.write_bytes(payload)
                client.upload(upload)
                self.assertTrue(any(file["name"] == "binary.dat" for file in client.list_files()))
                self.assertEqual((root / "server_uploads/client_tls_test/binary.dat").read_bytes(), payload)
                downloaded = client.download("binary.dat", root / "downloads/binary.dat")
                self.assertEqual(downloaded.read_bytes(), payload)
                with self.assertRaises(ClientError):
                    client.download("binary.dat", downloaded)
                with self.assertRaises(ClientError) as duplicate:
                    client.upload(upload)
                self.assertEqual(duplicate.exception.status, 409)

                text = root / "notes.txt"
                text.write_text("One backend for both clients.")
                client.upload(text)
                self.assertEqual(client.preview("notes.txt"), text.read_text())
                client.delete("notes.txt")
                client.delete("binary.dat")
                self.assertEqual(client.list_files(), [])
                client.logout()
                with self.assertRaises(ClientError) as signed_out:
                    client.list_files()
                self.assertEqual(signed_out.exception.status, 401)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                reader.join(3)
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
