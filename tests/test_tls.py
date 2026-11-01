"""Real TLS handshakes and application tests using disposable local fixtures."""

import ast
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
    def test_both_channels_login_upload_download_and_shutdown(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("auth.py", "database.py", "tls_transport.py"):
                shutil.copyfile(source / name, root / name)
            cert, _ = generate_certificate(root / "certs")
            auth.set_password("tls_test", "disposable-password", root / "users.db")

            # Pick two free adjacent ports; do not start/stop a user's real server.
            for _ in range(30):
                with socket.socket() as first, socket.socket() as second:
                    first.bind(("127.0.0.1", 0))
                    port = first.getsockname()[1]
                    if port >= 65535:
                        continue
                    try:
                        second.bind(("127.0.0.1", port + 1))
                    except OSError:
                        continue
                    break
            else:
                self.fail("Could not allocate adjacent test ports.")
            server_source = (source / "server.py").read_text().replace("PORT = 9999", f"PORT = {port}", 1)
            (root / "server.py").write_text(server_source)
            process = subprocess.Popen([sys.executable, "-u", "-B", "server.py"], cwd=root,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output = queue.Queue()
            def collect():
                for line in process.stdout:
                    output.put(line)
            reader = threading.Thread(target=collect, daemon=True)
            reader.start()
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    line = output.get(timeout=max(0.01, deadline - time.monotonic()))
                    if "TLS server listening" in line:
                        break
                else:
                    self.fail("Test server did not start.")
                # The real application must reject raw TCP on BOTH ports and
                # stay available for the next correctly secured client.
                with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                    raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    try:
                        self.assertEqual(raw.recv(128), b"")
                    except ConnectionResetError:
                        pass
                context = create_client_context(cert)
                with connect_tls("127.0.0.1", port, context) as incomplete:
                    incomplete.settimeout(3)
                    with socket.create_connection(("127.0.0.1", port + 1), timeout=3) as raw:
                        raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        try:
                            self.assertEqual(incomplete.recv(128), b"")
                        except ssl.SSLError:
                            pass
                with connect_tls("127.0.0.1", port, context) as data:
                    with connect_tls("127.0.0.1", port + 1, context) as notifications:
                        data.settimeout(5)
                        notifications.settimeout(5)
                        self.assertIsInstance(data, ssl.SSLSocket)
                        self.assertIsInstance(notifications, ssl.SSLSocket)
                        data.sendall(b"tls_test---wrong")
                        self.assertEqual(data.recv(128), b"Error")
                        data.sendall(b"tls_test---disposable-password")
                        self.assertEqual(receive_exact(data, len(b"200 Success")), b"200 Success")
                        self.assertIn(b"uploading", data.recv(4096))

                        # Exercise the real client's upload function in isolation.
                        # This avoids importing its top-level network connections.
                        tree = ast.parse((source / "client.py").read_text())
                        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                                        and node.name == "send_file")
                        namespace = dict(terminate=False, client_socket=data, os=os, time=time,
                                         BUFFER_SIZE=128 * 1024)
                        exec(compile(ast.Module(body=[function], type_ignores=[]), "client.py", "exec"), namespace)
                        payload = bytes(range(256)) * 8
                        upload = root / "binary.dat"
                        upload.write_bytes(payload)
                        data.sendall(b"1")
                        namespace["send_file"](str(upload))
                        self.assertIn(b"uploading", data.recv(4096))
                        stored = root / "server_uploads/client_tls_test/binary.dat"
                        self.assertEqual(stored.read_bytes(), payload)

                        data.sendall(b"3")
                        data.sendall(b"Send files in drive")
                        self.assertIn(b"binary.dat", data.recv(4096))
                        data.sendall(b"binary.dat")
                        self.assertEqual(receive_exact(data, 3), b"200")
                        self.assertEqual(receive_exact(data, len(payload)), payload)
                        self.assertEqual(receive_exact(data, 3), b"EOF")
                        data.sendall(b"Rx Complete")
                        self.assertIn(b"uploading", data.recv(4096))

                        # SIGTERM makes the real server send its TLS notification.
                        process.terminate()
                        self.assertEqual(notifications.recv(128), b"Terminate")
                        process.wait(timeout=5)
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
