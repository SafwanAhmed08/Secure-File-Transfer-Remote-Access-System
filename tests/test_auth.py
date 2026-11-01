"""Authentication regression tests; all account data lives in temporary folders."""

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import socket
import sqlite3
import stat
import tempfile
import threading
import unittest
from unittest.mock import Mock

import auth
import database


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "users.db"

    def test_schema_initialisation_is_repeatable_and_creates_no_accounts(self):
        database.initialise_database(self.path)
        database.initialise_database(self.path)
        self.assertIsNone(database.get_password_hash("alice", self.path))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_correct_wrong_and_unknown_passwords(self):
        auth.set_password("alice", "a long --- password café", self.path)
        self.assertTrue(auth.authenticate_user("alice", "a long --- password café", self.path))
        self.assertFalse(auth.authenticate_user("alice", "wrong", self.path))
        self.assertFalse(auth.authenticate_user("unknown", "a long --- password café", self.path))

    def test_salts_differ_for_equal_passwords_and_plaintext_is_not_stored(self):
        auth.set_password("alice", "same-password", self.path)
        auth.set_password("bob", "same-password", self.path)
        first = database.get_password_hash("alice", self.path)
        second = database.get_password_hash("bob", self.path)
        self.assertNotEqual(first, second)
        self.assertNotIn("same-password", first)
        auth.parse_hash(first)
        auth.parse_hash(second)

    def test_reset_preserves_user_id_other_accounts_and_schema_reinitialisation(self):
        auth.set_password("alice", "first", self.path)
        auth.set_password("bob", "second", self.path)
        with closing(sqlite3.connect(self.path)) as connection:
            old_id = connection.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
        auth.set_password("alice", "replacement", self.path)
        database.initialise_database(self.path)
        with closing(sqlite3.connect(self.path)) as connection:
            new_id = connection.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
            count = connection.execute("SELECT count(*) FROM users").fetchone()[0]
        self.assertEqual(old_id, new_id)
        self.assertEqual(count, 2)
        self.assertFalse(auth.authenticate_user("alice", "first", self.path))
        self.assertTrue(auth.authenticate_user("alice", "replacement", self.path))
        self.assertTrue(auth.authenticate_user("bob", "second", self.path))

    def test_invalid_username_or_empty_password_does_not_create_database(self):
        for name in ("", "../alice", "a b", "alice---bob", "a" * 65):
            with self.assertRaises(ValueError):
                auth.set_password(name, "secret", self.path)
        with self.assertRaises(ValueError):
            auth.set_password("alice", "", self.path)
        self.assertFalse(self.path.exists())

    def test_malformed_hash_and_plaintext_fail_closed(self):
        database.initialise_database(self.path)
        for stored in ("plaintext", "pbkdf2_sha256$1$ab$cd", "", None):
            self.assertFalse(auth.verify_password("plaintext", stored))
        database.save_password_hash("alice", "plaintext", self.path)
        self.assertFalse(auth.authenticate_user("alice", "plaintext", self.path))

    def test_parameterised_lookup_does_not_interpret_sql(self):
        auth.set_password("alice", "secret", self.path)
        self.assertIsNone(database.get_password_hash("' OR 1=1 --", self.path))
        self.assertTrue(auth.authenticate_user("alice", "secret", self.path))

    def test_unique_username_constraint_rejects_duplicate_insert(self):
        auth.set_password("alice", "secret", self.path)
        connection = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                                       ("alice", "invalid"))
        finally:
            connection.close()
        self.assertTrue(auth.authenticate_user("alice", "secret", self.path))

    def test_threaded_account_operations_use_independent_connections(self):
        database.initialise_database(self.path)
        def create_and_read(number):
            username = f"user_{number}"
            auth.set_password(username, f"password-{number}", self.path)
            return auth.authenticate_user(username, f"password-{number}", self.path)
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertTrue(all(pool.map(create_and_read, range(4))))


class ServerLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Compile the actual server functions without executing the legacy global
        # socket creation and signal registration during test discovery.
        path = Path(__file__).resolve().parents[1] / "server.py"
        tree = ast.parse(path.read_text())
        handlers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name in {"validate_user", "on_user"}]
        if len(handlers) != 2:
            raise AssertionError("Expected exactly one login handler and one connection handler.")
        cls.code = compile(ast.Module(body=handlers, type_ignores=[]), str(path), "exec")

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "users.db"
        auth.set_password("alice", "correct---password", self.path)
        self.namespace = dict(
            terminate_server=False, BUFFER_SIZE=128 * 1024, sqlite3=sqlite3,
            uname={}, fc={}, clients=[], termination_clients=[], send_options=Mock(),
            authenticate_user=lambda username, password: auth.authenticate_user(username, password, self.path),
        )
        exec(self.code, self.namespace)
        self.address = ("127.0.0.1", 12345)

    def test_wrong_password_then_correct_password_reaches_menu_over_socket(self):
        # A socket pair exercises actual byte I/O without opening network ports.
        server_side, client_side = socket.socketpair()
        server_side.settimeout(3)
        client_side.settimeout(3)
        termination = Mock()
        worker = threading.Thread(target=self.namespace["on_user"],
                                  args=(server_side, self.address, termination))
        worker.start()
        try:
            client_side.sendall(b"alice---wrong")
            self.assertEqual(client_side.recv(128), b"Error")
            client_side.sendall(b"alice---correct---password")
            self.assertEqual(client_side.recv(128), b"200 Success")
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.namespace["send_options"].assert_called_once_with(server_side, self.address)
        finally:
            client_side.close()
            server_side.close()
            worker.join(3)

    def test_malformed_unknown_and_disconnected_client_never_reaches_menu(self):
        client = Mock()
        client.recv.side_effect = [b"no separator", b"\xff", b"unknown---anything", b""]
        termination = Mock()
        self.namespace["on_user"](client, self.address, termination)
        self.namespace["send_options"].assert_not_called()
        self.assertEqual(self.namespace["uname"], {})
        self.assertEqual([call.args[0] for call in client.sendall.call_args_list],
                         [b"Error", b"Error", b"Error"])
        client.close.assert_called_once()
        termination.close.assert_called_once()
        self.assertEqual(self.namespace["clients"], [])
        self.assertEqual(self.namespace["termination_clients"], [])

    def test_database_failure_never_reaches_menu(self):
        self.namespace["authenticate_user"] = Mock(side_effect=sqlite3.OperationalError("unavailable"))
        client = Mock()
        client.recv.return_value = b"alice---correct---password"
        self.namespace["on_user"](client, self.address, Mock())
        self.namespace["send_options"].assert_not_called()
        client.sendall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
