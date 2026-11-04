"""Authentication regression tests; all account data lives in temporary folders."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
