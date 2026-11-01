"""SQLite storage only; password hashing belongs in auth.py.

Run `python3 database.py` to create an empty users table. Each operation opens
its own connection so the threaded server never shares a connection across
client threads. SQLite coordinates transactions; a connection waits up to five
seconds if another connection temporarily holds a write lock.
"""

from contextlib import contextmanager
from pathlib import Path
import sqlite3


# Resolve the location relative to this module, rather than the shell's current
# folder. Running the server elsewhere must still use the same account database.
DATABASE_FILE = Path(__file__).resolve().with_name("users.db")


@contextmanager
def _connect(path):
    """Open a connection for one operation and always close it afterward."""
    path = Path(path)
    # Avoid accidentally modifying another file through a symbolic-link alias.
    if path.is_symlink():
        raise ValueError("Database file must not be a symbolic link.")
    # touch creates a new file with owner-only permissions on macOS/Linux.
    # chmod also restricts an existing database created by the earlier example.
    # Hashes still deserve protection because a copied hash can be guessed offline.
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    connection = sqlite3.connect(path, timeout=5)
    try:
        yield connection
    finally:
        # A SQLite connection's `with` block commits/rolls back but does not close
        # it. This explicit finally prevents leaked connections and file handles.
        connection.close()


def initialise_database(path=DATABASE_FILE):
    """Create the schema once; repeating this does not erase existing accounts."""
    with _connect(path) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
            """)
    # INTEGER PRIMARY KEY provides a stable numeric user ID. UNIQUE creates an
    # index that both prevents duplicate usernames and speeds username lookups.
    # NOT NULL forbids NULL; auth.py separately rejects empty/unsafe usernames.


def get_password_hash(username, path=DATABASE_FILE):
    """Fetch only the requested user's hash instead of loading every account."""
    with _connect(path) as connection:
        # Bind values through ? placeholders. Never build SQL with f-strings:
        # user input must be treated as data, not executable SQL syntax.
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),  # The comma makes this a one-element tuple.
        ).fetchone()
    # fetchone returns a row tuple, or None when the username does not exist.
    return row[0] if row is not None else None


def save_password_hash(username, password_hash, path=DATABASE_FILE):
    """Create an account or update its hash without changing its numeric ID."""
    with _connect(path) as connection:
        # This transaction commits on success and rolls back if an exception
        # occurs. The upsert is one atomic statement, avoiding read/modify/write
        # races between two account updates.
        with connection:
            connection.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash
            """, (username, password_hash))
            # "excluded" refers to the proposed new row. A conflict on username
            # updates its password hash while leaving other accounts untouched.


if __name__ == "__main__":
    # Importing this module does not create a database; running it explicitly does.
    initialise_database()
    print("Database ready. Create an account with: python3 auth.py set-password USERNAME")
