"""Password hashing, verification and local account administration.

SQLite stores encoded hashes, never plaintext passwords. The client/server
protocol still needs TLS to protect passwords while they travel over a network.
"""

import argparse
import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3

from database import (
    DATABASE_FILE,
    get_password_hash,
    initialise_database,
    save_password_hash,
)


# PBKDF2 intentionally makes each password guess expensive. These parameters
# are also recorded in each stored hash so its format can be validated later.
ITERATIONS = 600_000

# fullmatch checks the entire username. Permit 1–64 letters/digits/_/-; disallow
# "---" because the existing client uses it to separate username from password.
# Restricting usernames also prevents path separators in per-user folder names.
USERNAME_PATTERN = re.compile(r"(?!.*---)[A-Za-z0-9_-]{1,64}")


def hash_password(password):
    """Return algorithm$iterations$salt$hash; hashing is not encryption."""
    if not password:
        raise ValueError("Password must not be empty.")

    # A salt is random, not secret. A fresh salt means equal passwords produce
    # different stored hashes, preventing reuse of precomputed guesses.
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),  # The hashing API operates on bytes, not text.
        salt,
        ITERATIONS,
    )
    # Hex encodes bytes as text; the password itself is never stored here.
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def parse_hash(stored):
    """Validate a stored record before using its salt and expected digest."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256" or iterations != str(ITERATIONS):
            raise ValueError
        if len(salt_hex) != 32 or len(digest_hex) != 64:
            raise ValueError
        salt = bytes.fromhex(salt_hex)
        digest = bytes.fromhex(digest_hex)
        if len(salt) != 16 or len(digest) != 32:
            raise ValueError
        return salt, digest
    except (ValueError, TypeError, AttributeError):
        # Reject malformed hashes and legacy plaintext; never silently fall back
        # to comparing raw passwords. Do not include credentials in errors.
        raise ValueError("Invalid stored password hash.") from None


def verify_password(password, stored):
    """Recompute with the original salt and compare; nothing is decrypted."""
    try:
        salt, expected_digest = parse_hash(stored)
    except ValueError:
        return False
    actual_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    )
    # Constant-time comparison avoids the early-exit behavior of ordinary ==.
    return hmac.compare_digest(actual_digest, expected_digest)


def authenticate_user(username, password, path=DATABASE_FILE):
    """Look up one account and return a boolean for the server's access gate."""
    if not USERNAME_PATTERN.fullmatch(username):
        return False
    stored_hash = get_password_hash(username, path)
    if stored_hash is None:
        return False
    # Query on every attempt so resets apply to later logins without restarting.
    # This does not revoke sessions that have already authenticated.
    return verify_password(password, stored_hash)


def set_password(username, password, path=DATABASE_FILE):
    """Create/reset one account, keeping the command-line interface unchanged."""
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Use 1–64 letters, numbers, underscores or hyphens; "
            "avoid three consecutive hyphens."
        )
    # Hash before opening a write transaction: the deliberately slow derivation
    # should not hold a database write lock or block other account updates.
    password_hash = hash_password(password)
    initialise_database(path)
    save_password_hash(username, password_hash, path)


def main():
    parser = argparse.ArgumentParser(
        description="Create an account or change its password in SQLite."
    )
    parser.add_argument("command", choices=["set-password"])
    parser.add_argument("username")
    args = parser.parse_args()
    try:
        # Prompts avoid putting passwords in command history or process arguments.
        # getpass hides terminal input; it does not encrypt network traffic.
        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match.")
        set_password(args.username, password)
        print("Password saved.")
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    # Account prompts run only when invoked as a script, not when imported.
    main()
