import argparse     #cmd line args
import getpass      #enter password wo displaying
import hashlib      #hashing fns
import hmac         #secure comparison for hash 
import os           
from pathlib import Path
import re
import secrets      #generate encrypted hash
import tempfile     


CREDENTIAL_FILE = Path(__file__).resolve().with_name("id_passwd.txt")
ITERATIONS = 600_000    #more itr => more expensive to crack pwd
USERNAME_PATTERN = re.compile(r"(?!.*---)[A-Za-z0-9_-]{1,64}")  #length 1 to 64, no ---


def hash_password(password):
    if not password:
        raise ValueError("Password must not be empty.")

    salt = secrets.token_bytes(16)
    # generates a fresh salt of 16 bytes, salt ensures identical text = diff hashes

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"), #convert text to bytes
        salt,
        ITERATIONS,
    ) # derives a hash using password, salt, iteration count

    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}" #.hex() convert bytes to text

def parse_hash(stored):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")

        if algorithm != "pbkdf2_sha256":
            raise ValueError

        if iterations != str(ITERATIONS):
            raise ValueError

        if len(salt_hex) != 32 or len(digest_hex) != 64:
            raise ValueError

        salt = bytes.fromhex(salt_hex)
        digest = bytes.fromhex(digest_hex)

        if len(salt) != 16 or len(digest) != 32:
            raise ValueError

        return salt, digest

    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid stored password hash.") from None


def verify_password(password, stored):
    try:
        salt, expected_digest = parse_hash(stored)
    except ValueError:
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
    )

    return hmac.compare_digest(actual_digest, expected_digest)


def load_credentials(path=CREDENTIAL_FILE):
    accounts = {}

    with open(path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            parts = line.split()

            if len(parts) != 2:
                raise ValueError(
                    f"Invalid credential record on line {line_number}."
                )

            username, stored_hash = parts

            if not USERNAME_PATTERN.fullmatch(username): #WHY
                raise ValueError(f"Invalid username on line {line_number}.")

            if username in accounts:
                raise ValueError(f"Duplicate username on line {line_number}.")

            parse_hash(stored_hash)
            accounts[username] = stored_hash

    return accounts


def write_credentials(accounts, path=CREDENTIAL_FILE):
    path = Path(path)

    if path.is_symlink(): #WHY
        raise ValueError("Credential file must not be a symbolic link.")

    # mkstemp creates a file readable/writable only by its owner.
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".credentials-",
        dir=path.parent,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            for username, stored_hash in accounts.items():
                file.write(f"{username} {stored_hash}\n")

            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, path)

    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def set_password(username, password, path=CREDENTIAL_FILE):
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "Use 1–64 letters, numbers, underscores or hyphens; "
            "avoid three consecutive hyphens."
        )

    if Path(path).exists():
        accounts = load_credentials(path)
    else:
        accounts = {}

    accounts[username] = hash_password(password)

    write_credentials(accounts, path)


def main():
    parser = argparse.ArgumentParser(
        description="Create an account or change its password."
    )
    parser.add_argument("command", choices=["set-password"])
    parser.add_argument("username")
    args = parser.parse_args()

    try:
        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm password: ")

        if password != confirmation:
            raise ValueError("Passwords do not match.")

        set_password(args.username, password)
        print("Password saved.")

    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()