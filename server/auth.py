import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

USERS_PATH = Path(__file__).resolve().parent.parent / "data" / "users.json"

def load_users(path=USERS_PATH):
    """Loads and validates predefined authentication records"""
    with Path(path).open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("users.json must contain a list")

    users = {}
    required = {"username", "salt", "password_hash", "n", "r", "p", "dklen"}

    for record in records:

        if not isinstance(record, dict) or not required.issubset(record):
            raise ValueError("User has missing required fields in the record.")

        username = record["username"]
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Username must be a non-empty string")

        if username in users:
            raise ValueError(f"Duplicate username: {username}")

        expected_parameters = {"n": 16384, "r": 8, "p": 1, "dklen": 32}
        for name, expected in expected_parameters.items():
            if type(record[name]) is not int or record[name] != expected:
                raise ValueError(f"Unsupported hashing parameter: {name}")

        try:
            if not isinstance(record["salt"], str):
                raise ValueError("Salt must be base64 text")
            if not isinstance(record["password_hash"], str):
                raise ValueError("Password hash must be base64 text")

            salt = base64.b64decode(record["salt"], validate=True)

            password_hash = base64.b64decode(record["password_hash"], validate=True)

        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid base64 authentication record") from exc

        if len(salt) < 16:
            raise ValueError("Salt must contain at least 16 bytes")

        if len(password_hash) != record["dklen"]:
            raise ValueError("Password hash length does not match dklen")

        users[username] = {
            **record, "salt": salt, "password_hash": password_hash,
        }

    return users


def verify_password(users, username, password):
    """Check a password against the user's stored salted hash."""
    user = users.get(username)

    if user is None:
        return False

    calculated_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=user["salt"],
        n=user["n"],
        r=user["r"],
        p=user["p"],
        dklen=user["dklen"],
    )

    return hmac.compare_digest(calculated_hash, user["password_hash"])

class LoginLimiter:
    def __init__(self, max_attempts=5, cooldown=60, clock=time.monotonic):
        self.max_attempts = max_attempts
        self.cooldown = cooldown
        self.clock = clock
        self.failures = {}
        self.locked_until = {}

    def is_locked(self, username):
        deadline = self.locked_until.get(username)

        if deadline is None:
            return False

        if self.clock() >= deadline:
            self.reset(username)
            return False

        return True

    def record_failure(self, username):
        if self.is_locked(username):
            return

        attempts = self.failures.get(username, 0) + 1
        self.failures[username] = attempts

        if attempts >= self.max_attempts:
            self.locked_until[username] = self.clock() + self.cooldown

    def reset(self, username):
        self.failures.pop(username, None)
        self.locked_until.pop(username, None)