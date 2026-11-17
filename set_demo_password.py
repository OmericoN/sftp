import base64
import getpass
import hashlib
import json
import secrets
from pathlib import Path

path = Path(__file__).resolve().parent / "data" / "users.json"
users = json.loads(path.read_text(encoding="utf-8"))

matches = [user for user in users if user["username"] == "alice"]
if len(matches) != 1:
    raise SystemExit("Expected exactly one Alice record.")

password = getpass.getpass("Choose Alice's demo password: ")
confirmation = getpass.getpass("Enter it again: ")

if not password or password != confirmation:
    raise SystemExit("Passwords are empty or do not match. Nothing changed.")

if len(password.encode("utf-8")) > 1024:
    raise SystemExit("Password is too long. Nothing changed.")

salt = secrets.token_bytes(16)
password_hash = hashlib.scrypt(
    password.encode("utf-8"),
    salt=salt,
    n=16384,
    r=8,
    p=1,
    dklen=32,
)

matches[0].update(
    salt=base64.b64encode(salt).decode("ascii"),
    password_hash=base64.b64encode(password_hash).decode("ascii"),
    n=16384,
    r=8,
    p=1,
    dklen=32,
)

path.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")
print("Alice's password record updated.")