import base64
import hashlib
import json
import tempfile
import unittest
import asyncio
from unittest.mock import Mock

from server.server import Server
from pathlib import Path

from server.auth import load_users, verify_password, LoginLimiter


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.users_path = Path(temporary.name) / "users.json"

        # Synthetic credentials used only by these tests.
        password = "test-password"
        salt = b"0123456789abcdef"
        password_hash = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=16384,
            r=8,
            p=1,
            dklen=32,
        )

        records = [
            {
                "username": "alice",
                "salt": base64.b64encode(salt).decode("ascii"),
                "password_hash": base64.b64encode(password_hash).decode("ascii"),
                "n": 16384,
                "r": 8,
                "p": 1,
                "dklen": 32,
            }
        ]

        self.users_path.write_text(json.dumps(records), encoding="utf-8")
        self.users = load_users(self.users_path)

    def test_correct_password(self):
        """accept a known user with the correct password."""
        self.assertTrue(
            verify_password(self.users, "alice", "test-password")
        )

    def test_wrong_password(self):
        """reject a known user with an incorrect password."""
        self.assertFalse(
            verify_password(self.users, "alice", "wrong-password")
        )

    def test_unknown_user(self):
        """reject a username absent from the dataset."""
        self.assertFalse(
            verify_password(self.users, "unknown", "test-password")
        )


class LoginLimiterTests(unittest.TestCase):
    """test temporary lockout after repeated authentication failures."""

    def setUp(self):
        self.now = 100.0
        self.limiter = LoginLimiter(
            max_attempts=5,
            cooldown=60,
            clock=lambda: self.now,
        )

    def test_new_user_is_not_locked(self):
        """allow attempts for a user with no failures."""
        self.assertFalse(self.limiter.is_locked("alice"))

    def test_below_threshold_is_not_locked(self):
        """keep the account unlocked before five failures."""
        for _ in range(4):
            self.limiter.record_failure("alice")

        self.assertFalse(self.limiter.is_locked("alice"))

    def test_threshold_locks_user(self):
        """lock the account after five failures."""
        for _ in range(5):
            self.limiter.record_failure("alice")

        self.assertTrue(self.limiter.is_locked("alice"))
        self.assertFalse(self.limiter.is_locked("bob"))

    def test_cooldown_expires(self):
        """unlock at the cooldown deadline and clear old failures."""
        for _ in range(5):
            self.limiter.record_failure("alice")

        self.now = 159.0
        self.assertTrue(self.limiter.is_locked("alice"))

        self.now = 160.0
        self.assertFalse(self.limiter.is_locked("alice"))

        self.limiter.record_failure("alice")
        self.assertEqual(self.limiter.failures["alice"], 1)

    def test_locked_attempt_does_not_extend_cooldown(self):
        """keep the original deadline when another failure is recorded."""
        for _ in range(5):
            self.limiter.record_failure("alice")

        self.now = 130.0
        self.limiter.record_failure("alice")

        self.now = 160.0
        self.assertFalse(self.limiter.is_locked("alice"))

    def test_reset_clears_failures(self):
        """clear failure history when reset is called."""
        for _ in range(4):
            self.limiter.record_failure("alice")

        self.limiter.reset("alice")
        self.limiter.record_failure("alice")

        self.assertEqual(self.limiter.failures["alice"], 1)
        self.assertFalse(self.limiter.is_locked("alice"))


class SessionIdentityTests(unittest.TestCase):
    def test_session_before_authentication_is_rejected(self):
        """Reject a session without an authenticated identity."""
        server = Server({}, LoginLimiter(), asyncio.Lock())

        self.assertFalse(server.session_requested())

    def test_authenticated_username_reaches_session(self):
        """Pass the SSH-authenticated username into the SFTP session."""
        server = Server({}, LoginLimiter(), asyncio.Lock())

        connection = Mock()
        connection.get_extra_info.return_value = "alice"

        server.connection_made(connection)
        server.begin_auth("alice")
        server.auth_completed()

        session = server.session_requested()

        self.assertEqual(session.username, "alice")
        connection.get_extra_info.assert_called_once_with("username")