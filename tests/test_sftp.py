import os
import errno
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import server as sftp


class PathTests(unittest.TestCase):
    def test_safe_join(self):
        """Normal paths stay inside the jail; escaping paths are rejected."""
        with tempfile.TemporaryDirectory() as root:
            jail = Path(root) / "jail"
            jail.mkdir()

            expected = str((jail / "notes.txt").resolve())
            self.assertEqual(
                sftp.safe_join(str(jail), b"/notes.txt"),
                expected,
            )

            for path in (
                b"../outside.txt",
                b"/../../outside.txt",
                b"C:/outside.txt",
                b"file:stream",
                b"bad\x00name",
            ):
                with self.subTest(path=path):
                    with self.assertRaises(PermissionError):
                        sftp.safe_join(str(jail), path)

    def test_symlink_paths(self):
        """Follow in-jail links, reject escaping targets/parents, and preserve links for LSTAT."""
        with tempfile.TemporaryDirectory() as root:
            jail = Path(root) / "jail"
            jail.mkdir()
            inside = jail / "inside.txt"
            inside.write_bytes(b"inside")
            outside = Path(root) / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_bytes(b"outside")
            try:
                (jail / "inside-link").symlink_to(inside)
                (jail / "outside-link").symlink_to(outside / "secret.txt")
                (jail / "parent-link").symlink_to(outside, target_is_directory=True)
            except OSError as error:
                if getattr(error, "winerror", None) == 1314 or error.errno in (
                    errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP
                ):
                    self.skipTest(f"Symlink creation unavailable or not permitted: {error}")
                raise

            self.assertEqual(
                sftp.safe_join(str(jail), b"/inside-link"), str(inside.resolve())
            )
            with self.assertRaises(PermissionError):
                sftp.safe_join(str(jail), b"/outside-link")
            for follow in (True, False):
                with self.subTest(parent_link=True, follow=follow):
                    with self.assertRaises(PermissionError):
                        sftp.safe_join(
                            str(jail), b"/parent-link/secret.txt", follow_symlinks=follow
                        )

            session = sftp.SFTPSession()
            session.initialized = True
            replies = []
            session._chan = SimpleNamespace(write=replies.append)
            with patch.object(sftp, "JAIL_ROOT", str(jail)):
                for name in (b"/inside-link", b"/outside-link"):
                    for kind in (sftp.SSH_FXP_STAT, sftp.SSH_FXP_LSTAT):
                        with self.subTest(path=name, request=kind):
                            session._handle(bytes([kind]) + sftp.p_u32(42) + sftp.p_str(name))
                            reply = replies.pop()
                            self.assertEqual(sftp.u32(reply, 5)[0], 42)
                            if kind == sftp.SSH_FXP_STAT and name == b"/outside-link":
                                self.assertEqual(reply[4], sftp.SSH_FXP_STATUS)
                                self.assertEqual(sftp.u32(reply, 9)[0], sftp.SSH_FX_PERMISSION_DENIED)
                            else:
                                self.assertEqual(reply[4], sftp.SSH_FXP_ATTRS)
                                permissions, _ = sftp.u32(reply, 21)
                                self.assertEqual(stat.S_ISLNK(permissions), kind == sftp.SSH_FXP_LSTAT)


class OpenTests(unittest.TestCase):
    def test_open_flags(self):
        """OPEN preserves access/content, creates exclusively, and appends despite a write offset."""
        cases = (
            (sftp.PF_READ, True, None, b"hello"),
            (sftp.PF_WRITE, True, None, b"hello"),
            (sftp.PF_READ | sftp.PF_WRITE | sftp.PF_TRUNC, True, None, b""),
            (sftp.PF_WRITE | sftp.PF_CREAT | sftp.PF_EXCL, False, None, b""),
            (sftp.PF_WRITE | sftp.PF_CREAT | sftp.PF_EXCL, True, sftp.SSH_FX_FAILURE, b"hello"),
            (sftp.PF_WRITE | sftp.PF_TRUNC, False, sftp.SSH_FX_NO_SUCH_FILE, None),
            (sftp.PF_WRITE | sftp.PF_APPEND, True, None, b"hello!"),
        )
        for flags, exists, error, expected in cases:
            with self.subTest(flags=flags, exists=exists), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "test.bin"
                if exists:
                    path.write_bytes(b"hello")
                session = sftp.SFTPSession()
                session.initialized = True
                replies = []
                session._chan = SimpleNamespace(write=replies.append)
                try:
                    with patch.object(sftp, "JAIL_ROOT", root):
                        session._handle(
                            bytes([sftp.SSH_FXP_OPEN]) + sftp.p_u32(42)
                            + sftp.p_str(b"/test.bin") + sftp.p_u32(flags) + sftp.p_u32(0)
                        )
                    reply = replies.pop()
                    self.assertEqual(sftp.u32(reply, 5)[0], 42)
                    if error is not None:
                        self.assertEqual(reply[4], sftp.SSH_FXP_STATUS)
                        self.assertEqual(sftp.u32(reply, 9)[0], error)
                    else:
                        self.assertEqual(reply[4], sftp.SSH_FXP_HANDLE)
                        handle, _ = sftp.ustr(reply, 9)
                        file = session.handles.get(handle)
                        self.assertEqual(file.readable(), bool(flags & sftp.PF_READ))
                        self.assertEqual(file.writable(), bool(flags & sftp.PF_WRITE))
                        if flags & sftp.PF_APPEND:
                            session._handle(
                                bytes([sftp.SSH_FXP_WRITE]) + sftp.p_u32(43)
                                + sftp.p_str(handle) + sftp.p_u64(0) + sftp.p_str(b"!")
                            )
                            self.assertEqual(sftp.u32(replies.pop(), 9)[0], sftp.SSH_FX_OK)
                finally:
                    session.handles.close_all()
                self.assertEqual(path.read_bytes() if path.exists() else None, expected)


class FstatTests(unittest.TestCase):
    def test_fstat(self):
        """FSTAT returns open-file attributes without seeking and rejects invalid handles/payloads."""
        session = sftp.SFTPSession()
        session.initialized = True
        replies = []
        session._chan = SimpleNamespace(write=replies.append)
        req_id = 42

        with tempfile.TemporaryFile() as file:
            file.write(b"hello")
            file.flush()
            file.seek(2)
            handle = session.handles.add(file)
            session._handle(bytes([sftp.SSH_FXP_FSTAT]) + sftp.p_u32(req_id) + handle)
            expected = sftp.pack_pkt(
                sftp.SSH_FXP_ATTRS,
                sftp.p_u32(req_id) + sftp.sftp_attrs_from_stat(os.fstat(file.fileno())),
            )
            self.assertEqual(replies.pop(), expected)
            self.assertEqual(file.tell(), 2)
            raw_handle, _ = sftp.ustr(handle, 0)
            session.handles.close(raw_handle)

            directory = session.handles.add(sftp.DirHandle([]))
            for invalid in (handle, directory, sftp.p_str(b"missing"), sftp.p_u32(10) + b"x"):
                with self.subTest(handle=invalid):
                    session._handle(
                        bytes([sftp.SSH_FXP_FSTAT]) + sftp.p_u32(req_id) + invalid
                    )
                    reply = replies.pop()
                    self.assertEqual(reply[4], sftp.SSH_FXP_STATUS)
                    self.assertEqual(sftp.u32(reply, 5)[0], req_id)
                    self.assertEqual(sftp.u32(reply, 9)[0], sftp.SSH_FX_FAILURE)
