"""S1-S7 server checks using temporary files and real SFTP packets, without an SSH listener."""

import contextlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from server import server as sftp


class AllowPolicy:
    def authorize(self, user, op, path):
        return True, "allowed"

    def path(self, path):
        return str(path)

    def mode(self, path):
        return None

    def audit_denial(self, user, op, path, reason):
        pass


class SessionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.jail = Path(temporary.name) / "jail"
        self.jail.mkdir()
        jail_patch = patch.object(sftp, "JAIL_ROOT", str(self.jail))
        jail_patch.start()
        self.addCleanup(jail_patch.stop)
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.new_session()

    def new_session(self, initialized=True):
        self.replies = []
        self.channel = SimpleNamespace(write=self.replies.append, close=Mock())
        self.session = sftp.SFTPSession("test", AllowPolicy())
        self.session.connection_made(self.channel)
        self.session.initialized = initialized
        self.addCleanup(self.session.handles.close_all)

    def request(self, kind, body=b"", req_id=42):
        self.session.data_received(sftp.pack_pkt(kind, sftp.p_u32(req_id) + body), None)
        self.assertEqual(len(self.replies), 1)
        reply = self.replies.pop()
        self.assertEqual(sftp.u32(reply, 0)[0], len(reply) - 4)
        self.assertEqual(sftp.u32(reply, 5)[0], req_id)
        self.channel.close.assert_not_called()
        return reply

    def assert_status(self, reply, code):
        self.assertEqual(reply[4], sftp.SSH_FXP_STATUS)
        self.assertEqual(sftp.u32(reply, 9)[0], code)
        message, off = sftp.ustr(reply, 13)
        _, off = sftp.ustr(reply, off)
        self.assertEqual(off, len(reply))
        return message

    def open_file(self, flags, path=b"/file.bin"):
        reply = self.request(
            sftp.SSH_FXP_OPEN, sftp.p_str(path) + sftp.p_u32(flags) + sftp.p_u32(0)
        )
        self.assertEqual(reply[4], sftp.SSH_FXP_HANDLE)
        handle, off = sftp.ustr(reply, 9)
        self.assertEqual(off, len(reply))
        return handle


class HandleCleanupTests(SessionTests):
    def test_close_file_and_directory(self):
        """S2: CLOSE releases file/directory handles and rejects repeated CLOSE and FSTAT."""
        (self.jail / "file.bin").write_bytes(b"hello")
        file_handle = self.open_file(sftp.PF_READ)
        file = self.session.handles.get(file_handle)
        reply = self.request(sftp.SSH_FXP_OPENDIR, sftp.p_str(b"/"))
        directory_handle, _ = sftp.ustr(reply, 9)
        for handle in (file_handle, directory_handle):
            with self.subTest(handle=handle):
                self.assert_status(
                    self.request(sftp.SSH_FXP_CLOSE, sftp.p_str(handle)), sftp.SSH_FX_OK
                )
                self.assertIsNone(self.session.handles.get(handle))
                with self.assertLogs(level="ERROR"):
                    self.assert_status(
                        self.request(sftp.SSH_FXP_CLOSE, sftp.p_str(handle)),
                        sftp.SSH_FX_FAILURE,
                    )
                self.assert_status(
                    self.request(sftp.SSH_FXP_FSTAT, sftp.p_str(handle)),
                    sftp.SSH_FX_FAILURE,
                )
        self.assertTrue(file.closed)

    def test_disconnect_closes_all_handles(self):
        """S2: Clean/error disconnects release every handle, and repeated cleanup is safe."""
        for error in (None, OSError("connection lost")):
            with self.subTest(error=error):
                self.new_session()
                files = [tempfile.TemporaryFile(), tempfile.TemporaryFile()]
                for file in files:
                    self.addCleanup(file.close)
                    self.session.handles.add(file, str(self.jail / "file.bin"))
                self.session.handles.add(sftp.DirHandle([]), str(self.jail))
                self.session.connection_lost(error)
                self.assertTrue(all(file.closed for file in files))
                self.assertEqual(self.session.handles._map, {})
                self.session.connection_lost(error)
                self.assertEqual(self.replies, [])

    def test_cleanup_continues_after_error(self):
        """S2: A failing close is logged without preventing remaining handles from closing."""
        broken = Mock()
        broken.close.side_effect = OSError("simulated close failure")
        self.session.handles.add(broken, str(self.jail / "file.bin"))
        with tempfile.TemporaryFile() as file:
            self.session.handles.add(file, str(self.jail / "file.bin"))
            with self.assertLogs(level="ERROR") as logs:
                self.session.handles.close_all()
            self.assertTrue(file.closed)
            self.assertEqual(self.session.handles._map, {})
            self.assertIn("simulated close failure", "\n".join(logs.output))

    def test_close_failure_is_not_success(self):
        """S2/S7: A file-close failure returns FAILURE and invalidates the handle."""
        file = Mock()
        file.close.side_effect = OSError("simulated flush failure")
        encoded = self.session.handles.add(file, str(self.jail / "file.bin"))
        handle, _ = sftp.ustr(encoded, 0)
        with self.assertLogs(level="ERROR"):
            self.assert_status(self.request(sftp.SSH_FXP_CLOSE, encoded), sftp.SSH_FX_FAILURE)
        self.assertIsNone(self.session.handles.get(handle))


class FileAccessTests(SessionTests):
    def test_invalid_open_flags_preserve_data(self):
        """S3: Invalid/unknown flags fail without opening handles or modifying existing data."""
        path = self.jail / "file.bin"
        path.write_bytes(b"original")
        for flags in (0, sftp.PF_READ | 0x40, sftp.PF_READ | sftp.PF_TRUNC,
                      sftp.PF_READ | sftp.PF_CREAT, sftp.PF_READ | sftp.PF_APPEND,
                      sftp.PF_WRITE | sftp.PF_EXCL):
            with self.subTest(flags=flags):
                reply = self.request(
                    sftp.SSH_FXP_OPEN,
                    sftp.p_str(b"/file.bin") + sftp.p_u32(flags) + sftp.p_u32(0),
                )
                self.assert_status(reply, sftp.SSH_FX_FAILURE)
                self.assertEqual(path.read_bytes(), b"original")
                self.assertEqual(self.session.handles._map, {})

    def test_access_restrictions(self):
        """S3: WRITE on read-only and READ on write-only handles return PERMISSION_DENIED."""
        path = self.jail / "file.bin"
        path.write_bytes(b"original")
        for flags, kind, tail in (
            (sftp.PF_READ, sftp.SSH_FXP_WRITE, sftp.p_str(b"changed")),
            (sftp.PF_WRITE, sftp.SSH_FXP_READ, sftp.p_u32(100)),
        ):
            with self.subTest(flags=flags):
                handle = self.open_file(flags)
                file = self.session.handles.get(handle)
                position = file.tell()
                self.assert_status(
                    self.request(kind, sftp.p_str(handle) + sftp.p_u64(2) + tail),
                    sftp.SSH_FX_PERMISSION_DENIED,
                )
                self.assertEqual(file.tell(), position)
                self.assertEqual(path.read_bytes(), b"original")

    def test_upload_download_and_offsets(self):
        """S3: Binary uploads/downloads preserve bytes, honor offsets, and return EOF."""
        handle = self.open_file(sftp.PF_READ | sftp.PF_WRITE | sftp.PF_CREAT)
        data = b"\x00\r\n\xffhello"
        for offset, chunk in ((0, data[:4]), (4, data[4:])):
            self.assert_status(
                self.request(sftp.SSH_FXP_WRITE,
                             sftp.p_str(handle) + sftp.p_u64(offset) + sftp.p_str(chunk)),
                sftp.SSH_FX_OK,
            )
        reply = self.request(
            sftp.SSH_FXP_READ, sftp.p_str(handle) + sftp.p_u64(2) + sftp.p_u32(100)
        )
        self.assertEqual(reply[4], sftp.SSH_FXP_DATA)
        self.assertEqual(sftp.ustr(reply, 9)[0], data[2:])
        self.assertEqual((self.jail / "file.bin").read_bytes(), data)
        self.assert_status(
            self.request(sftp.SSH_FXP_READ,
                         sftp.p_str(handle) + sftp.p_u64(len(data)) + sftp.p_u32(1)),
            sftp.SSH_FX_EOF,
        )

    def test_append_on_every_write(self):
        """S3: Multiple append writes ignore supplied offsets and preserve existing bytes."""
        path = self.jail / "file.bin"
        path.write_bytes(b"start")
        handle = self.open_file(sftp.PF_READ | sftp.PF_WRITE | sftp.PF_APPEND)
        for offset, data in ((0, b"A"), (1, b"B")):
            self.assert_status(
                self.request(sftp.SSH_FXP_WRITE,
                             sftp.p_str(handle) + sftp.p_u64(offset) + sftp.p_str(data)),
                sftp.SSH_FX_OK,
            )
        self.assertEqual(path.read_bytes(), b"startAB")

    def test_fdopen_failure_releases_descriptor(self):
        """S3: A failed file-object conversion closes the operating-system descriptor."""
        (self.jail / "file.bin").write_bytes(b"original")
        with patch.object(sftp.os, "fdopen", side_effect=OSError("wrap failed")), \
                patch.object(sftp.os, "close", wraps=os.close) as close, \
                self.assertLogs(level="ERROR"):
            reply = self.request(
                sftp.SSH_FXP_OPEN,
                sftp.p_str(b"/file.bin") + sftp.p_u32(sftp.PF_READ) + sftp.p_u32(0),
            )
        self.assert_status(reply, sftp.SSH_FX_FAILURE)
        close.assert_called_once()
        with self.assertRaises(OSError):
            os.fstat(close.call_args.args[0])
        self.assertEqual(self.session.handles._map, {})

    def test_invalid_handle_types(self):
        """S1/S3: File requests reject missing/directory handles; READDIR rejects file handles."""
        (self.jail / "file.bin").write_bytes(b"data")
        file_handle = self.open_file(sftp.PF_READ | sftp.PF_WRITE)
        directory, _ = sftp.ustr(self.session.handles.add(sftp.DirHandle([]), str(self.jail)), 0)
        for handle in (b"unknown", directory):
            for kind, tail in (
                (sftp.SSH_FXP_FSTAT, b""),
                (sftp.SSH_FXP_READ, sftp.p_u64(0) + sftp.p_u32(1)),
                (sftp.SSH_FXP_WRITE, sftp.p_u64(0) + sftp.p_str(b"x")),
            ):
                with self.subTest(handle=handle, kind=kind):
                    self.assert_status(
                        self.request(kind, sftp.p_str(handle) + tail), sftp.SSH_FX_FAILURE
                    )
        self.assert_status(
            self.request(sftp.SSH_FXP_READDIR, sftp.p_str(file_handle)), sftp.SSH_FX_FAILURE
        )


class PacketValidationTests(SessionTests):
    def test_init_versions_and_extensions(self):
        """S4: Valid INIT versions/extensions negotiate v3; initialization occurs only once."""
        for version in (3, 6):
            with self.subTest(version=version):
                self.new_session(initialized=False)
                packet = sftp.pack_pkt(
                    sftp.SSH_FXP_INIT,
                    sftp.p_u32(version) + sftp.p_str(b"test-extension") + sftp.p_str(b""),
                )
                self.session.data_received(packet, None)
                self.assertEqual(self.replies, [sftp.pack_pkt(sftp.SSH_FXP_VERSION, sftp.p_u32(3))])
                self.assertTrue(self.session.initialized)
                self.channel.close.assert_not_called()
                self.replies.clear()
                self.session.data_received(packet, None)
                self.channel.close.assert_called_once()
                self.assertEqual(self.replies, [])

    def test_invalid_init_and_first_request(self):
        """S4: Old versions, malformed extensions, and non-INIT startup packets close silently."""
        for kind, body in (
            (sftp.SSH_FXP_INIT, sftp.p_u32(2)),
            (sftp.SSH_FXP_INIT, sftp.p_u32(3) + sftp.p_str(b"unpaired-name")),
            (sftp.SSH_FXP_INIT, sftp.p_u32(3) + sftp.p_u32(20) + b"short"),
            (sftp.SSH_FXP_INIT, sftp.p_u32(3) + b"\x00"),
            (sftp.SSH_FXP_STAT, sftp.p_u32(42) + sftp.p_str(b"/")),
        ):
            with self.subTest(kind=kind, body=body):
                self.new_session(initialized=False)
                self.session.data_received(sftp.pack_pkt(kind, body), None)
                self.channel.close.assert_called_once()
                self.assertFalse(self.session.initialized)
                self.assertEqual(self.replies, [])
                self.assertEqual(self.session.buf, b"")

    def test_invalid_frame_lengths_and_headers(self):
        """S4: Zero/oversized frames and incomplete type/version/ID headers close the channel."""
        packets = [sftp.p_u32(0), sftp.p_u32(1024 * 1024 + 1)]
        packets += [sftp.p_u32(size) + b"\x01" * size for size in range(1, 5)]
        for packet in packets:
            with self.subTest(packet=packet):
                self.new_session(initialized=False)
                self.session.data_received(packet, None)
                self.channel.close.assert_called_once()
                self.assertEqual(self.replies, [])
                self.assertEqual(self.session.buf, b"")

    def test_fragmented_and_combined_packets(self):
        """S4: Arbitrarily split headers/payloads and batched requests produce ordered replies."""
        init = sftp.pack_pkt(sftp.SSH_FXP_INIT, sftp.p_u32(3))
        for split in range(1, len(init)):
            with self.subTest(split=split):
                self.new_session(initialized=False)
                self.session.data_received(init[:split], None)
                self.assertEqual(self.replies, [])
                self.session.data_received(init[split:], None)
                self.assertEqual(self.replies.pop(), sftp.pack_pkt(sftp.SSH_FXP_VERSION, sftp.p_u32(3)))
                self.assertEqual(self.session.buf, b"")
        self.new_session(initialized=False)
        packets = init + b"".join(
            sftp.pack_pkt(sftp.SSH_FXP_STAT, sftp.p_u32(i) + sftp.p_str(b"/"))
            for i in (11, 12)
        )
        for byte in packets:
            self.session.data_received(bytes([byte]), None)
        self.assertEqual([reply[4] for reply in self.replies],
                         [sftp.SSH_FXP_VERSION, sftp.SSH_FXP_ATTRS, sftp.SSH_FXP_ATTRS])
        self.assertEqual([sftp.u32(reply, 5)[0] for reply in self.replies[1:]], [11, 12])
        self.replies.clear()
        self.session.data_received(packets[len(init):], None)
        self.assertEqual([sftp.u32(reply, 5)[0] for reply in self.replies], [11, 12])

    def test_read_limit(self):
        """S4: A huge requested READ returns at most 64 KiB and supports subsequent chunks."""
        data = b"x" * (64 * 1024) + b"end"
        (self.jail / "file.bin").write_bytes(data)
        handle = self.open_file(sftp.PF_READ)
        for offset, expected in ((0, data[:64 * 1024]), (64 * 1024, b"end")):
            reply = self.request(
                sftp.SSH_FXP_READ,
                sftp.p_str(handle) + sftp.p_u64(offset) + sftp.p_u32(0xFFFFFFFF),
            )
            self.assertEqual(reply[4], sftp.SSH_FXP_DATA)
            self.assertEqual(sftp.ustr(reply, 9)[0], expected)

    def test_malformed_requests_do_not_change_resources(self):
        """S4: Every supported request rejects truncated/trailing fields before resource changes."""
        path = self.jail / "file.bin"
        path.write_bytes(b"original")
        handle = self.open_file(sftp.PF_READ | sftp.PF_WRITE)
        file = self.session.handles.get(handle)
        directory = sftp.DirHandle([])
        directory_handle, _ = sftp.ustr(self.session.handles.add(directory, str(self.jail)), 0)
        bodies = (
            (sftp.SSH_FXP_REALPATH, sftp.p_str(b"/file.bin")),
            (sftp.SSH_FXP_STAT, sftp.p_str(b"/file.bin")),
            (sftp.SSH_FXP_LSTAT, sftp.p_str(b"/file.bin")),
            (sftp.SSH_FXP_FSTAT, sftp.p_str(handle)),
            (sftp.SSH_FXP_OPENDIR, sftp.p_str(b"/")),
            (sftp.SSH_FXP_READDIR, sftp.p_str(directory_handle)),
            (sftp.SSH_FXP_MKDIR, sftp.p_str(b"/new") + sftp.p_u32(0)),
            (sftp.SSH_FXP_OPEN, sftp.p_str(b"/file.bin")
             + sftp.p_u32(sftp.PF_WRITE | sftp.PF_TRUNC) + sftp.p_u32(0)),
            (sftp.SSH_FXP_READ, sftp.p_str(handle) + sftp.p_u64(1) + sftp.p_u32(1)),
            (sftp.SSH_FXP_WRITE, sftp.p_str(handle) + sftp.p_u64(0) + sftp.p_str(b"x")),
            (sftp.SSH_FXP_CLOSE, sftp.p_str(handle)),
        )
        for kind, body in bodies:
            for malformed in (body[:-1], body + b"extra"):
                with self.subTest(kind=kind, malformed=malformed), \
                        patch.object(sftp.logging, "exception"):
                    before = self.session.handles._map.copy()
                    self.assert_status(self.request(kind, malformed), sftp.SSH_FX_FAILURE)
                    self.assertEqual(self.session.handles._map, before)
                    self.assertFalse(file.closed)
                    self.assertEqual(file.tell(), 0)
                    self.assertEqual(directory.idx, 0)
                    self.assertEqual(path.read_bytes(), b"original")
                    self.assertFalse((self.jail / "new").exists())
        self.assertEqual(self.request(sftp.SSH_FXP_STAT, sftp.p_str(b"/"))[4], sftp.SSH_FXP_ATTRS)

    def test_string_and_attribute_parsing(self):
        """S4: Strings/attributes enforce lengths, known flags, and paired extension strings."""
        for data in (b"", b"\x00", sftp.p_u32(5) + b"x"):
            with self.subTest(string=data):
                with self.assertRaises((ValueError, struct.error)):
                    sftp.ustr(data, 0)
        self.assertEqual(sftp.ustr(sftp.p_str(b""), 0), (b"", 4))
        attrs = sftp.p_u32(0x8000000F) + bytes(28) + sftp.p_u32(1)
        attrs += sftp.p_str(b"name") + sftp.p_str(b"value")
        self.assertEqual(sftp.parse_attrs_ignore(attrs, 0), len(attrs))
        invalid = [sftp.p_u32(0x10), attrs[:-1]]
        invalid += [sftp.p_u32(flag) + bytes(size - 1)
                    for flag, size in ((1, 8), (2, 8), (4, 4), (8, 8))]
        invalid += [sftp.p_u32(0x80000000) + sftp.p_u32(1) + sftp.p_str(b"name")]
        for data in invalid:
            with self.subTest(attributes=data):
                with self.assertRaises((ValueError, struct.error)):
                    sftp.parse_attrs_ignore(data, 0)


class PathAndDirectoryTests(SessionTests):
    def test_posix_normalization(self):
        """S5: Client paths normalize consistently, independent of the host path separator."""
        for path, expected in (
            (b"", "/"), (b".", "/"), (b"/", "/"),
            (b"./docs/../file.txt", "/file.txt"),
            (b"/docs//file.txt", "/docs/file.txt"),
            (b"docs\\file.txt", "/docs/file.txt"),
        ):
            with self.subTest(path=path):
                self.assertEqual(sftp.canon_sftp_path(path), expected)

    def test_jail_root_and_sibling_prefix(self):
        """S5: Root aliases work, while sibling directories with the jail-name prefix cannot escape."""
        for follow in (True, False):
            for path in (b"", b".", b"/", b"/docs/.."):
                with self.subTest(path=path, follow=follow):
                    self.assertEqual(
                        sftp.safe_join(str(self.jail), path, follow_symlinks=follow),
                        str(self.jail.resolve()),
                    )
            for path in (b"../jail-other/file", b"..\\outside", b"/../../outside"):
                with self.subTest(path=path, follow=follow):
                    with self.assertRaises(PermissionError):
                        sftp.safe_join(str(self.jail), path, follow_symlinks=follow)

    def test_traversal_requests_are_denied(self):
        """S5: Metadata/open/create requests cannot access a real file outside the jail."""
        outside = self.jail.parent / "outside.txt"
        outside.write_bytes(b"secret")
        path = sftp.p_str(b"../outside.txt")
        for kind, tail in (
            (sftp.SSH_FXP_REALPATH, b""), (sftp.SSH_FXP_STAT, b""),
            (sftp.SSH_FXP_LSTAT, b""), (sftp.SSH_FXP_OPENDIR, b""),
            (sftp.SSH_FXP_MKDIR, sftp.p_u32(0)),
            (sftp.SSH_FXP_OPEN, sftp.p_u32(sftp.PF_WRITE | sftp.PF_TRUNC) + sftp.p_u32(0)),
        ):
            with self.subTest(kind=kind):
                self.assert_status(self.request(kind, path + tail), sftp.SSH_FX_PERMISSION_DENIED)
                self.assertEqual(outside.read_bytes(), b"secret")

    def test_mkdir_results(self):
        """S6: MKDIR creates one directory, rejects duplicates, and never creates missing parents."""
        self.assert_status(
            self.request(sftp.SSH_FXP_MKDIR, sftp.p_str(b"/demo") + sftp.p_u32(0)),
            sftp.SSH_FX_OK,
        )
        self.assertTrue((self.jail / "demo").is_dir())
        self.assert_status(
            self.request(sftp.SSH_FXP_MKDIR, sftp.p_str(b"/demo") + sftp.p_u32(0)),
            sftp.SSH_FX_FAILURE,
        )
        self.assert_status(
            self.request(sftp.SSH_FXP_MKDIR, sftp.p_str(b"/missing/child") + sftp.p_u32(0)),
            sftp.SSH_FX_NO_SUCH_FILE,
        )
        self.assertFalse((self.jail / "missing").exists())

    def test_directory_listing_and_eof(self):
        """Protocol regression: READDIR batches all entries without duplicates, then returns EOF."""
        expected = {f"file-{i}" for i in range(65)}
        for name in expected:
            (self.jail / name).touch()
        reply = self.request(sftp.SSH_FXP_OPENDIR, sftp.p_str(b"/"))
        self.assertEqual(reply[4], sftp.SSH_FXP_HANDLE)
        handle, _ = sftp.ustr(reply, 9)
        names = []
        for expected_count in (64, 1):
            reply = self.request(sftp.SSH_FXP_READDIR, sftp.p_str(handle))
            self.assertEqual(reply[4], sftp.SSH_FXP_NAME)
            count, off = sftp.u32(reply, 9)
            self.assertEqual(count, expected_count)
            for _ in range(count):
                name, off = sftp.ustr(reply, off)
                _, off = sftp.ustr(reply, off)
                off = sftp.parse_attrs_ignore(reply, off)
                names.append(name.decode())
            self.assertEqual(off, len(reply))
        self.assertEqual(set(names), expected)
        self.assertEqual(len(names), len(expected))
        self.assert_status(
            self.request(sftp.SSH_FXP_READDIR, sftp.p_str(handle)), sftp.SSH_FX_EOF
        )


class ErrorResponseTests(SessionTests):
    def test_safe_internal_errors(self):
        """S7: Internal OPEN/MKDIR errors are logged in detail but sanitized in client replies."""
        secret = str(self.jail.parent / "private-host-path")
        for kind, target, body, message in (
            (sftp.SSH_FXP_OPEN, "open",
             sftp.p_str(b"/file.bin") + sftp.p_u32(sftp.PF_READ) + sftp.p_u32(0),
             b"operation failed"),
            (sftp.SSH_FXP_MKDIR, "mkdir", sftp.p_str(b"/new") + sftp.p_u32(0),
             b"directory creation failed"),
        ):
            with self.subTest(kind=kind), \
                    patch.object(sftp.os, target, side_effect=OSError(secret)), \
                    self.assertLogs(level="ERROR") as logs:
                reply = self.request(kind, body)
            self.assertEqual(self.assert_status(reply, sftp.SSH_FX_FAILURE), message)
            self.assertNotIn(secret.encode(), reply)
            logged = "\n".join(logs.output)
            self.assertIn(secret, logged)
            self.assertIn("42", logged)

    def test_status_mapping(self):
        """S7: Missing files, permission errors, and unknown requests map to expected STATUS codes."""
        for kind in (sftp.SSH_FXP_STAT, sftp.SSH_FXP_LSTAT):
            self.assert_status(
                self.request(kind, sftp.p_str(b"/missing")), sftp.SSH_FX_NO_SUCH_FILE
            )
        with patch.object(sftp.os, "mkdir", side_effect=PermissionError("denied")):
            self.assert_status(
                self.request(sftp.SSH_FXP_MKDIR, sftp.p_str(b"/new") + sftp.p_u32(0)),
                sftp.SSH_FX_PERMISSION_DENIED,
            )
        self.assert_status(self.request(255), sftp.SSH_FX_FAILURE)
