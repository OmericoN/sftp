import asyncio
import os
import posixpath
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from client import client as c


class WireAndAttrTests(unittest.TestCase):
    def test_primitive_pack_and_unpack(self):
        self.assertEqual(c.p_u32(0x12345678), b"\x12\x34\x56\x78")
        val, off = c.u32(b"\x12\x34\x56\x78\x99", 0)
        self.assertEqual(val, 0x12345678)
        self.assertEqual(off, 4)

        self.assertEqual(c.p_u64(0x1122334455667788), b"\x11\x22\x33\x44\x55\x66\x77\x88")
        val64, off64 = c.u64(b"\x11\x22\x33\x44\x55\x66\x77\x88\xaa", 0)
        self.assertEqual(val64, 0x1122334455667788)
        self.assertEqual(off64, 8)

        raw_str = b"hello sftp"
        packed_str = c.p_str(raw_str)
        self.assertEqual(packed_str, struct.pack(">I", 10) + raw_str)
        s_val, s_off = c.ustr(packed_str + b"extra", 0)
        self.assertEqual(s_val, raw_str)
        self.assertEqual(s_off, 14)

    def test_pack_packet(self):
        pkt = c.pack_packet(c.SSH_FXP_INIT, c.p_u32(3))
        self.assertEqual(pkt, b"\x00\x00\x00\x05\x01\x00\x00\x00\x03")

    def test_truncated_unpack(self):
        with self.assertRaises(ValueError):
            c.u32(b"\x00\x01")
        with self.assertRaises(ValueError):
            c.u64(b"\x00\x01\x02\x03")
        with self.assertRaises(ValueError):
            c.ustr(struct.pack(">I", 10) + b"abc")

    def test_parse_attrs_all_fields(self):
        flags = (
            c.ATTR_SIZE
            | c.ATTR_UIDGID
            | c.ATTR_PERMISSIONS
            | c.ATTR_ACMODTIME
            | c.ATTR_EXTENDED
        )
        payload = (
            c.p_u32(flags)
            + c.p_u64(1048576)
            + c.p_u32(1001)
            + c.p_u32(1002)
            + c.p_u32(0o644)
            + c.p_u32(1700000000)
            + c.p_u32(1700000500)
            + c.p_u32(1)
            + c.p_str(b"vendor@domain.com")
            + c.p_str(b"ext-val")
        )
        attrs, off = c.parse_attrs(payload, 0)
        self.assertEqual(off, len(payload))
        self.assertEqual(attrs["size"], 1048576)
        self.assertEqual(attrs["uid"], 1001)
        self.assertEqual(attrs["gid"], 1002)
        self.assertEqual(attrs["permissions"], 0o644)
        self.assertEqual(attrs["atime"], 1700000000)
        self.assertEqual(attrs["mtime"], 1700000500)
        self.assertEqual(attrs["extended"][b"vendor@domain.com"], b"ext-val")

    def test_parse_attrs_empty(self):
        attrs, off = c.parse_attrs(c.p_u32(0), 0)
        self.assertEqual(off, 4)
        self.assertEqual(attrs, {"flags": 0})


class SessionAndFramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_data_received_and_fragmentation(self):
        session = c.SFTPClientSession()
        fut = asyncio.get_running_loop().create_future()
        session._pending_requests[42] = fut

        reply_body = bytes([c.SSH_FXP_STATUS]) + c.p_u32(42) + c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK")
        wire = c.p_u32(len(reply_body)) + reply_body

        session.data_received(wire[:5])
        self.assertFalse(fut.done())
        session.data_received(wire[5:10])
        self.assertFalse(fut.done())
        session.data_received(wire[10:])
        self.assertTrue(fut.done())

        ptype, payload = fut.result()
        self.assertEqual(ptype, c.SSH_FXP_STATUS)
        code, off = c.u32(payload, 0)
        self.assertEqual(code, c.SSH_FX_OK)

    async def test_version_packet_handling(self):
        session = c.SFTPClientSession()
        version_body = bytes([c.SSH_FXP_VERSION]) + c.p_u32(3)
        wire = c.p_u32(len(version_body)) + version_body

        session.data_received(wire)
        self.assertTrue(session.version_future.done())
        self.assertEqual(session.version_future.result(), 3)

    async def test_connection_lost_cancels_pending(self):
        session = c.SFTPClientSession()
        fut = asyncio.get_running_loop().create_future()
        session._pending_requests[99] = fut

        session.connection_lost(ConnectionResetError("peer reset"))
        self.assertTrue(fut.done())
        with self.assertRaises(ConnectionResetError):
            await fut


class ClientOperationsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mock_chan = MagicMock()
        self.session = c.SFTPClientSession()
        self.client = c.SFTPClient(self.mock_chan, self.session)

    def _simulate_server_reply(self, ptype: int, req_id: int, payload_after_id: bytes):
        body = bytes([ptype]) + c.p_u32(req_id) + payload_after_id
        wire = c.p_u32(len(body)) + body
        self.session.data_received(wire)

    async def test_init_success(self):
        init_task = asyncio.create_task(self.client.init())
        await asyncio.sleep(0.01)
        version_body = bytes([c.SSH_FXP_VERSION]) + c.p_u32(3)
        self.session.data_received(c.p_u32(len(version_body)) + version_body)
        res = await init_task
        self.assertEqual(res, 3)

    async def test_init_unsupported_version(self):
        init_task = asyncio.create_task(self.client.init())
        await asyncio.sleep(0.01)
        version_body = bytes([c.SSH_FXP_VERSION]) + c.p_u32(4)
        self.session.data_received(c.p_u32(len(version_body)) + version_body)
        with self.assertRaises(ValueError):
            await init_task

    async def test_resolve_remote_path(self):
        self.client.cwd = "/base/dir"
        self.assertEqual(self.client._resolve_remote_path(None), "/base/dir")
        self.assertEqual(self.client._resolve_remote_path(""), "/base/dir")
        self.assertEqual(self.client._resolve_remote_path("/abs/path"), "/abs/path")
        self.assertEqual(self.client._resolve_remote_path("rel/file"), "/base/dir/rel/file")
        self.assertEqual(self.client._resolve_remote_path("../peer"), "/base/peer")

    async def test_pwd(self):
        self.client.cwd = "/projects"
        self.assertEqual(await self.client.pwd(), "/projects")

    async def test_mkdir_success(self):
        async def mock_server():
            await asyncio.sleep(0.01)
            self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK"))

        t = asyncio.create_task(mock_server())
        await self.client.mkdir("/testdir")
        await t

    async def test_mkdir_failure(self):
        async def mock_server():
            await asyncio.sleep(0.01)
            self._simulate_server_reply(
                c.SSH_FXP_STATUS,
                self.client._req_id,
                c.p_u32(c.SSH_FX_PERMISSION_DENIED) + c.p_str(b"Permission denied"),
            )

        t = asyncio.create_task(mock_server())
        with self.assertRaises(RuntimeError) as ctx:
            await self.client.mkdir("/admin/test")
        await t
        self.assertIn("Permission denied", str(ctx.exception))

    async def test_stat_success(self):
        async def mock_server():
            await asyncio.sleep(0.01)
            attr_bytes = c.p_u32(c.ATTR_SIZE | c.ATTR_PERMISSIONS) + c.p_u64(4096) + c.p_u32(0o755)
            self._simulate_server_reply(c.SSH_FXP_ATTRS, self.client._req_id, attr_bytes)

        t = asyncio.create_task(mock_server())
        res = await self.client.stat("/data")
        await t
        self.assertEqual(res["size"], 4096)
        self.assertEqual(res["permissions"], 0o755)

    async def test_ls_directory(self):
        async def mock_server():
            await asyncio.sleep(0.01)
            self._simulate_server_reply(c.SSH_FXP_HANDLE, self.client._req_id, c.p_str(b"dir-handle-1"))
            await asyncio.sleep(0.01)
            entry1 = c.p_str(b"file1.txt") + c.p_str(b"-rw-r--r-- 100 file1.txt") + c.p_u32(0)
            entry2 = c.p_str(b"file2.txt") + c.p_str(b"-rw-r--r-- 200 file2.txt") + c.p_u32(0)
            names_payload = c.p_u32(2) + entry1 + entry2
            self._simulate_server_reply(c.SSH_FXP_NAME, self.client._req_id, names_payload)
            await asyncio.sleep(0.01)
            self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_EOF) + c.p_str(b"EOF"))
            await asyncio.sleep(0.01)
            self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK"))

        t = asyncio.create_task(mock_server())
        entries = await self.client.ls("/somedir")
        await t
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["filename"], "file1.txt")
        self.assertEqual(entries[1]["filename"], "file2.txt")

    async def test_get_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "downloaded.txt")

            async def mock_server():
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_HANDLE, self.client._req_id, c.p_str(b"file-handle-1"))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_DATA, self.client._req_id, c.p_str(b"part 1 "))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_DATA, self.client._req_id, c.p_str(b"part 2"))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_EOF) + c.p_str(b"EOF"))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK"))

            t = asyncio.create_task(mock_server())
            await self.client.get("/remote/test.txt", dest)
            await t

            with open(dest, "rb") as f:
                content = f.read()
            self.assertEqual(content, b"part 1 part 2")

    async def test_put_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "upload.txt")
            with open(src, "wb") as f:
                f.write(b"content to upload")

            async def mock_server():
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_HANDLE, self.client._req_id, c.p_str(b"file-handle-2"))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK"))
                await asyncio.sleep(0.01)
                self._simulate_server_reply(c.SSH_FXP_STATUS, self.client._req_id, c.p_u32(c.SSH_FX_OK) + c.p_str(b"OK"))

            t = asyncio.create_task(mock_server())
            await self.client.put(src, "/remote/dest.txt")
            await t
