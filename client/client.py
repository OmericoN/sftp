#!/usr/bin/env python3
import argparse
import asyncio
import getpass
import os
import posixpath
import shlex
import struct
import sys
from datetime import timezone, datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

import asyncssh

# Client -> Server
SSH_FXP_INIT = 1
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_MKDIR = 14
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17

# Server -> Client
SSH_FXP_VERSION = 2
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

# Status codes
SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4
SSH_FX_BAD_MESSAGE = 5
SSH_FX_NO_CONNECTION = 6
SSH_FX_CONNECTION_LOST = 7
SSH_FX_OP_UNSUPPORTED = 8

STATUS_MESSAGES = {
    SSH_FX_OK: "Success",
    SSH_FX_EOF: "End of file",
    SSH_FX_NO_SUCH_FILE: "No such file or directory",
    SSH_FX_PERMISSION_DENIED: "Permission denied",
    SSH_FX_FAILURE: "Operation failed",
    SSH_FX_BAD_MESSAGE: "Bad message",
    SSH_FX_NO_CONNECTION: "No connection",
    SSH_FX_CONNECTION_LOST: "Connection lost",
    SSH_FX_OP_UNSUPPORTED: "Operation unsupported",
}

# Open flags
PF_READ = 0x00000001
PF_WRITE = 0x00000002
PF_APPEND = 0x00000004
PF_CREAT = 0x00000008
PF_TRUNC = 0x00000010
PF_EXCL = 0x00000020

# Attribute flags
ATTR_SIZE = 0x00000001
ATTR_UIDGID = 0x00000002
ATTR_PERMISSIONS = 0x00000004
ATTR_ACMODTIME = 0x00000008
ATTR_EXTENDED = 0x80000000

# SFTP chunk transfer limit
CHUNK_SIZE = 32768


def p_u32(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)


def p_u64(val: int) -> bytes:
    return struct.pack(">Q", val & 0xFFFFFFFFFFFFFFFF)


def p_str(data: bytes) -> bytes:
    return p_u32(len(data)) + data


def pack_packet(ptype: int, payload: bytes) -> bytes:
    body = bytes([ptype]) + payload
    return p_u32(len(body)) + body


def u32(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset + 4 > len(data):
        raise ValueError("Truncated u32 field")
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def u64(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset + 8 > len(data):
        raise ValueError("Truncated u64 field")
    return struct.unpack_from(">Q", data, offset)[0], offset + 8


def ustr(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    length, offset = u32(data, offset)
    if offset + length > len(data):
        raise ValueError("Truncated string field")
    return data[offset : offset + length], offset + length


def parse_attrs(data: bytes, offset: int = 0) -> Tuple[dict, int]:
    attrs = {}
    flags, offset = u32(data, offset)
    attrs["flags"] = flags

    if flags & ATTR_SIZE:
        attrs["size"], offset = u64(data, offset)

    if flags & ATTR_UIDGID:
        attrs["uid"], offset = u32(data, offset)
        attrs["gid"], offset = u32(data, offset)

    if flags & ATTR_PERMISSIONS:
        attrs["permissions"], offset = u32(data, offset)

    if flags & ATTR_ACMODTIME:
        attrs["atime"], offset = u32(data, offset)
        attrs["mtime"], offset = u32(data, offset)

    if flags & ATTR_EXTENDED:
        ext_count, offset = u32(data, offset)
        attrs["extended"] = {}
        for _ in range(ext_count):
            ext_type, offset = ustr(data, offset)
            ext_data, offset = ustr(data, offset)
            attrs["extended"][ext_type] = ext_data

    return attrs, offset


class TOFUClient(asyncssh.SSHClient):
    def __init__(self, known_hosts_path: Path):
        self.known_hosts_path = known_hosts_path

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        key_data = key.export_public_key().decode("ascii").strip()
        host_entry = f"[{host}]:{port}" if port != 22 else host

        if self.known_hosts_path.exists():
            for line in self.known_hosts_path.read_text("utf-8").splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == host_entry:
                    stored_key = f"{parts[1]} {parts[2]}"
                    if stored_key == key_data:
                        return True
                    print(f"WARNING: Host key for {host_entry} has changed!")
                    return False

        with self.known_hosts_path.open("a", encoding="utf-8") as f:
            f.write(f"{host_entry} {key_data}\n")
        print(f"Trusting host key for {host_entry} (TOFU).")
        return True


class SFTPClientSession(asyncssh.SSHClientSession):
    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._chan = None
        self._buffer = bytearray()
        self._loop = loop
        self._version_future: Optional[asyncio.Future] = None
        self._pending_requests: Dict[int, asyncio.Future] = {}

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.get_running_loop()
        return self._loop

    @property
    def version_future(self) -> asyncio.Future:
        if self._version_future is None:
            self._version_future = self._get_loop().create_future()
        return self._version_future

    def connection_made(self, chan):
        self._chan = chan
        try:
            self._chan.set_encoding(None)
        except AttributeError:
            pass

    def data_received(self, data, datatype=None):
        self._buffer += data

        while len(self._buffer) >= 4:
            length, _ = u32(self._buffer, 0)
            if len(self._buffer) < 4 + length:
                break

            packet = bytes(self._buffer[4 : 4 + length])
            del self._buffer[: 4 + length]

            ptype = packet[0]
            payload = packet[1:]

            if ptype == SSH_FXP_VERSION:
                version, _ = u32(payload, 0)
                if not self.version_future.done():
                    self.version_future.set_result(version)
            else:
                req_id, offset = u32(payload, 0)
                fut = self._pending_requests.pop(req_id, None)
                if fut is not None and not fut.done():
                    fut.set_result((ptype, payload[offset:]))

    def connection_lost(self, exc):
        err = exc or ConnectionError("Connection lost")
        if self._version_future is not None and not self._version_future.done():
            self._version_future.set_exception(err)

        for fut in self._pending_requests.values():
            if not fut.done():
                fut.set_exception(err)

        self._pending_requests.clear()


class SFTPClient:
    def __init__(self, chan: asyncssh.SSHClientChannel, session: SFTPClientSession):
        self.chan = chan
        self.session = session
        self._req_id = 0
        self.cwd = "/"

    def _next_id(self) -> int:
        self._req_id = (self._req_id + 1) & 0xFFFFFFFF
        return self._req_id

    async def init(self) -> int:
        packet = pack_packet(SSH_FXP_INIT, p_u32(3))
        self.chan.write(packet)
        server_version = await self.session.version_future

        if server_version != 3:
            raise ValueError(f"Unsupported SFTP version: {server_version}")
        return server_version

    async def _send_request(self, ptype: int, payload: bytes) -> Tuple[int, bytes]:
        req_id = self._next_id()
        fut = asyncio.get_running_loop().create_future()
        self.session._pending_requests[req_id] = fut
        packet = pack_packet(ptype, p_u32(req_id) + payload)

        try:
            self.chan.write(packet)
            return await fut
        finally:
            self.session._pending_requests.pop(req_id, None)

    def _resolve_remote_path(self, path: Optional[str]) -> str:
        if not path:
            return self.cwd
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    async def pwd(self) -> str:
        return self.cwd

    async def ls(self, remote_path: Optional[str] = None) -> list:
        target_path = self._resolve_remote_path(remote_path)

        reply_type, payload = await self._send_request(
            SSH_FXP_OPENDIR, p_str(target_path.encode("utf-8"))
        )
        if reply_type == SSH_FXP_STATUS:
            code, off = u32(payload, 0)
            msg, _ = ustr(payload, off)
            raise RuntimeError(
                f"OPENDIR failed (status {code}): {msg.decode('utf-8', 'replace')}"
            )
        if reply_type != SSH_FXP_HANDLE:
            raise RuntimeError(f"Unexpected response to OPENDIR: {reply_type}")

        handle, _ = ustr(payload, 0)
        entries = []

        try:
            while True:
                reply_type, payload = await self._send_request(
                    SSH_FXP_READDIR, p_str(handle)
                )

                if reply_type == SSH_FXP_STATUS:
                    code, off = u32(payload, 0)
                    if code == SSH_FX_EOF:
                        break
                    msg, _ = ustr(payload, off)
                    raise RuntimeError(
                        f"READDIR failed (status {code}): {msg.decode('utf-8', 'replace')}"
                    )

                if reply_type != SSH_FXP_NAME:
                    raise RuntimeError(f"Unexpected response to READDIR: {reply_type}")

                count, off = u32(payload, 0)
                for _ in range(count):
                    filename_bs, off = ustr(payload, off)
                    longname_bs, off = ustr(payload, off)
                    attrs, off = parse_attrs(payload, off)
                    entries.append(
                        {
                            "filename": filename_bs.decode("utf-8", "replace"),
                            "longname": longname_bs.decode("utf-8", "replace"),
                            "attrs": attrs,
                        }
                    )
        finally:
            close_type, close_payload = await self._send_request(
                SSH_FXP_CLOSE, p_str(handle)
            )
            if close_type == SSH_FXP_STATUS:
                code, off = u32(close_payload, 0)
                if code != SSH_FX_OK:
                    msg, _ = ustr(close_payload, off)
                    raise RuntimeError(
                        f"CLOSE failed (status {code}): {msg.decode('utf-8', 'replace')}"
                    )

        return entries

    async def mkdir(self, remote_path: str) -> None:
        target_path = self._resolve_remote_path(remote_path or ".")

        reply_type, payload = await self._send_request(
            SSH_FXP_MKDIR,
            p_str(target_path.encode("utf-8")) + p_u32(ATTR_PERMISSIONS) + p_u32(0o755),
        )
        if reply_type != SSH_FXP_STATUS:
            raise RuntimeError(f"Unexpected response to MKDIR: {reply_type}")

        code, off = u32(payload, 0)
        if code == SSH_FX_OK:
            return

        msg, _ = ustr(payload, off)
        raise RuntimeError(
            f"MKDIR failed for {target_path!r} (status {code}): {msg.decode('utf-8', 'replace')}"
        )

    async def stat(self, remote_path: str) -> dict:
        target_path = self._resolve_remote_path(remote_path or ".")

        reply_type, payload = await self._send_request(
            SSH_FXP_STAT, p_str(target_path.encode("utf-8"))
        )
        if reply_type == SSH_FXP_STATUS:
            code, off = u32(payload, 0)
            msg, _ = ustr(payload, off)
            raise RuntimeError(
                f"STAT failed (status {code}): {msg.decode('utf-8', 'replace')}"
            )

        if reply_type != SSH_FXP_ATTRS:
            raise RuntimeError(f"Unexpected response to STAT: {reply_type}")

        attrs, _ = parse_attrs(payload, 0)
        return attrs

    async def get(self, remote_path: str, local_path: Optional[str] = None) -> None:
        target_remote = self._resolve_remote_path(remote_path)
        dest_local = local_path or posixpath.basename(target_remote)
        if not dest_local:
            raise ValueError("Cannot determine local destination filename")

        reply_type, payload = await self._send_request(
            SSH_FXP_OPEN,
            p_str(target_remote.encode("utf-8")) + p_u32(PF_READ) + p_u32(0),
        )

        if reply_type == SSH_FXP_STATUS:
            code, off = u32(payload, 0)
            msg, _ = ustr(payload, off)
            raise RuntimeError(
                f"OPEN failed for {target_remote!r} (status {code}): {msg.decode('utf-8', 'replace')}"
            )

        if reply_type != SSH_FXP_HANDLE:
            raise RuntimeError(f"Unexpected response to OPEN: {reply_type}")

        handle, _ = ustr(payload, 0)
        current_offset = 0

        try:
            with open(dest_local, "wb") as local_file:
                while True:
                    reply_type, payload = await self._send_request(
                        SSH_FXP_READ,
                        p_str(handle) + p_u64(current_offset) + p_u32(CHUNK_SIZE),
                    )
                    if reply_type == SSH_FXP_STATUS:
                        code, off = u32(payload, 0)
                        if code == SSH_FX_EOF:
                            break
                        msg, _ = ustr(payload, off)
                        raise RuntimeError(
                            f"READ failed (status {code}): {msg.decode('utf-8', 'replace')}"
                        )

                    if reply_type != SSH_FXP_DATA:
                        raise RuntimeError(f"Unexpected response to READ: {reply_type}")

                    chunk, _ = ustr(payload, 0)
                    if not chunk:
                        break

                    local_file.write(chunk)
                    current_offset += len(chunk)
        finally:
            await self._send_request(SSH_FXP_CLOSE, p_str(handle))

    async def put(self, local_path: str, remote_path: str) -> None:
        if not local_path:
            raise ValueError("Local file path is required")

        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

        target_remote = remote_path or os.path.basename(local_path)
        target_remote = self._resolve_remote_path(target_remote)

        pflags = PF_WRITE | PF_CREAT | PF_TRUNC
        reply_type, payload = await self._send_request(
            SSH_FXP_OPEN,
            p_str(target_remote.encode("utf-8")) + p_u32(pflags) + p_u32(0),
        )

        if reply_type == SSH_FXP_STATUS:
            code, off = u32(payload, 0)
            msg, _ = ustr(payload, off)
            raise RuntimeError(
                f"OPEN failed for {target_remote!r} (status {code}): {msg.decode('utf-8', 'replace')}"
            )

        if reply_type != SSH_FXP_HANDLE:
            raise RuntimeError(f"Unexpected response to OPEN: {reply_type}")

        handle, _ = ustr(payload, 0)
        current_offset = 0

        try:
            with open(local_path, "rb") as local_file:
                while True:
                    chunk = local_file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    reply_type, payload = await self._send_request(
                        SSH_FXP_WRITE,
                        p_str(handle) + p_u64(current_offset) + p_str(chunk),
                    )
                    if reply_type != SSH_FXP_STATUS:
                        raise RuntimeError(
                            f"Unexpected response to WRITE: {reply_type}"
                        )

                    code, off = u32(payload, 0)
                    if code != SSH_FX_OK:
                        msg, _ = ustr(payload, off)
                        raise RuntimeError(
                            f"WRITE failed at offset {current_offset} (status {code}): "
                            f"{msg.decode('utf-8', 'replace')}"
                        )

                    current_offset += len(chunk)
        finally:
            await self._send_request(SSH_FXP_CLOSE, p_str(handle))

    async def close(self) -> None:
        if self.chan:
            self.chan.close()


async def sftp_repl(client: SFTPClient) -> None:
    print("SFTP interactive session started. Type 'help' or 'quit'.")
    while True:
        try:
            line = await asyncio.to_thread(input, "sftp> ")
            line = line.strip()
            if not line:
                continue

            parts = shlex.split(line)
            cmd, args = parts[0].lower(), parts[1:]

            if cmd in ("quit", "exit"):
                break

            elif cmd == "help":
                print(
                    "Supported commands: pwd, ls [path], mkdir <path>, stat <path>, get <rpath> [lpath], put <lpath> <rpath>, quit"
                )

            elif cmd == "pwd":
                if args:
                    print("Usage: pwd")
                    continue
                print(await client.pwd())

            elif cmd == "ls":
                if len(args) > 1:
                    print("Usage: ls [path]")
                    continue
                entries = await client.ls(args[0] if args else ".")
                for entry in entries:
                    print(entry["filename"])

            elif cmd == "mkdir":
                if len(args) != 1:
                    print("Usage: mkdir <path>")
                    continue
                await client.mkdir(args[0])
                print(f"Created directory: {args[0]}")

            elif cmd == "stat":
                if len(args) != 1:
                    print("Usage: stat <path>")
                    continue
                attrs = await client.stat(args[0])
                size = attrs.get("size", "N/A")
                perms = oct(attrs["permissions"]) if "permissions" in attrs else "N/A"
                mtime = (
                    datetime.fromtimestamp(attrs["mtime"], tz=timezone.utc).isoformat()
                    if "mtime" in attrs
                    else "N/A"
                )
                print(f"Size: {size} | Mode: {perms} | Modified: {mtime}")

            elif cmd == "get":
                if len(args) not in (1, 2):
                    print("Usage: get <rpath> [lpath]")
                    continue
                await client.get(args[0], args[1] if len(args) == 2 else None)
                print(f"Downloaded: {args[0]}")

            elif cmd == "put":
                if len(args) != 2:
                    print("Usage: put <lpath> <rpath>")
                    continue
                await client.put(args[0], args[1])
                print(f"Uploaded: {args[0]} -> {args[1]}")

            else:
                print(f"Unknown command: {cmd!r}. Type 'help' for available commands.")

        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        except Exception as exc:
            print(f"Error: {exc}")


async def connect_sftp(
    host: str,
    port: int,
    username: str,
    password: Optional[str] = None,
    known_hosts: Optional[str] = None,
) -> Tuple[asyncssh.SSHClientConnection, SFTPClient]:
    print(f"Connecting to {username}@{host}:{port}...")

    if known_hosts is not None:
        conn = await asyncssh.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            known_hosts=known_hosts,
        )
    else:
        default_kh = Path.home() / ".ssh" / "sftp_project_known_hosts"
        conn = await asyncssh.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            client_factory=lambda: TOFUClient(default_kh),
        )

    chan, session = await conn.create_session(
        SFTPClientSession,
        subsystem="sftp",
    )

    client = SFTPClient(chan, session)
    version = await client.init()
    print(f"Connected to SFTP subsystem (version {version}).")

    return conn, client


def parse_args():
    parser = argparse.ArgumentParser(description="SFTP v3 Command-Line Client")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target SFTP server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2222,
        help="Target SFTP server port (default: 2222)",
    )
    parser.add_argument(
        "--username",
        required=True,
        help="SSH username for authentication",
    )
    parser.add_argument(
        "--known-hosts",
        default=None,
        help="Path to known_hosts file for host key verification",
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    conn = None
    client = None
    try:
        conn, client = await connect_sftp(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            known_hosts=args.known_hosts,
        )
        await sftp_repl(client)
    except Exception as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if client:
            await client.close()
        if conn:
            conn.close()
            await conn.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
