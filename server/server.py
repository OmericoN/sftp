#!/usr/bin/env python3
import asyncio
import logging
import os
import posixpath
import stat
import struct
from pathlib import Path
from typing import override

import asyncssh

if __package__:
    from .auth import LoginLimiter, load_users, verify_password
    from .policy import load_policy
else:
    from auth import LoginLimiter, load_users, verify_password
    from policy import load_policy

# SFTP focus: TODO S1-S7 below map to section 3 of SERVER_TASKS.md.
# Verify each fix in tests/test_sftp.py; finish with an OpenSSH upload/download check.

# Console debug logging for AsyncSSH
logging.basicConfig(
    level=logging.DEBUG,  # or INFO
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logging.getLogger("asyncssh").setLevel(logging.DEBUG)
# Optional: quiet down noisy asyncio internals
logging.getLogger("asyncio").setLevel(logging.INFO)


SERVER_DIR = Path(__file__).resolve().parent

HOST_KEY_PATH = str(SERVER_DIR / "ssh_host_ed25519_key")
LISTEN_HOST, LISTEN_PORT = "", 2222
SFTP_SUBSYSTEM_NAME = "sftp"
JAIL_ROOT = str(SERVER_DIR / "sftp_root")

# --- SFTP constants (subset for INIT/REALPATH/OPENDIR/READDIR/CLOSE) ---
SSH_FXP_INIT, SSH_FXP_VERSION = 1, 2
SSH_FXP_OPENDIR, SSH_FXP_READDIR = 11, 12
SSH_FXP_REALPATH = 16
SSH_FXP_STATUS, SSH_FXP_HANDLE, SSH_FXP_NAME = 101, 102, 104
SSH_FX_OK, SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_PERMISSION_DENIED, SSH_FX_FAILURE = (
    0,
    1,
    2,
    3,
    4,
)
ATTR_SIZE, ATTR_PERMISSIONS, ATTR_ACMODTIME = 0x1, 0x4, 0x8

SSH_FXP_OPEN, SSH_FXP_CLOSE = 3, 4
SSH_FXP_WRITE = 6
SSH_FXP_MKDIR = 14
SSH_FXP_DATA = 103
SSH_FXP_READ = 5

# pflags
PF_READ, PF_WRITE, PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = (
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
)

SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_STAT = 17
SSH_FXP_ATTRS = 105


def parse_attrs_ignore(buf, off):
    # DONE S4: Check skipped attribute lengths so truncated attributes cannot pass validation.
    ATTR_SIZE, ATTR_UIDGID, ATTR_PERMISSIONS, ATTR_ACMODTIME, ATTR_EXTENDED = (
        0x1,
        0x2,
        0x4,
        0x8,
        0x80000000,
    )
    flags, off = u32(buf, off)

    supported_flags = (
        ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME | ATTR_EXTENDED
    )
    if flags & ~supported_flags:
        raise ValueError("unsupported attribute flags")

    if flags & ATTR_SIZE:
        off += 8
    if flags & ATTR_UIDGID:
        off += 8
    if flags & ATTR_PERMISSIONS:
        off += 4
    if flags & ATTR_ACMODTIME:
        off += 8
    if flags & ATTR_EXTENDED:
        n, off = u32(buf, off)
        for _ in range(n):
            _, off = ustr(buf, off)  # type
            _, off = ustr(buf, off)  # data
    if off > len(buf):
        raise ValueError("truncated attributes")
    return off


# DONE S5: Use POSIX normalization for client paths on all OSes; align with safe_join.
def canon_sftp_path(path_bs: bytes) -> str:
    """Return a canonical SFTP path (POSIX-style) relative to jail root."""
    s = path_bs.decode(errors="strict").replace("\\", "/")
    if not s or s == ".":
        return "/"
    if s.startswith("/"):
        rel = posixpath.normpath(s.lstrip("/"))
    else:
        rel = posixpath.normpath(s)
    rel = rel.replace("\\", "/").strip("/")
    return "/" if rel in ("", ".") else "/" + rel


def p_u32(n):
    return struct.pack(">I", n & 0xFFFFFFFF)


def p_u64(n):
    return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)


def p_byte(b):
    return struct.pack("B", b)


def p_str(bs):
    return p_u32(len(bs)) + bs


def pack_pkt(ptype, payload):
    body = bytes([ptype]) + payload
    return p_u32(len(body)) + body


def u32(b, off):
    return struct.unpack_from(">I", b, off)[0], off + 4


def u64(b, off):
    return struct.unpack_from(">Q", b, off)[0], off + 8


def ustr(b, off):
    # DONE S4: Reject declared string lengths beyond the remaining packet bytes.
    ln, off = u32(b, off)
    if off + ln > len(b):
        raise ValueError("truncated string")

    return b[off : off + ln], off + ln


def sftp_attrs_from_stat(st, mode=None):
    perms = stat.S_IFMT(st.st_mode) | (st.st_mode & 0o777 if mode is None else mode)
    return (
        p_u32(ATTR_SIZE | ATTR_PERMISSIONS | ATTR_ACMODTIME)
        + p_u64(st.st_size)
        + p_u32(perms)
        + p_u32(int(st.st_atime))
        + p_u32(int(st.st_mtime))
    )


class DirHandle:
    def __init__(self, entries):
        self.entries, self.idx = entries, 0


class Handles:
    def __init__(self):
        self._n, self._map, self._paths = 1, {}, {}

    def add(self, obj, path):
        hid = str(self._n).encode()
        self._n += 1
        self._map[hid] = obj
        self._paths[hid] = path
        return p_str(hid)

    def get(self, h):
        return self._map.get(h)

    def path(self, h):
        return self._paths.get(h)

    def close(self, h):
        # DONE S2: Close file objects explicitly; report missing handles to the CLOSE handler.
        obj = self._map.pop(h, None)
        self._paths.pop(h, None)
        if obj is None:
            raise ValueError("bad handle")
        if not isinstance(obj, DirHandle):
            obj.close()

    # DONE S2: Close all method for closing all handles and object if connection is to be lost
    def close_all(self):
        for h in list(self._map):
            try:
                self.close(h)
            except Exception:
                logging.exception("Failed to close handle %r", h)


def safe_join(jroot, path_bs, *, follow_symlinks=True):
    # shortcut: path checks are not atomic; use handle-relative operations if local writers can mutate the jail.
    # DONE S5: Harden/test jail resolution for Windows paths, symlink escapes, and replacement races;
    # preserve LSTAT's no-follow behavior instead of resolving its final symlink here.
    # Treat absolute path as relative to the jail root
    s = path_bs.decode(errors="strict").replace("\\", "/")
    if "\x00" in s or ":" in s:
        raise PermissionError("invalid path")

    rel = s.lstrip("/")
    rel = posixpath.normpath(rel)
    full = os.path.join(jroot, rel)

    if follow_symlinks or os.path.basename(full) in ("", ".", ".."):
        full = os.path.realpath(full)
    else:
        parent, name = os.path.split(full)
        full = os.path.join(os.path.realpath(parent), name)
    jail = os.path.realpath(jroot)

    try:
        common = os.path.commonpath([jail, full])
    except ValueError:
        raise PermissionError("path escape") from None
    if os.path.normcase(common) != os.path.normcase(jail):
        raise PermissionError("path escape")
    return full


class SFTPSession(asyncssh.SSHServerSession):
    def __init__(self, username, policy):
        self.username = username
        self.policy = policy
        self.buf = b""
        self.handles = Handles()
        self.initialized = False
        self._sftp_ok = False

    # Ensure the channel uses *binary* I/O from the start
    def connection_made(self, chan):
        self._chan = chan
        # Disable any text encoding so data_received gets bytes
        try:
            self._chan.set_encoding(None)  # newer AsyncSSH
        except AttributeError:
            try:
                self._chan.set_write_encoding(None)  # older AsyncSSH fallback
            except Exception:
                pass

    # DONE S2: Add connection_lost cleanup for all outstanding file handles.
    @override
    def connection_lost(self, exc) -> None:
        self.handles.close_all()

    # Accept only the SFTP subsystem
    def subsystem_requested(self, name: str) -> bool:
        if name == SFTP_SUBSYSTEM_NAME:  # usually "sftp"
            self._sftp_ok = True
            return True
        return False

    # Explicitly reject shell/exec so we don't get a line editor wrapper
    def shell_requested(self) -> bool:
        return False

    def exec_requested(self, command: str) -> bool:
        return False

    def session_started(self):
        if not self._sftp_ok:
            self._chan.close()
            return

    def data_received(self, data, datatype):
        # DONE S4: Reject zero/oversized frames and bound buffering; retain fragmented/batched input support.
        # After set_encoding(None), data should be bytes
        if isinstance(data, str):  # safety net
            data = data.encode("utf-8", "surrogatepass")

        self.buf += data
        while len(self.buf) >= 4:
            (n,) = struct.unpack(">I", self.buf[:4])
            if n == 0 or n > 1024 * 1024:
                self.buf = b""
                self._chan.close()
                return

            if len(self.buf) < 4 + n:
                break
            pkt = self.buf[4 : 4 + n]
            if len(pkt) < 5:
                self.buf = b""
                self._chan.close()
                return
            self.buf = self.buf[4 + n :]
            self._handle(pkt)

    def _send_status(self, req_id, code, msg=b""):
        self._chan.write(
            pack_pkt(
                SSH_FXP_STATUS, p_u32(req_id) + p_u32(code) + p_str(msg) + p_str(b"")
            )
        )

    def _authorized_full(self, full, op):
        if not self.policy.authorize(self.username, op, full)[0]:
            raise PermissionError("policy denied")
        return full

    def _authorized_path(self, path, op, *, follow_symlinks=True):
        try:
            full = safe_join(JAIL_ROOT, path, follow_symlinks=follow_symlinks)
        except PermissionError:
            self.policy.audit_denial(self.username, op, path, "jail_denied")
            raise
        return self._authorized_full(full, op)

    def _handle(self, pkt: bytes):
        # DONE S4: Validate type, INIT fields/order, and request ID inside error handling, not before it.
        ptype = pkt[0]
        payload = pkt[1:]

        # debug every packet type
        try:
            name = {
                1: "INIT",
                2: "VERSION",
                3: "OPEN",
                4: "CLOSE",
                5: "READ",
                6: "WRITE",
                7: "LSTAT",
                8: "FSTAT",
                11: "OPENDIR",
                12: "READDIR",
                14: "MKDIR",
                16: "REALPATH",
                17: "STAT",
                101: "STATUS",
                102: "HANDLE",
                103: "DATA",
                104: "NAME",
                105: "ATTRS",
            }.get(ptype, f"PTYPE_{ptype}")
            print(f"[PKT] type={name} len={len(payload)}")
        except Exception:
            pass

        # Expect INIT first; reply VERSION=3
        if not self.initialized:
            if ptype != SSH_FXP_INIT:
                self.buf = b""
                self._chan.close()
                return
            try:
                client_version, off = u32(payload, 0)
                while off < len(payload):
                    _, off = ustr(payload, off)
                    _, off = ustr(payload, off)
            except (ValueError, struct.error):
                self.buf = b""
                self._chan.close()
                return
            if client_version < 3:
                self.buf = b""
                self._chan.close()
                return

            self._chan.write(pack_pkt(SSH_FXP_VERSION, p_u32(3)))
            self.initialized = True
            return

        if ptype == SSH_FXP_INIT:
            self.buf = b""
            self._chan.close()
            return

        req_id, off = u32(payload, 0)
        try:
            if ptype == SSH_FXP_REALPATH:
                path, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return

                canon = canon_sftp_path(path)  # "./telnet.txt" -> "/telnet.txt"
                try:
                    full = self._authorized_path(path, "realpath")
                    # Debug every REALPATH, not just "."
                    print(
                        f"[REALPATH] request: {path!r} -> canon: {canon} -> full: {full}"
                    )

                    st = os.stat(full)
                    attrs = sftp_attrs_from_stat(st, self.policy.mode(full))
                except FileNotFoundError:
                    attrs = p_u32(0)  # return empty attrs when not found

                resp = (
                    p_u32(req_id)
                    + p_u32(1)
                    + p_str(canon.encode())  # filename
                    + p_str(canon.encode())  # longname
                    + attrs
                )
                self._chan.write(pack_pkt(SSH_FXP_NAME, resp))

            elif ptype in (SSH_FXP_STAT, SSH_FXP_LSTAT):
                path, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return
                full = self._authorized_path(
                    path, "stat", follow_symlinks=(ptype != SSH_FXP_LSTAT)
                )
                try:
                    st = os.lstat(full) if ptype == SSH_FXP_LSTAT else os.stat(full)
                except FileNotFoundError:
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
                    return
                # optional debug
                print(
                    f"[{'LSTAT' if ptype == SSH_FXP_LSTAT else 'STAT'}] {path!r} -> {full}"
                )
                self._chan.write(
                    pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st, self.policy.mode(full)))
                )

            # DONE: S1
            elif ptype == SSH_FXP_FSTAT:
                handle_bs, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad FSTAT payload")
                    return

                f = self.handles.get(handle_bs)
                if f is None or isinstance(f, DirHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return

                self._authorized_full(self.handles.path(handle_bs), "stat")
                st = os.fstat(f.fileno())
                self._chan.write(
                    pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st, self.policy.mode(self.handles.path(handle_bs))))
                )

            elif ptype == SSH_FXP_OPENDIR:
                path, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return
                full = self._authorized_path(path, "list")
                entries = list(os.scandir(full))
                handle = self.handles.add(DirHandle(entries), full)
                self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            elif ptype == SSH_FXP_READDIR:
                handle_bs, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return
                dh = self.handles.get(handle_bs)
                if not isinstance(dh, DirHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad dir handle")
                    return

                self._authorized_full(self.handles.path(handle_bs), "list")
                batch = []
                while dh.idx < len(dh.entries) and len(batch) < 64:
                    entry = dh.entries[dh.idx]
                    dh.idx += 1
                    if self.policy.authorize(self.username, "stat", entry.path)[0]:
                        batch.append(entry)
                if not batch:
                    self._send_status(req_id, SSH_FX_EOF, b"EOF")
                    return

                out = p_u32(req_id) + p_u32(len(batch))
                for e in batch:
                    name = e.name.encode()
                    try:
                        attrs = sftp_attrs_from_stat(e.stat(follow_symlinks=False), self.policy.mode(e.path))
                    except Exception:
                        attrs = p_u32(0)
                    out += p_str(name) + p_str(name) + attrs
                self._chan.write(pack_pkt(SSH_FXP_NAME, out))

            elif ptype == SSH_FXP_MKDIR:
                path, off = ustr(payload, off)
                off = parse_attrs_ignore(payload, off)  # ignore attrs (mode, etc.)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return
                try:
                    full = self._authorized_path(path, "mkdir")
                    # Debug (optional): print to console so you can see the resolved path
                    print(f"[MKDIR] request: {path!r} -> full: {full}")
                    # DONE S6: Use os.mkdir; a missing parent must fail rather than be created recursively.
                    os.mkdir(full)  # create exactly one dir
                except FileExistsError:
                    self._send_status(req_id, SSH_FX_FAILURE, b"already exists")
                except FileNotFoundError:
                    # parent doesn't exist (e.g., mkdir /a/b without /a)
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"parent missing")
                except PermissionError:
                    self._send_status(
                        req_id, SSH_FX_PERMISSION_DENIED, b"permission denied"
                    )
                except OSError:
                    # TODO S7: Map a few common errnos if you want, else generic failure
                    logging.exception("MKDIR failed for request %s", req_id)
                    self._send_status(
                        req_id, SSH_FX_FAILURE, b"directory creation failed"
                    )
                else:
                    self._send_status(req_id, SSH_FX_OK, b"OK")
            elif ptype == SSH_FXP_OPEN:
                print("[FXP_OPEN] request started")
                filename, off = ustr(payload, off)
                pflags, off = u32(payload, off)
                off = parse_attrs_ignore(payload, off)  # ignore attrs
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return

                # DONE S3: Reject unsupported flags and enforce access in READ/WRITE responses.
                supported_flags = (
                    PF_READ | PF_WRITE | PF_APPEND | PF_CREAT | PF_TRUNC | PF_EXCL
                )
                if pflags & ~supported_flags:
                    self._send_status(req_id, SSH_FX_FAILURE, b"unsupported OPEN flags")
                    return

                can_read = bool(pflags & PF_READ)
                can_write = bool(pflags & PF_WRITE)
                can_append = bool(pflags & PF_APPEND)
                if not can_read and not can_write:
                    self._send_status(req_id, SSH_FX_FAILURE, b"read or write required")
                    return

                if pflags & PF_TRUNC and not can_write:
                    self._send_status(
                        req_id, SSH_FX_FAILURE, b"truncate requires write access"
                    )
                    return

                if pflags & (PF_CREAT | PF_APPEND) and not can_write:
                    self._send_status(
                        req_id, SSH_FX_FAILURE, b"create or append requires write access"
                    )
                    return

                if pflags & PF_EXCL and not (pflags & PF_CREAT):
                    self._send_status(
                        req_id, SSH_FX_FAILURE, b"exclusive requires create"
                    )
                    return

                full = self._authorized_path(filename, "read" if can_read else "write")
                if can_read and can_write:
                    self._authorized_full(full, "write")
                print(f"[FXP_OPEN] request: {filename!r} -> full: {full}")

                if can_read and can_write:
                    os_flags = os.O_RDWR
                    mode = "r+b"
                elif can_write:
                    os_flags = os.O_WRONLY
                    mode = "wb"
                else:
                    os_flags = os.O_RDONLY
                    mode = "rb"

                if pflags & PF_CREAT:
                    os_flags |= os.O_CREAT

                if pflags & PF_TRUNC:
                    os_flags |= os.O_TRUNC

                if pflags & PF_EXCL:
                    os_flags |= os.O_EXCL

                if can_append:
                    os_flags |= os.O_APPEND

                os_flags |= getattr(os, "O_BINARY", 0)

                fd = os.open(full, os_flags, 0o600)
                try:
                    f = os.fdopen(fd, mode)
                except Exception:
                    os.close(fd)
                    raise

                handle = self.handles.add(f, full)
                self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            elif ptype == SSH_FXP_WRITE:
                # DONE S3: Reject writes on read-only handles; append on EVERY write regardless of offset.
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                data, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return

                f = self.handles.get(handle_bs)
                if not f or not hasattr(f, "write"):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return

                if not f.writable():
                    self.policy.audit_denial(
                        self.username, "write", self.policy.path(self.handles.path(handle_bs)), "handle_mode_denied"
                    )
                    self._send_status(
                        req_id, SSH_FX_PERMISSION_DENIED, b"handle not open for writing"
                    )
                    return
                self._authorized_full(self.handles.path(handle_bs), "write")
                f.seek(offset)
                f.write(data)
                f.flush()
                self._send_status(req_id, SSH_FX_OK, b"OK")

            elif ptype == SSH_FXP_READ:
                # DONE S3/S4: Reject reads on write-only handles and cap requested read length.
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                length, off = u32(payload, off)  # how many bytes client wants
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad request payload")
                    return

                f = self.handles.get(handle_bs)
                if not f or not hasattr(f, "read"):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return

                if not f.readable():
                    self.policy.audit_denial(
                        self.username, "read", self.policy.path(self.handles.path(handle_bs)), "handle_mode_denied"
                    )
                    self._send_status(
                        req_id, SSH_FX_PERMISSION_DENIED, b"handle not open for reading"
                    )
                    return

                self._authorized_full(self.handles.path(handle_bs), "read")
                f.seek(offset)
                data = f.read(min(length, 64 * 1024))
                if data is None or len(data) == 0:
                    self._send_status(req_id, SSH_FX_EOF, b"EOF")
                else:
                    # Send DATA packet
                    payload = p_u32(req_id) + p_str(data)
                    self._chan.write(pack_pkt(SSH_FXP_DATA, payload))

            elif ptype == SSH_FXP_CLOSE:
                # DONE S2: Return failure for invalid handles; send OK only after successful cleanup.
                handle_bs, off = ustr(payload, off)
                if off != len(payload):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad CLOSE payload")
                    return
                self.handles.close(handle_bs)
                self._send_status(req_id, SSH_FX_OK, b"OK")

            else:
                self._send_status(req_id, SSH_FX_FAILURE, b"unsupported")

        except FileNotFoundError:
            self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
        except PermissionError:
            self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")
        except Exception:
            # DONE S7: Log internal errors server-side; return safe messages and consistent STATUS codes.
            logging.exception("SFTP request %s failed", req_id)
            self._send_status(req_id, SSH_FX_FAILURE, b"operation failed")


class Server(asyncssh.SSHServer):
    def __init__(self, users, limiter, policy):
        self.users = users
        self.limiter = limiter
        self.policy = policy
        self.username = None

    # Tell AsyncSSH we will do user auth:
    def begin_auth(self, username):  # called when a new user starts auth
        self.username = None
        return True  # start authentication

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.username = None
        if self.limiter.is_locked(username):
            return False
        if verify_password(self.users, username, password):
            self.limiter.reset(username)
            self.username = username
            return True
        self.limiter.record_failure(username)
        return False

    def session_requested(self):
        return SFTPSession(self.username, self.policy) if self.username else False


async def main():
    os.makedirs(JAIL_ROOT, exist_ok=True)
    for name in ("projects", "admin", "public"):
        (Path(JAIL_ROOT) / name).mkdir(exist_ok=True)
    try:
        users = load_users()
        policy = load_policy(JAIL_ROOT, users)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Access-control startup failed: {exc}") from exc
    logging.info("Loaded users.json, user_roles.json, role_perms.csv, mac_labels.json, dac.json")
    limiter = LoginLimiter()
    print(f"Jail root: {JAIL_ROOT}")
    await asyncssh.listen(
        LISTEN_HOST,
        LISTEN_PORT,
        server_host_keys=[HOST_KEY_PATH],  # server identity key
        server_factory=lambda: Server(users, limiter, policy),
    )
    print(
        f"SFTP listening on {LISTEN_HOST or '0.0.0.0'}:{LISTEN_PORT} (subsystem '{SFTP_SUBSYSTEM_NAME}')"
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
