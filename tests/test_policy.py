"""Step 2 access-control tests with isolated users, paths, and policy data."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import server as sftp
from server.policy import load_policy


class PolicyFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jail = self.root / "jail"
        self.data = self.root / "data"
        self.jail.mkdir()
        self.data.mkdir()
        for name in ("projects", "admin", "public", "projects-other"):
            (self.jail / name).mkdir()
        for name, content in (
            ("projects/report.txt", b"report"),
            ("admin/secret.txt", b"secret"),
            ("public/note.txt", b"note"),
            ("projects-other/other.txt", b"other"),
        ):
            (self.jail / name).write_bytes(content)
        (self.data / "user_roles.json").write_text(json.dumps({
            "alice": ["admin"], "bob": ["analyst"], "eve": ["intern"]
        }))
        (self.data / "mac_labels.json").write_text(json.dumps({
            "users": {"alice": "confidential", "bob": "internal", "eve": "public"},
            "paths": {"/": "public", "/projects": "internal", "/admin": "confidential", "/public": "public"},
        }))
        (self.data / "dac.json").write_text(json.dumps({
            "users": {"alice": ["admins"], "bob": ["analysts"], "eve": ["interns"]},
            "paths": {
                "/": {"owner": "alice", "group": "admins", "mode": "0755"},
                "/projects": {"owner": "bob", "group": "analysts", "mode": "0750"},
                "/admin": {"owner": "alice", "group": "admins", "mode": "0700"},
                "/public": {"owner": "eve", "group": "interns", "mode": "0755"},
            },
        }))
        (self.data / "role_perms.csv").write_text(
            "role,resource,realpath,stat,list,mkdir,read,write\n"
            "admin,/,realpath,stat,list,mkdir,read,write\n"
            "analyst,/,realpath,stat,list,,,\n"
            "analyst,/projects,realpath,stat,list,mkdir,read,write\n"
            "intern,/,realpath,stat,list,,,\n"
            "intern,/public,realpath,stat,list,,read,\n"
        )
        self.audit = self.root / "audit.jsonl"
        self.policy = load_policy(self.jail, {"alice", "bob", "eve"}, self.data, self.audit)

    def check(self, user, op, path):
        return self.policy.authorize(user, op, self.jail / path)

    def records(self):
        return [json.loads(line) for line in self.audit.read_text().splitlines()]


class PolicyTests(PolicyFixture, unittest.TestCase):
    def test_dac_owner_group_other_and_directory_execute(self):
        """DAC permits an owner and same-group reader but blocks other writes and missing directory x."""
        self.assertTrue(self.check("bob", "read", "projects/report.txt")[0])
        self.assertTrue(self.check("bob", "write", "projects/report.txt")[0])
        self.assertEqual(self.check("alice", "write", "projects/report.txt")[1], "dac_denied")
        self.policy.dac["users"]["alice"].append("analysts")
        self.policy.mac["users"]["alice"] = "internal"
        self.assertTrue(self.check("alice", "read", "projects/report.txt")[0])
        self.policy.dac["paths"]["/projects"]["mode"] = 0o740
        self.assertEqual(self.check("alice", "list", "projects")[1], "dac_denied")
        self.assertEqual(self.check("alice", "stat", "projects/report.txt")[1], "dac_denied")

    def test_mac_no_read_up_or_write_down(self):
        """MAC allows internal reads at or below clearance and blocks read up and write down."""
        self.policy.grants["analyst"].append(("/public", {"read"}))
        self.assertTrue(self.check("bob", "read", "public/note.txt")[0])
        self.assertTrue(self.check("bob", "read", "projects/report.txt")[0])
        self.policy.dac["paths"]["/admin"]["mode"] = 0o755
        self.policy.grants["analyst"].append(("/admin", {"read"}))
        self.assertEqual(self.check("bob", "read", "admin/secret.txt")[1], "mac_denied")
        self.policy.dac["paths"]["/public"]["mode"] = 0o777
        self.assertEqual(self.check("alice", "write", "public/note.txt")[1], "mac_denied")
        self.policy.mac["paths"]["/projects/public-drop"] = "public"
        self.assertEqual(self.check("bob", "write", "projects/public-drop")[1], "mac_denied")

    def test_rbac_union_and_path_boundary(self):
        """RBAC denies an ungranted directory and sibling prefix, then accepts a second role."""
        self.policy.dac["paths"]["/admin"]["mode"] = 0o777
        self.policy.mac["paths"]["/admin"] = "internal"
        self.assertEqual(self.check("bob", "mkdir", "admin/new")[1], "rbac_denied")
        self.policy.roles["bob"].append("admin")
        self.assertTrue(self.check("bob", "mkdir", "admin/new")[0])
        self.policy.roles["bob"].remove("admin")
        self.assertEqual(self.check("bob", "read", "projects-other/other.txt")[1], "rbac_denied")

    def test_composition_default_deny_and_audit(self):
        """Every layer must allow; unknown identities and resources are denied and audited."""
        self.policy.dac["paths"]["/admin"]["mode"] = 0o755
        self.assertEqual(self.check("bob", "read", "admin/secret.txt")[1], "mac_denied")
        self.policy.mac["paths"]["/admin"] = "internal"
        self.assertEqual(self.check("bob", "read", "admin/secret.txt")[1], "rbac_denied")
        self.policy.dac["paths"]["/admin"]["mode"] = 0o700
        self.policy.grants["analyst"].append(("/admin", {"read"}))
        self.assertEqual(self.check("bob", "read", "admin/secret.txt")[1], "dac_denied")
        self.assertEqual(self.check("unknown", "read", "projects/report.txt")[1], "unknown_user_or_operation")
        self.assertEqual(self.check("bob", "delete", "projects/report.txt")[1], "unknown_user_or_operation")
        self.assertEqual(self.policy.authorize("bob", "read", self.root / "outside")[1], "jail_denied")
        record = self.records()[0]
        self.assertEqual(set(record), {"timestamp", "user", "op", "path", "allowed", "reason"})
        self.assertEqual((record["user"], record["path"], record["allowed"], record["reason"]),
                         ("bob", "/admin/secret.txt", False, "mac_denied"))
        self.assertTrue(self.check("bob", "read", "projects/report.txt")[0])
        allowed = self.records()[-1]
        self.assertEqual((allowed["user"], allowed["op"], allowed["path"], allowed["allowed"], allowed["reason"]),
                         ("bob", "read", "/projects/report.txt", True, "allowed"))

    def test_bad_required_policy_data_fails_startup(self):
        """Missing or malformed required policy data prevents startup."""
        (self.data / "mac_labels.json").unlink()
        with self.assertRaises(FileNotFoundError):
            load_policy(self.jail, {"alice", "bob", "eve"}, self.data, self.audit)
        (self.data / "mac_labels.json").write_text("not json")
        with self.assertRaises(ValueError):
            load_policy(self.jail, {"alice", "bob", "eve"}, self.data, self.audit)

    def test_audit_failure_fails_closed(self):
        """An authorization cannot succeed when its audit record cannot be written."""
        self.policy.audit_path = self.root / "missing" / "audit.jsonl"
        with self.assertRaises(OSError):
            self.check("bob", "read", "projects/report.txt")


class SFTPAuthorizationTests(PolicyFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        patcher = patch.object(sftp, "JAIL_ROOT", str(self.jail))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.replies = []
        self.session = sftp.SFTPSession("bob", self.policy)
        self.session.initialized = True
        self.session._chan = SimpleNamespace(write=self.replies.append)
        self.addCleanup(self.session.handles.close_all)

    def request(self, kind, body):
        self.session._handle(bytes([kind]) + sftp.p_u32(42) + body)
        return self.replies.pop()

    def status(self, reply):
        self.assertEqual(reply[4], sftp.SSH_FXP_STATUS)
        return sftp.u32(reply, 9)[0]

    def test_open_and_handles_recheck_policy(self):
        """OPEN checks before mutation; READ, WRITE, and FSTAT recheck the stored resource."""
        path = self.jail / "admin/secret.txt"
        for flags in (sftp.PF_WRITE | sftp.PF_TRUNC, sftp.PF_READ | sftp.PF_WRITE):
            reply = self.request(sftp.SSH_FXP_OPEN, sftp.p_str(b"/admin/secret.txt") + sftp.p_u32(flags) + sftp.p_u32(0))
            self.assertEqual(self.status(reply), sftp.SSH_FX_PERMISSION_DENIED)
            self.assertEqual(path.read_bytes(), b"secret")
        reply = self.request(sftp.SSH_FXP_OPEN, sftp.p_str(b"/admin/new.txt") + sftp.p_u32(sftp.PF_WRITE | sftp.PF_CREAT) + sftp.p_u32(0))
        self.assertEqual(self.status(reply), sftp.SSH_FX_PERMISSION_DENIED)
        self.assertFalse((self.jail / "admin/new.txt").exists())
        reply = self.request(sftp.SSH_FXP_OPEN, sftp.p_str(b"/projects/report.txt") + sftp.p_u32(sftp.PF_READ | sftp.PF_WRITE) + sftp.p_u32(0))
        self.assertEqual(reply[4], sftp.SSH_FXP_HANDLE)
        handle, _ = sftp.ustr(reply, 9)
        self.assertEqual(self.session.handles.path(handle), str((self.jail / "projects/report.txt").resolve()))
        self.policy.roles["bob"] = []
        self.assertEqual(self.status(self.request(sftp.SSH_FXP_READ, sftp.p_str(handle) + sftp.p_u64(0) + sftp.p_u32(2))), sftp.SSH_FX_PERMISSION_DENIED)
        self.assertEqual(self.status(self.request(sftp.SSH_FXP_WRITE, sftp.p_str(handle) + sftp.p_u64(0) + sftp.p_str(b"x"))), sftp.SSH_FX_PERMISSION_DENIED)
        self.assertEqual(self.status(self.request(sftp.SSH_FXP_FSTAT, sftp.p_str(handle))), sftp.SSH_FX_PERMISSION_DENIED)
        self.assertEqual((self.jail / "projects/report.txt").read_bytes(), b"report")

    def test_directory_listing_filters_and_rechecks(self):
        """READDIR hides inaccessible names and refuses a handle after list permission is removed."""
        reply = self.request(sftp.SSH_FXP_OPENDIR, sftp.p_str(b"/"))
        handle, _ = sftp.ustr(reply, 9)
        reply = self.request(sftp.SSH_FXP_READDIR, sftp.p_str(handle))
        self.assertEqual(reply[4], sftp.SSH_FXP_NAME)
        count, off = sftp.u32(reply, 9)
        names = []
        for _ in range(count):
            name, off = sftp.ustr(reply, off)
            _, off = sftp.ustr(reply, off)
            off = sftp.parse_attrs_ignore(reply, off)
            names.append(name.decode())
        self.assertIn("projects", names)
        self.assertNotIn("admin", names)
        self.policy.grants["analyst"] = []
        self.assertEqual(self.status(self.request(sftp.SSH_FXP_READDIR, sftp.p_str(handle))), sftp.SSH_FX_PERMISSION_DENIED)

    def test_traversal_denied_and_audited(self):
        """A jail escape is rejected before policy evaluation and produces a denial record."""
        reply = self.request(sftp.SSH_FXP_STAT, sftp.p_str(b"../outside"))
        self.assertEqual(self.status(reply), sftp.SSH_FX_PERMISSION_DENIED)
        self.assertEqual(self.records()[-1]["reason"], "jail_denied")

    def test_path_handlers_and_inherited_metadata(self):
        """Path requests enforce policy; new resources inherit DAC mode and MAC label."""
        for kind, tail in (
            (sftp.SSH_FXP_REALPATH, b""),
            (sftp.SSH_FXP_STAT, b""),
            (sftp.SSH_FXP_LSTAT, b""),
            (sftp.SSH_FXP_OPENDIR, b""),
            (sftp.SSH_FXP_MKDIR, sftp.p_u32(0)),
        ):
            with self.subTest(kind=kind):
                reply = self.request(kind, sftp.p_str(b"/admin/secret.txt" if kind != sftp.SSH_FXP_MKDIR else b"/admin/new") + tail)
                self.assertEqual(self.status(reply), sftp.SSH_FX_PERMISSION_DENIED)
        reply = self.request(sftp.SSH_FXP_MKDIR, sftp.p_str(b"/projects/new") + sftp.p_u32(0))
        self.assertEqual(self.status(reply), sftp.SSH_FX_OK)
        created = self.jail / "projects/new"
        self.assertEqual(self.policy.mode(created), 0o750)
        self.assertEqual(self.policy.mac["paths"]["/projects"], "internal")
        reply = self.request(sftp.SSH_FXP_STAT, sftp.p_str(b"/projects/new"))
        self.assertEqual(reply[4], sftp.SSH_FXP_ATTRS)
        permissions, _ = sftp.u32(reply, 21)
        self.assertEqual(permissions & 0o777, 0o750)

    def test_audit_failure_preserves_existing_file(self):
        """A failed audit prevents OPEN from truncating an existing file."""
        self.policy.audit_path = self.root / "missing" / "audit.jsonl"
        reply = self.request(sftp.SSH_FXP_OPEN, sftp.p_str(b"/projects/report.txt") + sftp.p_u32(sftp.PF_WRITE | sftp.PF_TRUNC) + sftp.p_u32(0))
        self.assertEqual(self.status(reply), sftp.SSH_FX_FAILURE)
        self.assertEqual((self.jail / "projects/report.txt").read_bytes(), b"report")
