"""DAC, MAC, and RBAC decisions for paths inside the SFTP jail."""

import csv
import json
import os
import posixpath
from datetime import datetime, timezone
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OPERATIONS = {"realpath", "stat", "list", "mkdir", "read", "write"}
GRANT_COLUMNS = ["realpath", "stat", "list", "mkdir", "read", "write"]
LEVELS = {"public": 0, "internal": 1, "confidential": 2}


class AuditError(OSError):
    pass


def _scope(path):
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or "\x00" in path
        or path != posixpath.normpath(path)
    ):
        raise ValueError(f"invalid policy path: {path!r}")
    return path


def _matches(path, prefix):
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _nearest(path, mapping):
    matches = [prefix for prefix in mapping if _matches(path, prefix)]
    return mapping[max(matches, key=len)] if matches else None


def load_policy(jail_root, usernames, data_dir=DATA_DIR, audit_path=None):
    """Load static policy files; reject malformed or incomplete configuration."""
    data_dir = Path(data_dir)
    with (data_dir / "user_roles.json").open(encoding="utf-8") as file:
        roles = json.load(file)
    with (data_dir / "mac_labels.json").open(encoding="utf-8") as file:
        mac = json.load(file)
    with (data_dir / "dac.json").open(encoding="utf-8") as file:
        dac = json.load(file)
    with (data_dir / "role_perms.csv").open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames != ["role", "resource", *GRANT_COLUMNS]:
            raise ValueError("role_perms.csv has invalid columns")
        grants = {}
        for row in reader:
            if None in row or not row["role"] or not row["resource"]:
                raise ValueError("invalid role grant")
            scope = _scope(row["resource"])
            ops = {op for op in OPERATIONS if row[op] == op}
            if any(row[op] not in ("", op) for op in OPERATIONS):
                raise ValueError("invalid role grant token")
            grants.setdefault(row["role"], []).append((scope, ops))

    users = set(usernames)
    if not users or not isinstance(roles, dict) or set(roles) != users:
        raise ValueError("user_roles.json must cover every authenticated user")
    if not isinstance(mac, dict) or set(mac) != {"users", "paths"}:
        raise ValueError("mac_labels.json must contain users and paths")
    if not isinstance(dac, dict) or set(dac) != {"users", "paths"}:
        raise ValueError("dac.json must contain users and paths")
    if not all(
        isinstance(x, dict)
        for x in (mac["users"], mac["paths"], dac["users"], dac["paths"])
    ):
        raise ValueError("invalid access-control mappings")
    if set(mac["users"]) != users or set(dac["users"]) != users:
        raise ValueError("MAC/DAC users must match authenticated users")
    if not mac["paths"] or not dac["paths"]:
        raise ValueError("MAC/DAC path mappings cannot be empty")
    for user in users:
        if not isinstance(roles[user], list) or not roles[user] or any(
            not isinstance(role, str) or role not in grants for role in roles[user]
        ):
            raise ValueError(f"invalid roles for {user}")
        if not isinstance(mac["users"][user], str) or mac["users"][user] not in LEVELS:
            raise ValueError(f"invalid clearance for {user}")
        if not isinstance(dac["users"][user], list) or any(
            not isinstance(group, str) or not group for group in dac["users"][user]
        ):
            raise ValueError(f"invalid DAC groups for {user}")
    for path, label in mac["paths"].items():
        _scope(path)
        if not isinstance(label, str) or label not in LEVELS:
            raise ValueError(f"invalid MAC label for {path}")
    for path, entry in dac["paths"].items():
        _scope(path)
        if not isinstance(entry, dict) or set(entry) != {"owner", "group", "mode"}:
            raise ValueError(f"invalid DAC entry for {path}")
        if (
            not isinstance(entry["owner"], str)
            or entry["owner"] not in users
            or not isinstance(entry["group"], str)
            or not entry["group"]
        ):
            raise ValueError(f"invalid DAC owner/group for {path}")
        try:
            mode = int(entry["mode"], 8)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid DAC mode for {path}") from exc
        if not 0 <= mode <= 0o777:
            raise ValueError(f"invalid DAC mode for {path}")
        entry["mode"] = mode
    if "/" not in mac["paths"] or "/" not in dac["paths"]:
        raise ValueError("MAC/DAC root metadata is required")
    return Policy(
        jail_root, roles, grants, mac, dac,
        audit_path or Path(__file__).resolve().parent / "audit.jsonl",
    )


class Policy:
    def __init__(self, jail_root, roles, grants, mac, dac, audit_path):
        self.jail_root = Path(jail_root).resolve()
        self.roles = roles
        self.grants = grants
        self.mac = mac
        self.dac = dac
        self.audit_path = Path(audit_path)

    def path(self, full_path):
        try:
            # Resolve parent aliases while preserving LSTAT's final symlink.
            full = Path(os.path.realpath(os.path.dirname(full_path))) / os.path.basename(
                full_path
            )
            relative = full.relative_to(self.jail_root)
        except ValueError:
            raise PermissionError("path outside jail") from None
        return "/" if relative == Path(".") else "/" + relative.as_posix()

    def _audit(self, user, op, path, allowed, reason):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": user,
            "op": op,
            "path": path,
            "allowed": allowed,
            "reason": reason,
        }
        try:
            with self.audit_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record) + "\n")
        except OSError as exc:
            raise AuditError("audit write failed") from exc

    def audit_denial(self, user, op, path, reason):
        if isinstance(path, bytes):
            path = path.decode("utf-8", "replace")
        self._audit(user, op, str(path), False, reason)

    def _dac_bits(self, user, path):
        entry = _nearest(path, self.dac["paths"])
        if entry is None:
            return 0
        shift = (
            6 if entry["owner"] == user else
            3 if entry["group"] in self.dac["users"][user] else 0
        )
        return (entry["mode"] >> shift) & 7

    def mode(self, full_path):
        return _nearest(self.path(full_path), self.dac["paths"])["mode"]

    def _dac_allows(self, user, op, path, exists, directory):
        parts = path.strip("/").split("/") if path != "/" else []
        ancestors = ["/"] + ["/" + "/".join(parts[:i]) for i in range(1, len(parts))]
        if any(not (self._dac_bits(user, parent) & 1) for parent in ancestors):
            return False
        if op == "mkdir" or (op == "write" and not exists):
            parent = posixpath.dirname(path) or "/"
            return path != "/" and (self._dac_bits(user, parent) & 3) == 3
        bits = self._dac_bits(user, path)
        if op == "list":
            return directory and (bits & 5) == 5
        if directory:
            return bool(bits & 1) if op in ("stat", "realpath") else False
        return bool(bits & (2 if op == "write" else 4))

    def authorize(self, user, op, full_path):
        """Return and audit a DAC AND MAC AND RBAC decision."""
        try:
            path = self.path(full_path)
        except PermissionError:
            self._audit(user, op, "<outside-jail>", False, "jail_denied")
            return False, "jail_denied"
        if user not in self.roles or op not in OPERATIONS:
            reason = "unknown_user_or_operation"
        else:
            exists = os.path.lexists(full_path)
            directory = (
                os.path.isdir(full_path)
                if exists and not os.path.islink(full_path) else False
            )
            label = _nearest(path, self.mac["paths"])
            if not self._dac_allows(user, op, path, exists, directory):
                reason = "dac_denied"
            elif label is None or (
                LEVELS[self.mac["users"][user]] > LEVELS[label] if op in ("write", "mkdir")
                else LEVELS[self.mac["users"][user]] < LEVELS[label]
            ):
                reason = "mac_denied"
            elif not any(
                op in ops and _matches(path, scope)
                for role in self.roles[user]
                for scope, ops in self.grants[role]
            ):
                reason = "rbac_denied"
            else:
                reason = "allowed"
        allowed = reason == "allowed"
        self._audit(user, op, path, allowed, reason)
        return allowed, reason
