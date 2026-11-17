# SFTP server

Python 3.12+ and `asyncssh` are required. From this directory, install with
`python3 -m pip install -e .` (Windows: `py -3.12 -m pip install -e .`) and run
`python3 server/server.py` (Windows: `py -3.12 server/server.py`). The server listens on
port 2222, creates its jail and the `projects`, `admin`, and `public` directories,
and uses the persistent `server/ssh_host_ed25519_key`. Generate that key once with
`ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key` if it is absent. Keep
the private key private. Verify its fingerprint before accepting it in a client.
Run tests with `python3 -m unittest discover -s tests -q`.
Use `sftp -P 2222 bob@127.0.0.1` with a verified host key to try the server.
The group `client/client.py` is still empty, so it cannot be tested yet.

## Access Control Design

After password verification, the authenticated username is stored on its SFTP
session. Each request is parsed, confined to `server/sftp_root` by `safe_join`,
authorized by `policy.authorize(user, op, full_path)`, then executed. The gate
returns `(allowed, reason)` and requires **DAC AND MAC AND RBAC**. Unknown users,
operations, and ungranted resources are denied. Handles retain their resource
path and are rechecked on later requests; no identity comes from SFTP packets.
Path resolution and existence/type checks needed to evaluate a policy are
read-only metadata lookups before the decision. Content reads, directory entry
metadata, creation, truncation, and writes happen only after authorization.

| SFTP request | Policy operation |
| --- | --- |
| REALPATH | `realpath` |
| STAT, LSTAT, FSTAT | `stat` |
| OPENDIR, READDIR | `list` |
| MKDIR | `mkdir` |
| OPEN for read, READ | `read` |
| OPEN for write, WRITE | `write` |

An OPEN requesting both read and write needs both decisions. READDIR also checks
`stat` on each entry and omits entries the user cannot inspect. CLOSE only
releases a handle. Remove and rename are not implemented.

**DAC.** `data/dac.json` maps each SFTP user to groups and each path prefix to
an owner, group, and octal mode. The longest matching prefix supplies metadata.
The owner/group/other triad is selected in that order. File read and metadata
need `r`; file write needs `w`. Directory listing needs `r+x`, directory
metadata needs `x`, and every ancestor needs `x`. MKDIR or file creation needs
`w+x` on the parent. Newly created resources use the nearest matching prefix's
owner, group, and mode, normally inherited from their parent; changing these
static rules requires a restart. For example, Bob owns `/projects` with `0750`
and can read/write there; Alice, who
is not in `analysts`, cannot write there. A same-group user can read it while
group `r+x` is present, and loses access if directory `x` is removed. An
unrelated user gets the other bits.

**MAC.** `data/mac_labels.json` assigns user clearances and longest-prefix
resource labels ordered `public < internal < confidential`. Read-like operations
(`realpath`, `stat`, `list`, `read`) require clearance at least as high as the
resource label: no read up. Write and creation require clearance no higher than
the target label: no write down. A new resource inherits its parent's label
unless a more specific static label is configured.
Bob (internal) may read public and internal resources but not `/admin`
(confidential). Alice (confidential) cannot write a public resource even if
DAC and RBAC grant it.

**RBAC.** `data/user_roles.json` gives users roles; `data/role_perms.csv` gives
each role operations on POSIX path prefixes. Grants from all roles are combined.
Prefix matching includes a path itself and its descendants, so `/projects`
never matches `/projects-other`. There are no per-user overrides; an absent
grant denies. The admin role grants all operations from `/`, but DAC and MAC
still apply. The analyst role grants file work under `/projects`, and the
intern role grants reads under `/public`. All roles can resolve, stat, and list
the jail root, subject to DAC and MAC.

| DAC | MAC | RBAC | Final decision |
| --- | --- | --- | --- |
| allow | allow | allow | allow |
| allow | deny | allow | deny |
| deny | allow | allow | deny |
| allow | allow | deny | deny |

The static users are Alice (admin, confidential), Bob (analyst, internal), and
Eve (intern, public). Authentication records in `data/users.json` contain only
salted password hashes; no plaintext passwords are logged or documented.
`data/acm_users.csv` is a legacy action matrix and is not loaded as DAC metadata.
All required datasets load at startup; missing or malformed data stops the
server with an error.

Each decision appends a JSON line to `server/audit.jsonl` with UTC timestamp,
user, operation, jail-relative path, allowed flag, and reason. A failed audit
write fails the request closed. A sample record is:

```json
{"timestamp":"2026-11-17T15:00:00+00:00","user":"bob","op":"read","path":"/admin/secret.txt","allowed":false,"reason":"dac_denied"}
```

The automated tests use temporary jails and policy files to show owner,
same-group, and other DAC results; MAC read-up/write-down denials; RBAC role
union and path boundaries; AND composition; jail traversal; audit records;
and checks on open handles and directory listings.

## Known limit

`safe_join` resolves paths before using them but the check and filesystem call
are not atomic. The jail must not be writable by untrusted local processes; if
that changes, use handle-relative filesystem operations to prevent path
replacement races.
