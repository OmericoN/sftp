# SFTP client and server

## Setup and server

Use Python 3.12 or newer and run the commands from the repository root. OpenSSH
provides `ssh-keygen` and the optional `sftp` client.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install "asyncssh>=2.24.1"
```

macOS and Linux:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'asyncssh>=2.24.1'
```

Generate a fresh Ed25519 host key locally before using this checkout. The
current checkout includes a tracked private host key. Move that key and its
public counterpart aside before generating the replacement. Keep the new
private key out of Git and reuse it between server runs.

```text
ssh-keygen -t ed25519 -f server/ssh_host_ed25519_key
ssh-keygen -lf server/ssh_host_ed25519_key.pub
```

Press Enter twice when `ssh-keygen` prompts for a passphrase so the server can
load the key unattended. Start the server with `python server/server.py` on
macOS/Linux or `.\.venv\Scripts\python.exe server/server.py` in PowerShell.
It logs the loaded policy files, creates the jail and its `projects`, `admin`,
and `public` directories as needed, and listens on port 2222.

## Connect and try the client

Create a local `known_hosts` file from the verified server public key. Prefix
the contents of `server/ssh_host_ed25519_key.pub` with `[127.0.0.1]:2222 ` on
the same line. Use `--known-hosts` on every group-client connection while the
default connection still disables host-key verification.

```powershell
.\.venv\Scripts\python.exe client/client.py --host 127.0.0.1 --port 2222 --username bob --known-hosts known_hosts
```

On macOS/Linux, use `python` in place of `.\.venv\Scripts\python.exe`.
Enter Bob's configured password at the prompt. The client prints `Connected to
SFTP subsystem (version 3).` and opens the `sftp>` prompt. Run this example
from the repository root with a new directory name under `/projects`:

```text
sftp> pwd
sftp> ls /
sftp> mkdir /projects/demo
sftp> put README.md /projects/demo/README.md
sftp> stat /projects/demo/README.md
sftp> get /projects/demo/README.md README.copy.md
sftp> ls /admin
sftp> quit
```

`pwd` prints `/`, `stat` shows the uploaded file's metadata, and `get` writes
`README.copy.md` locally. Listing `/admin` as Bob returns permission denied.
To try OpenSSH with the same host key, run `sftp -o UserKnownHostsFile=known_hosts
-o StrictHostKeyChecking=yes -P 2222 bob@127.0.0.1` as a single command.

## Tests

Run `python -m unittest discover -s tests -q` on macOS/Linux or
`.\.venv\Scripts\python.exe -m unittest discover -s tests -q` on Windows.
The Windows run had 68 passes and one skip because Windows denied permission
to create symlinks (`WinError 1314`). The skipped test passed in a separate
Administrator PowerShell run, bringing the verified total to 69 across the
two runs. To repeat the symlink check, run this in Administrator PowerShell:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_sftp.py' -k test_symlink_paths -v
```

The live group-client test exercised all seven commands with a pinned host key
and a byte-identical round trip. A Windows OpenSSH batch test with temporary authentication also
transferred matching bytes in both directions, then timed out before clean exit.
See [Tasks.md](Tasks.md) for the remaining checks and submission items.

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
