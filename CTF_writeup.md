# SFTP Capture-the-Flag Report

## Flag and intended access

The synthetic flag is stored at `server/sftp_root/admin/flag.txt` and is available through SFTP at `/admin/flag.txt`. Alice should be able to list the admin directory and download the flag. Bob and Eve should be denied even if they know the exact path. Anyone with a repository checkout can inspect the fixture directly, so the exercise tests the boundary for authenticated SFTP users.

A naive server that hides a directory entry but accepts a direct file open could disclose the flag. This implementation checks both directory listing and file access. It confines the path to the jail before applying authorization and rechecks file reads against the resource associated with the handle.

## Protection layers

| Layer | Rule protecting the flag |
| --- | --- |
| DAC | Alice owns `/admin`, with mode `0700`. Bob and Eve lack directory traversal permission, so a direct file request is denied as well as listing. |
| MAC | `/admin` and its descendants are `confidential`. Alice has confidential clearance. Bob (`internal`) and Eve (`public`) cannot read up. |
| RBAC | Alice's `admin` role grants read access throughout the jail, subject to DAC and MAC. Bob's `analyst` and Eve's `intern` roles have no read grant under `/admin`. |

`server/policy.py` requires DAC, MAC, and RBAC to allow an operation. The static rules are stored in `data/dac.json`, `data/mac_labels.json`, `data/user_roles.json`, and `data/role_perms.csv`.

## Live SFTP verification

On 22 November 2026, the group client connected over localhost to the project server using the repository policy, a copy of the flag in a temporary jail, temporary passwords, and a pinned Ed25519 host key. All three users authenticated successfully.

| User | List `/admin` | Download `/admin/flag.txt` |
| --- | --- | --- |
| Alice | `flag.txt` appeared | Download matched the repository fixture byte for byte |
| Bob | SFTP status 3 | SFTP status 3 |
| Eve | SFTP status 3 | SFTP status 3 |

Status 3 is `SSH_FX_PERMISSION_DENIED`. Neither denied download created a local output file.

## Traversal regression

The existing `test_traversal_denied_and_audited` test checks an out-of-jail path in a temporary fixture. The server returned `SSH_FX_PERMISSION_DENIED` and recorded `jail_denied`, confirming that the jail check blocked the request. All 11 tests in `tests/test_policy.py` passed, including separate MAC and RBAC tests. The symlink test also passed in Administrator PowerShell and verified the distinction between following a link with `STAT` and inspecting the link itself with `LSTAT`.

## Audit evidence

These direct flag-access decisions were captured during the live SFTP run. The server audits the authorization decision for the remote path. The test separately checked the bytes Alice received.

| Timestamp (UTC) | User | Operation | Path | Allowed | Reason |
| --- | --- | --- | --- | --- | --- |
| 18:11:49.823756 | alice | `read` | `/admin/flag.txt` | true | `allowed` |
| 18:11:49.975001 | bob | `read` | `/admin/flag.txt` | false | `dac_denied` |
| 18:11:50.120446 | eve | `read` | `/admin/flag.txt` | false | `dac_denied` |

The audit fields show who requested the flag and why access stopped. `dac_denied` is the first failed policy check. The separate MAC and RBAC tests establish how those controls behave when evaluated. The traversal regression's `jail_denied` reason identifies a different event, a request blocked at the jail boundary before access-control evaluation.

## Scope and AI disclosure

The file-jail checks assume that only trusted local processes can modify the jail. Canonicalization and file access occur separately, so a local path replacement between them remains a documented limitation.

Codex reviewed the flag placement and protections, helped run and interpret the isolated verification, and edited and formatted this report. This disclosure covers the documented CTF review and write-up.
