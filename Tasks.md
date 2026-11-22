# Project tasks

This checklist follows the **Project Requirements** numbering in the assignment PDF. The deadline stated there is **18 November**.

The starter already implements most basic SFTP operations. Keep that code: add missing security, fix specific bugs, and demonstrate that it works. An unchecked box means implementation or verification remains; it does not mean you must rewrite the surrounding code.

## Current progress

- `server/server.py` contains the starter in the required entrypoint; `main.py` has been removed.
- AsyncSSH transport, the SFTP subsystem, and shell/exec rejection are implemented. The default private host key is tracked in Git and needs replacing before submission.
- All required SFTP handlers exist, including FSTAT. S1-S4 and S6-S7 have automated coverage; S5 still has the limitations below.
- Password verification and lockout are wired into the server; the verified username reaches each SFTP session.
- `policy.py` loads the static DAC/MAC/RBAC data, enforces one gate, and audits decisions. `acm_users.csv` is unused legacy data.
- The Windows suite ran 69 tests: 68 passed and the symlink test skipped with `WinError 1314`. The symlink test passed when rerun separately in Administrator PowerShell. All 69 tests passed across the two runs.
- The group client completed all seven commands with a verified `known_hosts` file. A 100,000-byte upload/download matched byte for byte, and the live audit log captured an access denial. The default client connection still disables host-key verification.
- Windows OpenSSH `sftp` transferred matching bytes in both directions with a pinned host key and temporary test authentication. The batch process timed out after the transfer, so clean exit remains open.
- Path-replacement races remain unresolved and are documented in `README.md`.

## 1) SSH transport via AsyncSSH

**Intuition:** SSH provides the encrypted connection and login exchange. SFTP is the language spoken inside that connection. Reuse SSH; implement the SFTP messages yourself.

Main files: `server/server.py`, `server/auth.py`, `data/users.json`.

### Transport

- [x] Put the starter in `server/server.py`.
- [x] Retain AsyncSSH transport, accept the `sftp` subsystem, and reject shell/exec requests.
- [ ] Confirm startup uses a persistent Ed25519 host key and creates `server/sftp_root/` when missing. Do not regenerate the key on every run.
- [ ] Replace the committed private host key, remove the private key from version control, and ignore its local path.
- [ ] Confirm server paths work independently of the current working directory.

### Password authentication

**Question this answers:** "Who is connecting?" Login does not automatically grant access to every file.

- [x] Implement password verification in `auth.py` using salted hashes and parameters from `users.json`. Standard-library `hashlib.scrypt` and constant-time comparison fit the assignment constraints.
- [x] Replace the hardcoded credential check with the verifier; reject incorrect passwords and unknown users.
- [x] Add failed-login throttling or temporary lockout; the grading rubric explicitly includes this.
- [x] Keep passwords/hashes out of logs and carry the authenticated username into each SFTP session for authorization/auditing.

**Done when:** the server starts, valid credentials open an SFTP session, invalid credentials fail, repeated failures are limited, and shell/exec remain unavailable.

## 2) Authorization and access control: DAC, MAC, RBAC

**Intuition:** After login, every request asks "May this user perform this operation on this resource?" The jail determines where a path points; access control determines whether it may be used.

Main files: `server/policy.py` for decisions/auditing and `server/server.py` for enforcement.

### Implement one gate

- [x] Provide `authorize(user, op, full_path) -> (allowed, reason)`, with default deny for unknown/ungranted users, operations, and resources.
- [x] **DAC:** check owner/group/other permission bits. Define file read/write, directory listing/traversal (`x`), and parent permissions for creation.
- [x] **MAC:** define user clearances and resource labels, such as `public < internal < confidential`. Enforce no read up and no write down.
- [x] **RBAC:** grant operations on resource prefixes through roles; combine grants from all roles. Match path boundaries so `/projects` does not include `/projects-other`.
- [x] Compose the decision as **DAC AND MAC AND RBAC**, as recommended in the PDF. All three must allow the operation.

Example: an analyst role may grant read access to `/projects/report.txt`, but a confidential label still blocks a user with internal clearance. A role grant does not override MAC or DAC.

### Connect the gate to the server

Use this sequence: **parse -> canonicalize/check jail -> authorize -> perform the requested filesystem operation -> reply**. Document metadata lookups needed for path resolution and policy evaluation.

| SFTP request | Policy operation | What matters |
| --- | --- | --- |
| REALPATH | `realpath` | Permission before revealing resolved names/metadata. |
| STAT / LSTAT / FSTAT | `stat` | Metadata access; FSTAT obtains the resource from its handle. |
| OPENDIR / READDIR | `list` | Listing and relevant directory traversal permissions. |
| MKDIR | `mkdir` | Destination and parent permissions. |
| OPEN for reading / READ | `read` | Read permission and handle access mode. |
| OPEN for writing / WRITE | `write` | Permission before creation/truncation or writing. |

- [x] Apply the gate to every operation above, including requests using existing handles.
- [x] Require both permissions for read/write OPEN; denied creation/truncation must leave data unchanged.
- [x] Store the path with each handle and enforce the file object's requested access mode so handles cannot bypass policy.
- [x] Define ownership, modes, and labels inherited by newly created files/directories.
- [x] Decide/document whether directory listings filter inaccessible entries.
- [x] Append each allow/deny decision to `server/audit.jsonl`: user, op, path, allowed, reason, timestamp. Keep secrets out.

**Done when:** one user can perform an allowed action and is denied a forbidden action, both are audited, and no alternate request/handle bypasses the gate.

## 2a) Applying DAC, MAC, RBAC and self-tests

**Intuition:** Show that each rule works independently, then prove their combination works. Tests are evidence for your security claims.

Main files: `tests/test_sftp.py` and an **Access Control Design** section in `README.md` or a separate `policy.md`.

### Required automated tests

Each test needs a one-line objective/docstring and isolated fixtures: temporary jail paths, users, roles, and labels, without manual setup.

- [x] **DAC:** owner reads/writes their file; another user cannot write without permission; directory execute permission affects listing/stat as documented.
- [x] **MAC:** internal user reads public/internal but not confidential; confidential user cannot write to public.
- [x] **RBAC:** analyst reads/writes under `/projects` but cannot mkdir under `/admin`; adding admin permits it when DAC/MAC also allow it.
- [x] **Composition:** DAC allows/MAC denies and DAC denies/MAC allows both deny under AND composition.
- [x] **Jail:** at least one traversal attempt is denied.
- [x] **Audit:** allow/deny records contain correct fields and values.
- [x] Test authentication failures/throttling once authentication is implemented.
- [x] Test the protocol, handles, and symlink behavior from section 3. The path-replacement race remains documented below.

### Required design explanation

- [x] Describe operation mapping, default deny, and the enforcement point.
- [x] Explain DAC ownership/groups, file vs directory `r/w/x`, inheritance, and owner/group/other examples.
- [x] Explain MAC label ordering, clearances, label storage, no read up, and no write down.
- [x] Explain the RBAC permission matrix, union of roles, path scopes, and conflict handling.
- [x] Include the composition rule, a 2x2 example outcome table, and a sample audit record.

**Done when:** automated tests demonstrate the examples and a teammate can explain each allow/deny decision from the documentation.

Page 3 explicitly requires these self-tests, despite the later repository-tree comment describing tests as optional.

## 2b) User and role management: static datasets

**Intuition:** The files describe your small demonstration organization. Load them at startup; no runtime user-management API or role editor is needed.

- [x] Validate `data/users.json`: username, base64 salt/hash, and hashing parameters.
- [x] Validate `data/user_roles.json`: username -> role list.
- [x] Validate `data/role_perms.csv`: role, resource/prefix, and operation grants.
- [x] Define MAC clearances/labels in `data/mac_labels.json` or another documented mapping permitted by the PDF.
- [x] Choose DAC ownership/group/mode storage: project metadata in `data/dac.json`; `acm_users.csv` is not DAC ownership data.
- [x] Include multiple users who demonstrate different roles/clearances and both allowed/denied actions.
- [x] Load/validate required files at startup, log successful loads, and fail cleanly with readable errors for missing/malformed required files.
- [x] Keep user/role/label configuration static until restart; explain metadata inheritance for new resources.
- [x] Document usernames and intended powers/limits; keep only salted password hashes in datasets.

**Done when:** valid files start the server, invalid required files prevent startup, and multiple users are exercised in tests. Existing files alone do not prove the server uses them.

## 3) SFTP v3 server commands

**Intuition:** Each request is a binary message with a defined reply. Most handlers already exist; complete the missing request and fix specific behavior rather than rebuilding SFTP.

Main file: `server/server.py`.

### S1-S7 completion

These labels are our implementation breakdown, not separate numbered tasks in the PDF.

- [x] **S1:** Implement FSTAT and test valid, invalid, directory, and removed handles.
- [x] **S2:** Explicit file closure, invalid-handle rejection, disconnect cleanup, and continuation after cleanup errors.
- [x] **S3:** OPEN flags/access modes, atomic exclusive creation, append writes, and READ/WRITE access restrictions.
- [x] **S4:** Frame/string/attribute/payload validation, INIT checks, read limits, fragmented packets, and batched requests.
- [ ] **S5:** Windows path and symlink checks passed. Verify path behavior on macOS/Linux and address the remaining race risk if the jail must support untrusted local writers.
- [x] **S6:** Non-recursive MKDIR with success, duplicate, and missing-parent tests.
- [x] **S7:** Safe error responses, server-side exception logging, and STATUS mapping tests.

### Command status

The tests exercise protocol handlers through in-memory channels and policy fixtures. The group client and Windows OpenSSH both completed live file transfers.

| Request | Expected reply | Current status / remaining work |
| --- | --- | --- |
| INIT | VERSION(3) | Implemented and tested: versions, extensions, ordering, and repeated INIT rejection. |
| REALPATH | NAME | Path checks and authorization tested; OpenSSH exercised it. |
| STAT / LSTAT | ATTRS or STATUS | Metadata and policy checks tested. The symlink test passed in Administrator PowerShell. |
| FSTAT | ATTRS | File-handle policy recheck tested. |
| OPENDIR | HANDLE | Directory policy check tested. |
| READDIR | NAME, then STATUS(EOF) | Handle recheck, filtering, batching, and EOF tested. |
| MKDIR | STATUS | Parent policy and inherited metadata tested. |
| OPEN | HANDLE | Read/write/create/truncate/append/exclusive behavior and policy checks tested. |
| READ | DATA or STATUS(EOF) | Handle mode and policy recheck tested. |
| WRITE | STATUS | Handle mode and policy recheck tested. |
| CLOSE | STATUS | Explicit closure, invalid handles, and cleanup failures tested. |

### Shared fixes and checks

- [x] Validate packet/field/string lengths, request IDs, and initialization order; malformed-request tests pass.
- [x] Reject zero/oversized frames, cap read sizes, and handle fragmented/batched packets in tests.
- [x] Use POSIX client-path normalization and map paths into the OS jail; normalization/containment tests pass on Windows.
- [ ] Run the path tests on macOS/Linux as well as Windows.
- [x] Reject traversal, null bytes, drive/stream syntax, and sibling-prefix escapes in tests.
- [x] Implement separate STAT/LSTAT symlink resolution and add symlink tests.
- [x] Run the symlink test with permission to create links. On Windows, elevated PowerShell verified in-jail links, rejection of paths that resolve outside the jail, and `LSTAT` reporting the link itself.
- [x] Document the path-replacement race limitation and trusted-local-writer assumption in `README.md`.
- [ ] Prevent path-replacement races if untrusted local writers can modify jail directories; the current checks are not atomic.
- [x] Honor OPEN capabilities throughout handle use; make exclusive creation atomic and preserve append semantics on every WRITE.
- [x] Use `os.mkdir` for one directory rather than recursively creating missing parents.
- [x] Close outstanding files on disconnect/error and keep handle tables private to sessions.
- [x] Return STATUS codes appropriately: OK(0), EOF(1), NO_SUCH_FILE(2), PERMISSION_DENIED(3), FAILURE(4). Reject unknown requests cleanly.
- [x] Log internal errors server-side without exposing host paths/details in client responses.

**Done when:** every required request is covered, transfers preserve bytes, malformed requests fail predictably, and file handles are cleaned up.

## 4) Client-side commands

**Intuition:** Your teammate builds the CLI; your server must understand its messages. Agree on SFTP v3 behavior, not a custom replacement protocol.

- [x] Implement and test `pwd`, `ls`, `mkdir`, `stat`, `get`, `put`, and `quit` in the group client.
- [x] Document how to connect with a verified `known_hosts` file and display the server's host-key fingerprint.
- [ ] Fix the default host-key verification path. Explicit `--known-hosts` works, but the default connection disables verification.
- [x] Test listing, directory creation, metadata, upload, and download with both clients using pinned host keys. Verify uploaded and downloaded bytes match.
- [x] Verify that the group client reports a clear permission error and the server records the denial.
- [ ] Verify that Windows OpenSSH exits cleanly after the transfer.

**Done when:** both clients complete the supported workflow with host-key verification enabled.

## 5) Capture-the-Flag and write-up

**Intuition:** The flag demonstrates that your controls protect something valuable. An intended user can reach it; an unauthorized user is stopped for an explainable reason.

- [x] Place a synthetic flag at `/admin/flag.txt` and protect it with DAC, MAC, and RBAC.
- [x] Verify that the traversal regression test denies and audits the attempt. Describe the result in `CTF_writeup.md`.
- [x] Record live SFTP results for Alice, Bob, and Eve and include audit excerpts from the same run in the write-up.
- [x] Supply `CTF_writeup.pdf` with the flag location, intended protections, traversal regression, and audit evidence.

**Done when:** the write-up's claims can be reproduced and supported by server evidence.

## Final deliverables and handoff

- [ ] Follow the required repository structure: server entrypoint/auth/policy, runtime audit log/jail, client, tests, README, and CTF PDF.
- [x] Document Windows/macOS/Linux setup, host-key generation, run commands, expected outputs, predefined users, and limitations.
- [x] Record the Windows result: 68 passed in the normal run, plus the symlink test passed in a separate Administrator PowerShell run.
- [x] Complete authentication/authorization/audit tests as those features are implemented.
- [x] Verify a byte-identical OpenSSH `sftp` round trip with host-key verification and verify denial using the group client.
- [ ] Disclose generative AI use and which code/report components it helped with, as required by the assignment.

**Scope:** public-key login, MFA, runtime user/role administration, remove/rename, and per-user overrides are not needed for the required subset. If per-user overrides are implemented, explicit deny must win.

## Remaining work in priority order

1. Fix default host-key verification and replace the tracked private key (1 and 4).
2. Complete the group-wide AI-use disclosure. `CTF_writeup.pdf` covers the CTF review and report assistance (5).
3. Check OpenSSH session exit and repeat path tests on macOS or Linux (3 and 4).

Write relevant tests alongside each piece. Rubric: transport/protocol 25 points, authentication 10, authorization 35, client 10, security quality 10, CTF/write-up 10.
