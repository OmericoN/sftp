# Project tasks: server first

This checklist follows the **Project Requirements** numbering in the assignment PDF. The deadline stated there is **18 November**. The suggested coding order at the end accounts for dependencies between sections.

The starter already implements most basic SFTP operations. Keep that code: add missing security, fix specific bugs, and demonstrate that it works. An unchecked box means implementation or verification remains; it does not mean you must rewrite the surrounding code.

## Current progress

- `server/server.py` contains the starter in the required entrypoint; `main.py` has been removed.
- AsyncSSH transport, the SFTP subsystem, and shell/exec rejection are present. A host-key file exists; startup has not been tested here.
- All required SFTP handlers now exist, including FSTAT. S1-S4 and S6-S7 have automated coverage; S5 still has the limitations below.
- Authentication still uses `bob` / `test`; `auth.py` and `policy.py` are empty.
- `data/users.json`, `user_roles.json`, `role_perms.csv`, and `acm_users.csv` exist. Their contents and loading have not been validated here.
- Tests live in `tests/test_sftp.py` and `tests/test_server_hardening.py`.
- Latest run (16 November 2026): **27 passed, 1 skipped**. Windows denied symlink creation (error 1314); live SSH/OpenSSH and other operating systems have not been tested.
- Path-replacement races remain unresolved and are documented in `README.md`.

## 1) SSH transport via AsyncSSH

**Intuition:** SSH provides the encrypted connection and login exchange. SFTP is the language spoken inside that connection. Reuse SSH; implement the SFTP messages yourself.

Main files: `server/server.py`, `server/auth.py`, `data/users.json`.

### Transport

- [x] Put the starter in `server/server.py`.
- [x] Retain AsyncSSH transport, accept the `sftp` subsystem, and reject shell/exec requests.
- [ ] Confirm startup uses a persistent Ed25519 host key and creates `server/sftp_root/` when missing. Do not regenerate the key on every run.
- [ ] Confirm server paths work independently of the current working directory.

### Password authentication

**Question this answers:** "Who is connecting?" Login does not automatically grant access to every file.

- [ ] Implement password verification in `auth.py` using salted hashes and parameters from `users.json`. Standard-library `hashlib.scrypt` and constant-time comparison fit the assignment constraints.
- [ ] Replace the hardcoded credential check with the verifier; reject incorrect passwords and unknown users.
- [ ] Add failed-login throttling or temporary lockout; the grading rubric explicitly includes this.
- [ ] Keep passwords/hashes out of logs and carry the authenticated username into each SFTP session for authorization/auditing.

**Done when:** the server starts, valid credentials open an SFTP session, invalid credentials fail, repeated failures are limited, and shell/exec remain unavailable.

## 2) Authorization and access control: DAC, MAC, RBAC

**Intuition:** After login, every request asks "May this user perform this operation on this resource?" The jail determines where a path points; access control determines whether it may be used.

Main files: `server/policy.py` for decisions/auditing and `server/server.py` for enforcement.

### Implement one gate

- [ ] Provide `authorize(user, op, full_path) -> (allowed, reason)`, with default deny for unknown/ungranted users, operations, and resources.
- [ ] **DAC:** check owner/group/other permission bits. Define file read/write, directory listing/traversal (`x`), and parent permissions for creation.
- [ ] **MAC:** define user clearances and resource labels, such as `public < internal < confidential`. Enforce no read up and no write down.
- [ ] **RBAC:** grant operations on resource prefixes through roles; combine grants from all roles. Match path boundaries so `/projects` does not include `/projects-other`.
- [ ] Compose the decision as **DAC AND MAC AND RBAC**, as recommended in the PDF. All three must allow the operation.

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

- [ ] Apply the gate to every operation above, including requests using existing handles.
- [ ] Require both permissions for read/write OPEN; denied creation/truncation must leave data unchanged.
- [ ] Store the path and requested access mode with each handle so it cannot bypass policy checks.
- [ ] Define ownership, modes, and labels inherited by newly created files/directories.
- [ ] Decide/document whether directory listings filter inaccessible entries.
- [ ] Append each allow/deny decision to `server/audit.jsonl`: user, op, path, allowed, reason, timestamp. Keep secrets out.

**Done when:** one user can perform an allowed action and is denied a forbidden action, both are audited, and no alternate request/handle bypasses the gate.

## 2a) Applying DAC, MAC, RBAC and self-tests

**Intuition:** Show that each rule works independently, then prove their combination works. Tests are evidence for your security claims.

Main files: `tests/test_sftp.py` and an **Access Control Design** section in `README.md` or a separate `policy.md`.

### Required automated tests

Each test needs a one-line objective/docstring and isolated fixtures: temporary jail paths, users, roles, and labels, without manual setup.

- [ ] **DAC:** owner reads/writes their file; another user cannot write without permission; directory execute permission affects listing/stat as documented.
- [ ] **MAC:** internal user reads public/internal but not confidential; confidential user cannot write to public.
- [ ] **RBAC:** analyst reads/writes under `/projects` but cannot mkdir under `/admin`; adding admin permits it when DAC/MAC also allow it.
- [ ] **Composition:** DAC allows/MAC denies and DAC denies/MAC allows both deny under AND composition.
- [x] **Jail:** at least one traversal attempt is denied.
- [ ] **Audit:** allow/deny records contain correct fields and values.
- [ ] Test authentication failures/throttling once authentication is implemented.
- [x] Test the protocol/handle fixes from section 3, with the S5 symlink/race limitations recorded below.

### Required design explanation

- [ ] Describe operation mapping, default deny, and the enforcement point.
- [ ] Explain DAC ownership/groups, file vs directory `r/w/x`, inheritance, and owner/group/other examples.
- [ ] Explain MAC label ordering, clearances, label storage, no read up, and no write down.
- [ ] Explain the RBAC permission matrix, union of roles, path scopes, and conflict handling.
- [ ] Include the composition rule, a 2x2 example outcome table, and a sample audit record.

**Done when:** automated tests demonstrate the examples and a teammate can explain each allow/deny decision from the documentation.

Page 3 explicitly requires these self-tests, despite the later repository-tree comment describing tests as optional.

## 2b) User and role management: static datasets

**Intuition:** The files describe your small demonstration organization. Load them at startup; no runtime user-management API or role editor is needed.

- [ ] Validate `data/users.json`: username, base64 salt/hash, and hashing parameters.
- [ ] Validate `data/user_roles.json`: username -> role list.
- [ ] Validate `data/role_perms.csv`: role, resource/prefix, and operation grants.
- [ ] Define MAC clearances/labels in `data/mac_labels.json` or another documented mapping permitted by the PDF.
- [ ] Choose DAC ownership/group/mode storage: the PDF permits `data/dac_owners.csv` or OS metadata. Check whether existing `acm_users.csv` serves that purpose before adding another file.
- [ ] Include multiple users who demonstrate different roles/clearances and both allowed/denied actions.
- [ ] Load/validate required files at startup, log successful loads, and fail cleanly with readable errors for missing/malformed required files.
- [ ] Keep user/role/label configuration static until restart; explain metadata inheritance for new resources.
- [ ] Document usernames and intended powers/limits; keep only salted password hashes in datasets.

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
- [ ] **S5:** Complete path-security verification and address the remaining race risk; implemented/tested parts are split below.
- [x] **S6:** Non-recursive MKDIR with success, duplicate, and missing-parent tests.
- [x] **S7:** Safe error responses, server-side exception logging, and STATUS mapping tests.

### Command status

The tests exercise protocol handlers through in-memory channels; access-control policy and live client integration are separate unfinished work.

| Request | Expected reply | Current status / remaining work |
| --- | --- | --- |
| INIT | VERSION(3) | Implemented and tested: versions, extensions, ordering, and repeated INIT rejection. |
| REALPATH | NAME | Handler and path checks implemented; authorization and live-client verification pending. |
| STAT / LSTAT | ATTRS or STATUS | Metadata/error checks tested; symlink no-follow test skipped on Windows. Authorization pending. |
| FSTAT | ATTRS | Implemented/tested using a file handle and `os.fstat`; policy integration pending. |
| OPENDIR | HANDLE | Directory handle creation tested; DAC/MAC/RBAC permissions pending. |
| READDIR | NAME, then STATUS(EOF) | Batching, handle checks, and EOF tested; policy integration pending. |
| MKDIR | STATUS | Non-recursive creation/errors tested; policy checks and metadata inheritance pending. |
| OPEN | HANDLE | Read/write/create/truncate/append/exclusive behavior tested; policy integration pending. |
| READ | DATA or STATUS(EOF) | Handle access, offsets, bounded reads, and EOF tested; policy integration pending. |
| WRITE | STATUS | Handle access, offsets, binary data, and repeated append tested; policy integration pending. |
| CLOSE | STATUS | Explicit closure, invalid handles, and cleanup failures tested. |

### Shared fixes and checks

- [x] Validate packet/field/string lengths, request IDs, and initialization order; malformed-request tests pass.
- [x] Reject zero/oversized frames, cap read sizes, and handle fragmented/batched packets in tests.
- [x] Use POSIX client-path normalization and map paths into the OS jail; normalization/containment tests pass on Windows.
- [ ] Run the path tests on macOS/Linux as well as Windows.
- [x] Reject traversal, null bytes, drive/stream syntax, and sibling-prefix escapes in tests.
- [x] Implement separate STAT/LSTAT symlink resolution and add symlink tests.
- [ ] Run symlink tests successfully on a system permitting link creation; current test is skipped.
- [x] Document the path-replacement race limitation and trusted-local-writer assumption in `README.md`.
- [ ] Prevent path-replacement races if untrusted local writers can modify jail directories; the current checks are not atomic.
- [x] Honor OPEN capabilities throughout handle use; make exclusive creation atomic and preserve append semantics on every WRITE.
- [x] Use `os.mkdir` for one directory rather than recursively creating missing parents.
- [x] Close outstanding files on disconnect/error and keep handle tables private to sessions.
- [x] Return STATUS codes appropriately: OK(0), EOF(1), NO_SUCH_FILE(2), PERMISSION_DENIED(3), FAILURE(4). Reject unknown requests cleanly.
- [x] Log internal errors server-side without exposing host paths/details in client responses.

**Done when:** every required request is covered, transfers preserve bytes, malformed requests fail predictably, and file handles are cleaned up.

## 4) Client-side commands: teammate integration

**Intuition:** Your teammate builds the CLI; your server must understand its messages. Agree on SFTP v3 behavior, not a custom replacement protocol.

- [ ] Coordinate `pwd`, `ls`, `mkdir`, `stat`, `get`, `put`, and `quit` with the client teammate.
- [ ] Supply connection details and the host-key fingerprint/public key for verification. Keep the private key private.
- [ ] Verify the client uses known_hosts or TOFU for host-key verification; this is primarily client work.
- [ ] Test listing, directory creation, upload, download, and metadata with both the group client and OpenSSH `sftp`.
- [ ] Compare uploaded/downloaded bytes and confirm forbidden operations produce clear errors.

**Done when:** both clients complete the supported workflow with host-key verification enabled.

## 5) Capture-the-Flag and write-up

**Intuition:** The flag demonstrates that your controls protect something valuable. An intended user can reach it; an unauthorized user is stopped for an explainable reason.

- [ ] Place a synthetic flag inside the jail and protect it with at least two layers, such as MAC plus DAC.
- [ ] Demonstrate at least one realistic attack attempt: traversal, symlink trick, handle reuse, or a race.
- [ ] Capture audit/log evidence and screenshots where useful, showing the outcome and protections.
- [ ] Supply or write `CTF_writeup.pdf`: flag location, intended protections, how a naive design exposes it, attack attempt, fixes, and evidence.

**Done when:** the write-up's claims can be reproduced and supported by server evidence.

## Final deliverables and handoff

- [ ] Follow the required repository structure: server entrypoint/auth/policy, runtime audit log/jail, client, tests, README, and CTF PDF.
- [ ] Document Windows/macOS/Linux setup, host-key generation, run commands, expected outputs, predefined users, and limitations.
- [x] Run the current S1-S7 automated suite and record results: 27 passed, 1 symlink test skipped.
- [ ] Complete authentication/authorization/audit tests as those features are implemented.
- [ ] Run OpenSSH interoperability checks and record results for the group.
- [ ] Disclose generative AI use and which code/report components it helped with, as required by the assignment.

**Scope:** public-key login, MFA, runtime user/role administration, remove/rename, and per-user overrides are not needed for the required subset. If per-user overrides are implemented, explicit deny must win.

## Suggested implementation order

The headings above match the PDF; dependencies make this a practical coding order:

1. Validate existing datasets (2b) and replace hardcoded authentication (1).
2. Implement and test the policy gate (2 and 2a).
3. Connect authorization to handlers and fix protocol/handle issues (2 and 3).
4. Check both clients, collect CTF evidence, and finish documentation (4 and 5).

Write relevant tests alongside each piece. Rubric: transport/protocol 25 points, authentication 10, authorization 35, client 10, security quality 10, CTF/write-up 10.
