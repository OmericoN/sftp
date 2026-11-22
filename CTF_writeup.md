# SFTP Capture-the-Flag Report

## Flag placement

The flag is a synthetic plaintext token stored at `server/sftp_root/admin/flag.txt`. Its SFTP path is `/admin/flag.txt`. We placed it inside the existing protected admin directory. An authorized user can find and download it using ordinary SFTP commands.

## Protection layers

- **Discretionary access control (DAC).** In [data/dac.json](data/dac.json), Alice owns `/admin` and its mode is `0700`. Bob cannot list or traverse that directory, even if he knows the flag's exact path.
- **Mandatory access control (MAC).** In [data/mac_labels.json](data/mac_labels.json), `/admin` and its descendants are labeled `confidential`. Alice has confidential clearance, while Bob has internal clearance. The no-read-up rule would reject Bob's read even if DAC permitted it.
- **Role-based access control (RBAC).** In [data/role_perms.csv](data/role_perms.csv), Alice's admin role can read files across the jail. Bob's analyst role grants file reads under `/projects`. The [authorization policy](server/policy.py) requires all three checks to pass.

A server that hides an entry from directory listings but allows any authenticated user to open a known path would expose the flag to someone who guesses its location. This implementation applies authorization to directory and file operations, including direct access by path.

## Validation and audit evidence

We exercised the authorization policy against the actual flag file. Alice was allowed to stat and list `/admin` and read `/admin/flag.txt`. Bob was denied all three operations, including the read with the exact path.

The audit record identifies the account, requested operation, target, and reason. Bob's request stopped at DAC because the policy evaluates DAC first. The record therefore demonstrates the DAC denial. The MAC configuration establishes the separate clearance requirement.

## Directory traversal attempt

The existing [traversal regression test](tests/test_policy.py) sends an SFTP metadata request for a path outside a temporary jail. A naive server that joins the requested path to the jail root without checking the resulting location could expose files elsewhere on the host. The server validates that the path stays inside the jail before applying file authorization. The test verifies that the server returns `SSH_FX_PERMISSION_DENIED` and logs `jail_denied`. The policy suite passed all 11 tests.

## Live SFTP verification

Both Alice and Bob authenticated successfully and connected to the SFTP v3 subsystem at `127.0.0.1:2222`.

**Alice.** The command `ls /admin` showed `flag.txt`. The command `get /admin/flag.txt` returned `Downloaded: /admin/flag.txt`.

![Alice lists and downloads the flag](Capture%20d%E2%80%99e%CC%81cran%202026-11-22%20a%CC%80%2012.43.47.png)

**Bob.** The command `ls /admin` failed at `OPENDIR` with SFTP status 3 (permission denied). The command `get /admin/flag.txt` failed at `OPEN` with the same status, even though Bob supplied the exact path.

![Bob is denied directory listing and direct flag access](Capture%20d%E2%80%99e%CC%81cran%202026-11-22%20a%CC%80%2012.45.30.png)

The screenshots show the live client results. The audit entries above come from the separate policy check and identify DAC as the reason for Bob's denial in that check.
