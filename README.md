# HumanMsg 1.0.0 research reference implementation

HumanMsg is an evaluated Python/JavaScript research reference implementation of encrypted message and file exchange. It includes a Flask/SQLite relay, a portable Python command-line client, an independent Web Crypto envelope module tested under Node.js, automated tests, a live HTTP demo, and raw local benchmark data.

It is a research prototype, not a reviewed production service. It has no forward secrecy, group messaging, hardware keystore, mobile app, browser UI, automatic recovery, streaming, or field deployment evidence. No external service is contacted by the demo or tests. Use synthetic data for experiments.

## Install and reproduce

Use Python 3.12 and Node.js 24 (recorded versions are in `evidence/benchmark-summary.json`). In a writable directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=. .venv/bin/python tests/test_reference.py
.venv/bin/python demo.py
.venv/bin/python benchmark.py
```

If Node is not on PATH, set `HUMANMSG_NODE` to its absolute executable path. Direct execution of `tests/test_reference.py` requires the repository root on `PYTHONPATH`, for example:

```sh
PYTHONPATH=. .venv/bin/python tests/test_reference.py
```

The direct test runner writes `evidence/security-tests.json`; unittest discovery only prints outcomes. The benchmark writes 200 rows to `evidence/benchmark-raw.csv` and a summary JSON. Five warm-ups precede 50 measured trials at each of four sizes. Rerunning changes the measured evidence files; preserve the supplied files separately when comparing with the manuscript.

Functional test fixtures deliberately use bcrypt cost 4. The shipped relay default, benchmark enrolment, and live HTTP demonstration use cost 12. Authentication and vault unlock are not included in timed benchmark intervals.

## Run a local relay

Generate separate fresh secrets in your shell without printing them:

```sh
export HUMANMSG_JWT_SECRET="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export HUMANMSG_ENROLMENT_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
.venv/bin/python -m humanmsg.server --database relay.sqlite --port 8765
```

The server binds to `127.0.0.1`. Keep the enrolment token and database private. This development server does not supply TLS or hardened operational hosting. Provide the enrolment token to authorised experiment participants through an appropriate separate channel; the client prompts for it. Avoid shell debug tracing when handling secrets.

## Two-user client workflow

In separate terminals, enrol each synthetic user:

```sh
.venv/bin/python -m humanmsg.cli --user alice --state alice-state register
.venv/bin/python -m humanmsg.cli --user bob --state bob-state register
```

Registration creates an encrypted local identity vault, displays a TOTP provisioning URI for enrolment in an authenticator, and prints the public bundle fingerprint. Store the vault password and TOTP seed separately and securely. The server account password and vault password serve separate purposes. Reusing a state directory for another account is unsupported.

Independently compare fingerprints before pinning. `BOB_VERIFIED_FINGERPRINT` and `ALICE_VERIFIED_FINGERPRINT` below are placeholders for the 64-character values obtained through that independent verification, not values to copy blindly from the relay.

```sh
.venv/bin/python -m humanmsg.cli --user alice --state alice-state pin bob BOB_VERIFIED_FINGERPRINT
.venv/bin/python -m humanmsg.cli --user bob --state bob-state pin alice ALICE_VERIFIED_FINGERPRINT
.venv/bin/python -m humanmsg.cli --user alice --state alice-state send bob synthetic.txt
.venv/bin/python -m humanmsg.cli --user bob --state bob-state inbox
.venv/bin/python -m humanmsg.cli --user bob --state bob-state receive alice MESSAGE_ID received-synthetic.txt
.venv/bin/python -m humanmsg.cli --user bob --state bob-state logout
```

The receive command chooses its output path explicitly and never overwrites an existing file. Received filenames are encrypted metadata and never used as filesystem paths. Message IDs are printed by send and inbox. Each accepted TOTP code is usable only once for login; reuse a cached 15-minute session or wait for the authenticator’s next code. If a cached session has been revoked remotely, remove that state directory’s `session.json` and log in again. Logout revokes all of the account’s earlier sessions.

The client records accepted envelopes before returning plaintext; disk-write failure after that commit is not an atomic transaction with replay state. Keep the ciphertext for explicit recovery. No automatic vault recovery, key change override, or key rotation is provided.

## What the evidence establishes

- `security-tests.json`: executable pass/fail outcomes. One test deliberately demonstrates that long-term recipient-key compromise reveals recorded content.
- `http-demo.json`: a synthetic live loopback HTTP transfer with the default bcrypt cost; not a remote-network or TLS test.
- `benchmark-raw.csv`: sequential per-trial sealing, opening, and in-process Flask POST–GET timing.
- `benchmark-summary.json`: environment, medians, nearest-rank p95, bootstrap intervals, envelope sizes, and separately measured Python allocations.
- `SOURCE_MANIFEST.json`: SHA-256 hashes of the packaged source and documentation. Experimental keys, credentials, vaults, and databases are temporary and are not included.

No mobile, WAN, concurrent-user, energy, usability, independent audit, or beneficiary outcome claims follow from these measurements. A successful synthetic test is not a security proof.

## Reference and publication

Suggested manuscript reference: Gamundani, A.M., Gahirwa, R., Muponesi, S.T.: HumanMsg 1.0.0: Reference implementation and evaluation data for encrypted humanitarian messaging. Companion research artifact (2026). https://github.com/AMG2020/Humanitarian-Messaging.

The repository contains the research artifact, runnable demonstration, automated tests, and raw measurements. Use the source manifest to identify the evaluated version. The authors must confirm attribution and choose a software licence before release; no licence grant, public DOI, or independent security review is asserted.

## Demonstration and manuscript

See [the demonstration walkthrough](docs/DEMONSTRATION.md), [protocol specification](PROTOCOL.md), and `evidence/` for the recorded outcomes and raw benchmark data. The paper is provided in `paper/Humanitarian_Messaging_SMARTCOM_2027_Final.docx`. The GitHub Actions workflow is supplied for future runs; a successful hosted CI run is not claimed.
