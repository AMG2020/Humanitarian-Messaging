# Reproduce the encrypted-transfer demonstration

The demonstration uses two synthetic accounts and an ephemeral Flask relay on a dynamically allocated loopback port. No real beneficiary information is used, and no external server is contacted. All experimental keys, passwords, TOTP seeds, vaults, and databases are temporary.

## Run

From the repository root, follow the README installation instructions, then run:

```sh
.venv/bin/python demo.py
```

The demonstration performs these operations:

1. Start the relay with persistent SQLite storage and default bcrypt cost 12.
2. Generate separate encryption and signing keys for Alice and Bob.
3. Encrypt and reload their password-protected local identity vaults.
4. Enrol their public bundles and log in with password plus TOTP.
5. Fetch and pin the known synthetic fingerprints, modelling an independently verified channel.
6. Encrypt a synthetic referral and its filename on Alice's client.
7. Send the authenticated envelope through live HTTP and retrieve Bob's inbox.
8. Verify, unwrap, and decrypt on Bob's client; compare recovered bytes and metadata.
9. Reopen Bob's local state and confirm rejection of the repeated envelope.
10. Delete the encrypted object as the authorised recipient and check the empty inbox.

It writes `evidence/http-demo.json`. The supplied record reports each operation as successful. There is no screenshot or video asserted; this is an executable demonstration with machine-readable outcomes. Loopback HTTP is intentionally used for a local experiment and is not an internet TLS test.

## Security tests

```sh
PYTHONPATH=. .venv/bin/python tests/test_reference.py
```

The supplied evaluation contains 37 passing test methods. They cover content boundaries, tampering, identity checks, duplicate handling, persistence, account access, token and MFA failures, vault protection, CLI transfer, and Python/JavaScript interoperability. One passing method deliberately demonstrates long-term RSA-key compromise revealing recorded content. It must not be described as forward-secrecy protection.

## Benchmarks

```sh
.venv/bin/python benchmark.py
```

The supplied CSV records 50 measured trials after five warm-ups at each of 0 B, 1 KiB, 64 KiB, and 1 MiB. Sealing, opening, and the in-process relay POST–GET cycle are separately timed. These relay times exclude the network, TLS and recipient decryption. New measurements overwrite the local evidence outputs; retain the supplied files separately before reproducing.

The raw CSV and summary JSON are the results behind the paper's table. The separate allocation measurement tracks Python-managed memory, not total resident or native cryptographic memory. Single-host measurements do not establish mobile performance, field usability, energy benefits or production readiness.
