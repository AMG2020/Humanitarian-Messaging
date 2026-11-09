# HumanMsg 1 envelope profile

A research profile, not a standardised secure-messaging protocol.

## Public bundle and trusted identity

A bundle has exactly `enc` and `sig`. Each is standard padded Base64 of DER SubjectPublicKeyInfo for a distinct RSA-2048 key, exponent 65537. SHA-256 of the compact sorted-key ASCII JSON bundle is its fingerprint. The Python client requires an independently obtained expected fingerprint for first pinning; changed bundles fail closed. The JavaScript module is a cryptographic component and relies on its caller for authenticated bundle selection, pin persistence, and replay state.

## Envelope

Exactly five fields: `header`, `nonce`, `wrapped_key`, `ciphertext`, `signature`.

The header has exactly these fields:

| Field | Value |
| --- | --- |
| version | JSON integer 1 |
| suite | RSA2048-OAEP-SHA256+A256GCM+RSA2048-PSS-SHA256 |
| sender, recipient | 1–32 ASCII letters, digits, underscore or hyphen |
| sender_fp, recipient_fp | 64 lowercase hexadecimal characters |
| message_id, conversation_id | 32 lowercase hexadecimal characters |

Identifiers are independently random 16-byte values. A caller may reuse a conversation identifier. The constrained header uses only ASCII strings and one integer. Compact sorted-key JSON without whitespace is the canonical byte representation. This is not a claim of general JSON canonicalisation; externally supplied raw JSON duplicate-key ambiguity is not separately parsed/rejected before Flask's parser. The authenticated object is the parsed constrained schema.

The inner frame is `HM1` (three bytes), metadata length (four-byte unsigned big-endian), metadata JSON, then original content bytes. Content is capped at 1 MiB; metadata at 4096 bytes. Metadata must decode to an object.

For each envelope:

1. Sample a 32-byte CEK and 12-byte nonce from secure randomness.
2. AES-256-GCM encrypt the frame, using canonical header bytes as AAD, and append the 16-byte tag.
3. RSA-OAEP encrypt the CEK to the recipient encryption key with SHA-256, MGF1-SHA-256, and the canonical header as label.
4. Encode nonce, wrapped CEK and ciphertext-plus-tag with standard padded Base64.
5. Sign `HumanMsg-1-envelope\x00` followed by canonical unsigned-envelope JSON using the sender's distinct signing key, RSA-PSS, SHA-256, MGF1-SHA-256, salt length 32. Base64-encode the signature.

The receiver checks schema/profile, account and fingerprint bindings, then the signature, then unwraps the CEK and verifies GCM before parsing plaintext. The Python client additionally requires the sender pin and atomically inserts its replay tuple before returning content. The module-level `open_envelope` alone is intentionally stateless and does not reject replay. The JavaScript module alone is also stateless.

## Relay and account access

JWTs are HS256-only, valid for 900 seconds, with fixed issuer `humanmsg-relay`, audience `humanmsg-api`, and required `sub`, `iat`, `exp`, `jti`, `epoch` claims. The relay compares the epoch against persistent account state. Logout increments it. Five failed logins within 300 seconds trigger account-level throttling. TOTP uses six digits, 30-second steps, and no skew window; the last accepted login step is persisted. The relay database holds TOTP seeds; at-rest protection of these authentication secrets is not implemented.

Registration requires an organisation enrolment token, signature over `HumanMsg-1-register\x00` plus canonical `{username,bundle}`, and a valid code for the submitted TOTP seed. Proof of the signing key is not proof of possession of the separate decryption key or proof of a real-world person's identity.

## Vault

A vault derives 32 bytes with scrypt (N=32768, r=8, p=1) using a random 16-byte salt. AES-GCM encrypts JSON containing Base64 PKCS#8 private-key values, using a fresh 12-byte nonce and AAD `HumanMsg-1-vault`. Version, salt, nonce, and authenticated ciphertext are stored in a mode-0600 file. The client state directory is mode 0700. Cryptographic erasure, hardware isolation, password recovery, and key rotation are not implemented.

## Residual risks

RSA transport is not forward secret. Do not retain RSA-recoverable fallback keys and claim ratcheting secrecy. Routing identities, timing, ciphertext lengths and access events remain observable. Endpoint compromise, coercion, malicious software delivery, weak passwords, and an authorised recipient's disclosures can expose information. Signatures can make communications transferable as evidence. Messages are processed whole, not streamed. SQLite deletion is not certified physical erasure. The first-contact fingerprint ceremony requires a genuinely independent trusted channel. This prototype has not undergone an independent audit or production deployment assessment.
