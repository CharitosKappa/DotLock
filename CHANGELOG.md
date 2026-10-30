# Changelog

All notable changes to DotLock are recorded here, newest first.

## Unreleased

- T5a completed: reviewed PR #7 merged after all CI passed. Primitive fixtures
  are frozen; T5b format/auth coverage remains tracked separately.

- T5 split approved and merged in PR #6. T5a adds public synthetic primitive
  fixtures, a deterministic non-writing check mode, exclusive initialization,
  frozen-byte/hash tests and CI checks on all Rust runners. Production APIs keep
  OS-generated nonces. T5b format/auth coverage remains deferred to its tasks.
- T5 requirements review: recorded slot distinguishability/framing, cloud HMAC
  verification, and deterministic serialization questions before freezing v1 bytes.
- T4 completed: PR #5 merged after all CI passed; credentials and generated
  BIP-39 recovery are now on main.

- T4: approved v1 recovery scope merged in PR #4. Added pattern validation and
  lattice-point auto-fill, NFKD passphrase encoding, advisory strength guidance,
  and 128-bit English BIP-39 generation/restoration with checksum validation.
  Owned credentials, normalization buffers, entropy and recovery text zeroize;
  secret types do not implement Debug/Display. Custom recovery phrases deferred.
- T3 completed: PR #3 merged after all CI passed, including the 2 GiB Linux test.
- T4 requirements review started; custom recovery phrase acceptance and Argon2
  output length questions recorded before implementation, per AGENTS.md.
- T2 completed: PR #2 merged after Linux/macOS/Windows Rust and Flutter CI passed.
- T3: STREAM BE32 Read adapters and encrypted Write sink, authenticated 1 MiB
  chunks, length validation, terminal errors and zeroizing buffers. Boundary,
  tampering and property tests; generated 2 GiB round trip added to Linux CI.
- T2: Argon2id v1.3 with validated minimums and zeroizing working memory;
  fixed-label HKDF-SHA256; XChaCha20-Poly1305 with random nonces and AAD;
  opaque zeroizing keys/plaintext; negative and property tests. Pending review.
- T1 scaffold: six Rust core crates, server placeholder, empty Flutter app with
  iOS/Android/Windows/macOS hosts, bootstrap widget test, and cross-platform CI.
  No encryption or vault operations are implemented yet.
- Project kit: plan, spec v1, task list, testing and threat model.

- T1 completed: PR #1 merged after CI run 41093785632 passed Rust checks on all three runners and Flutter checks.
