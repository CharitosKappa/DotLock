# T2 symmetric primitives

Spec: SPEC §§2,4; acceptance: TASKS T2. All implementation remains in
`core/dotlock-crypto`. No format, streaming, credential encoding or FFI changes.

- [x] Write failing tests for Argon2id defaults/minimums and reference output,
  HKDF domain labels/salts, and AEAD round trip/failure paths.
- [x] Implement zeroizing 32-byte Key, validated Argon2 parameters, fixed-label
  HKDF-SHA256 and random-nonce XChaCha20-Poly1305 with caller-provided AAD.
- [x] Verify negative trait assertions: Key has no Debug, Display, Copy or Clone.
- [x] Run Rust fmt/clippy/tests and Flutter analyze/tests; update changelog.
- [x] Commit T2 and open a separate PR. Tick the parent task only upon merge.

Borrowed inputs remain caller-owned; owned credential/plaintext/output buffers
use zeroize. Decryption must zeroize its buffer even on authentication failure.
Use upstream algorithms, enable available secret-state zeroization features;
never add a custom cryptographic algorithm. No frozen vectors before T5.


Verification: observed unresolved API imports before implementation, then six Rust tests passed (including randomized AEAD round trips). The SecretBytes trait test also failed before adding the opaque buffer. Rust fmt/clippy/workspace tests and Flutter analysis/bootstrap test pass. No frozen vectors changed. Review found HKDF temporary-output erasure missing upstream. Added a vendored zeroization-only patch; source review confirmed the issue is resolved. An RFC5869 case-one test verifies the patched output.


T2 split: T2a dependencies/generated lockfile; T2b primitive implementation, tests and docs; T2c vendored upstream HKDF source/licenses and erasure patch. Vendored source and lockfile are isolated from the handwritten wrapper.
