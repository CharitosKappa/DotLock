# Upstream provenance and local patch

Source: RustCrypto `hkdf` 0.13.0 from crates.io; upstream src, README and
MIT/Apache licenses retained. Package manifest is reduced to runtime dependencies.

Local changes do not alter HKDF outputs:

- Wipe discarded PRK arrays in `GenericHkdf::new` and optional Kdf adapter.
- Wrap expansion output arrays in `ErasedOutput`, whose Drop wipes the bytes.
  This erases the previous block on replacement and the last block on return.
- Enable HMAC/SHA-256 state erasure via dependency features.

Explicit `extract`/`finalize` APIs still return caller-owned raw PRK arrays by
upstream design. DotLock only uses the patched `new`/`expand` path.
This patch does not promise erasure of compiler-created register/stack copies.
Retain the patch until upstream supplies equivalent temporary-buffer erasure.
