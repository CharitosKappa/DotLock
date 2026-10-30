# T3 STREAM adapters

Spec: §§2,6. Implement only the raw STREAM body in dotlock-crypto; object
headers, authenticated lengths and Padme padding remain later format tasks.

- [x] Tests first: chunk boundaries, upstream BE32 compatibility, tampering,
  truncation/reorder/duplication, poisoned readers, short/interrupted reads.
- [x] Add EncryptReader and DecryptReader (Read), plus encrypt_to (Write sink).
- [x] Use 1 MiB plaintext chunks, 19-byte OS nonce, final flag on last chunk;
  empty inputs emit one authenticated empty final chunk. No new framing bytes.
- [x] Bound each adapter to one zeroizing chunk buffer. Reject length mismatch,
  trailing bytes and counter overflow; poison after errors.
- [x] Run a generated 2 GiB encrypt/decrypt pipeline without storing the stream;
  validate output with a counting sink and measure process memory externally.
- [ ] Run required gates, source review, docs/changelog and separate draft PR.

Lengths are supplied by the caller (eventually authenticated object headers).
DecryptReader must receive a reader bounded to the ciphertext body, excluding
padding. Earlier authenticated chunks can be read before a later error; callers
must consume to EOF and discard partial imports on failure. Caller plaintext
buffers must be zeroizing and must not target persistent storage.

Verification: tests first failed for the missing streaming API. Five streaming tests now pass (plus six primitive tests); the separate 2 GiB release test passed in 5.75 s, sampled peak working set 8.07 MiB. Rust fmt/clippy/workspace tests and Flutter checks passed. Focused source review found no actionable defects. No frozen vectors or normative format changes.
