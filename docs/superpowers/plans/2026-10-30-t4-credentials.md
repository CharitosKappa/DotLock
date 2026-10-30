# T4 credentials implementation record

Scope: SPEC §§3,4 and TASKS T4. User approved custom recovery phrase deferral;
spec PR #4 was merged after updated CI passed. No additional passphrase or KDF
is applied to BIP-39 entropy. Pattern/passphrase credentials remain supported.

- [x] Write failing table tests for lattice-point auto-fill, repeats, validity,
  byte prefixes, NFKD/whitespace and English BIP-39 count/checksum.
- [x] Implement Pattern, encode_passphrase, RecoveryPhrase and SecretText in
  dotlock-crypto, with owned secrets in zeroizing buffers and no Debug/Display.
- [x] Property-test canonical pattern idempotence, BIP-39 mapping against upstream
  Mnemonic and restore round trips; check normalization against upstream NFKD.
- [x] Add advisory pattern-strength guidance independent of format validity.
- [x] Source review: identified upstream NFKD iterator's unzeroized reorder buffer;
  replaced it with decomposition callbacks and zeroizing stable counting-sort
  storage. Reviewer confirmed the finding resolved, with no new actionable defects.
- [x] Run final Rust/Flutter checks and the existing 2 GiB release test.
- [x] Commit implementation and open a separate PR. Tick T4 only upon merge.

The English wordlist comes from bip39; bit packing/checksum buffers are owned
here to avoid unzeroized library mnemonic temporaries. SHA-256 remains upstream.
No frozen vectors changed; format vectors remain T5. Seven credential tests pass,
including randomized upstream comparisons. Secret cleanup proof is ownership/source
review, not an unsafe read of freed memory or a compiler/register erasure claim.

Final verification: Rust fmt, Clippy with warnings denied, workspace tests (18 regular crypto tests), generated 2 GiB release test, Flutter analyze and bootstrap test all passed locally. Hosted CI passed on Linux, macOS, Windows and Flutter (runs 41100440111 and 41100445798). PR #5 merged on 2026-10-30 after user authorization. T4 is complete.
