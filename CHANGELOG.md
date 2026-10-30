# Changelog

All notable changes to DotLock are recorded here, newest first.

## Unreleased

- T2: Argon2id v1.3 with validated minimums and zeroizing working memory;
  fixed-label HKDF-SHA256; XChaCha20-Poly1305 with random nonces and AAD;
  opaque zeroizing keys/plaintext; negative and property tests. Pending review.
- T1 scaffold: six Rust core crates, server placeholder, empty Flutter app with
  iOS/Android/Windows/macOS hosts, bootstrap widget test, and cross-platform CI.
  No encryption or vault operations are implemented yet.
- Project kit: plan, spec v1, task list, testing and threat model.

- T1 completed: PR #1 merged after CI run 41093785632 passed Rust checks on all three runners and Flutter checks.
