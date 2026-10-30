# DotLock

DotLock is a cross-platform encrypted photo and file vault for **iOS, Android, Windows and macOS**.
Files are encrypted on the device under a key derived from a pattern the user draws on a 5×5 dot grid
(or a passphrase). There are no accounts. Our servers only ever see ciphertext.

Read these before any task:

| File | What it is |
| --- | --- |
| `docs/PLAN.md` | Product, architecture, platform matrix, open decisions |
| `docs/SPEC.md` | Crypto + vault format spec v1. **Normative. Follow exactly.** |
| `docs/TASKS.md` | The ordered task list (T1–T30) with acceptance criteria |
| `docs/TESTING.md` | Test strategy, CI jobs, release per store |
| `docs/THREAT_MODEL.md` | What we protect against and what we don't |

## Stack

- `core/` — Rust workspace: all crypto, vault format, storage, sync. The security boundary.
- `server/` — Rust (axum) blind blob + share service. Stores ciphertext only.
- `app/` — Flutter app for all four platforms, talking to core via flutter_rust_bridge.
- Native adapter code lives in `app/ios`, `app/android`, `app/windows`, `app/macos`.

## Golden rules (never break these)

1. Never implement or change cryptography outside `core/dotlock-crypto`. Follow `docs/SPEC.md` exactly.
   If the spec looks wrong or incomplete, **stop** and add a note to `docs/SPEC_QUESTIONS.md` instead of
   changing behaviour.
2. Never log, print, persist in plaintext, or send keys, patterns, phrases, file names or file contents.
   No analytics or crash-reporting SDKs.
3. All secret material uses `zeroize` / `secrecy` types. No `unsafe` in core without a comment and a test.
4. Never weaken, edit or delete a frozen test vector. A new format version adds new vectors.
5. The app must work fully offline. Network code lives only in `core/dotlock-sync`.
6. Dart/Flutter never sees raw keys. It calls core through opaque handles from `core/dotlock-ffi`.
7. Never write decrypted file contents to persistent storage. Viewers stream from core; any temp file
   must live in a wiped app-private temp dir and be deleted on lock.
8. A wrong pattern must open an empty vault indistinguishable from a real one (no error, same KDF cost).

## Workflow for every task

1. Open `docs/TASKS.md`, take the **first unchecked task** unless told otherwise. Read the SPEC sections it cites.
2. Plan briefly, then write tests first.
3. Implement the smallest change that passes.
4. Run the checks below; all must pass.
5. Update docs and `CHANGELOG.md`, tick the task in `docs/TASKS.md`, and commit with message `T<n>: <title>`.
6. Keep each task under ~600 changed lines. If it's bigger, split it and note the split in TASKS.md.

## Commands

```bash
# Rust core + server
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Flutter app
cd app
flutter analyze
flutter test
flutter test integration_test   # when a device/emulator is available

# Regenerate FFI bindings after changing core/dotlock-ffi
flutter_rust_bridge_codegen generate
```

## Conventions

- Rust 2021, `thiserror` for errors, no panics across FFI (return `Result`).
- Flutter: Riverpod for state, go_router for navigation, `intl`/ARB for every user-facing string.
- Platform features go behind a Dart interface in `app/lib/platform/` with a fake implementation for tests.
- Generated code (`app/lib/core_bridge/`) is never hand-edited.
- Bundle / package id: `app.dotlock.vault` (confirm before first store upload).
