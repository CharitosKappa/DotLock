# DotLock

Cross-platform encrypted photo and file vault for iOS, Android, Windows and macOS.
Development has just started: the repository contains scaffolding, not a usable vault.

Read [AGENTS.md](AGENTS.md) and [the ordered tasks](docs/TASKS.md) before contributing.
The [vault specification](docs/SPEC.md) is normative.

## Development

Install Rust stable with rustfmt and Clippy, Flutter stable, and Git.
For native builds, install Visual Studio's Desktop development with C++ workload
and Windows SDK on Windows, Xcode on macOS (required for iOS/macOS), and the
Android SDK for Android. Rust milestones M1/M2 do not require a mobile emulator.

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

From `app/`:

```sh
flutter pub get
flutter analyze
flutter test
```

The Rust workspace has six core crates (including test-vector support) and the
server binary. Symmetric primitives, streaming adapters, pattern/passphrase
credentials and BIP-39 recovery are implemented in `dotlock-crypto` (T2–T4);
there are no vault operations yet. Frozen vectors start at T5 and the HTTP
service implementation starts at T24.
CI runs Rust checks on Linux, macOS and Windows, plus Flutter checks on Linux.

## Local tool locations (initial Windows setup)

Rust was installed in `%USERPROFILE%\.cargo\bin` and Flutter in
`%USERPROFILE%\.codex\tools\flutter\bin`, without changing the persistent PATH.
Add these locations to your terminal PATH to use `cargo` and `flutter`.
This machine's MSVC installation contains the OneCore runtime libraries but lacks
the default `lib/x64/msvcrt.lib`. Local Rust scaffold tests were run with the
OneCore x64 library directory added to the process-local `LIB` variable. Install
or repair the desktop C++ workload before native Windows app builds.
