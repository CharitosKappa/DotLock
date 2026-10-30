# DotLock Testing, CI and Release

Losing a user's photos is the one unrecoverable failure, so the test budget leans on the core and on
format compatibility.

## Testing

- T5a primitive fixture gate (all Rust runners):
  `cargo run -p dotlock-test-vectors --bin generate-vectors --locked -- --check`.
  Workspace tests compare complete generated JSON bytes and an independent
  frozen-file hash; CLI tests prove mismatch detection and overwrite refusal.
  Fixtures contain PUBLIC synthetic inputs only. STREAM bodies are pinned with
  complete-ciphertext SHA-256 and length; AEAD ciphertext is stored in full.
  See `core/test-vectors/README.md`; T5b format/auth coverage is tracked separately.
- T3 local proof (Windows, optimized build): generated 2 GiB encrypted/decrypted
  pipeline passed in 5.75 s with sampled peak working set 8.07 MiB. The source
  generates bytes and the sink verifies/counts them without storing the stream.
  Each adapter allocates one chunk buffer; this measurement is supporting evidence,
  not a cross-platform memory benchmark. Run the dedicated ignored test in release
  mode as configured in CI. Ordinary workspace tests cover adversarial streams.
- Rust unit + property tests (`proptest`) for every crypto and format function.
- `cargo-fuzz` targets for header, slot, index and object parsers; run nightly.
- Frozen test vectors per format version (`core/test-vectors/`); every release must open every older vector.
- Cross-platform compatibility job: create a vault on each OS runner, upload as artifact, then open all
  of them on every runner.
- Flutter widget tests with fake platform adapters; `integration_test` on emulators and desktop runners.
- Before public launch: external audit of `core/` and `server/` (e.g. Cure53, Trail of Bits, NCC);
  publish the report.

## Manual QA checklist (every release, every platform)

- [ ] Wrong pattern shows an empty vault; no error, similar delay.
- [ ] Screenshot / screen recording blocked or blanked in vault views and on the phrase screen.
- [ ] App-switcher preview is blurred.
- [ ] Auto-lock on background and after timeout; `tmp/` empty after lock.
- [ ] Import from gallery/files/share sheet; delete-originals works and only after success.
- [ ] Video plays without plaintext temp files (or only in `tmp/`, wiped on lock).
- [ ] Duress pattern opens decoy vault; other vaults no longer open; slot count unchanged.
- [ ] Restore by phrase on a fresh install of a *different* platform.
- [ ] Purchase, restore purchase, lifetime unlock on a second platform.
- [ ] Airplane mode: everything except backup/share works.

## CI (GitHub Actions)

| Job | Runner | Gate |
| --- | --- | --- |
| Core fmt + clippy + test + vectors | ubuntu, macos, windows | Every PR |
| Flutter analyze + unit/widget tests | ubuntu | Every PR |
| App integration tests | macos (iOS sim, macOS), ubuntu (Android emulator), windows | Every PR to main |
| Cross-platform vault compatibility | all three | Every PR touching `core/` |
| Server integration tests | ubuntu | Every PR touching `server/` or `dotlock-sync` |
| Fuzzing | ubuntu | Nightly |
| `cargo audit` + `cargo deny` | ubuntu | Every PR |

## Release

| Platform | Build | Ship via |
| --- | --- | --- |
| iOS | Fastlane on macOS runner (or Xcode Cloud) | TestFlight → App Store |
| Android | Gradle AAB, Play App Signing | Internal track → Production |
| macOS | Signed + notarized | Mac App Store and DMG on the website |
| Windows | MSIX | Microsoft Store (winget later) |

Privacy labels: with no analytics SDK, declare no data collected except purchase records handled by the stores.
