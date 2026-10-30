# DotLock Task List

Work top to bottom. One task per session/PR. Tick the box when the task is merged.
M1 and M2 are pure Rust and must be green before any UI work starts.

Format: **ID — title** · SPEC refs · Done when.

## M1 — Crypto core (Rust)

- [x] **T1 — Scaffold repo and CI** · — · Cargo workspace with the six crates from `docs/PLAN.md`, empty Flutter app in `app/`, `server/` crate, GitHub Actions running fmt/clippy/test on ubuntu, macos, windows. Done when: CI is green on all three runners.
  - Split: T1a Rust workspace; T1b generated Flutter platform hosts; T1c empty
    app, bootstrap test, docs and CI. SDK-generated hosts are committed separately
    and exceed the approximate 600-line guideline. Keep T1 unchecked until CI
    passes and the task is merged.
- [x] **T2 — Symmetric primitives** · §2, §4 · `dotlock-crypto`: Argon2id wrapper (params struct, minimums enforced), HKDF with label constants, XChaCha20-Poly1305 seal/open with `aad`, zeroizing key newtypes. Done when: round-trip, wrong-key, wrong-aad and tamper tests pass; secrets don't implement `Debug`.
  - Split: T2a dependency manifest/lockfile (generated lockfile exceeds 600 lines);
    T2b primitive APIs, tests and documentation; T2c upstream HKDF source/licenses
    with temporary-buffer erasure patch. Keep unchecked until merged.
- [x] **T3 — Streaming file encryption** · §2, §6 · STREAM BE32, 1 MiB chunks, last-chunk flag, `Read`/`Write` adapters. Done when: truncation, chunk reorder, chunk duplication and bit-flip tests fail closed; a 2 GB stream runs in constant memory (test with a generated reader).
- [x] **T4 — Credentials and phrases** · §3, §4 · Pattern validator + encoder (incl. auto-added in-between dots), passphrase NFKD encoder, 12-word English BIP-39 generate/parse/validate, advisory pattern strength estimator; custom recovery phrases deferred beyond v1. Done when: table-driven tests cover valid/invalid patterns, auto-add cases, NFKD edge cases, bad checksum phrases.
  - Custom recovery phrase deferral approved on 2026-10-30; see SPEC_QUESTIONS Q1/Q2.
    Implementation and tests merged in PR #5 after all CI passed.
- [ ] **T5 — Freeze v1 test vectors** · §12 · Generator binary + JSON vectors + a test that asserts them. Done when: regenerating produces byte-identical files and CI fails if outputs change.

## M2 — Vault format and storage (Rust)

- [ ] **T6 — Container and slots** · §5 · Create container: header + 16 random slots of `SLOT_SIZE`. Done when: a new container always has exactly 16 identical-size slot files; header round-trips; weak Argon2 headers are rejected.
- [ ] **T7 — Create / unlock / empty vault** · §5, §7 · Create vault (claims a slot), unlock, ephemeral empty vault on failure. Done when: wrong credential returns an empty-vault session after one full Argon2 run; no distinguishing error crosses the FFI boundary; 17th vault returns `VaultLimitReached`.
- [ ] **T8 — Index** · §6 · CBOR index with folders, files, settings, Lamport clock; atomic write sequence. Done when: a kill-mid-write test (simulated crash at each step) never yields a corrupt or lost index.
- [ ] **T9 — Object store** · §6 · Add/read/delete/move files, Padmé padding, thumbnail generation in core (`image` crate) for JPEG/PNG/HEIC*/WebP. Done when: CRUD tests pass, sizes match Padmé, thumbnails ≤ 512 px. (*HEIC via platform decode passed in as RGBA if no Rust decoder; note in SPEC_QUESTIONS.)
- [ ] **T10 — Change credential and recover** · §4, §5 · Rewrap master key under a new credential (slot rename + rewrite only); local phrase recovery. Done when: credential change touches only the slot; phrase recovery works on a fresh container with backup off.
- [ ] **T11 — Duress** · §8 · Duress flag + background wipe. Done when: after trigger, other slots are re-randomized and renamed, slot count/sizes unchanged, their objects gone, duress vault fully usable, sync marked isolated.
- [ ] **T12 — FFI surface** · — · `dotlock-ffi` with flutter_rust_bridge: opaque `SessionHandle`, streams for import/export/view, error enum without secret detail. Done when: a Dart integration test creates, fills, locks and reopens a vault on macOS, Windows, Android emulator and iOS simulator.

## M3 — App MVP (Flutter, all four platforms)

- [ ] **T13 — App shell** · — · Theming (light/dark), ARB i18n scaffold, Riverpod, go_router, app-wide lock state. Done when: runs on iOS sim, Android emulator, Windows, macOS.
- [ ] **T14 — Pattern pad** · §3 · 5×5 dot grid widget: drag to draw, auto-add in-between dots, haptics on mobile, mouse/trackpad on desktop, strength meter, passphrase fallback screen. Done when: widget tests cover drawing, auto-add, min rules and accessibility labels; no pattern data in logs.
- [ ] **T15 — Onboarding** · §4 · Create first vault → show 12-word phrase → confirm 3 random words → done. Done when: cannot finish without confirming; screenshot blocked on phrase screen.
- [ ] **T16 — Vault browser** · §6 · Virtualized thumbnail grid, folders, sort, multi-select, rename, move, delete, search by name. Done when: 10,000 items scroll smoothly on a mid-range Android (profile trace attached to PR).
- [ ] **T17 — Viewer** · §6 · Photos (zoom), video (decrypt-stream to player via custom data source; no plaintext temp file unless unavoidable, then in `tmp/`), PDF, generic files. Done when: a test asserts no plaintext is written outside `tmp/` and `tmp/` is empty after lock.
- [ ] **T18 — Import** · — · Platform pickers, share extension (iOS/macOS) and share intent (Android), drag-drop (desktop), progress + cancel, optional delete-originals. Done when: works on each platform; originals deleted only after successful encrypt + verify.
- [ ] **T19 — Export / share-out** · — · Explicit confirmation sheet for every export. Done when: no export path skips confirmation.
- [ ] **T20 — Privacy guards** · PLAN matrix · Auto-lock on background/timeout, app-switcher blur, screenshot/recording blocking per platform. Done when: manual QA checklist in `docs/TESTING.md` passes on all four.

## M4 — Platform extras

- [ ] **T21 — Secure camera** · — · iOS (AVFoundation) and Android (CameraX) capture straight into core. Done when: nothing appears in the system gallery or recent files.
- [ ] **T22 — Optional biometric unlock** · — · Hardware-bound key (Secure Enclave / Keystore / Windows Hello / Touch ID) wraps a copy of `vault_key`; off by default; never offered for a duress vault. Done when: removing or changing enrolled biometrics invalidates the wrap.
- [ ] **T23 — Alternate icons** · — · iOS and Android disguise icons (Pro). Done when: switching works and the pattern screen still opens.

## M5 — Cloud, sync and sharing

- [ ] **T24 — Blind server** · §9 · axum service: bucket init, HMAC auth, object CRUD, list, multipart upload, quotas, rate limits, share endpoints, Dockerfile. Done when: integration tests prove only ciphertext and token hashes are stored and no request body/IP is logged.
- [ ] **T25 — Backup and restore** · §9, §10 · `dotlock-sync` uploads objects + `recovery.obj`, resumable. Done when: back up on Android, restore by phrase only on macOS in an automated test against a local server.
- [ ] **T26 — Multi-device sync** · §10 · LWW with Lamport clocks, conflict copies. Done when: a two-client randomized fuzz test converges to identical indexes.
- [ ] **T27 — Sharing** · §11 · Create, claim once, read-only updates, revoke, server-side expiry. Done when: expired or revoked share bucket is gone server-side and the client shows "share ended".

## M6 — Monetization and release

- [ ] **T28 — Paywall and entitlements** · — · Free caps enforced in core (vault count, item count, backup quota), RevenueCat across StoreKit 2 / Play Billing / Microsoft Store, restore purchases, lifetime cross-platform unlock. Done when: sandbox purchases unlock Pro on each store.
- [ ] **T29 — Localization and accessibility** · — · Top 10 languages, VoiceOver/TalkBack/Narrator pass, dynamic type. Done when: no untranslated strings; accessibility checklist passes.
- [ ] **T30 — Release pipelines** · TESTING.md · Fastlane (iOS/macOS), Gradle AAB (Android), MSIX (Windows), notarized DMG, store metadata and privacy labels. Done when: a tagged release produces signed artifacts for all four platforms.
