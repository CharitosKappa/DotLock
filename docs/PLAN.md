# DotLock — Product and Architecture Plan

## Summary

Build one **Rust core** (crypto, vault format, storage, sync) and one **Flutter UI** for iOS, Android,
Windows and macOS, joined by flutter_rust_bridge. Thin native adapters handle what Flutter can't:
secure key storage, biometrics, camera, screenshot blocking and in-app purchases.

Why this stack:

- **One vault format everywhere.** The core is the security boundary; writing it once in Rust means one
  implementation to test, fuzz and audit, and a vault made on iPhone opens on Windows.
- **One UI codebase.** Flutter is stable on all four targets.
- **Agent-friendly.** Rust and Dart have strong type checkers and fast unit tests: tight feedback loops.
- **Cross-platform backup needs our own blind cloud.** CloudKit only covers Apple. We run a zero-knowledge
  blob store (no accounts, ciphertext only) so a vault backed up on Android restores on a Mac.

Trade-off accepted: Flutter looks slightly less native than SwiftUI/Compose. For a vault app, trust and
correctness beat polish.

## Positioning vs Vaultaire (main competitor, iOS only)

DotLock matches Vaultaire's baseline (real on-device encryption, pattern unlock, hidden vaults, recovery
phrase, duress mode, encrypted backup, sharing, no account, no ads) and wins on:

- All four platforms with cross-platform restore.
- Argon2id instead of PBKDF2; hidden vault **count** (fixed padded slots).
- Phrase-only restore on any device.
- Share expiry and revocation enforced server-side, not just in the client.
- Fully offline by default, no analytics SDK.
- Optional, off-by-default biometric unlock; planned public audit and open-source core.

Build clean-room from public descriptions only. Never copy Vaultaire's code, text, screenshots or branding.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ Flutter app (one codebase: iOS, Android, Windows, macOS)             │
│ unlock · vault grid · viewer · import · share · paywall              │
└───────────────┬───────────────────────────────────┬──────────────────┘
                ▼                                   ▼
┌───────────────────────────────┐   ┌──────────────────────────────────┐
│ dotlock-ffi bridge            │   │ Platform adapters (Dart ifaces)  │
│ opaque session handles only   │   │ keystore, biometrics, camera,    │
└───────────────┬───────────────┘   │ capture block, IAP               │
                ▼                   └────────────────┬─────────────────┘
┌───────────────────────────────┐                    ▼
│ RUST CORE (security boundary) │   ┌──────────────────────────────────┐
│ dotlock-crypto  dotlock-format│   │ Native code per OS               │
│ dotlock-store   dotlock-sync ─┼─┐ │ iOS, Android, Windows, macOS     │
└───────────────┬───────────────┘ │ └──────────────────────────────────┘
                ▼                 │ HTTPS, ciphertext only
┌───────────────────────────────┐ │ ┌──────────────────────────────────┐
│ Local container               │ └▶│ Blind cloud server               │
│ header, 16 padded slots, objs │   │ ciphertext buckets + shares      │
└───────────────────────────────┘   └──────────────────────────────────┘
```

The UI talks to the core only through session handles; the server receives ciphertext and
HMAC-authenticated requests, never keys, names or accounts.

## Platform matrix

| Capability | iOS | Android | Windows | macOS |
| --- | --- | --- | --- | --- |
| Device secret store | Keychain, ThisDeviceOnly | Keystore (StrongBox if present) | DPAPI + Credential Manager | Keychain, ThisDeviceOnly |
| Hardware-bound key (optional unlock) | Secure Enclave + Face/Touch ID | Keystore + BiometricPrompt | TPM via Windows Hello | Secure Enclave + Touch ID |
| Block screenshots / recording | Secure-field layer trick + capture notifications (best effort) | FLAG_SECURE | SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) | NSWindow sharingType = none |
| Hide in app switcher | Blur on resign-active | FLAG_SECURE | Blur on focus loss | Blur on resign-active |
| Import | PHPicker + share extension | Photo picker + share intent | File picker + drag-drop | File picker + drag-drop + share extension |
| Delete originals after import | PHAssetChangeRequest | MediaStore delete request | Optional, user-confirmed | Optional, user-confirmed |
| Secure camera | AVFoundation → core | CameraX → core | Not in v1 | Not in v1 |
| Alternate icon | setAlternateIconName | activity-alias | n/a | Dock icon only |
| Purchases | StoreKit 2 | Play Billing | Microsoft Store | Mac App Store (StoreKit 2) |
| Cloud backup | Our blind store; optional iCloud Drive | Our blind store; optional Drive app folder | Our blind store; optional OneDrive | Our blind store; optional iCloud Drive |
| Distribution | App Store | Play Store (+ signed APK) | Microsoft Store (MSIX) | Mac App Store + notarised DMG |

Use RevenueCat (or a thin own wrapper) so entitlements look identical across stores; a lifetime purchase
on one platform unlocks the others via an anonymous, purchase-linked entitlement ID.

## Repo layout

```
dotlock/
  CLAUDE.md  AGENTS.md  CHANGELOG.md
  docs/PLAN.md  docs/SPEC.md  docs/TASKS.md  docs/TESTING.md  docs/THREAT_MODEL.md
  core/                          Rust workspace
    dotlock-crypto/              KDF, AEAD, STREAM, keys (no I/O)
    dotlock-format/              container, slots, index, objects
    dotlock-store/               filesystem backend, padding, duress
    dotlock-sync/                blind-cloud client, share client
    dotlock-ffi/                 flutter_rust_bridge API surface
    test-vectors/                JSON vectors, frozen per format version
  server/                        Rust axum blind blob + share service
  app/                           Flutter app
    lib/core_bridge/             generated bindings (never hand-edit)
    lib/features/                unlock, vault, viewer, import, settings, share, paywall
    lib/platform/                Dart interfaces for adapters (+ fakes)
    ios/ android/ windows/ macos/
  .github/workflows/
```

## Open decisions (settle before M3)

- [x] App name: **DotLock**.
- [ ] Flutter vs native UIs. Plan assumes Flutter; native UIs on the same core roughly triple UI work.
- [ ] Biometric unlock: plan makes it optional and off by default.
- [ ] Cloud backend host and jurisdiction: EU (fits a Greece-based company and GDPR story) vs US.
- [ ] Pricing. Suggested: free (3 vaults, 200 items, small backup quota); Pro $14.99/year or $39.99 lifetime, all platforms.
- [ ] Open-source the core? Strongest trust signal; also makes cloning easier.
- [ ] Desktop scope for v1: full vault on Windows/macOS, or viewer + importer first?
- [ ] Trademark clearance for "DotLock" (US Classes 9 and 42, EU via TMview) and domain.
