# DotLock Crypto and Vault Format Spec — v1

**Status: normative.** Code must match this document exactly. Any change needs a spec PR first.
Open questions go in `docs/SPEC_QUESTIONS.md`.

Section numbers (§) are referenced from `docs/TASKS.md`.

## §1 Design goals

1. Every byte of user content and metadata on disk or in the cloud is authenticated ciphertext.
2. A credential (pattern or passphrase) unlocks a vault on this device; a 12-word recovery phrase alone
   restores a vault on any device.
3. The number of vaults on a device is not observable from the file system.
4. A wrong credential is indistinguishable from an empty vault through the UI.
5. Servers learn nothing but ciphertext sizes, timing and bucket identifiers.

## §2 Primitives

All implemented in Rust (`core/dotlock-crypto`). No platform crypto is used for vault data.

| Purpose | Primitive | Rust crate |
| --- | --- | --- |
| Credential stretching | Argon2id v1.3; default m = 64 MiB, t = 3, p = 1 | `argon2` |
| Subkey derivation | HKDF-SHA256 with fixed ASCII `info` labels (§4) | `hkdf`, `sha2` |
| Small objects (slots, index, headers, wraps) | XChaCha20-Poly1305, random 24-byte nonce | `chacha20poly1305` |
| File content | XChaCha20-Poly1305 STREAM (BE32), 1 MiB plaintext chunks, last-chunk flag | `chacha20poly1305::aead::stream` |
| Recovery / share phrase | BIP-39 English wordlist, 12 words (128-bit entropy) | `bip39` |
| Randomness | OS CSPRNG | `rand_core::OsRng` / `getrandom` |
| Key hygiene | Zero on drop; secrets never `Debug`/`Display` | `zeroize`, `secrecy` |
| Structured encoding | CBOR with explicit version fields | `ciborium` |
| Request auth (cloud) | HMAC-SHA256 | `hmac` |
| Size padding | Padmé | own impl, tested |

Argon2 parameters are stored in the container header so they can be raised later without a format break.
Minimum accepted on read: m ≥ 19 MiB, t ≥ 2. Reject weaker headers.

## §3 Credentials

**Pattern.** 5×5 grid, dots indexed 0–24 row-major (0 = top-left, 24 = bottom-right).

- Valid pattern: ≥ 6 distinct dots, each dot used at most once, ≥ 1 direction change.
- Passing over an unvisited dot that lies exactly on the straight segment between two chosen dots
  auto-adds it (Android-style). This is a UI rule; the serialized sequence includes the auto-added dot.
- Encoding: `credential_bytes = 0x01 || 0x05 || dot_1 || dot_2 || … || dot_n` (one byte per dot).

**Passphrase.** `credential_bytes = 0x02 || UTF-8(NFKD(passphrase))`. Minimum 8 characters after
normalization. No trimming beyond NFKD.

**Strength meter (UI only, not enforced by format).** Estimate bits ≈ log2 of patterns of the same length
on a 5×5 grid, minus penalties for common shapes (straight lines, L, Z, perimeter, letters). Show weak /
fair / strong. Default minimum to proceed: "fair" (≥ 8 dots or ≥ 2 turns), user can override with a warning.

## §4 Key hierarchy

```text
container_salt   = 32 random bytes, one per container (per install), in header (not secret)

credential_key   = Argon2id(password = credential_bytes, salt = container_salt, params from header) → 32 B
vault_key        = HKDF(ikm = credential_key, salt = ∅, info = "dotlock/vault/v1")    → 32 B
locator          = hex(HKDF(ikm = credential_key, salt = ∅, info = "dotlock/locator/v1")[0..16])

master_key       = 32 random bytes per vault. Never changes. Changing a credential only rewraps it.
index_key        = HKDF(ikm = master_key, info = "dotlock/index/v1")
thumb_key(obj)   = HKDF(ikm = master_key, salt = object_id, info = "dotlock/thumb/v1")
file_key(obj)    = HKDF(ikm = master_key, salt = object_id, info = "dotlock/file/v1")

phrase_entropy   = 16 random bytes → BIP-39 12 words (shown once at vault creation)
recovery_root    = HKDF(ikm = phrase_entropy, info = "dotlock/recovery/v1")
recovery_wrap_key= HKDF(ikm = recovery_root, info = "dotlock/recovery-wrap/v1")
bucket_id        = hex(HKDF(ikm = recovery_root, info = "dotlock/bucket/v1")[0..16])
bucket_token     = HKDF(ikm = recovery_root, info = "dotlock/bucket-auth/v1")
sync_key         = HKDF(ikm = master_key, info = "dotlock/sync/v1")
```

The phrase has 128 bits of entropy, so it needs no slow KDF. It alone locates the cloud bucket and
unwraps the master key, so restore works on any device without the original container salt.

In v1, recovery phrases are generated from 16 bytes of OS CSPRNG entropy and encoded
as 12 English BIP-39 words. Restore accepts a valid 12-word English BIP-39 phrase
with its checksum verified and recovers the original 16-byte entropy directly;
do not derive a BIP-39 seed or apply an additional passphrase/KDF to this entropy.
User-written custom recovery phrases and their strength-estimation/KDF path are
deferred beyond v1. Pattern and passphrase credentials in §3 remain supported.

## §5 Container layout (local, per install)

```text
<app-private-dir>/dotlock/
  header.bin
  slots/<name>.slot          exactly 16 files, all the same size (SLOT_SIZE)
  objects/<aa>/<object_id>.obj
  tmp/                       wiped on every lock and app start
```

**header.bin** (CBOR): `{ magic: "DLCK", version: 1, salt: bytes32, argon2: {m_kib, t, p}, slot_size }`.
Not encrypted; contains nothing secret.

**Slots.** On container creation write 16 slot files with random names (`hex(16 random bytes)`) and
random content of exactly `SLOT_SIZE` bytes. A used slot's file name is its vault's `locator`. Unused slots
keep random names and random content. When a vault is created, one random unused slot file is
**replaced** (renamed to the locator and overwritten), so the count never changes. If all 16 are used,
creation fails with `VaultLimitReached`.

`SLOT_SIZE` = 64 KiB in v1. Slot content:

```text
slot = version(1 B = 0x01) || nonce(24) || AEAD(vault_key, plaintext = wrap_record, aad = "dotlock/slot/v1")
       || index_pointer || random padding to SLOT_SIZE
wrap_record (CBOR) = { master_key: bytes32, vault_id: bytes16, index_object_id: bytes16, created: u64 }
```

The index itself is stored as a normal object (§6) encrypted under `index_key`, so it can grow without
changing slot size. `index_pointer` is not needed outside the AEAD; padding is random bytes.

**Recovery records** live inside the container at `objects/` as ordinary objects, plus a per-vault
`recovery_wrap = AEAD(recovery_wrap_key, master_key || vault_id, aad = "dotlock/recovery/v1")` stored in
the cloud bucket (§9) and, when backup is off, in the slot plaintext so local phrase recovery still works.

## §6 Objects

Every file, thumbnail and the index are objects. `object_id` = 16 random bytes. Path:
`objects/<first 2 hex chars>/<hex object_id>.obj`.

```text
obj = magic("DLOB") || version(0x01) || kind(1 B: 0 index, 1 file, 2 thumb)
      || header_nonce(24) || header_len(u32 BE) || AEAD(key, header_cbor, aad = object_id || kind)
      || stream_nonce(19) || STREAM chunks...
      || random padding to Padmé(total_len)
header_cbor (file) = { name, mime, size_plain, created, modified, chunk_count, width?, height?, duration_ms? }
```

- Key: `index_key` for the index, `file_key(obj)` for files, `thumb_key(obj)` for thumbnails.
- STREAM: 1 MiB plaintext chunks, BE32 counter, last-chunk flag; any truncation, reorder or bit flip
  must fail decryption.
- Padmé padding is applied to the whole object file.
- Thumbnails: JPEG/WebP, max 512 px long edge, generated in core from the decoded image, never by the OS
  thumbnail cache.

**Index** (CBOR, versioned):
`{ version: 1, folders: [{id, parent_id?, name, sort}], files: [{object_id, thumb_id?, folder_id?, name, mime, size, created, imported_at, tags?}], settings: {...}, duress: bool }`.

All index writes are atomic: write new object, fsync, update the slot's `index_object_id`, fsync, then delete
the old index object.

## §7 Unlock

1. Read header; run Argon2id **once** for every attempt (no shortcut on failure).
2. Derive `locator`. If a slot file with that name exists, AEAD-open it with `vault_key`.
3. On success: open index, return a session handle.
4. On any failure (no slot, AEAD error): return a session handle to an **ephemeral empty vault** that behaves
   like a real one in the UI. Adding a file to it creates a real vault with that credential (if a slot is free).
5. Lock: drop session, zeroize keys, clear decoded caches, wipe `tmp/`.

No lockout counter is stored (it would leak attempts). Argon2 cost is the rate limit.

## §8 Duress

One vault may be flagged `duress: true` (in its index; Pro feature). When that vault is unlocked:

1. Open it normally and return its session to the UI immediately.
2. In the background, for every other slot whose name ≠ this locator: overwrite with fresh random bytes of
   `SLOT_SIZE` and rename to a random name. Slot count and sizes stay identical.
3. Delete objects not referenced by the duress vault's index (crypto-shred: without the slot, the master key
   is gone, so deletion is defense in depth).
4. Pause sync and mark the device "isolated" so local deletions never propagate to the cloud.
5. Rotate the duress vault's recovery phrase is **not** done automatically (avoid visible prompts); clear the
   duress flag.

Other vaults remain restorable from cloud backup with their own recovery phrase.

## §9 Blind cloud API (no accounts)

Base: `https://api.dotlock.app/v1` (placeholder).

| Method | Path | Body | Notes |
| --- | --- | --- | --- |
| PUT | `/b/{bucket_id}/{object_id}` | ciphertext | Create/replace |
| GET | `/b/{bucket_id}/{object_id}` | — | Fetch |
| DELETE | `/b/{bucket_id}/{object_id}` | — | Delete |
| GET | `/b/{bucket_id}?cursor=` | — | List object ids + sizes + etags |
| POST | `/b/{bucket_id}/init` | `{ token_verifier }` | First write registers `SHA256(bucket_token)` |
| POST | `/s` | `{ policy }` | Create share bucket, returns share id |
| POST | `/s/{share_id}/claim` | `{ claim_proof }` | One-time claim |
| DELETE | `/s/{share_id}` | — | Revoke (owner) |

Auth: header `X-DL-Auth: HMAC-SHA256(bucket_token, method || path || sha256(body) || timestamp)` plus
`X-DL-Time`. Server stores only `SHA256(bucket_token)` and rejects skew > 5 min.

Quota: an anonymous entitlement token (issued after store receipt validation, **not linked** to any bucket)
is sent as `X-DL-Entitlement`; free tier has a small quota.

Server must not log IPs beyond in-memory rate limiting, must not log bodies, and stores ciphertext in object
storage (R2/S3) under `bucket_id/object_id`.

Cloud objects: the same `.obj` bytes as local (§6), plus per vault one `recovery.obj` holding
`recovery_wrap` and the current `index_object_id`.

## §10 Sync

- Last-writer-wins per index record (file or folder) using a Lamport clock stored in the index.
- Conflicting renames produce a "conflict copy" entry.
- Objects are immutable; edits create new objects.
- Uploads are resumable (chunked PUTs of ≤ 8 MiB parts, server-side multipart).

## §11 Sharing (Pro to create, free to open)

1. Owner chooses files/folder snapshot and policy `{ expires_at, max_opens, allow_export: bool }`.
2. Generate `share_entropy` (16 B) → 12-word share phrase. `share_root = HKDF(share_entropy, "dotlock/share/v1")`.
3. Re-encrypt the snapshot's objects under keys derived from `share_root` (same object format) and upload
   to a new share bucket; register policy server-side.
4. Recipient enters phrase → `claim_proof = HMAC(share_root, "claim")` → server marks claimed (once),
   returns a per-recipient read token.
5. Server deletes the share bucket at `expires_at` or on revoke. `max_opens` and `allow_export` are enforced
   client-side (stated honestly in UI copy). Owner pushes updates by re-uploading changed objects.

## §12 Test vectors

`core/test-vectors/v1/*.json` contain fixed inputs (credential bytes, salt, Argon2 params, entropy,
object ids, plaintexts, nonces) and expected outputs for: Argon2id, every HKDF label in §4, slot seal,
object seal (small and multi-chunk), index CBOR, BIP-39 mapping, cloud auth header. Vectors are frozen once
merged; v2 adds a new folder.
