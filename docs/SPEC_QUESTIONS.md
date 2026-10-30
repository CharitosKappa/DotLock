# Spec questions

When the spec looks wrong, ambiguous or incomplete, add an entry here instead of changing behaviour.

Format: `## Qn — <short title>` · task · SPEC section · question · proposed answer.

## Q1 — Custom recovery phrase acceptance policy

Task: T4. SPEC: §4. Status: resolved by user approval on 2026-10-30.

The original spec required an estimate of at least 100 bits before accepting a user-written
recovery phrase, but defined no estimator, dictionaries, version, or scoring rules.
Different choices accept different secrets. String length or character variety
alone must not be treated as proof of 100 bits of entropy; stretching a weak
phrase does not supply missing entropy.

Approved answer: defer user-written recovery phrases from v1. T4 generates,
parses and validates English 12-word BIP-39 phrases backed by 16 bytes of OS entropy.
Pattern/passphrase credentials remain available. SPEC §4 and TASKS T4 now reflect
the approved scope. No custom-phrase strength estimator or KDF is implemented.

Alternative: retain custom phrases and specify a concrete estimator/version,
normalization, threshold calculation and acceptance/rejection fixtures in a spec
PR before implementing that path. Estimated guessing cost must not be presented
as guaranteed entropy.

## Q2 — Custom phrase Argon2 output length

Task: T4. SPEC: §4. Status: deferred beyond v1 by the approved Q1 decision.

Generated `phrase_entropy` is explicitly 16 bytes. The custom phrase Argon2id
formula fixed salt, memory, passes and lanes, but omitted the output length.
Argon2 with a 16-byte output is not equivalent to truncating its 32-byte output;
this choice affects every derived recovery key and future restore compatibility.

Proposed answer if this path is retained: specify a direct 16-byte Argon2id v1.3
output, matching the defined entropy width, with no truncation. Also settle Q1
before implementing it. Under the recommended deferral, this remains a future
format decision and no derivation is implemented now.

## Q3 — Cloud request verification cannot use only a token hash

Task: T5, later T24. SPEC: §§9,12. Status: open; cloud-auth vectors not frozen.

Clients compute HMAC using bucket_token, while the server stores only
SHA256(bucket_token). A server cannot verify that HMAC from the hash alone.
The exact timestamp/body/path encoding is also not specified. A frozen vector
must not endorse a protocol the server cannot implement.

Proposal: defer cloud-auth vectors until a separate spec PR defines a verifiable
authentication protocol and unambiguous request canonicalization. Do not silently
store the token, substitute its hash as the HMAC key, or invent a signature scheme.

## Q4 — Slot framing exposes used slots and lacks an AEAD boundary

Task: T5, later T6/T7. SPEC: §§1,5,12. Status: open; slot vectors not frozen.

Used slots start with a public 0x01 byte; unused slots are random. Counting that
marker distinguishes used slots with high confidence, contrary to the vault-count
hiding goal. The layout also has variable ciphertext followed by untyped
index_pointer/padding, without a ciphertext length or another decryptable boundary.

Proposal for a separate spec PR: use the container header's version and make every
slot exactly a 24-byte nonce plus fixed-size AEAD ciphertext/tag. Pad the plaintext
wrap record inside AEAD; its CBOR decoder consumes one record and ignores only
authenticated padding. Keep index_object_id inside that record and remove the
external index_pointer. Unused slots remain uniformly random bytes of SLOT_SIZE.
This proposal is not implemented or adopted by these vector changes.

## Q5 — Deterministic serialization and format implementation order

Task: T5, later T6–T9. SPEC: §§5,6,10,12. Status: open; format vectors not frozen.

§12 asks for slot/object/index outputs before their implementations exist.
CBOR map order/definite lengths and settings/Lamport fields are not fully defined;
freezing serializer defaults now would silently choose permanent format behavior.

Proposal: split T5a (implemented credential/crypto/STREAM/BIP-39 vectors) from
T5b (slot/object/index/auth vectors after their specs and implementations are
settled). Adopt an explicit deterministic CBOR profile in a format spec PR before
freezing serialized fixtures. Keep the parent T5 unchecked until all coverage exists.

User approved the staged task order: T5a first, format vectors with T6–T9 and
auth vectors with T24. This resolves scheduling only; deterministic serialization,
slot format (Q4) and authentication (Q3) still require separate spec decisions.
