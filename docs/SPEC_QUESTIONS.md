# Spec questions

When the spec looks wrong, ambiguous or incomplete, add an entry here instead of changing behaviour.

Format: `## Qn — <short title>` · task · SPEC section · question · proposed answer.

## Q1 — Custom recovery phrase acceptance policy

Task: T4. SPEC: §4. Status: resolved by user approval on 2026-10-30.

The spec requires an estimate of at least 100 bits before accepting a user-written
recovery phrase, but defines no estimator, dictionaries, version, or scoring rules.
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
formula fixes salt, memory, passes and lanes, but omits the output length.
Argon2 with a 16-byte output is not equivalent to truncating its 32-byte output;
this choice affects every derived recovery key and future restore compatibility.

Proposed answer if this path is retained: specify a direct 16-byte Argon2id v1.3
output, matching the defined entropy width, with no truncation. Also settle Q1
before implementing it. Under the recommended deferral, this remains a future
format decision and no derivation is implemented now.
