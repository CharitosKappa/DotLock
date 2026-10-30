# Public v1 primitive fixtures (T5a)

All inputs/outputs here are fixed, PUBLIC, synthetic test data. Never use these
keys/nonces with user data. The generator accepts an output directory only,
never keys, credentials, phrases or file contents.

`v1/primitives.json` contains Argon2id with default parameters, all ten §4 HKDF
labels using the stated hierarchy, raw XChaCha20-Poly1305, credential encoding,
BIP-39 mapping, and raw BE32 streams (empty, small and multiple chunks).
STREAM fixtures specify a repeated plaintext byte and exact length, with the
complete ciphertext's SHA-256 digest and length as expected output. Small AEAD
ciphertext is stored in full. No slot, object, index or cloud-auth format is implied.

From the repository root, check without writing:

```sh
cargo run -p dotlock-test-vectors --bin generate-vectors --locked -- --check
```

For first creation into an empty directory only:

```sh
cargo run -p dotlock-test-vectors --bin generate-vectors --locked -- --init OUTPUT_DIRECTORY
```

`--init` uses exclusive file creation and refuses any existing fixture. There is
no overwrite/force option. `--check` compares generated JSON bytes exactly, including
the final LF. Git attributes enforce LF on every OS. Tests also pin the original
file's SHA-256 independently of generator code and exercise the CLI on temporary
copies, including mismatches and overwrite refusal.

Frozen files become immutable when merged. Never edit them or update the pinned
fingerprint to accommodate changed output. Fix a regression, or introduce a new
format version. Add future T5b coverage as new files without rewriting this one.
The test-only core feature accepts no caller-supplied nonce/key/plaintext and
reuses private production encryption paths; normal APIs always use OS nonces.
