# Symmetric primitives (T2)

Implements SPEC v1 §§2,4 with upstream RustCrypto crates. There is no vault
serialization here yet.

- `Key` and `SecretBytes` own zeroizing storage and have no Debug, Display,
  Clone or Copy implementations. Borrowed byte views must never be logged.
- `Argon2Params` defaults to 65536 KiB, 3 passes, 1 lane; every derivation
  validates the 19456 KiB / 2 pass minimum and upstream parameter constraints.
  Credential derivation accepts a 32-byte container salt and returns 32 bytes.
  The memory-hard working buffer is explicitly zeroized on drop.
- `derive_subkey` uses HKDF-SHA256 extract-and-expand with the exact §4 labels.
  Supply an object ID salt for file/thumbnail keys, and None for unsalted
  derivations. Identifier hex encoding/truncation belongs to later format tasks.
- `seal` obtains a fresh 24-byte nonce from the OS. `open` authenticates the
  nonce, ciphertext and supplied AAD before returning opaque plaintext.
  Both success and error paths erase owned plaintext working buffers.

Tests include negative trait assertions, Argon2/HKDF reference comparisons,
AEAD mutation checks and randomized round trips. These are wrapper tests,
not the frozen cross-platform format vectors planned for T5 or a security audit.

## Streaming (T3)

`streaming::EncryptReader` and `DecryptReader` implement Read; `encrypt_to`
targets a Write sink. They use upstream STREAM BE32, 1 MiB plaintext chunks
and a fresh 19-byte nonce. The final chunk carries the last flag; empty content
has one empty authenticated final chunk. No framing bytes or padding are added.

Supply the expected plaintext length from authenticated metadata. Decryption
must receive an input bounded to the ciphertext body, excluding object padding.
Wrong length, trailing bytes, truncation and authentication failures are errors.
Errors poison the reader and erase its buffer/key state. Each returned chunk is
authenticated, but earlier chunks can be returned before a later failure.
Read through EOF to verify completion and discard incomplete imports on error.
Plaintext caller buffers must be zeroizing; never target persistent storage.

Each adapter holds one zeroizing chunk buffer, independent of file size.
The generated 2 GiB round trip is a dedicated release-mode Linux CI check:
`cargo test --release -p dotlock-crypto --test streaming --locked generated_two_gib -- --ignored --exact`.
