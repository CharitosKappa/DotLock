//! PUBLIC synthetic fixtures only. No caller keys, nonces or plaintext accepted.
//! Feature-gated tooling, never a deterministic encryption API for application data.
use crate::{
    seal_with_nonce,
    streaming::{EncryptReader, CHUNK_SIZE},
    CryptoError, Key, Sealed, SecretBytes,
};
use std::io::{self, Cursor, Read};
use zeroize::Zeroizing;

pub const AAD: &[u8] = b"dotlock/public-fixture/v1";
pub const PLAINTEXT: &[u8] = b"public synthetic fixture";

pub fn aead_sample() -> Result<Sealed, CryptoError> {
    let key = Key::from_bytes(Zeroizing::new([7; 32]));
    let plaintext = SecretBytes::from_bytes(Zeroizing::new(PLAINTEXT.to_vec()));
    seal_with_nonce(&key, &plaintext, AAD, [9; 24])
}

pub fn stream_samples() -> io::Result<Vec<(usize, Vec<u8>)>> {
    let key = Key::from_bytes(Zeroizing::new([7; 32]));
    let mut samples = Vec::new();
    for len in [0, 23, CHUNK_SIZE + 3] {
        let plaintext = Zeroizing::new(vec![0x5a; len]);
        let mut reader = EncryptReader::with_nonce(
            Cursor::new(plaintext.as_slice()),
            &key,
            len as u64,
            AAD,
            [11; 19],
        )?;
        let mut ciphertext = Vec::new();
        reader.read_to_end(&mut ciphertext)?;
        samples.push((len, ciphertext));
    }
    Ok(samples)
}
