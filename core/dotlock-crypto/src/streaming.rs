//! Raw STREAM BE32 bodies, excluding object headers/nonces and Padme padding.
//! Lengths must come from authenticated metadata. Supply a bounded ciphertext
//! reader, and consume to EOF to verify completion. Earlier authenticated chunks
//! may be returned before a later error: discard partial imports on failure.
//! Caller plaintext buffers must be zeroizing; never stream them to disk.

use crate::Key;
use chacha20poly1305::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use std::io::{self, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_SIZE: usize = 16;
type Encryptor = EncryptorBE32<XChaCha20Poly1305>;
type Decryptor = DecryptorBE32<XChaCha20Poly1305>;

enum Cipher {
    Encrypt(Option<Encryptor>),
    Decrypt(Option<Decryptor>),
}

struct Chunks<R> {
    source: R,
    cipher: Cipher,
    remaining: u64,
    aad: Zeroizing<Vec<u8>>,
    buffer: Zeroizing<Vec<u8>>,
    position: usize,
    finished: bool,
    poisoned: bool,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid encrypted stream")
}

impl<R: Read> Chunks<R> {
    fn new(source: R, cipher: Cipher, len: u64, aad: &[u8]) -> io::Result<Self> {
        // BE32 can use counter MAX only for the final chunk.
        let count = len.saturating_sub(1) / CHUNK_SIZE as u64 + 1;
        if count > u32::MAX as u64 + 1 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            source,
            cipher,
            remaining: len,
            aad: Zeroizing::new(aad.to_vec()),
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE + TAG_SIZE)),
            position: 0,
            finished: false,
            poisoned: false,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        let n = self.remaining.min(CHUNK_SIZE as u64) as usize;
        let last = self.remaining <= CHUNK_SIZE as u64;
        let input_len = n + if matches!(self.cipher, Cipher::Decrypt(_)) {
            TAG_SIZE
        } else {
            0
        };
        self.buffer.zeroize();
        self.buffer.resize(input_len, 0);
        self.source.read_exact(&mut self.buffer)?;
        if last {
            // Reject trailing bytes before releasing the final authenticated chunk.
            // Object readers must exclude random padding from this input.
            let mut extra = Zeroizing::new([0]);
            loop {
                match self.source.read(extra.as_mut()) {
                    Ok(0) => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    _ => return Err(invalid()),
                }
            }
        }
        let result = match &mut self.cipher {
            Cipher::Encrypt(state) => {
                if last {
                    state
                        .take()
                        .ok_or_else(invalid)?
                        .encrypt_last_in_place(&self.aad, &mut *self.buffer)
                } else {
                    state
                        .as_mut()
                        .ok_or_else(invalid)?
                        .encrypt_next_in_place(&self.aad, &mut *self.buffer)
                }
            }
            Cipher::Decrypt(state) => {
                if last {
                    state
                        .take()
                        .ok_or_else(invalid)?
                        .decrypt_last_in_place(&self.aad, &mut *self.buffer)
                } else {
                    state
                        .as_mut()
                        .ok_or_else(invalid)?
                        .decrypt_next_in_place(&self.aad, &mut *self.buffer)
                }
            }
        };
        result.map_err(|_| invalid())?;
        self.remaining -= n as u64;
        self.position = 0;
        self.finished = last;
        Ok(())
    }
}

impl<R: Read> Read for Chunks<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.poisoned {
            return Err(invalid());
        }
        if self.position == self.buffer.len() {
            if self.finished {
                return Ok(0);
            }
            if let Err(error) = self.fill() {
                self.poisoned = true;
                self.buffer.zeroize();
                match &mut self.cipher {
                    Cipher::Encrypt(state) => {
                        state.take();
                    }
                    Cipher::Decrypt(state) => {
                        state.take();
                    }
                }
                return Err(error);
            }
        }
        let n = output.len().min(self.buffer.len() - self.position);
        output[..n].copy_from_slice(&self.buffer[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}

/// Ciphertext Read adapter; the public nonce must be stored by the object layer.
pub struct EncryptReader<R> {
    chunks: Chunks<R>,
    nonce: [u8; 19],
}

impl<R: Read> EncryptReader<R> {
    pub fn new(source: R, key: &Key, plaintext_len: u64, aad: &[u8]) -> io::Result<Self> {
        let mut nonce = [0; 19];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| io::Error::other("randomness unavailable"))?;
        let cipher = Cipher::Encrypt(Some(Encryptor::new(key.expose().into(), (&nonce).into())));
        Ok(Self {
            chunks: Chunks::new(source, cipher, plaintext_len, aad)?,
            nonce,
        })
    }

    pub fn nonce(&self) -> [u8; 19] {
        self.nonce
    }
}

impl<R: Read> Read for EncryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.chunks.read(output)
    }
}

/// Authenticated plaintext Read adapter. No unverified chunk is returned.
pub struct DecryptReader<R>(Chunks<R>);

impl<R: Read> DecryptReader<R> {
    pub fn new(
        source: R,
        key: &Key,
        nonce: [u8; 19],
        plaintext_len: u64,
        aad: &[u8],
    ) -> io::Result<Self> {
        let cipher = Cipher::Decrypt(Some(Decryptor::new(key.expose().into(), (&nonce).into())));
        Ok(Self(Chunks::new(source, cipher, plaintext_len, aad)?))
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output)
    }
}

/// Encrypt to any Write sink. On error the caller must discard partial output.
/// Does not flush/fsync/commit the sink; those belong to the storage layer.
pub fn encrypt_to<R: Read, W: Write>(
    source: R,
    sink: &mut W,
    key: &Key,
    plaintext_len: u64,
    aad: &[u8],
) -> io::Result<[u8; 19]> {
    let mut encrypted = EncryptReader::new(source, key, plaintext_len, aad)?;
    io::copy(&mut encrypted, sink)?;
    Ok(encrypted.nonce())
}
