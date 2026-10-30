//! Crypto and credentials for SPEC v1 §§2,3,4,6. No vault serialization.
//! Borrowed secrets must be kept in caller-owned zeroizing storage.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub mod credentials;
pub mod streaming;
#[cfg(feature = "vector-fixtures")]
pub mod vector_fixtures;

/// A 32-byte secret, erased on drop. Deliberately has no formatting or cloning.
pub struct Key(Zeroizing<[u8; 32]>);

/// Owned credential or plaintext bytes, erased on drop and never formattable.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Borrow only for cryptographic operations or an authorized content viewer.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Key {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Borrow for cryptographic operations only; never log or persist this view.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid Argon2 parameters")]
    InvalidParameters,
    #[error("key derivation failed")]
    Derivation,
    #[error("randomness unavailable")]
    Randomness,
    #[error("authenticated encryption failed")]
    Authentication,
    #[error("memory allocation failed")]
    Allocation,
}

/// Header parameters, revalidated whenever used, including after deserialization.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

impl Argon2Params {
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self, CryptoError> {
        let params = Self { m_kib, t, p };
        params.validated()?;
        Ok(params)
    }

    fn validated(self) -> Result<Params, CryptoError> {
        if self.m_kib < 19 * 1024 || self.t < 2 {
            return Err(CryptoError::InvalidParameters);
        }
        Params::new(self.m_kib, self.t, self.p, Some(32))
            .map_err(|_| CryptoError::InvalidParameters)
    }
}

pub fn derive_credential_key(
    credential: &SecretBytes,
    salt: &[u8; 32],
    params: Argon2Params,
) -> Result<Key, CryptoError> {
    let params = params.validated()?;
    // The upstream allocating helper doesn't erase its memory-hard workspace.
    // Own and erase the workspace explicitly, including on failure.
    let mut blocks = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| CryptoError::Allocation)?;
    blocks.resize(params.block_count(), argon2::Block::default());
    let mut output = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            credential.as_slice(),
            salt,
            output.as_mut(),
            blocks.as_mut_slice(),
        )
        .map_err(|_| CryptoError::Derivation)?;
    Ok(Key(output))
}

/// Fixed domain separation labels from SPEC §4.
#[derive(Clone, Copy)]
pub enum Label {
    Vault,
    Locator,
    Index,
    Thumb,
    File,
    Recovery,
    RecoveryWrap,
    Bucket,
    BucketAuth,
    Sync,
}

impl Label {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Vault => b"dotlock/vault/v1",
            Self::Locator => b"dotlock/locator/v1",
            Self::Index => b"dotlock/index/v1",
            Self::Thumb => b"dotlock/thumb/v1",
            Self::File => b"dotlock/file/v1",
            Self::Recovery => b"dotlock/recovery/v1",
            Self::RecoveryWrap => b"dotlock/recovery-wrap/v1",
            Self::Bucket => b"dotlock/bucket/v1",
            Self::BucketAuth => b"dotlock/bucket-auth/v1",
            Self::Sync => b"dotlock/sync/v1",
        }
    }
}

/// HKDF-SHA256 extract-and-expand, including when the optional salt is absent.
/// IKM is borrowed to also support 16-byte recovery entropy in later tasks.
pub fn derive_subkey(ikm: &[u8], salt: Option<&[u8]>, label: Label) -> Result<Key, CryptoError> {
    let mut output = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
        .expand(label.as_bytes(), output.as_mut())
        .map_err(|_| CryptoError::Derivation)?;
    Ok(Key(output))
}

/// Ciphertext with its public nonce; serialization belongs to dotlock-format.
#[derive(Clone)]
pub struct Sealed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seal a small object with a fresh OS-generated nonce and caller-provided AAD.
pub fn seal(key: &Key, plaintext: &SecretBytes, aad: &[u8]) -> Result<Sealed, CryptoError> {
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::Randomness)?;
    seal_with_nonce(key, plaintext, aad, nonce)
}

fn seal_with_nonce(
    key: &Key,
    plaintext: &SecretBytes,
    aad: &[u8],
    nonce: [u8; 24],
) -> Result<Sealed, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut buffer = Zeroizing::new(plaintext.as_slice().to_vec());
    cipher
        .encrypt_in_place(XNonce::from_slice(&nonce), aad, &mut *buffer)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(Sealed {
        nonce,
        ciphertext: buffer.to_vec(),
    })
}

/// Returns plaintext only after successful authentication; failures erase buffers.
pub fn open(key: &Key, sealed: &Sealed, aad: &[u8]) -> Result<SecretBytes, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut buffer = Zeroizing::new(sealed.ciphertext.clone());
    cipher
        .decrypt_in_place(XNonce::from_slice(&sealed.nonce), aad, &mut *buffer)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(SecretBytes(buffer))
}
