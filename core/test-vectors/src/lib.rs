//! Versioned PUBLIC synthetic vectors. No user-supplied secret inputs.
use dotlock_crypto::{
    credentials::{encode_passphrase, Pattern, RecoveryPhrase},
    derive_credential_key, derive_subkey, vector_fixtures, Argon2Params, Key, Label,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{error::Error, io};
use zeroize::Zeroizing;

pub const FILE_NAME: &str = "primitives.json";
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Integrity fingerprint of public fixture bytes, not vault cryptography.
pub fn fingerprint(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn render() -> Result<Vec<u8>> {
    let credential = encode_passphrase("public fixture passphrase")?;
    let params = Argon2Params::default();
    let salt = [1; 32];
    let credential_key = derive_credential_key(&credential, &salt, params)?;
    let master = Key::from_bytes(Zeroizing::new([2; 32]));
    let phrase = RecoveryPhrase::from_entropy(Zeroizing::new([3; 16]));
    let object_id = [4; 16];
    let recovery = derive_subkey(phrase.entropy(), None, Label::Recovery)?;
    let mut hkdf = Vec::new();
    for (label, ikm, salt) in [
        (Label::Vault, &credential_key.expose()[..], None),
        (Label::Locator, &credential_key.expose()[..], None),
        (Label::Index, &master.expose()[..], None),
        (Label::Thumb, &master.expose()[..], Some(&object_id[..])),
        (Label::File, &master.expose()[..], Some(&object_id[..])),
        (Label::Recovery, &phrase.entropy()[..], None),
        (Label::RecoveryWrap, &recovery.expose()[..], None),
        (Label::Bucket, &recovery.expose()[..], None),
        (Label::BucketAuth, &recovery.expose()[..], None),
        (Label::Sync, &master.expose()[..], None),
    ] {
        let output = derive_subkey(ikm, salt, label)?;
        hkdf.push(
            json!({"label": std::str::from_utf8(label.as_bytes())?, "ikm_hex": hex(ikm),
            "salt_hex": salt.map(hex), "expected_key_hex": hex(output.expose())}),
        );
    }
    let aead = vector_fixtures::aead_sample()?;
    let mut streams = Vec::new();
    for (len, ciphertext) in vector_fixtures::stream_samples()? {
        streams.push(json!({"plaintext_length": len, "plaintext_byte_hex": "5a",
            "key_hex": hex(&[7;32]), "nonce_hex": hex(&[11;19]), "aad_hex": hex(vector_fixtures::AAD),
            "ciphertext_length": ciphertext.len(), "expected_ciphertext_sha256": fingerprint(&ciphertext)}));
    }
    let pattern = Pattern::new(&[0, 4, 24])?;
    let passphrase = encode_passphrase("ﬁxture passphrase")?;
    let document = json!({
        "format_version": 1, "scope": "implemented-primitives-only",
        "notice": "PUBLIC synthetic fixtures; never use these keys or nonces for user data",
        "argon2id": {"credential_hex": hex(credential.as_slice()), "salt_hex": hex(&salt),
            "m_kib": params.m_kib, "t": params.t, "p": params.p, "expected_key_hex": hex(credential_key.expose())},
        "hkdf_sha256": hkdf,
        "xchacha20poly1305": {"key_hex": hex(&[7;32]), "nonce_hex": hex(&aead.nonce),
            "aad_hex": hex(vector_fixtures::AAD), "plaintext_hex": hex(vector_fixtures::PLAINTEXT),
            "expected_ciphertext_hex": hex(&aead.ciphertext)},
        "stream_be32": streams,
        "bip39": {"entropy_hex": hex(phrase.entropy()), "expected_words": phrase.words().as_str()},
        "pattern": {"drawn": [0,4,24], "expected_credential_hex": hex(pattern.credential().as_slice())},
        "passphrase": {"input": "ﬁxture passphrase", "expected_credential_hex": hex(passphrase.as_slice())}
    });
    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn verify(frozen: &[u8]) -> Result<()> {
    if render()? != frozen {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frozen fixture mismatch").into());
    }
    Ok(())
}
