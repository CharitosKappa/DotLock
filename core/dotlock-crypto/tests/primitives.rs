use dotlock_crypto::{
    derive_credential_key, derive_subkey, open, seal, Argon2Params, Key, Label, SecretBytes,
};
use static_assertions::assert_not_impl_any;
use zeroize::Zeroizing;

assert_not_impl_any!(SecretBytes: std::fmt::Debug, std::fmt::Display, Clone, Copy);
assert_not_impl_any!(Key: std::fmt::Debug, std::fmt::Display, Clone, Copy);

fn key(byte: u8) -> Key {
    Key::from_bytes(Zeroizing::new([byte; 32]))
}

#[test]
fn patched_hkdf_preserves_rfc5869_case_one() {
    let mut output = Zeroizing::new([0; 42]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&(0u8..13).collect::<Vec<_>>()), &[0x0b; 22])
        .expand(&(0xf0u8..=0xf9).collect::<Vec<_>>(), output.as_mut())
        .unwrap();
    let expected = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    assert!(output.as_ref() == expected);
}

#[test]
fn argon2_parameters_enforce_spec_minimums() {
    let defaults = Argon2Params::default();
    assert_eq!((defaults.m_kib, defaults.t, defaults.p), (65536, 3, 1));
    for (m, t, p) in [(19455, 2, 1), (19456, 1, 1), (19456, 2, 0)] {
        assert!(Argon2Params::new(m, t, p).is_err());
    }
    assert!(Argon2Params::new(19456, 2, 1).is_ok());
    // Public header fields must be revalidated at the derivation boundary.
    let weak = Argon2Params {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert!(derive_credential_key(
        &SecretBytes::from_bytes(Zeroizing::new(vec![1])),
        &[2; 32],
        weak
    )
    .is_err());
}

#[test]
fn credential_key_matches_argon2id_v13() {
    let credential = SecretBytes::from_bytes(Zeroizing::new(b"test credential".to_vec()));
    let salt = [3; 32];
    let params = Argon2Params::new(19456, 2, 1).unwrap();
    let actual = derive_credential_key(&credential, &salt, params).unwrap();
    let mut expected = Zeroizing::new([0; 32]);
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19456, 2, 1, Some(32)).unwrap(),
    )
    .hash_password_into(credential.as_slice(), &salt, expected.as_mut())
    .unwrap();
    assert!(actual.expose() == expected.as_ref());
}

#[test]
fn hkdf_uses_exact_spec_labels_and_object_salt() {
    let root = key(4);
    let labels = [
        (Label::Vault, "dotlock/vault/v1"),
        (Label::Locator, "dotlock/locator/v1"),
        (Label::Index, "dotlock/index/v1"),
        (Label::Thumb, "dotlock/thumb/v1"),
        (Label::File, "dotlock/file/v1"),
        (Label::Recovery, "dotlock/recovery/v1"),
        (Label::RecoveryWrap, "dotlock/recovery-wrap/v1"),
        (Label::Bucket, "dotlock/bucket/v1"),
        (Label::BucketAuth, "dotlock/bucket-auth/v1"),
        (Label::Sync, "dotlock/sync/v1"),
    ];
    for (label, text) in labels {
        assert_eq!(label.as_bytes(), text.as_bytes());
        let actual = derive_subkey(root.expose(), Some(&[5; 16]), label).unwrap();
        let mut expected = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&[5; 16]), root.expose())
            .expand(text.as_bytes(), expected.as_mut())
            .unwrap();
        assert!(actual.expose() == expected.as_ref());
    }
    let a = derive_subkey(root.expose(), None, Label::Vault).unwrap();
    let b = derive_subkey(root.expose(), None, Label::Locator).unwrap();
    let c = derive_subkey(root.expose(), Some(&[0; 16]), Label::File).unwrap();
    let d = derive_subkey(root.expose(), Some(&[1; 16]), Label::File).unwrap();
    assert!(a.expose() != b.expose());
    assert!(c.expose() != d.expose());
}

#[test]
fn aead_authenticates_key_aad_nonce_and_ciphertext() {
    let k = key(6);
    let plaintext = SecretBytes::from_bytes(Zeroizing::new(b"test content".to_vec()));
    let sealed = seal(&k, &plaintext, b"context").unwrap();
    assert!(open(&k, &sealed, b"context").unwrap().as_slice() == plaintext.as_slice());
    assert!(open(&key(7), &sealed, b"context").is_err());
    assert!(open(&k, &sealed, b"wrong").is_err());
    let mut changed = sealed.clone();
    changed.nonce[0] ^= 1;
    assert!(open(&k, &changed, b"context").is_err());
    for i in 0..sealed.ciphertext.len() {
        let mut changed = sealed.clone();
        changed.ciphertext[i] ^= 1;
        assert!(open(&k, &changed, b"context").is_err());
    }
    let mut truncated = sealed.clone();
    truncated.ciphertext.truncate(15);
    assert!(open(&k, &truncated, b"context").is_err());
    let other = seal(&k, &plaintext, b"context").unwrap();
    assert_ne!(sealed.nonce, other.nonce);
}

proptest::proptest! {
    #[test]
    fn aead_roundtrip(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
                      aad in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
        let data = SecretBytes::from_bytes(Zeroizing::new(data));
        let k = key(8);
        let sealed = seal(&k, &data, &aad).unwrap();
        let opened = open(&k, &sealed, &aad).unwrap();
        proptest::prop_assert!(opened.as_slice() == data.as_slice());
    }
}
