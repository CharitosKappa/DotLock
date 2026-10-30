use dotlock_crypto::credentials::{
    encode_passphrase, Pattern, RecoveryPhrase, SecretText, Strength,
};
use static_assertions::assert_not_impl_any;
use zeroize::Zeroizing;

assert_not_impl_any!(Pattern: std::fmt::Debug, std::fmt::Display, Clone, Copy);
assert_not_impl_any!(RecoveryPhrase: std::fmt::Debug, std::fmt::Display, Clone, Copy);
assert_not_impl_any!(SecretText: std::fmt::Debug, std::fmt::Display, Clone, Copy);

#[test]
fn pattern_tables_cover_auto_fill_and_encoding() {
    let cases: &[(&[u8], &[u8])] = &[
        (&[0, 4, 24], &[0, 1, 2, 3, 4, 9, 14, 19, 24]),
        (&[0, 12, 14, 24], &[0, 6, 12, 13, 14, 19, 24]),
        (&[0, 14, 24, 20], &[0, 7, 14, 19, 24, 23, 22, 21, 20]),
        (
            &[0, 12, 4, 20, 24],
            &[0, 6, 12, 8, 4, 16, 20, 21, 22, 23, 24],
        ),
    ];
    for (drawn, expected) in cases {
        let pattern = Pattern::new(drawn).unwrap();
        let encoded = pattern.credential().as_slice();
        assert!(encoded[..2] == [1, 5]);
        assert!(encoded[2..] == **expected);
    }
    for invalid in [
        &[][..],
        &[0, 1, 2, 3, 4],
        &[0, 25],
        &[0, 4, 0],
        &[0, 4, 2],
        &[24, 24],
    ] {
        assert!(Pattern::new(invalid).is_err());
    }
}

#[test]
fn strength_guidance_does_not_change_pattern_validity() {
    assert_eq!(
        Pattern::new(&[0, 4, 9]).unwrap().strength().level,
        Strength::Weak
    );
    assert_eq!(
        Pattern::new(&[0, 4, 24]).unwrap().strength().level,
        Strength::Fair
    );
    assert_eq!(
        Pattern::new(&[0, 2, 12, 10]).unwrap().strength().level,
        Strength::Fair
    );
    let strong = Pattern::new(&[0, 1, 6, 7, 2, 3, 8, 13, 12, 17, 18, 23]).unwrap();
    assert_eq!(strong.strength().level, Strength::Strong);
    assert!(strong.strength().estimated_bits.is_finite());
    assert!(strong.strength().estimated_bits >= 0.0);
}

#[test]
fn passphrases_use_nfkd_without_trimming() {
    for (input, normalized) in [
        ("password", "password"),
        ("ﬁabcdef", "fiabcdef"),
        ("éabcdef", "e\u{301}abcdef"),
        ("가abcdef", "\u{1100}\u{1161}abcdef"),
        ("abcde\u{315}\u{300}\u{5ae}", "abcde\u{5ae}\u{300}\u{315}"),
        ("  abcdef  ", "  abcdef  "),
        ("        ", "        "),
    ] {
        let actual = encode_passphrase(input).unwrap();
        assert_eq!(actual.as_slice()[0], 2);
        assert!(actual.as_slice()[1..] == *normalized.as_bytes());
    }
    for invalid in ["", "1234567", "éabcde"] {
        assert!(encode_passphrase(invalid).is_err());
    }
    let a = encode_passphrase("éabcdef").unwrap();
    let b = encode_passphrase("e\u{301}abcdef").unwrap();
    assert!(a.as_slice() == b.as_slice());
}

#[test]
fn bip39_known_mapping_and_invalid_phrases() {
    let fixture = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let phrase = RecoveryPhrase::from_entropy(Zeroizing::new([0; 16]));
    assert!(phrase.words().as_str() == fixture);
    assert!(RecoveryPhrase::parse(fixture).unwrap().entropy() == &[0; 16]);
    for invalid in ["", "arbitrary user written recovery phrase", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon typo"] {
        assert!(RecoveryPhrase::parse(invalid).is_err());
    }
    let words15 = bip39::Mnemonic::from_entropy(&[0; 20]).unwrap();
    assert!(RecoveryPhrase::parse(&words15.to_string()).is_err());
    let generated = RecoveryPhrase::generate().unwrap();
    let text = generated.words();
    assert_eq!(text.as_str().split_whitespace().count(), 12);
    assert!(RecoveryPhrase::parse(text.as_str()).unwrap().entropy() == generated.entropy());
}

proptest::proptest! {
    #[test]
    fn passphrase_matches_upstream_nfkd(chars in proptest::collection::vec(proptest::prelude::any::<char>(), 0..64)) {
        use unicode_normalization::UnicodeNormalization;
        let input = Zeroizing::new(chars.iter().collect::<String>());
        let expected = Zeroizing::new(input.nfkd().collect::<String>());
        match encode_passphrase(&input) {
            Ok(actual) => {
                proptest::prop_assert!(expected.chars().count() >= 8);
                proptest::prop_assert!(actual.as_slice()[1..] == *expected.as_bytes());
            }
            Err(_) => proptest::prop_assert!(expected.chars().count() < 8),
        }
    }
    #[test]
    fn bip39_roundtrip(entropy in proptest::array::uniform16(proptest::prelude::any::<u8>())) {
        let phrase = RecoveryPhrase::from_entropy(Zeroizing::new(entropy));
        let text = phrase.words();
        let upstream = bip39::Mnemonic::from_entropy(phrase.entropy()).unwrap();
        let expected = Zeroizing::new(upstream.to_string());
        proptest::prop_assert!(text.as_str() == expected.as_str());
        let restored = RecoveryPhrase::parse(text.as_str()).unwrap();
        proptest::prop_assert!(restored.entropy() == phrase.entropy());
    }

    #[test]
    fn canonical_patterns_are_valid_and_idempotent(drawn in proptest::collection::vec(0u8..25, 0..26)) {
        if let Ok(pattern) = Pattern::new(&drawn) {
            let canonical = &pattern.credential().as_slice()[2..];
            let again = Pattern::new(canonical).unwrap();
            proptest::prop_assert!(again.credential().as_slice() == pattern.credential().as_slice());
            proptest::prop_assert!((6..=25).contains(&canonical.len()));
        }
    }
}
