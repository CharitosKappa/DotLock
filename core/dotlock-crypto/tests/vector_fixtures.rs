#![cfg(feature = "vector-fixtures")]
use dotlock_crypto::{open, streaming::DecryptReader, vector_fixtures, Key};
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

#[test]
fn fixed_fixtures_open_through_production_apis() {
    let key = Key::from_bytes(Zeroizing::new([7; 32]));
    let sealed = vector_fixtures::aead_sample().unwrap();
    assert_eq!(sealed.nonce, [9; 24]);
    assert!(
        open(&key, &sealed, vector_fixtures::AAD)
            .unwrap()
            .as_slice()
            == vector_fixtures::PLAINTEXT
    );
    for (len, encrypted) in vector_fixtures::stream_samples().unwrap() {
        let mut reader = DecryptReader::new(
            Cursor::new(encrypted),
            &key,
            [11; 19],
            len as u64,
            vector_fixtures::AAD,
        )
        .unwrap();
        let mut plaintext = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext.len(), len);
        assert!(plaintext.iter().all(|b| *b == 0x5a));
    }
}
