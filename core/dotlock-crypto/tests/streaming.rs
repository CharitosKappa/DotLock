use chacha20poly1305::{
    aead::{stream::EncryptorBE32, Payload},
    XChaCha20Poly1305,
};
use dotlock_crypto::{
    streaming::{encrypt_to, DecryptReader, EncryptReader, CHUNK_SIZE},
    Key,
};
use std::io::{self, Cursor, Read, Write};
use zeroize::Zeroizing;

fn key() -> Key {
    Key::from_bytes(Zeroizing::new([17; 32]))
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(16))]
    #[test]
    fn randomized_stream_roundtrip(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
        let data = Zeroizing::new(data);
        let (nonce, encrypted) = encrypted(&data);
        let decoded = decode(nonce, &encrypted, data.len()).unwrap();
        proptest::prop_assert!(decoded.as_slice() == data.as_slice());
    }
}
fn encrypted(data: &[u8]) -> ([u8; 19], Vec<u8>) {
    let mut out = Vec::new();
    let nonce = encrypt_to(
        Cursor::new(data),
        &mut out,
        &key(),
        data.len() as u64,
        b"aad",
    )
    .unwrap();
    (nonce, out)
}
fn decode(nonce: [u8; 19], data: &[u8], len: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut reader = DecryptReader::new(Cursor::new(data), &key(), nonce, len as u64, b"aad")?;
    let mut out = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn boundaries_match_upstream_be32_and_roundtrip() {
    for len in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
    ] {
        let data = Zeroizing::new(vec![91; len]);
        let (nonce, out) = encrypted(&data);
        assert!(decode(nonce, &out, len).unwrap().as_slice() == data.as_slice());
        let mut upstream =
            EncryptorBE32::<XChaCha20Poly1305>::new(key().expose().into(), (&nonce).into());
        let mut expected = Vec::new();
        let chunks = len.saturating_sub(1) / CHUNK_SIZE;
        for i in 0..chunks {
            expected.extend(
                upstream
                    .encrypt_next(Payload {
                        msg: &data[i * CHUNK_SIZE..(i + 1) * CHUNK_SIZE],
                        aad: b"aad",
                    })
                    .unwrap(),
            );
        }
        expected.extend(
            upstream
                .encrypt_last(Payload {
                    msg: &data[chunks * CHUNK_SIZE..],
                    aad: b"aad",
                })
                .unwrap(),
        );
        assert_eq!(out, expected);
    }
}

#[test]
fn rejects_truncation_reordering_duplication_and_bit_flips() {
    let len = 2 * CHUNK_SIZE + 7;
    let (nonce, original) = encrypted(&vec![19; len]);
    let width = CHUNK_SIZE + 16;
    for end in [0, 15, width, width + 3, 2 * width, original.len() - 1] {
        assert!(decode(nonce, &original[..end], len).is_err());
    }
    let mut changed = original.clone();
    changed[..2 * width].rotate_left(width);
    assert!(decode(nonce, &changed, len).is_err());
    changed = original.clone();
    changed[width..2 * width].copy_from_slice(&original[..width]);
    assert!(decode(nonce, &changed, len).is_err());
    changed = original.clone();
    changed.extend_from_slice(&original[..width]);
    assert!(decode(nonce, &changed, len).is_err());
    for offset in [0, CHUNK_SIZE, width + 5, original.len() - 1] {
        changed = original.clone();
        changed[offset] ^= 1;
        assert!(decode(nonce, &changed, len).is_err());
    }
    assert!(decode(nonce, &original, CHUNK_SIZE).is_err());
}

#[test]
fn authentication_failure_is_terminal_and_does_not_fill_output() {
    let (nonce, data) = encrypted(b"synthetic content");
    let mut r = DecryptReader::new(Cursor::new(data), &key(), nonce, 17, b"wrong aad").unwrap();
    let mut output = Zeroizing::new([0xcc; 32]);
    assert_eq!(r.read(&mut []).unwrap(), 0);
    for _ in 0..2 {
        assert!(r.read(output.as_mut()).is_err());
        assert!(output.iter().all(|b| *b == 0xcc));
    }
}

struct ShortReads<R>(R, bool);
impl<R: Read> Read for ShortReads<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.1 = !self.1;
        if self.1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = out.len().min(101);
        self.0.read(&mut out[..n])
    }
}

#[test]
fn handles_short_reads_and_rejects_source_length_mismatch() {
    let source = Zeroizing::new(vec![7; CHUNK_SIZE + 3]);
    let mut r = EncryptReader::new(
        ShortReads(Cursor::new(source.as_slice()), false),
        &key(),
        source.len() as u64,
        b"aad",
    )
    .unwrap();
    let nonce = r.nonce();
    let mut ciphertext = Vec::new();
    r.read_to_end(&mut ciphertext).unwrap();
    let mut d = DecryptReader::new(
        ShortReads(Cursor::new(ciphertext), false),
        &key(),
        nonce,
        source.len() as u64,
        b"aad",
    )
    .unwrap();
    let mut opened = Zeroizing::new(Vec::new());
    d.read_to_end(&mut opened).unwrap();
    assert!(opened.as_slice() == source.as_slice());
    for len in [0, 2, 4] {
        assert!(encrypt_to(Cursor::new(b"abc"), &mut io::sink(), &key(), len, b"").is_err());
    }
    assert!(EncryptReader::new(io::empty(), &key(), u64::MAX, b"").is_err());
}

struct Generated(u64);
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.0.min(out.len() as u64) as usize;
        out[..n].fill(0x73);
        self.0 -= n as u64;
        Ok(n)
    }
}
struct Verified(u64);
impl Write for Verified {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        assert!(data.iter().all(|b| *b == 0x73));
        self.0 += data.len() as u64;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
#[ignore = "2 GiB release-mode streaming/memory proof; dedicated CI step"]
fn generated_two_gib() {
    let len = 2 * 1024 * 1024 * 1024u64;
    let encrypted = EncryptReader::new(Generated(len), &key(), len, b"aad").unwrap();
    let nonce = encrypted.nonce();
    let mut decrypted = DecryptReader::new(encrypted, &key(), nonce, len, b"aad").unwrap();
    let mut sink = Verified(0);
    let mut buffer = Zeroizing::new(vec![0; 32 * 1024]);
    loop {
        let n = decrypted.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        sink.write_all(&buffer[..n]).unwrap();
    }
    assert_eq!(sink.0, len);
}
