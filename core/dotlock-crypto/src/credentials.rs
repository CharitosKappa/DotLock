//! Credential encoding and 128-bit English BIP-39 recovery phrases.
//! Borrowed input must remain caller-owned secret storage. No logs or I/O.
use crate::SecretBytes;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use unicode_normalization::char::{canonical_combining_class, decompose_compatible};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid pattern")]
    Pattern,
    #[error("passphrase is too short")]
    Passphrase,
    #[error("invalid recovery phrase")]
    Phrase,
    #[error("randomness unavailable")]
    Randomness,
}

/// Opaque secret text, explicitly borrowed only for authorized display/input.
pub struct SecretText(Zeroizing<String>);
impl SecretText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical valid pattern, including all unvisited lattice points crossed.
pub struct Pattern(SecretBytes);
fn gcd(mut a: i16, mut b: i16) -> i16 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
fn direction(a: u8, b: u8) -> (i16, i16) {
    let dx = (b % 5) as i16 - (a % 5) as i16;
    let dy = (b / 5) as i16 - (a / 5) as i16;
    let divisor = gcd(dx, dy);
    (dx / divisor, dy / divisor)
}
fn turns(dots: &[u8]) -> usize {
    dots.windows(3)
        .filter(|w| direction(w[0], w[1]) != direction(w[1], w[2]))
        .count()
}
impl Pattern {
    pub fn new(drawn: &[u8]) -> Result<Self, CredentialError> {
        if drawn.is_empty() || drawn.len() > 25 {
            return Err(CredentialError::Pattern);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(27));
        bytes.extend_from_slice(&[1, 5]);
        for &dot in drawn {
            if dot >= 25 || bytes[2..].contains(&dot) {
                return Err(CredentialError::Pattern);
            }
            if bytes.len() > 2 {
                let previous = bytes[bytes.len() - 1];
                let dx = (dot % 5) as i16 - (previous % 5) as i16;
                let dy = (dot / 5) as i16 - (previous / 5) as i16;
                let steps = gcd(dx, dy);
                for step in 1..steps {
                    let x = (previous % 5) as i16 + dx / steps * step;
                    let y = (previous / 5) as i16 + dy / steps * step;
                    let crossed = (y * 5 + x) as u8;
                    if !bytes[2..].contains(&crossed) {
                        bytes.push(crossed);
                    }
                }
            }
            bytes.push(dot);
        }
        if bytes.len() < 8 || turns(&bytes[2..]) == 0 {
            return Err(CredentialError::Pattern);
        }
        Ok(Self(SecretBytes::from_bytes(bytes)))
    }
    pub fn credential(&self) -> &SecretBytes {
        &self.0
    }

    /// Advisory heuristic, not measured entropy or a credential validity rule.
    pub fn strength(&self) -> PatternStrength {
        let dots = &self.0.as_slice()[2..];
        let count = turns(dots);
        let level = if dots.len() >= 12 && count >= 4 {
            Strength::Strong
        } else if dots.len() >= 8 || count >= 2 {
            Strength::Fair
        } else {
            Strength::Weak
        };
        // Upper bound ignores lattice restrictions; penalize simple line/letter
        // shapes (L/Z/U etc.) and perimeter paths. Never use for secret acceptance.
        let base: f64 = (0..dots.len()).map(|n| ((25 - n) as f64).log2()).sum();
        let simple_penalty = match count {
            0..=1 => 16.0,
            2 => 12.0,
            3 => 8.0,
            _ => 0.0,
        };
        let perimeter = dots
            .iter()
            .all(|d| d % 5 == 0 || d % 5 == 4 || d / 5 == 0 || d / 5 == 4);
        PatternStrength {
            level,
            estimated_bits: (base - simple_penalty - if perimeter { 12.0 } else { 0.0 }).max(0.0),
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Strength {
    Weak,
    Fair,
    Strong,
}
pub struct PatternStrength {
    pub level: Strength,
    pub estimated_bits: f64,
}

/// Minimum length counts Unicode scalar values after NFKD; whitespace is retained.
pub fn encode_passphrase(input: &str) -> Result<SecretBytes, CredentialError> {
    let mut count = 0;
    for c in input.chars() {
        decompose_compatible(c, |_| count += 1);
    }
    if count < 8 {
        return Err(CredentialError::Passphrase);
    }
    // Use upstream decomposition tables without its unzeroized iterator buffer.
    let mut normalized = Zeroizing::new(Vec::with_capacity(count));
    for c in input.chars() {
        decompose_compatible(c, |d| normalized.push(d));
    }
    // Canonical ordering is stable by combining class within each nonstarter run.
    // Counting sort avoids hidden sort allocations and quadratic combining runs.
    let mut scratch = Zeroizing::new(vec!['\0'; count]);
    let mut offsets = Zeroizing::new([0usize; 256]);
    let mut begin = 0;
    while begin < count {
        if canonical_combining_class(normalized[begin]) == 0 {
            begin += 1;
            continue;
        }
        let mut end = begin + 1;
        while end < count && canonical_combining_class(normalized[end]) != 0 {
            end += 1;
        }
        offsets.fill(0);
        for &c in &normalized[begin..end] {
            offsets[canonical_combining_class(c) as usize] += 1;
        }
        let mut position = 0;
        for value in offsets.iter_mut() {
            let length = *value;
            *value = position;
            position += length;
        }
        for &c in &normalized[begin..end] {
            let class = canonical_combining_class(c) as usize;
            scratch[offsets[class]] = c;
            offsets[class] += 1;
        }
        normalized[begin..end].copy_from_slice(&scratch[..end - begin]);
        scratch[..end - begin].zeroize();
        begin = end;
    }
    let size: usize = normalized.iter().map(|c| c.len_utf8()).sum();
    let mut bytes = Zeroizing::new(Vec::with_capacity(size + 1));
    bytes.push(2);
    let mut utf8 = Zeroizing::new([0u8; 4]);
    for &c in normalized.iter() {
        bytes.extend_from_slice(c.encode_utf8(utf8.as_mut()).as_bytes());
    }
    Ok(SecretBytes::from_bytes(bytes))
}

/// Recovery entropy is not a BIP-39 seed. No custom phrase or extra KDF path.
pub struct RecoveryPhrase(Zeroizing<[u8; 16]>);
impl RecoveryPhrase {
    pub fn from_entropy(entropy: Zeroizing<[u8; 16]>) -> Self {
        Self(entropy)
    }
    pub fn generate() -> Result<Self, CredentialError> {
        let mut entropy = Zeroizing::new([0; 16]);
        OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|_| CredentialError::Randomness)?;
        Ok(Self(entropy))
    }
    pub fn entropy(&self) -> &[u8; 16] {
        &self.0
    }

    /// Standard 128-bit BIP-39 bit packing with the upstream English wordlist.
    /// Own the bit/checksum buffers here so they are erased rather than relying
    /// on mnemonic-library temporary arrays that do not implement zeroization.
    pub fn words(&self) -> SecretText {
        let mut bits = Zeroizing::new([0u8; 17]);
        bits[..16].copy_from_slice(self.0.as_ref());
        let checksum = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(self.0.as_ref())));
        bits[16] = checksum[0] & 0xf0;
        let list = bip39::Language::English.word_list();
        let mut text = Zeroizing::new(String::with_capacity(12 * 9));
        for word in 0..12 {
            let mut index = Zeroizing::new(0usize);
            for bit in word * 11..(word + 1) * 11 {
                *index = (*index << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1) as usize;
            }
            if word != 0 {
                text.push(' ');
            }
            text.push_str(list[*index]);
        }
        SecretText(text)
    }
    pub fn parse(input: &str) -> Result<Self, CredentialError> {
        if input.split_whitespace().count() != 12 {
            return Err(CredentialError::Phrase);
        }
        let list = bip39::Language::English.word_list();
        let mut bits = Zeroizing::new([0u8; 17]);
        for (position, word) in input.split_whitespace().enumerate() {
            let index = Zeroizing::new(
                list.binary_search(&word)
                    .map_err(|_| CredentialError::Phrase)?,
            );
            for j in 0..11 {
                let bit = position * 11 + j;
                bits[bit / 8] |= (((*index >> (10 - j)) & 1) as u8) << (7 - bit % 8);
            }
        }
        let checksum = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&bits[..16])));
        if bits[16] != checksum[0] & 0xf0 {
            return Err(CredentialError::Phrase);
        }
        let mut entropy = Zeroizing::new([0; 16]);
        entropy.copy_from_slice(&bits[..16]);
        Ok(Self(entropy))
    }
}
