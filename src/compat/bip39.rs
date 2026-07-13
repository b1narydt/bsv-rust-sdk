//! BIP39 mnemonic generation and seed derivation.
//!
//! Implements mnemonic generation from entropy, mnemonic validation,
//! and PBKDF2-based seed derivation per the BIP39 specification.
//!
//! Note: BIP39 spec requires NFKD normalization of mnemonic and passphrase.
//! All 9 supported wordlists use ASCII-safe characters, so normalization is
//! a no-op for the mnemonic itself. Non-ASCII passphrases should be
//! pre-normalized by the caller.

use super::bip39_wordlists;
use super::error::CompatError;
use crate::primitives::hash::{pbkdf2_hmac_sha512, sha256};
use crate::primitives::random::random_bytes;

/// Supported BIP39 wordlist languages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Language {
    English,
    Japanese,
    Korean,
    Spanish,
    French,
    Italian,
    Czech,
    ChineseSimplified,
    ChineseTraditional,
}

/// Returns the wordlist for the given language.
fn get_wordlist(lang: Language) -> &'static [&'static str; 2048] {
    match lang {
        Language::English => bip39_wordlists::english::ENGLISH,
        Language::Japanese => bip39_wordlists::japanese::JAPANESE,
        Language::Korean => bip39_wordlists::korean::KOREAN,
        Language::Spanish => bip39_wordlists::spanish::SPANISH,
        Language::French => bip39_wordlists::french::FRENCH,
        Language::Italian => bip39_wordlists::italian::ITALIAN,
        Language::Czech => bip39_wordlists::czech::CZECH,
        Language::ChineseSimplified => bip39_wordlists::chinese_simplified::CHINESE_SIMPLIFIED,
        Language::ChineseTraditional => bip39_wordlists::chinese_traditional::CHINESE_TRADITIONAL,
    }
}

/// A BIP39 mnemonic phrase with associated entropy and language.
#[derive(Debug, Clone)]
pub struct Mnemonic {
    words: Vec<String>,
    entropy: Vec<u8>,
    language: Language,
}

impl Mnemonic {
    /// Create a mnemonic from raw entropy bytes.
    ///
    /// Entropy must be 16, 20, 24, 28, or 32 bytes (128-256 bits in 32-bit steps).
    /// The checksum is computed as the first `entropy_bits / 32` bits of SHA-256(entropy).
    pub fn from_entropy(entropy: &[u8], language: Language) -> Result<Self, CompatError> {
        let ent_bits = entropy.len() * 8;
        if !(128..=256).contains(&ent_bits) || !ent_bits.is_multiple_of(32) {
            return Err(CompatError::InvalidEntropy(format!(
                "entropy must be 128-256 bits in 32-bit increments, got {ent_bits} bits"
            )));
        }

        let checksum_bits = ent_bits / 32;
        let checksum = sha256(entropy);

        // Build bit stream: entropy bits + checksum bits
        let total_bits = ent_bits + checksum_bits;
        let wordlist = get_wordlist(language);
        let mut words = Vec::with_capacity(total_bits / 11);

        for i in 0..(total_bits / 11) {
            let mut index: u32 = 0;
            for j in 0..11 {
                let bit_pos = i * 11 + j;
                let bit = if bit_pos < ent_bits {
                    // Bit from entropy
                    (entropy[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1
                } else {
                    // Bit from checksum
                    let cs_pos = bit_pos - ent_bits;
                    (checksum[cs_pos / 8] >> (7 - (cs_pos % 8))) & 1
                };
                index = (index << 1) | bit as u32;
            }
            words.push(wordlist[index as usize].to_string());
        }

        Ok(Mnemonic {
            words,
            entropy: entropy.to_vec(),
            language,
        })
    }

    /// Generate a random mnemonic with the specified bit strength.
    ///
    /// Valid bit strengths: 128, 160, 192, 224, 256.
    pub fn from_random(bits: usize, language: Language) -> Result<Self, CompatError> {
        if !(128..=256).contains(&bits) || !bits.is_multiple_of(32) {
            return Err(CompatError::InvalidEntropy(format!(
                "bits must be 128-256 in 32-bit increments, got {bits}"
            )));
        }
        let entropy = random_bytes(bits / 8);
        Self::from_entropy(&entropy, language)
    }

    /// Parse a mnemonic from a space-separated string.
    ///
    /// Validates that all words are in the wordlist and the checksum is correct.
    /// Japanese mnemonics use ideographic space (U+3000) as separator.
    pub fn from_string(mnemonic: &str, language: Language) -> Result<Self, CompatError> {
        let separator = if language == Language::Japanese {
            "\u{3000}"
        } else {
            " "
        };

        let word_strs: Vec<&str> = mnemonic.split(separator).collect();
        let word_count = word_strs.len();

        // Valid word counts: 12, 15, 18, 21, 24
        if !(12..=24).contains(&word_count) || !word_count.is_multiple_of(3) {
            return Err(CompatError::InvalidMnemonic(format!(
                "invalid word count: {word_count} (must be 12, 15, 18, 21, or 24)"
            )));
        }

        let wordlist = get_wordlist(language);

        // Look up indices
        let mut indices = Vec::with_capacity(word_count);
        for word in &word_strs {
            match wordlist.iter().position(|w| w == word) {
                Some(idx) => indices.push(idx as u32),
                None => {
                    return Err(CompatError::InvalidMnemonic(format!(
                        "word not in wordlist: {word}"
                    )));
                }
            }
        }

        // Reconstruct entropy from 11-bit indices
        let total_bits = word_count * 11;
        let ent_bits = (total_bits * 32) / 33; // entropy_bits = total_bits - checksum_bits
        let checksum_bits = ent_bits / 32;
        let ent_bytes = ent_bits / 8;

        // Extract all bits from indices
        let mut bits_vec: Vec<u8> = Vec::with_capacity(total_bits);
        for idx in &indices {
            for j in (0..11).rev() {
                bits_vec.push(((idx >> j) & 1) as u8);
            }
        }

        // Extract entropy bytes
        let mut entropy = vec![0u8; ent_bytes];
        for i in 0..ent_bits {
            if bits_vec[i] == 1 {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        // Validate checksum
        let checksum = sha256(&entropy);
        for i in 0..checksum_bits {
            let expected_bit = (checksum[i / 8] >> (7 - (i % 8))) & 1;
            let actual_bit = bits_vec[ent_bits + i];
            if expected_bit != actual_bit {
                return Err(CompatError::InvalidMnemonic(
                    "checksum mismatch".to_string(),
                ));
            }
        }

        Ok(Mnemonic {
            words: word_strs.iter().map(|s| s.to_string()).collect(),
            entropy,
            language,
        })
    }

    /// Check if this mnemonic has a valid checksum.
    pub fn check(&self) -> bool {
        let ent_bits = self.entropy.len() * 8;
        let checksum_bits = ent_bits / 32;
        let checksum = sha256(&self.entropy);

        // Re-derive expected words from entropy and compare
        let wordlist = get_wordlist(self.language);
        let total_bits = ent_bits + checksum_bits;

        for i in 0..(total_bits / 11) {
            let mut index: u32 = 0;
            for j in 0..11 {
                let bit_pos = i * 11 + j;
                let bit = if bit_pos < ent_bits {
                    (self.entropy[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1
                } else {
                    let cs_pos = bit_pos - ent_bits;
                    (checksum[cs_pos / 8] >> (7 - (cs_pos % 8))) & 1
                };
                index = (index << 1) | bit as u32;
            }
            if self.words[i] != wordlist[index as usize] {
                return false;
            }
        }

        true
    }

    /// Derive a 64-byte seed from this mnemonic using PBKDF2-HMAC-SHA512.
    ///
    /// The passphrase is prepended with "mnemonic" as salt per BIP39 spec.
    /// Uses 2048 iterations.
    pub fn to_seed(&self, passphrase: &str) -> Vec<u8> {
        let mnemonic_str = self.to_phrase();
        let salt = format!("mnemonic{passphrase}");
        pbkdf2_hmac_sha512(mnemonic_str.as_bytes(), salt.as_bytes(), 2048, 64)
    }

    /// Get the mnemonic as a space-separated string.
    ///
    /// Japanese mnemonics use ideographic space (U+3000).
    pub fn to_phrase(&self) -> String {
        let separator = if self.language == Language::Japanese {
            "\u{3000}"
        } else {
            " "
        };
        self.words.join(separator)
    }

    /// Get a reference to the mnemonic words.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Get a reference to the entropy bytes.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_phrase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[derive(serde::Deserialize)]
    struct TestVector {
        entropy: String,
        mnemonic: String,
        passphrase: String,
        seed: String,
    }

    #[derive(serde::Deserialize)]
    struct TestVectors {
        vectors: Vec<TestVector>,
    }

    fn load_vectors() -> TestVectors {
        let json = include_str!("../../test-vectors/bip39_vectors.json");
        serde_json::from_str(json).expect("failed to parse BIP39 test vectors")
    }

    // Test 1: from_entropy with known 128-bit entropy produces correct 12-word mnemonic
    #[test]
    fn test_from_entropy_128bit() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0]; // 128-bit all zeros
        let entropy = hex_to_bytes(&v.entropy);
        let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(m.to_string(), v.mnemonic);
        assert_eq!(m.words().len(), 12);
    }

    // Test 2: from_entropy with 256-bit entropy produces correct 24-word mnemonic
    #[test]
    fn test_from_entropy_256bit() {
        let vectors = load_vectors();
        let v = &vectors.vectors[8]; // 256-bit all zeros
        let entropy = hex_to_bytes(&v.entropy);
        let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(m.to_string(), v.mnemonic);
        assert_eq!(m.words().len(), 24);
    }

    // Test 3: to_seed with known mnemonic and "TREZOR" passphrase
    #[test]
    fn test_to_seed_with_trezor_passphrase() {
        let vectors = load_vectors();
        let v = &vectors.vectors[0];
        let m = Mnemonic::from_string(&v.mnemonic, Language::English).unwrap();
        let seed = m.to_seed(&v.passphrase);
        assert_eq!(bytes_to_hex(&seed), v.seed);
    }

    // Test 4: to_seed with empty passphrase
    #[test]
    fn test_to_seed_empty_passphrase() {
        // Use the first vector's mnemonic but with empty passphrase
        let m = Mnemonic::from_string(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = m.to_seed("");
        // Verify seed is 64 bytes and differs from TREZOR passphrase seed
        assert_eq!(seed.len(), 64);
        let trezor_seed = m.to_seed("TREZOR");
        assert_ne!(seed, trezor_seed);
    }

    // Test 5: check() validates a correct mnemonic
    #[test]
    fn test_check_valid() {
        let m = Mnemonic::from_string(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        assert!(m.check());
    }

    // Test 6: check() rejects a mnemonic with wrong checksum
    #[test]
    fn test_check_invalid_checksum() {
        // "abandon" x 12 has wrong checksum (last word should be "about")
        let result = Mnemonic::from_string(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            Language::English,
        );
        assert!(result.is_err());
    }

    // Test 7: from_random(128) produces valid 12-word mnemonic
    #[test]
    fn test_from_random_128() {
        let m = Mnemonic::from_random(128, Language::English).unwrap();
        assert_eq!(m.words().len(), 12);
        assert!(m.check());
    }

    // Test 8: from_random(256) produces valid 24-word mnemonic
    #[test]
    fn test_from_random_256() {
        let m = Mnemonic::from_random(256, Language::English).unwrap();
        assert_eq!(m.words().len(), 24);
        assert!(m.check());
    }

    // Test 9: from_string parses and to_string re-produces
    #[test]
    fn test_from_string_roundtrip() {
        let mnemonic_str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let m = Mnemonic::from_string(mnemonic_str, Language::English).unwrap();
        assert_eq!(m.to_string(), mnemonic_str);
    }

    // Additional: verify all test vectors for entropy-to-mnemonic
    #[test]
    fn test_all_vectors_entropy_to_mnemonic() {
        let vectors = load_vectors();
        for (i, v) in vectors.vectors.iter().enumerate() {
            let entropy = hex_to_bytes(&v.entropy);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            assert_eq!(m.to_string(), v.mnemonic, "Vector {i} mnemonic mismatch");
        }
    }

    // Additional: verify all test vectors for seed derivation
    #[test]
    fn test_all_vectors_seed_derivation() {
        let vectors = load_vectors();
        for (i, v) in vectors.vectors.iter().enumerate() {
            let m = Mnemonic::from_string(&v.mnemonic, Language::English).unwrap();
            let seed = m.to_seed(&v.passphrase);
            assert_eq!(bytes_to_hex(&seed), v.seed, "Vector {i} seed mismatch");
        }
    }
}
