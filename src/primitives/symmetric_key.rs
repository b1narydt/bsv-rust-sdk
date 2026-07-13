//! Symmetric encryption key for AES-GCM operations.
//!
//! SymmetricKey wraps a 32-byte key and provides encrypt/decrypt using AES-GCM
//! with the TS SDK's 32-byte IV convention. Ciphertext format:
//! IV(32) || ciphertext || authTag(16).

use crate::primitives::aes_gcm::{aes_gcm_decrypt_ts_compat, aes_gcm_encrypt_ts_compat};
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::error::PrimitivesError;
use crate::primitives::random::random_bytes;

/// A symmetric key for AES-GCM encryption/decryption.
///
/// Uses composition over BigNumber (Rust equivalent of TS SDK's `extends BigNumber`).
/// The key is always 32 bytes (256-bit AES).
pub struct SymmetricKey {
    key: BigNumber,
}

impl SymmetricKey {
    /// Generate a random 32-byte symmetric key.
    pub fn from_random() -> Self {
        let bytes = random_bytes(32);
        SymmetricKey {
            key: BigNumber::from_bytes(&bytes, Endian::Big),
        }
    }

    /// Parse a symmetric key from a 64-character hex string.
    pub fn from_hex(hex: &str) -> Result<Self, PrimitivesError> {
        if hex.len() != 64 {
            return Err(PrimitivesError::InvalidLength(format!(
                "symmetric key hex must be 64 characters, got {}",
                hex.len()
            )));
        }
        let key = BigNumber::from_hex(hex)?;
        Ok(SymmetricKey { key })
    }

    /// Create a symmetric key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.len() != 32 {
            return Err(PrimitivesError::InvalidLength(format!(
                "symmetric key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(SymmetricKey {
            key: BigNumber::from_bytes(bytes, Endian::Big),
        })
    }

    /// Encrypt plaintext using AES-GCM with a random 32-byte IV.
    ///
    /// Returns IV(32) || ciphertext || authTag(16).
    /// Uses the TS SDK compatible GCM variant for cross-SDK interoperability.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        let iv = random_bytes(32);
        let key_bytes = self.key.to_array(Endian::Big, Some(32));
        // aes_gcm_encrypt_ts_compat returns ciphertext || authTag(16)
        let ct_and_tag = aes_gcm_encrypt_ts_compat(&key_bytes, &iv, plaintext)?;
        // Prepend IV: result = IV(32) || ciphertext || authTag(16)
        let mut result = Vec::with_capacity(iv.len() + ct_and_tag.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ct_and_tag);
        Ok(result)
    }

    /// Test-only deterministic encryption with a caller-supplied 32-byte IV.
    ///
    /// **Production code MUST use [`encrypt`] instead.** Reusing an IV with the
    /// same key irrecoverably breaks AES-GCM authenticity (forgery becomes
    /// trivial). This entry point exists so cross-impl conformance vectors can
    /// byte-lock the canonical wire format. See MPC-Spec §06.16 and ADR-0030.
    ///
    /// Returns IV(32) || ciphertext || authTag(16) — identical layout to [`encrypt`].
    pub fn encrypt_with_iv(
        &self,
        plaintext: &[u8],
        iv: &[u8; 32],
    ) -> Result<Vec<u8>, PrimitivesError> {
        let key_bytes = self.key.to_array(Endian::Big, Some(32));
        let ct_and_tag = aes_gcm_encrypt_ts_compat(&key_bytes, iv, plaintext)?;
        let mut result = Vec::with_capacity(iv.len() + ct_and_tag.len());
        result.extend_from_slice(iv);
        result.extend_from_slice(&ct_and_tag);
        Ok(result)
    }

    /// Decrypt data encrypted with `encrypt`.
    ///
    /// Expects format: IV(32) || ciphertext || authTag(16).
    /// Uses the TS SDK compatible GCM variant for cross-SDK interoperability.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        if data.len() < 48 {
            return Err(PrimitivesError::DecryptionFailed);
        }
        let iv = &data[0..32];
        let ciphertext_with_tag = &data[32..];
        let key_bytes = self.key.to_array(Endian::Big, Some(32));
        aes_gcm_decrypt_ts_compat(&key_bytes, iv, ciphertext_with_tag)
    }

    /// Return the key as a hex string.
    pub fn to_hex(&self) -> String {
        let bytes = self.key.to_array(Endian::Big, Some(32));
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Return the key as 32 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_array(Endian::Big, Some(32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_random_produces_32_byte_key() {
        let key = SymmetricKey::from_random();
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    fn test_from_hex_round_trip() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = SymmetricKey::from_hex(hex).unwrap();
        assert_eq!(key.to_hex(), hex);
    }

    #[test]
    fn test_from_bytes_round_trip() {
        let bytes = vec![0xabu8; 32];
        let key = SymmetricKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_from_hex_invalid_length() {
        // Too short
        let result = SymmetricKey::from_hex("0123456789abcdef");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_empty() {
        let key = SymmetricKey::from_random();
        let plaintext = b"";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_1_byte() {
        let key = SymmetricKey::from_random();
        let plaintext = b"\x42";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_16_bytes() {
        let key = SymmetricKey::from_random();
        let plaintext = b"0123456789abcdef";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_100_bytes() {
        let key = SymmetricKey::from_random();
        let plaintext = vec![0x55u8; 100];
        let ciphertext = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_1000_bytes() {
        let key = SymmetricKey::from_random();
        let plaintext = vec![0x77u8; 1000];
        let ciphertext = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_format_iv32_ct_tag16() {
        let key = SymmetricKey::from_random();
        let plaintext = b"hello world";
        let ciphertext = key.encrypt(plaintext).unwrap();
        // IV(32) + plaintext_len + tag(16)
        assert_eq!(ciphertext.len(), 32 + plaintext.len() + 16);
    }

    #[test]
    fn test_decrypt_rejects_tampered_ciphertext() {
        let key = SymmetricKey::from_random();
        let plaintext = b"test message";
        let mut ciphertext = key.encrypt(plaintext).unwrap();
        // Tamper with a ciphertext byte (after IV, before tag)
        if ciphertext.len() > 33 {
            ciphertext[33] ^= 0xff;
        }
        let result = key.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rejects_truncated_data() {
        let key = SymmetricKey::from_random();
        // Data too short for IV(32) + tag(16) = 48 bytes minimum
        let short_data = vec![0u8; 47];
        let result = key.decrypt(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_two_encryptions_produce_different_ciphertext() {
        let key = SymmetricKey::from_random();
        let plaintext = b"same plaintext";
        let ct1 = key.encrypt(plaintext).unwrap();
        let ct2 = key.encrypt(plaintext).unwrap();
        // Different random IVs mean different ciphertext
        assert_ne!(ct1, ct2);
        // But both decrypt to the same plaintext
        assert_eq!(key.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(key.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_to_hex_returns_64_chars() {
        let key = SymmetricKey::from_random();
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_encrypt_with_iv_deterministic() {
        // Hard byte-lock: fixed (key, iv, plaintext) → fixed ciphertext hex.
        // Acts as a regression fence on the seam — any future change to the
        // IV-derivation, key-derivation, or AEAD args will fail this exact match.
        let key = SymmetricKey::from_bytes(&[0x42u8; 32]).unwrap();
        let iv = [0x07u8; 32];
        let plaintext = b"deterministic test";
        let ct = key.encrypt_with_iv(plaintext, &iv).unwrap();

        // Hard-coded expected output (captured from a known-good reference run).
        const EXPECTED_HEX: &str = "070707070707070707070707070707070707070707070707070707070707070767d8ad1a0389e26b420c948718d57def0d4fc1293a77d8ecb542aed22b87d6942025";
        assert_eq!(hex::encode(&ct), EXPECTED_HEX);

        // Layout sanity: IV(32) || ciphertext(plaintext_len) || tag(16)
        assert_eq!(ct.len(), 32 + plaintext.len() + 16);
        assert_eq!(&ct[..32], &iv);
    }

    #[test]
    fn test_encrypt_with_iv_decrypts_via_encrypt() {
        // Output of encrypt_with_iv must decrypt successfully via the standard `decrypt` path.
        // Proves seam emits the same on-the-wire format as `encrypt`.
        let key = SymmetricKey::from_random();
        let iv = [0x11u8; 32];
        let plaintext = b"round trip via decrypt";
        let ct = key.encrypt_with_iv(plaintext, &iv).unwrap();
        let pt = key.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }
}
