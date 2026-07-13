//! Bitcoin Signed Messages (BSM) implementation.
//!
//! Provides legacy message signing and verification compatible with
//! the "Bitcoin Signed Message:\n" prefix convention. This is a
//! backward-compatibility feature; the preferred modern equivalent
//! is BRC-77.

use crate::compat::CompatError;
use crate::primitives::big_number::{BigNumber, Endian};
use crate::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use crate::primitives::hash::hash256;
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::signature::Signature;

const BSM_PREFIX: &[u8] = b"Bitcoin Signed Message:\n";

/// Bitcoin Signed Messages (BSM) -- legacy message signing and verification.
///
/// BSM uses a magic prefix to prevent cross-protocol signature attacks.
/// Messages are double-SHA256 hashed with the prefix before signing.
pub struct BSM;

/// Write a Bitcoin VarInt to a buffer.
///
/// Encoding:
/// - value < 0xfd: 1 byte
/// - value <= 0xffff: 0xfd + 2 bytes LE
/// - value <= 0xffffffff: 0xfe + 4 bytes LE
/// - else: 0xff + 8 bytes LE
fn write_varint(buf: &mut Vec<u8>, value: usize) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

impl BSM {
    /// Compute the BSM magic hash of a message.
    ///
    /// Constructs the prefixed buffer:
    ///   VarInt(25) || "Bitcoin Signed Message:\n" || VarInt(message.len()) || message
    ///
    /// Then returns hash256 (double SHA-256) of the buffer.
    pub fn magic_hash(message: &[u8]) -> [u8; 32] {
        let mut buf = Vec::new();
        write_varint(&mut buf, BSM_PREFIX.len());
        buf.extend_from_slice(BSM_PREFIX);
        write_varint(&mut buf, message.len());
        buf.extend_from_slice(message);
        hash256(&buf)
    }

    /// Sign a message using BSM.
    ///
    /// Returns a 65-byte compact BSM signature (recovery byte + 32-byte r + 32-byte s).
    /// The magic hash is computed, then ECDSA signing is performed with the hash256 output.
    /// Recovery factor is calculated and encoded in the first byte.
    pub fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, CompatError> {
        let msg_hash = Self::magic_hash(message);

        // ecdsa_sign expects [u8; 32] message hash -- pass hash256 output directly
        let sig = ecdsa_sign(&msg_hash, private_key.bn(), true)?;

        // Calculate recovery factor
        let pub_key = private_key.to_public_key();
        let msg_bn = BigNumber::from_bytes(&msg_hash, Endian::Big);
        let recovery = sig.calculate_recovery_factor(&pub_key, &msg_bn)?;

        // Return compact BSM format (65 bytes, always compressed)
        Ok(sig.to_compact_bsm(recovery, true))
    }

    /// Verify a BSM signed message.
    ///
    /// The signature must be in 65-byte compact BSM format.
    /// Verifies the signature against the provided public key.
    pub fn verify(
        message: &[u8],
        sig_bytes: &[u8],
        pub_key: &PublicKey,
    ) -> Result<bool, CompatError> {
        let (signature, _recovery, _compressed) = Signature::from_compact_bsm(sig_bytes)?;

        let msg_hash = Self::magic_hash(message);

        Ok(ecdsa_verify(&msg_hash, &signature, pub_key.point()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Base64 decode helper
    fn base64_decode(input: &str) -> Vec<u8> {
        let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = Vec::new();
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;

        for &byte in input.as_bytes() {
            if byte == b'=' {
                break;
            }
            let val = table.iter().position(|&b| b == byte);
            if let Some(v) = val {
                buf = (buf << 6) | (v as u32);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    result.push((buf >> bits) as u8);
                    buf &= (1 << bits) - 1;
                }
            }
        }
        result
    }

    // Base64 encode helper
    fn base64_encode(data: &[u8]) -> String {
        let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        let mut i = 0;
        while i < data.len() {
            let b0 = data[i] as u32;
            let b1 = if i + 1 < data.len() {
                data[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < data.len() {
                data[i + 2] as u32
            } else {
                0
            };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(table[((triple >> 18) & 0x3f) as usize] as char);
            result.push(table[((triple >> 12) & 0x3f) as usize] as char);
            if i + 1 < data.len() {
                result.push(table[((triple >> 6) & 0x3f) as usize] as char);
            } else {
                result.push('=');
            }
            if i + 2 < data.len() {
                result.push(table[(triple & 0x3f) as usize] as char);
            } else {
                result.push('=');
            }
            i += 3;
        }
        result
    }

    #[test]
    fn test_magic_hash_produces_32_bytes() {
        let hash = BSM::magic_hash(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_magic_hash_deterministic() {
        let h1 = BSM::magic_hash(b"hello");
        let h2 = BSM::magic_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_magic_hash_different_messages() {
        let h1 = BSM::magic_hash(b"hello");
        let h2 = BSM::magic_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sign_produces_65_bytes() {
        let priv_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let sig = BSM::sign(b"test message", &priv_key).unwrap();
        assert_eq!(sig.len(), 65, "BSM signature must be 65 bytes");
    }

    #[test]
    fn test_verify_correct_signature() {
        let priv_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pub_key = priv_key.to_public_key();
        let message = b"test message";
        let sig = BSM::sign(message, &priv_key).unwrap();
        let result = BSM::verify(message, &sig, &pub_key).unwrap();
        assert!(result, "verify should return true for matching sig");
    }

    #[test]
    fn test_verify_wrong_message() {
        let priv_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pub_key = priv_key.to_public_key();
        let sig = BSM::sign(b"correct message", &priv_key).unwrap();
        let result = BSM::verify(b"wrong message", &sig, &pub_key).unwrap();
        assert!(!result, "verify should return false for wrong message");
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let priv_key1 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let priv_key2 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let wrong_pub_key = priv_key2.to_public_key();
        let sig = BSM::sign(b"test message", &priv_key1).unwrap();
        let result = BSM::verify(b"test message", &sig, &wrong_pub_key).unwrap();
        assert!(!result, "verify should return false for wrong public key");
    }

    #[test]
    fn test_sign_verify_roundtrip_various_messages() {
        let priv_key = PrivateKey::from_hex(
            "00000000000000000000000000000000000000000000000000000000deadbeef",
        )
        .unwrap();
        let pub_key = priv_key.to_public_key();

        let messages: &[&[u8]] = &[
            b"",
            b"a",
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 256],
        ];

        for msg in messages {
            let sig = BSM::sign(msg, &priv_key).unwrap();
            assert_eq!(sig.len(), 65);
            let result = BSM::verify(msg, &sig, &pub_key).unwrap();
            assert!(
                result,
                "round-trip failed for message of length {}",
                msg.len()
            );
        }
    }

    #[test]
    fn test_cross_sdk_sign_vector() {
        // From TS SDK BSM test: WIF L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu
        // Message: "hello world"
        // Expected base64: H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk=
        let priv_key =
            PrivateKey::from_wif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu").unwrap();
        let message = b"hello world";
        let sig = BSM::sign(message, &priv_key).unwrap();
        let sig_b64 = base64_encode(&sig);
        assert_eq!(
            sig_b64,
            "H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk=",
            "BSM signature should match TS SDK output"
        );
    }

    #[test]
    fn test_cross_sdk_verify_vector() {
        // From TS SDK BSM test: verify "Texas" with known public key
        let sig_b64 = "IAV89EkfHSzAIA8cEWbbKHUYzJqcShkpWaXGJ5+mf4+YIlf3XNlr0bj9X60sNe1A7+x9qyk+zmXropMDY4370n8=";
        let sig_bytes = base64_decode(sig_b64);
        let pub_key = PublicKey::from_string(
            "03d4d1a6c5d8c03b0e671bc1891b69afaecb40c0686188fe9019f93581b43e8334",
        )
        .unwrap();
        let message = b"Texas";
        let result = BSM::verify(message, &sig_bytes, &pub_key).unwrap();
        assert!(result, "should verify TS SDK BSM signature for 'Texas'");
    }
}
