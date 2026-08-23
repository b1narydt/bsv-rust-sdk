//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementation.
//!
//! Provides both Electrum and Bitcore variants of ECIES encryption
//! for backward compatibility with existing BSV ecosystem tools.
//! The preferred modern equivalent is BRC-78.

use crate::compat::CompatError;
use crate::primitives::aes_cbc::{aes_cbc_decrypt, aes_cbc_encrypt};
use crate::primitives::big_number::Endian;
use crate::primitives::hash::{sha256_hmac, sha512};
use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::random::random_bytes;

/// ECIES encryption with Electrum and Bitcore variants.
///
/// Electrum uses BIE1 magic bytes, derives IV from ECDH shared secret,
/// and uses AES-128-CBC.
///
/// Bitcore uses a random IV prepended to ciphertext, derives a 32-byte
/// key from ECDH shared secret, and uses AES-256-CBC.
pub struct ECIES;

/// Derive Electrum-variant keys from ECDH shared secret.
///
/// ECDH: P = pub_key.point * priv_key
/// S = compressed encoding of P (33 bytes)
/// hash = SHA-512(S)
/// Returns (iv[16], kE[16], kM[32])
fn derive_electrum_keys(
    priv_key: &PrivateKey,
    pub_key: &PublicKey,
) -> ([u8; 16], [u8; 16], [u8; 32]) {
    let p = pub_key.point().mul(priv_key.bn());
    let s_buf = p.to_der(true); // compressed 33 bytes
    let hash = sha512(&s_buf);

    let mut iv = [0u8; 16];
    let mut k_e = [0u8; 16];
    let mut k_m = [0u8; 32];
    iv.copy_from_slice(&hash[0..16]);
    k_e.copy_from_slice(&hash[16..32]);
    k_m.copy_from_slice(&hash[32..64]);

    (iv, k_e, k_m)
}

/// Derive Bitcore-variant keys from ECDH shared secret.
///
/// ECDH: P = pub_key.point * priv_key
/// S = P.x as 32-byte big-endian
/// hash = SHA-512(S)
/// Returns (kE[32], kM[32])
fn derive_bitcore_keys(priv_key: &PrivateKey, pub_key: &PublicKey) -> ([u8; 32], [u8; 32]) {
    let p = pub_key.point().mul(priv_key.bn());
    let s_buf = p.get_x().to_array(Endian::Big, Some(32));
    let hash = sha512(&s_buf);

    let mut k_e = [0u8; 32];
    let mut k_m = [0u8; 32];
    k_e.copy_from_slice(&hash[0..32]);
    k_m.copy_from_slice(&hash[32..64]);

    (k_e, k_m)
}

impl ECIES {
    /// Encrypt plaintext using the Electrum ECIES variant (BIE1 format).
    ///
    /// Format: "BIE1" (4 bytes) || [sender_pubkey] || ciphertext || HMAC (32 bytes)
    ///
    /// If sender_priv_key is provided, it is used instead of an ephemeral key.
    /// When `no_key` is true, the sender public key is omitted and decryptors
    /// must supply it separately to [`Self::electrum_decrypt`].
    pub fn electrum_encrypt(
        plaintext: &[u8],
        recipient_pub_key: &PublicKey,
        sender_priv_key: Option<&PrivateKey>,
        no_key: bool,
    ) -> Result<Vec<u8>, CompatError> {
        let ephemeral_key = match sender_priv_key {
            Some(key) => key.clone(),
            None => PrivateKey::from_random()?,
        };

        let (iv, k_e, k_m) = derive_electrum_keys(&ephemeral_key, recipient_pub_key);

        // Encrypt with AES-128-CBC (16-byte key)
        let ct = aes_cbc_encrypt(&k_e, &iv, plaintext)?;

        // Build payload: "BIE1" + optional sender compressed pubkey + ciphertext.
        let mut payload = Vec::with_capacity(4 + usize::from(!no_key) * 33 + ct.len() + 32);
        payload.extend_from_slice(b"BIE1");
        if !no_key {
            payload.extend_from_slice(&ephemeral_key.to_public_key().to_der());
        }
        payload.extend_from_slice(&ct);

        // HMAC over payload (before appending HMAC)
        let mac = sha256_hmac(&k_m, &payload);

        payload.extend_from_slice(&mac);
        Ok(payload)
    }

    /// Decrypt ciphertext using the Electrum ECIES variant (BIE1 format).
    ///
    /// The sender key is normally read from the ciphertext. For `no_key`
    /// ciphertexts, pass the sender public key explicitly.
    pub fn electrum_decrypt(
        ciphertext: &[u8],
        recipient_priv_key: &PrivateKey,
        sender_pub_key: Option<&PublicKey>,
    ) -> Result<Vec<u8>, CompatError> {
        // Minimum no-key payload: BIE1 + one AES block + HMAC.
        if ciphertext.len() < 52 {
            return Err(CompatError::InvalidCiphertext(format!(
                "electrum ciphertext too short: {} bytes (min 52)",
                ciphertext.len()
            )));
        }

        // Verify magic bytes
        if &ciphertext[0..4] != b"BIE1" {
            return Err(CompatError::InvalidMagic);
        }

        let hmac_start = ciphertext.len() - 32;
        let embedded_key_len = if hmac_start - 4 >= 33 {
            match ciphertext[4] {
                0x02 | 0x03 => Some(33),
                0x04 if hmac_start - 4 >= 65 => Some(65),
                _ => None,
            }
        } else {
            None
        };
        let encrypted_start = 4 + embedded_key_len.unwrap_or(0);
        let encrypted_data = &ciphertext[encrypted_start..hmac_start];
        let mac = &ciphertext[hmac_start..];

        let embedded_pub = embedded_key_len
            .map(|len| PublicKey::from_der_bytes(&ciphertext[4..4 + len]))
            .transpose()?;
        let sender_pub = sender_pub_key
            .or(embedded_pub.as_ref())
            .ok_or(CompatError::SenderKeyRequired)?;

        // Derive keys
        let (iv, k_e, k_m) = derive_electrum_keys(recipient_priv_key, sender_pub);

        // Verify HMAC over everything except the HMAC itself
        let expected_mac = sha256_hmac(&k_m, &ciphertext[0..hmac_start]);
        if mac != expected_mac {
            return Err(CompatError::HmacMismatch);
        }

        // Decrypt
        let plaintext = aes_cbc_decrypt(&k_e, &iv, encrypted_data)?;
        Ok(plaintext)
    }

    /// Encrypt plaintext using the Bitcore ECIES variant.
    ///
    /// Format: ephemeral_pubkey (33) || iv (16) || aes_ciphertext || HMAC (32)
    /// HMAC is over iv + aes_ciphertext only (not including pubkey).
    ///
    /// Uses AES-256-CBC with a 32-byte key derived from ECDH.
    pub fn bitcore_encrypt(
        plaintext: &[u8],
        recipient_pub_key: &PublicKey,
        sender_priv_key: Option<&PrivateKey>,
    ) -> Result<Vec<u8>, CompatError> {
        let ephemeral_key = match sender_priv_key {
            Some(key) => key.clone(),
            None => PrivateKey::from_random()?,
        };

        let (k_e, k_m) = derive_bitcore_keys(&ephemeral_key, recipient_pub_key);

        // Generate random 16-byte IV
        let iv_vec = random_bytes(16);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_vec);

        // Encrypt with AES-256-CBC (32-byte key)
        let ct = aes_cbc_encrypt(&k_e, &iv, plaintext)?;

        // Build c = iv || ciphertext (matching TS SDK AESCBC.encrypt with concatIvBuf=true)
        let mut c = Vec::with_capacity(16 + ct.len());
        c.extend_from_slice(&iv);
        c.extend_from_slice(&ct);

        // HMAC over c (iv + ciphertext, NOT including pubkey)
        let mac = sha256_hmac(&k_m, &c);

        // Final output: pubkey || c || hmac
        let r_buf = ephemeral_key.to_public_key().to_der();
        let mut result = Vec::with_capacity(33 + c.len() + 32);
        result.extend_from_slice(&r_buf);
        result.extend_from_slice(&c);
        result.extend_from_slice(&mac);
        Ok(result)
    }

    /// Decrypt ciphertext using the Bitcore ECIES variant.
    ///
    /// Expects format: pubkey (33) || iv (16) || aes_ciphertext || HMAC (32)
    /// HMAC is verified over iv + aes_ciphertext only.
    pub fn bitcore_decrypt(
        ciphertext: &[u8],
        recipient_priv_key: &PrivateKey,
    ) -> Result<Vec<u8>, CompatError> {
        // Minimum: 33 (pubkey) + 16 (iv) + 16 (min ct block) + 32 (hmac) = 97
        if ciphertext.len() < 97 {
            return Err(CompatError::InvalidCiphertext(format!(
                "bitcore ciphertext too short: {} bytes (min 97)",
                ciphertext.len()
            )));
        }

        // Extract ephemeral public key
        let ephemeral_pub_bytes = &ciphertext[0..33];
        let ephemeral_pub = PublicKey::from_der_bytes(ephemeral_pub_bytes)?;

        // c = everything between pubkey and hmac (iv + aes ciphertext)
        let c = &ciphertext[33..ciphertext.len() - 32];
        let mac = &ciphertext[ciphertext.len() - 32..];

        // Derive keys
        let (k_e, k_m) = derive_bitcore_keys(recipient_priv_key, &ephemeral_pub);

        // Verify HMAC over c (iv + aes ciphertext)
        let expected_mac = sha256_hmac(&k_m, c);
        if mac != expected_mac {
            return Err(CompatError::HmacMismatch);
        }

        // Extract IV and ciphertext from c
        // Length check above guarantees c.len() >= 32, so this slice is always valid.
        let iv: [u8; 16] = c[0..16]
            .try_into()
            .map_err(|_| CompatError::InvalidCiphertext("IV extraction failed".into()))?;
        let encrypted_data = &c[16..];

        // Decrypt with AES-256-CBC
        let plaintext = aes_cbc_decrypt(&k_e, &iv, encrypted_data)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::sha256;

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

    #[allow(dead_code)]
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[allow(dead_code)]
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- Electrum tests ----

    #[test]
    fn test_electrum_encrypt_decrypt_roundtrip() {
        let sender_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let recipient_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let plaintext = b"this is my test message";
        let encrypted =
            ECIES::electrum_encrypt(plaintext, &recipient_pub, Some(&sender_key), false).unwrap();
        let decrypted = ECIES::electrum_decrypt(&encrypted, &recipient_key, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_electrum_ciphertext_starts_with_bie1() {
        let recipient_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let encrypted = ECIES::electrum_encrypt(b"hello", &recipient_pub, None, false).unwrap();
        assert_eq!(
            &encrypted[0..4],
            b"BIE1",
            "Electrum ciphertext must start with BIE1"
        );
    }

    #[test]
    fn test_electrum_hmac_rejects_tampered_ciphertext() {
        let recipient_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let sender_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let mut encrypted =
            ECIES::electrum_encrypt(b"hello", &recipient_pub, Some(&sender_key), false).unwrap();

        // Tamper with a byte in the middle (ciphertext area)
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xff;

        let result = ECIES::electrum_decrypt(&encrypted, &recipient_key, None);
        assert!(result.is_err(), "should reject tampered ciphertext");
    }

    #[test]
    fn test_electrum_decrypt_wrong_key_fails() {
        let sender_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let recipient_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let wrong_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let recipient_pub = recipient_key.to_public_key();
        let encrypted =
            ECIES::electrum_encrypt(b"secret", &recipient_pub, Some(&sender_key), false).unwrap();

        let result = ECIES::electrum_decrypt(&encrypted, &wrong_key, None);
        assert!(result.is_err(), "should fail with wrong private key");
    }

    // ---- Cross-SDK Electrum tests ----

    #[test]
    fn test_electrum_cross_sdk_decrypt_alice_to_bob() {
        // From TS SDK ECIES test: alice encrypts for bob
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();

        let ciphertext = base64_decode(
            "QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo="
        );

        let plaintext = ECIES::electrum_decrypt(&ciphertext, &bob_key, None).unwrap();
        assert_eq!(
            std::str::from_utf8(&plaintext).unwrap(),
            "this is my test message"
        );
    }

    #[test]
    fn test_electrum_cross_sdk_decrypt_bob_to_alice() {
        // From TS SDK ECIES test: bob encrypts for alice
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();

        let ciphertext = base64_decode(
            "QklFMQOGFyMXLo9Qv047K3BYJhmnJgt58EC8skYP/R2QU/U0yXXHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbiaH4FsxKIOOvzolIFVAS0FplUmib2HnlAM1yP/iiPsU="
        );

        let plaintext = ECIES::electrum_decrypt(&ciphertext, &alice_key, None).unwrap();
        assert_eq!(
            std::str::from_utf8(&plaintext).unwrap(),
            "this is my test message"
        );
    }

    #[test]
    fn test_electrum_cross_sdk_encrypt_matches_ts() {
        // Verify that our encrypt output matches TS SDK exactly (deterministic with known keys)
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let bob_pub = bob_key.to_public_key();

        let message = b"this is my test message";
        let encrypted =
            ECIES::electrum_encrypt(message, &bob_pub, Some(&alice_key), false).unwrap();
        let expected_b64 = "QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo=";
        assert_eq!(base64_encode(&encrypted), expected_b64);
    }

    #[test]
    fn test_electrum_no_key_is_symmetric_and_requires_sender_key_to_decrypt() {
        let alice = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let alice_public = alice.to_public_key();
        let bob_public = bob.to_public_key();
        let message = b"this is my ECDH test message";

        let alice_to_bob =
            ECIES::electrum_encrypt(message, &bob_public, Some(&alice), true).unwrap();
        let bob_to_alice =
            ECIES::electrum_encrypt(message, &alice_public, Some(&bob), true).unwrap();
        assert_eq!(alice_to_bob, bob_to_alice);
        assert_eq!(&alice_to_bob[..4], b"BIE1");
        assert!(matches!(
            ECIES::electrum_decrypt(&alice_to_bob, &bob, None),
            Err(CompatError::SenderKeyRequired)
        ));
        assert_eq!(
            ECIES::electrum_decrypt(&alice_to_bob, &bob, Some(&alice_public)).unwrap(),
            message
        );
    }

    // ---- Bitcore tests ----

    #[test]
    fn test_bitcore_encrypt_decrypt_roundtrip() {
        let sender_key = PrivateKey::from_hex(
            "000000000000000000000000000000000000000000000000000000000000002a",
        )
        .unwrap();
        let recipient_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000058",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        // Use sha256 of a message as plaintext (matching TS SDK test pattern)
        let plaintext = sha256(b"my message is the hash of this string");

        let encrypted =
            ECIES::bitcore_encrypt(&plaintext, &recipient_pub, Some(&sender_key)).unwrap();
        let decrypted = ECIES::bitcore_decrypt(&encrypted, &recipient_key).unwrap();

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_bitcore_no_bie1_magic() {
        let recipient_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000058",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let encrypted = ECIES::bitcore_encrypt(b"hello", &recipient_pub, None).unwrap();
        assert_ne!(
            &encrypted[0..4],
            b"BIE1",
            "Bitcore should NOT have BIE1 magic"
        );
        // First byte should be 0x02 or 0x03 (compressed pubkey)
        assert!(
            encrypted[0] == 0x02 || encrypted[0] == 0x03,
            "Bitcore ciphertext should start with compressed pubkey prefix"
        );
    }

    #[test]
    fn test_bitcore_encrypt_decrypt_with_random_ephemeral() {
        let recipient_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000058",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let plaintext = sha256(b"random ephemeral test");
        let encrypted = ECIES::bitcore_encrypt(&plaintext, &recipient_pub, None).unwrap();
        let decrypted = ECIES::bitcore_decrypt(&encrypted, &recipient_key).unwrap();

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_bitcore_hmac_rejects_tampered() {
        let sender_key = PrivateKey::from_hex(
            "000000000000000000000000000000000000000000000000000000000000002a",
        )
        .unwrap();
        let recipient_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000058",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let mut encrypted =
            ECIES::bitcore_encrypt(b"secret data", &recipient_pub, Some(&sender_key)).unwrap();

        // Tamper with ciphertext (not the pubkey or hmac)
        let mid = 33 + 8; // past the pubkey, in the iv/ct area
        encrypted[mid] ^= 0xff;

        let result = ECIES::bitcore_decrypt(&encrypted, &recipient_key);
        assert!(result.is_err(), "should reject tampered bitcore ciphertext");
    }

    #[test]
    fn test_electrum_ephemeral_encrypt_decrypt() {
        let recipient_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let recipient_pub = recipient_key.to_public_key();

        let plaintext = b"ephemeral key test message";
        let encrypted = ECIES::electrum_encrypt(plaintext, &recipient_pub, None, false).unwrap();
        let decrypted = ECIES::electrum_decrypt(&encrypted, &recipient_key, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
