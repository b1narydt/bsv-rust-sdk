//! BRC-78 Encrypted Message implementation.
//!
//! Translates the TS SDK EncryptedMessage.ts. Provides encrypt/decrypt functions
//! for the BRC-78 message encryption protocol using Type-42 key derivation
//! and AES-GCM symmetric encryption.

use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::random::random_bytes;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::services::ServicesError;

/// BRC-78 encrypted message version bytes.
const ENCRYPTED_MESSAGE_VERSION: [u8; 4] = [0x42, 0x42, 0x10, 0x33];

/// Encrypt a message using the BRC-78 message encryption protocol.
///
/// Binary output format:
/// [4-byte version][33-byte sender compressed pubkey]
/// [33-byte recipient compressed pubkey][32-byte keyID][encrypted data]
pub fn encrypt(
    message: &[u8],
    sender: &PrivateKey,
    recipient: &PublicKey,
) -> Result<Vec<u8>, ServicesError> {
    let key_id = random_bytes(32);
    let key_id_base64 = to_base64(&key_id);
    let invoice_number = format!("2-message encryption-{key_id_base64}");

    // Derive child keys using Type-42.
    // sender_derived_priv = sender_priv.derive_child(recipient_pub, invoice)
    let sender_derived_priv = sender
        .derive_child(recipient, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive sender child: {e}")))?;

    // recipient_derived_pub = recipient_pub.derive_child(sender_priv, invoice)
    let recipient_derived_pub = recipient
        .derive_child(sender, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive recipient child: {e}")))?;

    // Compute shared secret: sender_derived_priv * recipient_derived_pub
    let shared_secret = sender_derived_priv
        .derive_shared_secret(&recipient_derived_pub)
        .map_err(|e| ServicesError::Messages(format!("shared secret: {e}")))?;

    // Derive symmetric key from shared secret (compressed, skip prefix byte).
    let shared_compressed = shared_secret.to_der(true);
    let sym_key = SymmetricKey::from_bytes(&shared_compressed[1..])
        .map_err(|e| ServicesError::Messages(format!("symmetric key: {e}")))?;

    // Encrypt the message.
    let encrypted = sym_key
        .encrypt(message)
        .map_err(|e| ServicesError::Messages(format!("encrypt: {e}")))?;

    // Assemble output.
    let sender_pubkey = sender.to_public_key().to_der();
    let recipient_pubkey = recipient.to_der();

    let mut result = Vec::with_capacity(4 + 33 + 33 + 32 + encrypted.len());
    result.extend_from_slice(&ENCRYPTED_MESSAGE_VERSION);
    result.extend_from_slice(&sender_pubkey);
    result.extend_from_slice(&recipient_pubkey);
    result.extend_from_slice(&key_id);
    result.extend_from_slice(&encrypted);

    Ok(result)
}

/// Decrypt a BRC-78 encrypted message.
///
/// Returns (plaintext, sender_pubkey) on success.
pub fn decrypt(
    encrypted_message: &[u8],
    recipient: &PrivateKey,
) -> Result<(Vec<u8>, PublicKey), ServicesError> {
    if encrypted_message.len() < 4 + 33 + 33 + 32 {
        return Err(ServicesError::Messages(
            "encrypted message too short".to_string(),
        ));
    }

    // Parse version.
    let version = &encrypted_message[0..4];
    if version != ENCRYPTED_MESSAGE_VERSION {
        return Err(ServicesError::Messages(format!(
            "Message version mismatch: expected {:02x}{:02x}{:02x}{:02x}, received {:02x}{:02x}{:02x}{:02x}",
            ENCRYPTED_MESSAGE_VERSION[0], ENCRYPTED_MESSAGE_VERSION[1],
            ENCRYPTED_MESSAGE_VERSION[2], ENCRYPTED_MESSAGE_VERSION[3],
            version[0], version[1], version[2], version[3]
        )));
    }

    let mut pos = 4;

    // Parse sender public key (33 bytes).
    let sender_pub = PublicKey::from_der_bytes(&encrypted_message[pos..pos + 33])
        .map_err(|e| ServicesError::Messages(format!("invalid sender pubkey: {e}")))?;
    pos += 33;

    // Parse expected recipient public key (33 bytes).
    let expected_recipient_bytes = &encrypted_message[pos..pos + 33];
    pos += 33;

    // Verify recipient matches.
    let actual_recipient_pubkey = recipient.to_public_key();
    let actual_recipient_bytes = actual_recipient_pubkey.to_der();
    if expected_recipient_bytes != actual_recipient_bytes.as_slice() {
        return Err(ServicesError::Messages(format!(
            "Recipient public key mismatch: expected {}, got {}",
            hex_encode(expected_recipient_bytes),
            hex_encode(&actual_recipient_bytes),
        )));
    }

    // Parse keyID (32 bytes).
    let key_id = &encrypted_message[pos..pos + 32];
    pos += 32;

    // Parse encrypted data (remaining bytes).
    let encrypted_data = &encrypted_message[pos..];

    // Recompute shared secret using Type-42 derivation.
    let key_id_base64 = to_base64(key_id);
    let invoice_number = format!("2-message encryption-{key_id_base64}");

    // In decrypt context (matching TS SDK):
    // sender_derived_pub = sender_pub.derive_child(recipient_priv, invoice) -> PublicKey
    let sender_derived_pub = sender_pub
        .derive_child(recipient, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive sender child pub: {e}")))?;

    // recipient_derived_priv = recipient_priv.derive_child(sender_pub, invoice) -> PrivateKey
    let recipient_derived_priv = recipient
        .derive_child(&sender_pub, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive recipient child priv: {e}")))?;

    // shared_secret = recipient_derived_priv * sender_derived_pub
    let shared_secret = recipient_derived_priv
        .derive_shared_secret(&sender_derived_pub)
        .map_err(|e| ServicesError::Messages(format!("shared secret: {e}")))?;

    let shared_compressed = shared_secret.to_der(true);
    let sym_key = SymmetricKey::from_bytes(&shared_compressed[1..])
        .map_err(|e| ServicesError::Messages(format!("symmetric key: {e}")))?;

    let plaintext = sym_key
        .decrypt(encrypted_data)
        .map_err(|e| ServicesError::Messages(format!("decrypt: {e}")))?;

    Ok((plaintext, sender_pub))
}

/// Inline base64 encoder (no external crate dependency).
fn to_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let sender = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();
        let recipient_priv = PrivateKey::from_hex(
            "c8bc2c2575f2cf350b5aa0f3497b4e38f70270cd53d23b29da54ea3a685bbf39",
        )
        .unwrap();
        let recipient_pub = recipient_priv.to_public_key();

        let message = b"Hello BRC-78!";
        let encrypted = encrypt(message, &sender, &recipient_pub).unwrap();
        let (decrypted, sender_back) = decrypt(&encrypted, &recipient_priv).unwrap();

        assert_eq!(decrypted, message);
        let expected_sender = sender.to_public_key();
        assert_eq!(sender_back.to_der(), expected_sender.to_der());
    }

    #[test]
    fn test_decrypt_wrong_recipient_fails() {
        let sender = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();
        let recipient_priv = PrivateKey::from_hex(
            "c8bc2c2575f2cf350b5aa0f3497b4e38f70270cd53d23b29da54ea3a685bbf39",
        )
        .unwrap();
        let wrong_recipient = PrivateKey::from_hex("1").unwrap();
        let recipient_pub = recipient_priv.to_public_key();

        let message = b"Secret!";
        let encrypted = encrypt(message, &sender, &recipient_pub).unwrap();

        let result = decrypt(&encrypted, &wrong_recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rejects_tampered_ciphertext() {
        let sender = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();
        let recipient_priv = PrivateKey::from_hex(
            "c8bc2c2575f2cf350b5aa0f3497b4e38f70270cd53d23b29da54ea3a685bbf39",
        )
        .unwrap();
        let recipient_pub = recipient_priv.to_public_key();

        let message = b"Tamper test";
        let mut encrypted = encrypt(message, &sender, &recipient_pub).unwrap();

        // Tamper with a ciphertext byte (after header).
        if encrypted.len() > 110 {
            encrypted[110] ^= 0xff;
        }

        let result = decrypt(&encrypted, &recipient_priv);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_message_format() {
        let sender = PrivateKey::from_hex("1").unwrap();
        let recipient_priv = PrivateKey::from_hex("2").unwrap();
        let recipient_pub = recipient_priv.to_public_key();

        let message = b"test";
        let encrypted = encrypt(message, &sender, &recipient_pub).unwrap();

        // Version (4) + sender (33) + recipient (33) + keyID (32) + encrypted data
        assert!(encrypted.len() >= 4 + 33 + 33 + 32);
        assert_eq!(&encrypted[0..4], &ENCRYPTED_MESSAGE_VERSION);
    }
}
