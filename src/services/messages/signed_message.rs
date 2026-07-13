//! BRC-77 Signed Message implementation.
//!
//! Translates the TS SDK SignedMessage.ts. Provides sign/verify functions
//! for the BRC-77 message signing protocol using Type-42 key derivation.

use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::random::random_bytes;
use crate::primitives::signature::Signature;
use crate::services::ServicesError;

/// BRC-77 signed message version bytes.
const SIGNED_MESSAGE_VERSION: [u8; 4] = [0x42, 0x42, 0x33, 0x01];

/// Sign a message using the BRC-77 message signing protocol.
///
/// If `verifier` is None, the message can be verified by anyone using the
/// "anyone" key (PrivateKey(1)).
///
/// Binary output format:
/// [4-byte version][33-byte sender compressed pubkey]
/// [1-byte 0x00 if anyone OR 33-byte verifier compressed pubkey]
/// [32-byte keyID][DER signature]
pub fn sign(
    message: &[u8],
    signer: &PrivateKey,
    verifier: Option<&PublicKey>,
) -> Result<Vec<u8>, ServicesError> {
    let recipient_anyone = verifier.is_none();
    let verifier_key = match verifier {
        Some(v) => v.clone(),
        None => {
            // "Anyone" key: PrivateKey(1).to_public_key()
            let anyone = PrivateKey::from_hex("1")
                .map_err(|e| ServicesError::Messages(format!("anyone key: {e}")))?;
            anyone.to_public_key()
        }
    };

    let key_id = random_bytes(32);
    let key_id_base64 = to_base64(&key_id);
    let invoice_number = format!("2-message signing-{key_id_base64}");

    let signing_key = signer
        .derive_child(&verifier_key, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive signing key: {e}")))?;

    let signature = signing_key
        .sign(message, true)
        .map_err(|e| ServicesError::Messages(format!("sign: {e}")))?;
    let sig_der = signature.to_der();

    let sender_pubkey = signer.to_public_key().to_der();

    let mut result =
        Vec::with_capacity(4 + 33 + if recipient_anyone { 1 } else { 33 } + 32 + sig_der.len());
    result.extend_from_slice(&SIGNED_MESSAGE_VERSION);
    result.extend_from_slice(&sender_pubkey);
    if recipient_anyone {
        result.push(0x00);
    } else {
        result.extend_from_slice(&verifier_key.to_der());
    }
    result.extend_from_slice(&key_id);
    result.extend_from_slice(&sig_der);

    Ok(result)
}

/// Verify a BRC-77 signed message.
///
/// If the message was signed for a specific verifier, `recipient` must be
/// that verifier's private key. If the message was signed for "anyone",
/// `recipient` can be None.
///
/// Returns the sender's public key on success.
pub fn verify(
    signed_message: &[u8],
    message: &[u8],
    recipient: Option<&PrivateKey>,
) -> Result<PublicKey, ServicesError> {
    if signed_message.len() < 4 {
        return Err(ServicesError::Messages(
            "signed message too short".to_string(),
        ));
    }

    // Parse version.
    let version = &signed_message[0..4];
    if version != SIGNED_MESSAGE_VERSION {
        return Err(ServicesError::Messages(format!(
            "Message version mismatch: expected {:02x}{:02x}{:02x}{:02x}, received {:02x}{:02x}{:02x}{:02x}",
            SIGNED_MESSAGE_VERSION[0], SIGNED_MESSAGE_VERSION[1],
            SIGNED_MESSAGE_VERSION[2], SIGNED_MESSAGE_VERSION[3],
            version[0], version[1], version[2], version[3]
        )));
    }

    let mut pos = 4;

    // Parse sender public key (33 bytes).
    if pos + 33 > signed_message.len() {
        return Err(ServicesError::Messages(
            "truncated sender pubkey".to_string(),
        ));
    }
    let sender_bytes = &signed_message[pos..pos + 33];
    let sender = PublicKey::from_der_bytes(sender_bytes)
        .map_err(|e| ServicesError::Messages(format!("invalid sender pubkey: {e}")))?;
    pos += 33;

    // Parse verifier indicator.
    if pos >= signed_message.len() {
        return Err(ServicesError::Messages(
            "truncated verifier field".to_string(),
        ));
    }

    let verifier_first = signed_message[pos];
    pos += 1;

    let actual_recipient: PrivateKey;
    if verifier_first == 0x00 {
        // Anyone mode.
        actual_recipient = PrivateKey::from_hex("1")
            .map_err(|e| ServicesError::Messages(format!("anyone key: {e}")))?;
    } else {
        // Specific verifier: read remaining 32 bytes to form 33-byte compressed pubkey.
        if pos + 32 > signed_message.len() {
            return Err(ServicesError::Messages(
                "truncated verifier pubkey".to_string(),
            ));
        }
        let mut verifier_bytes = vec![verifier_first];
        verifier_bytes.extend_from_slice(&signed_message[pos..pos + 32]);
        pos += 32;

        let verifier_pubkey = PublicKey::from_der_bytes(&verifier_bytes)
            .map_err(|e| ServicesError::Messages(format!("invalid verifier pubkey: {e}")))?;

        match recipient {
            Some(r) => {
                let recipient_pubkey = r.to_public_key();
                if recipient_pubkey != verifier_pubkey {
                    return Err(ServicesError::Messages(format!(
                        "Recipient public key mismatch: expected {}, got {}",
                        hex_encode(&verifier_pubkey.to_der()),
                        hex_encode(&recipient_pubkey.to_der()),
                    )));
                }
                actual_recipient = r.clone();
            }
            None => {
                return Err(ServicesError::Messages(format!(
                    "This signature requires a specific private key to verify. \
                     Associated public key: {}",
                    hex_encode(&verifier_pubkey.to_der()),
                )));
            }
        }
    }

    // Parse keyID (32 bytes).
    if pos + 32 > signed_message.len() {
        return Err(ServicesError::Messages("truncated keyID".to_string()));
    }
    let key_id = &signed_message[pos..pos + 32];
    pos += 32;

    // Parse DER signature (remaining bytes).
    if pos >= signed_message.len() {
        return Err(ServicesError::Messages("truncated signature".to_string()));
    }
    let sig_der = &signed_message[pos..];
    let signature = Signature::from_der(sig_der)
        .map_err(|e| ServicesError::Messages(format!("invalid DER signature: {e}")))?;

    // Recompute the verification key.
    // In the TS SDK verify: signingKey = signer.deriveChild(recipient, invoiceNumber)
    // signer is PublicKey (sender), recipient is PrivateKey
    // PublicKey.deriveChild(PrivateKey, invoice) -> returns PublicKey
    let key_id_base64 = to_base64(key_id);
    let invoice_number = format!("2-message signing-{key_id_base64}");

    let verification_key = sender
        .derive_child(&actual_recipient, &invoice_number)
        .map_err(|e| ServicesError::Messages(format!("derive verification key: {e}")))?;

    // Verify the signature.
    if verification_key.verify(message, &signature) {
        Ok(sender)
    } else {
        Err(ServicesError::Messages(
            "signature verification failed".to_string(),
        ))
    }
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
    fn test_sign_verify_round_trip_specific_verifier() {
        let signer = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();
        let verifier_priv = PrivateKey::from_hex(
            "c8bc2c2575f2cf350b5aa0f3497b4e38f70270cd53d23b29da54ea3a685bbf39",
        )
        .unwrap();
        let verifier_pub = verifier_priv.to_public_key();

        let message = b"Hello BRC-77!";
        let signed = sign(message, &signer, Some(&verifier_pub)).unwrap();

        let sender_back = verify(&signed, message, Some(&verifier_priv)).unwrap();
        let expected_sender = signer.to_public_key();
        assert_eq!(sender_back.to_der(), expected_sender.to_der());
    }

    #[test]
    fn test_sign_verify_round_trip_anyone() {
        let signer = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();

        let message = b"Public announcement";
        let signed = sign(message, &signer, None).unwrap();

        // Verify with None (anyone).
        let sender_back = verify(&signed, message, None).unwrap();
        let expected_sender = signer.to_public_key();
        assert_eq!(sender_back.to_der(), expected_sender.to_der());
    }

    #[test]
    fn test_verify_rejects_tampered_message() {
        let signer = PrivateKey::from_hex(
            "e6baf19a8b0f6d2ab882bc22e53ef18587e1b2a35ce998d4dbeb3e5f97647e0e",
        )
        .unwrap();

        let message = b"Original message";
        let signed = sign(message, &signer, None).unwrap();

        let tampered = b"Tampered message";
        let result = verify(&signed, tampered, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_version() {
        let mut bad_msg = vec![0xFF, 0xFF, 0xFF, 0xFF];
        bad_msg.extend_from_slice(&[0u8; 100]);
        let result = verify(&bad_msg, b"message", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version mismatch"));
    }

    #[test]
    fn test_signed_message_format_anyone() {
        let signer = PrivateKey::from_hex("1").unwrap();
        let message = b"test";
        let signed = sign(message, &signer, None).unwrap();

        // Version (4) + sender pubkey (33) + anyone byte (1) + keyID (32) + DER sig (variable)
        assert!(signed.len() >= 4 + 33 + 1 + 32);
        assert_eq!(&signed[0..4], &SIGNED_MESSAGE_VERSION);
        // Anyone byte at offset 37
        assert_eq!(signed[37], 0x00);
    }

    #[test]
    fn test_signed_message_format_specific() {
        let signer = PrivateKey::from_hex("1").unwrap();
        let verifier_priv = PrivateKey::from_hex("2").unwrap();
        let verifier_pub = verifier_priv.to_public_key();
        let message = b"test";
        let signed = sign(message, &signer, Some(&verifier_pub)).unwrap();

        // Version (4) + sender pubkey (33) + verifier pubkey (33) + keyID (32) + DER sig
        assert!(signed.len() >= 4 + 33 + 33 + 32);
        assert_eq!(&signed[0..4], &SIGNED_MESSAGE_VERSION);
        // First byte of verifier should be 0x02 or 0x03 (compressed pubkey prefix)
        assert!(signed[37] == 0x02 || signed[37] == 0x03);
    }
}
