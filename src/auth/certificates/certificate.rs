//! AuthCertificate: auth-layer wrapper around wallet::Certificate.
//!
//! Provides sign, verify, field encryption/decryption, and serialization
//! methods for the BRC-31 certificate protocol. Translates from
//! TS SDK Certificate.ts and Go SDK certificate.go.

use std::collections::HashMap;
use std::ops::Deref;

use crate::auth::AuthError;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::interfaces::{
    Certificate, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    VerifySignatureArgs, WalletInterface,
};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Protocol string used when signing/verifying certificates.
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";

/// Protocol string used when encrypting/decrypting certificate field keys.
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";

/// Security level for certificate operations.
pub const SECURITY_LEVEL: u8 = 2;

// ---------------------------------------------------------------------------
// Base64 encode/decode helpers (self-contained, no external crate)
// ---------------------------------------------------------------------------

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    fn char_to_val(c: u8) -> Result<u8, AuthError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(AuthError::SerializationError(format!(
                "invalid base64 character: {}",
                c as char
            ))),
        }
    }
    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            break;
        }
        let a = char_to_val(bytes[i])?;
        let b = if i + 1 < bytes.len() && bytes[i + 1] != b'=' {
            char_to_val(bytes[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            char_to_val(bytes[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            char_to_val(bytes[i + 3])?
        } else {
            0
        };
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// AuthCertificate
// ---------------------------------------------------------------------------

/// Auth-layer wrapper around wallet::Certificate.
///
/// Adds sign, verify, and field encryption/decryption methods used by
/// the BRC-31 authentication protocol. Derefs to the inner
/// wallet::Certificate for transparent field access.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthCertificate {
    /// The underlying wallet Certificate.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Certificate,
}

impl Deref for AuthCertificate {
    type Target = Certificate;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AuthCertificate {
    /// Create a new AuthCertificate wrapping the given wallet Certificate.
    pub fn new(inner: Certificate) -> Self {
        AuthCertificate { inner }
    }

    /// Serialize the certificate to binary for signing/verification.
    ///
    /// Follows the TS SDK Certificate.toBinary(false) format:
    /// cert_type(32) + serial_number(32) + subject(33) + certifier(33)
    /// + revocation_outpoint(txid_32 + varint_output_index)
    /// + varint(num_fields) + for each field: varint(name_len) + name + varint(val_len) + val
    fn to_binary_for_signing(cert: &Certificate) -> Vec<u8> {
        let mut data = Vec::new();

        // cert_type: 32 bytes
        data.extend_from_slice(&cert.cert_type.0);

        // serial_number: 32 bytes
        data.extend_from_slice(&cert.serial_number.0);

        // subject: 33 bytes compressed public key
        let subject_bytes = cert.subject.to_der();
        data.extend_from_slice(&subject_bytes);

        // certifier: 33 bytes compressed public key
        let certifier_bytes = cert.certifier.to_der();
        data.extend_from_slice(&certifier_bytes);

        // revocation_outpoint: txid(32 bytes) + varint(output_index)
        if let Some(ref outpoint) = cert.revocation_outpoint {
            if let Some(dot_idx) = outpoint.find('.') {
                let txid_hex = &outpoint[..dot_idx];
                let output_index_str = &outpoint[dot_idx + 1..];
                // Decode txid hex to bytes
                let txid_bytes = hex_decode(txid_hex);
                data.extend_from_slice(&txid_bytes);
                // Write output index as varint
                let output_index: u64 = output_index_str.parse().unwrap_or(0);
                write_varint(&mut data, output_index);
            }
        }

        // fields: sorted by name
        if let Some(ref fields) = cert.fields {
            let mut field_names: Vec<&String> = fields.keys().collect();
            field_names.sort();
            write_varint(&mut data, field_names.len() as u64);
            for name in field_names {
                let name_bytes = name.as_bytes();
                write_varint(&mut data, name_bytes.len() as u64);
                data.extend_from_slice(name_bytes);

                let value = &fields[name];
                let value_bytes = value.as_bytes();
                write_varint(&mut data, value_bytes.len() as u64);
                data.extend_from_slice(value_bytes);
            }
        } else {
            write_varint(&mut data, 0);
        }

        data
    }

    /// Sign the certificate using the certifier wallet.
    ///
    /// Sets the certificate's signature field. The certifier wallet's identity
    /// key is used as the signing key.
    ///
    /// Translated from TS SDK Certificate.prototype.sign().
    pub async fn sign<W: WalletInterface + ?Sized>(
        cert: &mut Certificate,
        wallet: &W,
    ) -> Result<(), AuthError> {
        if cert.signature.is_some() {
            return Err(AuthError::CertificateValidation(
                "certificate has already been signed".to_string(),
            ));
        }

        // Set certifier to the wallet's identity key
        let identity_result = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;
        cert.certifier = identity_result.public_key;

        let preimage = Self::to_binary_for_signing(cert);
        let key_id = format!(
            "{} {}",
            base64_encode(&cert.cert_type.0),
            base64_encode(&cert.serial_number.0)
        );

        let result = wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(preimage),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: SECURITY_LEVEL,
                        protocol: CERTIFICATE_SIGNATURE_PROTOCOL.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Uninitialized,
                        public_key: None,
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        cert.signature = Some(result.signature);
        Ok(())
    }

    /// Verify the certificate's signature.
    ///
    /// Uses an "anyone" wallet (ProtoWallet with no specific identity) to verify
    /// that the certifier actually signed this certificate.
    ///
    /// Translated from TS SDK Certificate.prototype.verify().
    pub async fn verify<W: WalletInterface + ?Sized>(
        cert: &Certificate,
        wallet: &W,
    ) -> Result<bool, AuthError> {
        let preimage = Self::to_binary_for_signing(cert);
        let signature = cert.signature.clone().unwrap_or_default();
        let key_id = format!(
            "{} {}",
            base64_encode(&cert.cert_type.0),
            base64_encode(&cert.serial_number.0)
        );

        let result = wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(preimage),
                    hash_to_directly_verify: None,
                    signature,
                    protocol_id: Protocol {
                        security_level: SECURITY_LEVEL,
                        protocol: CERTIFICATE_SIGNATURE_PROTOCOL.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(cert.certifier.clone()),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        Ok(result.valid)
    }

    /// Get the protocol ID and key ID for certificate field encryption.
    ///
    /// For master cert fields (no serial number yet), pass None for serial_number
    /// and the key_id is just the field_name. For verifiable certificate keyrings,
    /// pass Some(serial_number) and key_id is "{serial_number} {field_name}".
    ///
    /// Translated from TS SDK Certificate.getCertificateFieldEncryptionDetails().
    pub fn get_certificate_field_encryption_details(
        field_name: &str,
        serial_number: Option<&str>,
    ) -> (Protocol, String) {
        let key_id = match serial_number {
            Some(sn) => format!("{} {}", sn, field_name),
            None => field_name.to_string(),
        };
        (
            Protocol {
                security_level: SECURITY_LEVEL,
                protocol: CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL.to_string(),
            },
            key_id,
        )
    }

    /// Encrypt certificate fields using the wallet.
    ///
    /// For each field, generates a random symmetric key, encrypts the field value
    /// with it, then encrypts the symmetric key using the wallet's encrypt method
    /// for the given counterparty.
    ///
    /// Returns (encrypted_fields, keyring) where encrypted_fields maps field names
    /// to base64-encoded encrypted values, and keyring maps field names to
    /// base64-encoded encrypted symmetric keys.
    pub async fn encrypt_fields<W: WalletInterface + ?Sized>(
        fields: &HashMap<String, String>,
        serial_number: Option<&str>,
        counterparty: &PublicKey,
        wallet: &W,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>), AuthError> {
        let mut encrypted_fields = HashMap::new();
        let mut keyring = HashMap::new();

        for (field_name, field_value) in fields {
            // Generate random symmetric key
            let sym_key = SymmetricKey::from_random();

            // Encrypt field value with symmetric key
            let encrypted_value = sym_key.encrypt(field_value.as_bytes())?;
            encrypted_fields.insert(field_name.clone(), base64_encode(&encrypted_value));

            // Encrypt the symmetric key for the counterparty
            let (protocol, key_id) =
                Self::get_certificate_field_encryption_details(field_name, serial_number);

            let encrypt_result = wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: sym_key.to_bytes(),
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(counterparty.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            keyring.insert(
                field_name.clone(),
                base64_encode(&encrypt_result.ciphertext),
            );
        }

        Ok((encrypted_fields, keyring))
    }

    /// Decrypt certificate fields using a keyring and the wallet.
    ///
    /// For each field in the keyring:
    /// 1. Decrypt the keyring entry to get the symmetric key
    /// 2. Use the symmetric key to decrypt the field value
    ///
    /// The counterparty is the subject (the party who encrypted the fields).
    pub async fn decrypt_fields<W: WalletInterface + ?Sized>(
        encrypted_fields: &HashMap<String, String>,
        keyring: &HashMap<String, String>,
        serial_number: &str,
        counterparty: &PublicKey,
        wallet: &W,
    ) -> Result<HashMap<String, String>, AuthError> {
        if keyring.is_empty() {
            return Err(AuthError::CertificateValidation(
                "a keyring is required to decrypt certificate fields".to_string(),
            ));
        }

        let mut decrypted = HashMap::new();

        for (field_name, encrypted_key_b64) in keyring {
            // Decrypt the field revelation key from the keyring
            let encrypted_key = base64_decode(encrypted_key_b64)?;
            let (protocol, key_id) =
                Self::get_certificate_field_encryption_details(field_name, Some(serial_number));

            let decrypt_result = wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: encrypted_key,
                        protocol_id: protocol,
                        key_id,
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(counterparty.clone()),
                        },
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await?;

            // Use the decrypted symmetric key to decrypt the field value
            let sym_key = SymmetricKey::from_bytes(&decrypt_result.plaintext)?;
            let encrypted_field_value = match encrypted_fields.get(field_name) {
                Some(v) => base64_decode(v)?,
                None => {
                    return Err(AuthError::CertificateValidation(format!(
                        "field '{}' not found in encrypted fields",
                        field_name
                    )));
                }
            };
            let plaintext_bytes = sym_key.decrypt(&encrypted_field_value)?;
            let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| {
                AuthError::CertificateValidation(format!(
                    "decrypted field '{}' is not valid UTF-8: {}",
                    field_name, e
                ))
            })?;
            decrypted.insert(field_name.clone(), plaintext);
        }

        Ok(decrypted)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Decode hex string to bytes.
fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    let hex_bytes = hex.as_bytes();
    while i + 1 < hex_bytes.len() {
        let hi = hex_nibble(hex_bytes[i]);
        let lo = hex_nibble(hex_bytes[i + 1]);
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    bytes
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Write a Bitcoin-style varint to a buffer.
fn write_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}
