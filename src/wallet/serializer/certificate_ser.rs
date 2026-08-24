//! Shared certificate serialization/deserialization helpers.
//!
//! Used by list_certificates, prove_certificate, and discovery result serializers.

use super::acquire_certificate::{base64_decode, base64_encode};
use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use indexmap::IndexMap;

/// Serialize a Certificate (including signature at the end).
pub fn serialize_certificate(cert: &Certificate) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Type (32 bytes)
        write_raw_bytes(w, cert.cert_type.bytes())?;
        // Serial number (32 bytes)
        write_raw_bytes(w, &cert.serial_number.0)?;
        // Subject (33 bytes)
        write_public_key(w, &cert.subject)?;
        // Certifier (33 bytes)
        write_public_key(w, &cert.certifier)?;
        // Revocation outpoint
        if let Some(ref outpoint) = cert.revocation_outpoint {
            write_outpoint(w, outpoint)?;
        } else {
            // Write zeroed outpoint
            write_raw_bytes(w, &[0u8; 32])?;
            write_varint(w, 0)?;
        }
        // Fields (sorted by key)
        let fields = cert.fields.clone().unwrap_or_default();
        let mut keys: Vec<&String> = fields.keys().collect();
        keys.sort();
        write_varint(w, keys.len() as u64)?;
        for key in keys {
            write_bytes(w, key.as_bytes())?;
            write_bytes(w, fields[key].as_bytes())?;
        }
        // Signature (raw bytes at end, no length prefix)
        if let Some(ref sig) = cert.signature {
            write_raw_bytes(w, sig)?;
        }
        Ok(())
    })
}

/// Deserialize a Certificate from length-prefixed bytes (as used in list results).
pub fn deserialize_certificate(data: &[u8]) -> Result<Certificate, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Type (32 bytes)
    let mut type_bytes = [0u8; 32];
    let tb = read_raw_bytes(&mut r, SIZE_TYPE)?;
    type_bytes.copy_from_slice(&tb);
    let cert_type = CertificateType(type_bytes);
    // Serial number (32 bytes)
    let mut sn_bytes = [0u8; 32];
    let sb = read_raw_bytes(&mut r, SIZE_SERIAL)?;
    sn_bytes.copy_from_slice(&sb);
    let serial_number = SerialNumber(sn_bytes);
    // Subject (33 bytes)
    let subject = read_public_key(&mut r)?;
    // Certifier (33 bytes)
    let certifier = read_public_key(&mut r)?;
    // Revocation outpoint
    let revocation_outpoint = Some(read_outpoint(&mut r)?);
    // Fields
    let fields_len = read_varint(&mut r)?;
    let mut fields = IndexMap::with_capacity(fields_len as usize);
    for _ in 0..fields_len {
        let key = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        let value = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        fields.insert(key, value);
    }
    // Signature (remaining bytes)
    let pos = r.position() as usize;
    let remaining = &data[pos..];
    let signature = if remaining.is_empty() {
        None
    } else {
        Some(remaining.to_vec())
    };
    Ok(Certificate {
        cert_type,
        serial_number,
        subject,
        certifier,
        revocation_outpoint,
        fields: if fields.is_empty() {
            None
        } else {
            Some(fields)
        },
        signature,
    })
}

/// Serialize an IdentityCertificate for discovery results.
pub fn serialize_identity_certificate(cert: &IdentityCertificate) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Base certificate as length-prefixed bytes
        let cert_bytes = serialize_certificate(&cert.certificate)?;
        write_bytes(w, &cert_bytes)?;
        // CertifierInfo
        write_string(w, &cert.certifier_info.name)?;
        write_string(w, &cert.certifier_info.icon_url)?;
        write_string(w, &cert.certifier_info.description)?;
        write_byte(w, cert.certifier_info.trust)?;
        // TS serializes both maps with Object.entries insertion order.
        write_varint(w, cert.publicly_revealed_keyring.len() as u64)?;
        for (key, value) in &cert.publicly_revealed_keyring {
            write_string(w, key)?;
            let value_bytes = base64_decode(value)?;
            write_bytes(w, &value_bytes)?;
        }
        write_varint(w, cert.decrypted_fields.len() as u64)?;
        for (key, value) in &cert.decrypted_fields {
            write_string(w, key)?;
            write_string(w, value)?;
        }
        Ok(())
    })
}

/// Deserialize an IdentityCertificate from a reader.
pub fn deserialize_identity_certificate(
    reader: &mut impl std::io::Read,
) -> Result<IdentityCertificate, WalletError> {
    // Base certificate from length-prefixed bytes
    let cert_bytes = read_bytes(reader)?;
    let certificate = deserialize_certificate(&cert_bytes)?;
    // CertifierInfo
    let name = read_string(reader)?;
    let icon_url = read_string(reader)?;
    let description = read_string(reader)?;
    let trust = read_byte(reader)?;
    // PubliclyRevealedKeyring
    let keyring_len = read_varint(reader)?;
    let mut publicly_revealed_keyring = IndexMap::with_capacity(keyring_len as usize);
    for _ in 0..keyring_len {
        let key = read_string(reader)?;
        let value_bytes = read_bytes(reader)?;
        publicly_revealed_keyring.insert(key, base64_encode(&value_bytes));
    }
    // DecryptedFields
    let decrypted_fields_len = read_varint(reader)?;
    let mut decrypted_fields = IndexMap::with_capacity(decrypted_fields_len as usize);
    for _ in 0..decrypted_fields_len {
        decrypted_fields.insert(read_string(reader)?, read_string(reader)?);
    }
    Ok(IdentityCertificate {
        certificate,
        certifier_info: IdentityCertifier {
            name,
            icon_url,
            description,
            trust,
        },
        publicly_revealed_keyring,
        decrypted_fields,
    })
}
