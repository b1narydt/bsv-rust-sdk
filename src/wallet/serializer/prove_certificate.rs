//! ProveCertificate args/result serialization.

use super::acquire_certificate::{base64_decode, base64_encode};
use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::BooleanDefaultFalse;
use std::collections::HashMap;

pub fn serialize_prove_certificate_args(
    args: &ProveCertificateArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Certificate type (32 bytes)
        write_raw_bytes(
            w,
            args.certificate
                .cert_type
                .as_ref()
                .expect("cert_type required")
                .bytes(),
        )?;
        // Subject (33 bytes)
        write_public_key(
            w,
            args.certificate.subject.as_ref().expect("subject required"),
        )?;
        // Serial number (32 bytes)
        write_raw_bytes(
            w,
            &args
                .certificate
                .serial_number
                .as_ref()
                .expect("serial_number required")
                .0,
        )?;
        // Certifier (33 bytes)
        write_public_key(
            w,
            args.certificate
                .certifier
                .as_ref()
                .expect("certifier required"),
        )?;
        // Revocation outpoint
        if let Some(ref outpoint) = args.certificate.revocation_outpoint {
            write_outpoint(w, outpoint)?;
        } else {
            write_raw_bytes(w, &[0u8; 32])?;
            write_varint(w, 0)?;
        }
        // Signature (length-prefixed)
        if let Some(ref sig) = args.certificate.signature {
            write_bytes(w, sig)?;
        } else {
            write_bytes(w, &[])?;
        }
        // Fields (sorted, length-prefixed key and value)
        let fields = args.certificate.fields.clone().unwrap_or_default();
        let mut keys: Vec<&String> = fields.keys().collect();
        keys.sort();
        write_varint(w, keys.len() as u64)?;
        for key in keys {
            write_bytes(w, key.as_bytes())?;
            write_bytes(w, fields[key].as_bytes())?;
        }
        // Fields to reveal
        write_varint(w, args.fields_to_reveal.len() as u64)?;
        for field in &args.fields_to_reveal {
            write_bytes(w, field.as_bytes())?;
        }
        // Verifier (33 bytes)
        write_public_key(w, &args.verifier)?;
        // Privileged params
        write_privileged_params(
            w,
            args.privileged.0,
            &args.privileged_reason.clone().unwrap_or_default(),
        )
    })
}

pub fn deserialize_prove_certificate_args(
    data: &[u8],
) -> Result<ProveCertificateArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Certificate type (32 bytes)
    let mut type_bytes = [0u8; 32];
    let tb = read_raw_bytes(&mut r, SIZE_TYPE)?;
    type_bytes.copy_from_slice(&tb);
    let cert_type = CertificateType(type_bytes);
    // Subject (33 bytes)
    let subject = read_public_key(&mut r)?;
    // Serial number (32 bytes)
    let mut sn_bytes = [0u8; 32];
    let sb = read_raw_bytes(&mut r, SIZE_SERIAL)?;
    sn_bytes.copy_from_slice(&sb);
    let serial_number = SerialNumber(sn_bytes);
    // Certifier (33 bytes)
    let certifier = read_public_key(&mut r)?;
    // Revocation outpoint
    let revocation_outpoint = Some(read_outpoint(&mut r)?);
    // Signature (length-prefixed)
    let sig_bytes = read_bytes(&mut r)?;
    let signature = if sig_bytes.is_empty() {
        None
    } else {
        Some(sig_bytes)
    };
    // Fields
    let fields_len = read_varint(&mut r)?;
    let mut fields = HashMap::with_capacity(fields_len as usize);
    for _ in 0..fields_len {
        let key = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        let value = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        fields.insert(key, value);
    }
    // Fields to reveal
    let reveal_len = read_varint(&mut r)?;
    let mut fields_to_reveal = Vec::with_capacity(reveal_len as usize);
    for _ in 0..reveal_len {
        let field = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        fields_to_reveal.push(field);
    }
    // Verifier (33 bytes)
    let verifier = read_public_key(&mut r)?;
    // Privileged params
    let (privileged, privileged_reason) = read_privileged_params(&mut r)?;
    Ok(ProveCertificateArgs {
        certificate: Certificate {
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
        }
        .into(),
        fields_to_reveal,
        verifier,
        privileged: BooleanDefaultFalse(privileged),
        privileged_reason: if privileged_reason.is_empty() {
            None
        } else {
            Some(privileged_reason)
        },
    })
}

pub fn serialize_prove_certificate_result(
    result: &ProveCertificateResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_varint(w, result.keyring_for_verifier.len() as u64)?;
        let mut keys: Vec<&String> = result.keyring_for_verifier.keys().collect();
        keys.sort();
        for key in keys {
            write_bytes(w, key.as_bytes())?;
            let value_bytes = base64_decode(&result.keyring_for_verifier[key])?;
            write_bytes(w, &value_bytes)?;
        }
        Ok(())
    })
}

pub fn deserialize_prove_certificate_result(
    data: &[u8],
) -> Result<ProveCertificateResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let keyring_len = read_varint(&mut r)?;
    let mut keyring_for_verifier = HashMap::with_capacity(keyring_len as usize);
    for _ in 0..keyring_len {
        let key = String::from_utf8(read_bytes(&mut r)?)
            .map_err(|e| WalletError::Internal(e.to_string()))?;
        let value_bytes = read_bytes(&mut r)?;
        keyring_for_verifier.insert(key, base64_encode(&value_bytes));
    }
    Ok(ProveCertificateResult {
        keyring_for_verifier,
        certificate: None,
        verifier: None,
    })
}
