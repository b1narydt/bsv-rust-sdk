//! ListCertificates args/result serialization.

use super::acquire_certificate::{base64_decode, base64_encode};
use super::certificate_ser::{deserialize_certificate, serialize_certificate};
use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::BooleanDefaultFalse;
use std::collections::HashMap;

pub fn serialize_list_certificates_args(
    args: &ListCertificatesArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Certifiers
        write_varint(w, args.certifiers.len() as u64)?;
        for certifier in &args.certifiers {
            write_raw_bytes(w, &certifier.to_der())?;
        }
        // Types
        write_varint(w, args.types.len() as u64)?;
        for t in &args.types {
            write_raw_bytes(w, t.bytes())?;
        }
        // Limit and offset
        write_optional_uint32(w, args.limit)?;
        write_optional_uint32(w, args.offset)?;
        // Privileged params
        write_privileged_params(
            w,
            args.privileged.0,
            &args.privileged_reason.clone().unwrap_or_default(),
        )
    })
}

pub fn deserialize_list_certificates_args(
    data: &[u8],
) -> Result<ListCertificatesArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Certifiers
    let certifiers_len = read_varint(&mut r)?;
    let mut certifiers = Vec::with_capacity(certifiers_len as usize);
    for _ in 0..certifiers_len {
        certifiers.push(read_public_key(&mut r)?);
    }
    // Types
    let types_len = read_varint(&mut r)?;
    let mut types = Vec::with_capacity(types_len as usize);
    for _ in 0..types_len {
        let mut type_bytes = [0u8; 32];
        let tb = read_raw_bytes(&mut r, SIZE_TYPE)?;
        type_bytes.copy_from_slice(&tb);
        types.push(CertificateType(type_bytes));
    }
    // Limit, offset
    let limit = read_optional_uint32(&mut r)?;
    let offset = read_optional_uint32(&mut r)?;
    // Privileged params
    let (privileged, privileged_reason) = read_privileged_params(&mut r)?;
    Ok(ListCertificatesArgs {
        certifiers,
        types,
        limit,
        offset,
        privileged: BooleanDefaultFalse(privileged),
        privileged_reason: if privileged_reason.is_empty() {
            None
        } else {
            Some(privileged_reason)
        },
        partial: None,
    })
}

pub fn serialize_list_certificates_result(
    result: &ListCertificatesResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_varint(w, result.total_certificates as u64)?;
        for cert_result in &result.certificates {
            // Certificate as length-prefixed bytes
            let cert_bytes = serialize_certificate(&cert_result.certificate)?;
            write_bytes(w, &cert_bytes)?;
            // Keyring (flag byte + sorted map with base64 values)
            if cert_result.keyring.is_empty() {
                write_byte(w, 0)?;
            } else {
                write_byte(w, 1)?;
                let mut keys: Vec<&String> = cert_result.keyring.keys().collect();
                keys.sort();
                write_varint(w, keys.len() as u64)?;
                for key in keys {
                    write_string(w, key)?;
                    let value_bytes = base64_decode(&cert_result.keyring[key])?;
                    write_bytes(w, &value_bytes)?;
                }
            }
            // Verifier as length-prefixed bytes
            if let Some(ref v) = cert_result.verifier {
                write_bytes(w, v)?;
            } else {
                write_bytes(w, &[])?;
            }
        }
        Ok(())
    })
}

pub fn deserialize_list_certificates_result(
    data: &[u8],
) -> Result<ListCertificatesResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let total_certificates = read_varint(&mut r)? as u32;
    let mut certificates = Vec::with_capacity(total_certificates as usize);
    for _ in 0..total_certificates {
        // Certificate from length-prefixed bytes
        let cert_bytes = read_bytes(&mut r)?;
        let certificate = deserialize_certificate(&cert_bytes)?;
        // Keyring
        let keyring_flag = read_byte(&mut r)?;
        let keyring = if keyring_flag == 1 {
            let keyring_len = read_varint(&mut r)?;
            let mut map = HashMap::with_capacity(keyring_len as usize);
            for _ in 0..keyring_len {
                let key = read_string(&mut r)?;
                let value_bytes = read_bytes(&mut r)?;
                map.insert(key, base64_encode(&value_bytes));
            }
            map
        } else {
            HashMap::new()
        };
        // Verifier
        let verifier_bytes = read_bytes(&mut r)?;
        let verifier = if verifier_bytes.is_empty() {
            None
        } else {
            Some(verifier_bytes)
        };
        certificates.push(CertificateResult {
            certificate,
            keyring,
            verifier,
        });
    }
    Ok(ListCertificatesResult {
        total_certificates,
        certificates,
    })
}
