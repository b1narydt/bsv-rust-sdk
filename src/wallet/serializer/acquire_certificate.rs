//! AcquireCertificate args serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use std::collections::HashMap;

const ACQUISITION_PROTOCOL_DIRECT: u8 = 1;
const ACQUISITION_PROTOCOL_ISSUANCE: u8 = 2;
const KEYRING_REVEALER_CERTIFIER: u8 = 11;

pub fn serialize_acquire_certificate_args(
    args: &AcquireCertificateArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Type (32 bytes)
        write_raw_bytes(w, args.cert_type.bytes())?;
        // Certifier (33 bytes)
        write_public_key(w, &args.certifier)?;
        // Fields (sorted map)
        write_string_map(w, &args.fields)?;
        // Privileged params
        write_privileged_params(
            w,
            Some(args.privileged),
            &args.privileged_reason.clone().unwrap_or_default(),
        )?;
        // Acquisition protocol
        match args.acquisition_protocol {
            AcquisitionProtocol::Direct => {
                write_byte(w, ACQUISITION_PROTOCOL_DIRECT)?;
                // Serial number
                let sn = args.serial_number.as_ref().ok_or_else(|| {
                    WalletError::Internal(
                        "serial number required for direct acquisition".to_string(),
                    )
                })?;
                write_raw_bytes(w, &sn.0)?;
                // Revocation outpoint
                let rev = args.revocation_outpoint.as_ref().ok_or_else(|| {
                    WalletError::Internal(
                        "revocation outpoint required for direct acquisition".to_string(),
                    )
                })?;
                write_outpoint(w, rev)?;
                // Signature
                write_bytes(w, args.signature.as_deref().unwrap_or(&[]))?;
                // Keyring revealer
                let kr = args.keyring_revealer.as_ref().ok_or_else(|| {
                    WalletError::Internal(
                        "keyring revealer required for direct acquisition".to_string(),
                    )
                })?;
                match kr {
                    KeyringRevealer::Certifier => write_byte(w, KEYRING_REVEALER_CERTIFIER)?,
                    KeyringRevealer::PubKey(pk) => write_public_key(w, pk)?,
                }
                // Keyring for subject
                let keyring = args.keyring_for_subject.clone().unwrap_or_default();
                let mut keys: Vec<&String> = keyring.keys().collect();
                keys.sort();
                write_varint(w, keys.len() as u64)?;
                for key in keys {
                    write_bytes(w, key.as_bytes())?;
                    // Values are base64-encoded in Go SDK
                    let value_bytes = base64_decode(&keyring[key])?;
                    write_bytes(w, &value_bytes)?;
                }
            }
            AcquisitionProtocol::Issuance => {
                write_byte(w, ACQUISITION_PROTOCOL_ISSUANCE)?;
                write_string(w, &args.certifier_url.clone().unwrap_or_default())?;
            }
        }
        Ok(())
    })
}

pub fn deserialize_acquire_certificate_args(
    data: &[u8],
) -> Result<AcquireCertificateArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let mut type_bytes = [0u8; 32];
    let tb = read_raw_bytes(&mut r, SIZE_TYPE)?;
    type_bytes.copy_from_slice(&tb);
    let cert_type = CertificateType(type_bytes);
    let certifier = read_public_key(&mut r)?;
    let fields = read_string_map(&mut r)?;
    let (privileged, privileged_reason) = read_privileged_params(&mut r)?;
    let protocol_byte = read_byte(&mut r)?;
    let acquisition_protocol = match protocol_byte {
        ACQUISITION_PROTOCOL_DIRECT => AcquisitionProtocol::Direct,
        ACQUISITION_PROTOCOL_ISSUANCE => AcquisitionProtocol::Issuance,
        _ => {
            return Err(WalletError::Internal(format!(
                "invalid acquisition protocol: {protocol_byte}"
            )))
        }
    };
    let (
        serial_number,
        revocation_outpoint,
        signature,
        keyring_revealer,
        keyring_for_subject,
        certifier_url,
    ) = if acquisition_protocol == AcquisitionProtocol::Direct {
        let mut sn_bytes = [0u8; 32];
        let sb = read_raw_bytes(&mut r, SIZE_SERIAL)?;
        sn_bytes.copy_from_slice(&sb);
        let serial_number = Some(SerialNumber(sn_bytes));
        let revocation_outpoint = Some(read_outpoint(&mut r)?);
        let sig_bytes = read_bytes(&mut r)?;
        let signature = if sig_bytes.is_empty() {
            None
        } else {
            Some(sig_bytes)
        };
        // Keyring revealer
        let kr_byte = read_byte(&mut r)?;
        let keyring_revealer = if kr_byte == KEYRING_REVEALER_CERTIFIER {
            Some(KeyringRevealer::Certifier)
        } else {
            let mut full_bytes = vec![kr_byte];
            let rest = read_raw_bytes(&mut r, SIZE_PUB_KEY - 1)?;
            full_bytes.extend_from_slice(&rest);
            let pk = crate::primitives::public_key::PublicKey::from_der_bytes(&full_bytes)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            Some(KeyringRevealer::PubKey(pk))
        };
        // Keyring for subject
        let kr_count = read_varint(&mut r)?;
        let keyring_for_subject = if kr_count > 0 {
            let mut map = HashMap::with_capacity(kr_count as usize);
            for _ in 0..kr_count {
                let key = String::from_utf8(read_bytes(&mut r)?)
                    .map_err(|e| WalletError::Internal(e.to_string()))?;
                let value_bytes = read_bytes(&mut r)?;
                map.insert(key, base64_encode(&value_bytes));
            }
            Some(map)
        } else {
            None
        };
        (
            serial_number,
            revocation_outpoint,
            signature,
            keyring_revealer,
            keyring_for_subject,
            None,
        )
    } else {
        let certifier_url = Some(read_string(&mut r)?);
        (None, None, None, None, None, certifier_url)
    };
    Ok(AcquireCertificateArgs {
        cert_type,
        certifier,
        acquisition_protocol,
        fields,
        serial_number,
        revocation_outpoint,
        signature,
        certifier_url,
        keyring_revealer,
        keyring_for_subject,
        privileged: privileged.unwrap_or(false),
        privileged_reason: if privileged_reason.is_empty() {
            None
        } else {
            Some(privileged_reason)
        },
    })
}

// Base64 helpers
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, WalletError> {
    // Standard base64 decoding
    let mut result = Vec::new();
    let chars: Vec<char> = s
        .chars()
        .filter(|c| *c != '=' && *c != '\n' && *c != '\r')
        .collect();
    let mut i = 0;
    while i < chars.len() {
        let a = b64_val(chars[i])?;
        let b = if i + 1 < chars.len() {
            b64_val(chars[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < chars.len() {
            b64_val(chars[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < chars.len() {
            b64_val(chars[i + 3])?
        } else {
            0
        };
        let n = (a as u32) << 18 | (b as u32) << 12 | (c as u32) << 6 | (d as u32);
        result.push((n >> 16) as u8);
        if i + 2 < chars.len() {
            result.push((n >> 8) as u8);
        }
        if i + 3 < chars.len() {
            result.push(n as u8);
        }
        i += 4;
    }
    Ok(result)
}

fn b64_val(c: char) -> Result<u8, WalletError> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(c as u8 - b'a' + 26),
        '0'..='9' => Ok(c as u8 - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(WalletError::Internal(format!("invalid base64 char: {c}"))),
    }
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let a = data[i] as u32;
        let b = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let c = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let n = (a << 16) | (b << 8) | c;
        result.push(CHARS[(n >> 18 & 0x3f) as usize] as char);
        result.push(CHARS[(n >> 12 & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[(n >> 6 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}
