//! CreateSignature args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{CreateSignatureArgs, CreateSignatureResult};

pub fn serialize_create_signature_args(args: &CreateSignatureArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_key_related_params(
            w,
            &KeyRelatedParams {
                protocol: args.protocol_id.clone(),
                key_id: args.key_id.clone(),
                counterparty: args.counterparty.clone(),
                privileged: Some(args.privileged),
                privileged_reason: args.privileged_reason.clone().unwrap_or_default(),
            },
        )?;
        // Data flag: 1 = data provided, 2 = hash_to_directly_sign provided
        if let Some(ref data) = args.data {
            write_byte(w, 1)?;
            write_varint(w, data.len() as u64)?;
            write_raw_bytes(w, data)?;
        } else if let Some(ref hash) = args.hash_to_directly_sign {
            write_byte(w, 2)?;
            write_raw_bytes(w, hash)?;
        } else {
            // No data — write empty data flag
            write_byte(w, 1)?;
            write_varint(w, 0)?;
        }
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_create_signature_args(data: &[u8]) -> Result<CreateSignatureArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let data_type_flag = read_byte(&mut r)?;
    let (sig_data, hash_to_directly_sign) = match data_type_flag {
        1 => {
            let data_len = read_varint(&mut r)?;
            let d = read_raw_bytes(&mut r, data_len as usize)?;
            (if d.is_empty() { None } else { Some(d) }, None)
        }
        2 => {
            // Hash to directly sign (32 bytes)
            let h = read_raw_bytes(&mut r, 32)?;
            (None, Some(h))
        }
        _ => {
            return Err(WalletError::Internal(format!(
                "invalid data type flag: {}",
                data_type_flag
            )))
        }
    };
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(CreateSignatureArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        data: sig_data,
        hash_to_directly_sign,
        seek_permission,
    })
}

pub fn serialize_create_signature_result(
    result: &CreateSignatureResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(result.signature.clone())
}

pub fn deserialize_create_signature_result(
    data: &[u8],
) -> Result<CreateSignatureResult, WalletError> {
    Ok(CreateSignatureResult {
        signature: data.to_vec(),
    })
}
