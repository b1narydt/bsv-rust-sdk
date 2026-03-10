//! VerifySignature args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{VerifySignatureArgs, VerifySignatureResult};

pub fn serialize_verify_signature_args(args: &VerifySignatureArgs) -> Result<Vec<u8>, WalletError> {
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
        // forSelf flag
        write_optional_bool(w, args.for_self)?;
        // Signature (length-prefixed)
        write_bytes(w, &args.signature)?;
        // Data flag: 1 = data, 2 = hash_to_directly_verify
        if let Some(ref data) = args.data {
            write_byte(w, 1)?;
            write_bytes(w, data)?;
        } else if let Some(ref hash) = args.hash_to_directly_verify {
            write_byte(w, 2)?;
            write_raw_bytes(w, hash)?;
        } else {
            write_byte(w, 1)?;
            write_bytes(w, &[])?;
        }
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_verify_signature_args(data: &[u8]) -> Result<VerifySignatureArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let for_self = read_optional_bool(&mut r)?;
    let signature = read_bytes(&mut r)?;
    let data_type_flag = read_byte(&mut r)?;
    let (sig_data, hash_to_directly_verify) = match data_type_flag {
        1 => {
            let d = read_bytes(&mut r)?;
            (if d.is_empty() { None } else { Some(d) }, None)
        }
        2 => {
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
    Ok(VerifySignatureArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        for_self,
        signature,
        data: sig_data,
        hash_to_directly_verify,
        seek_permission,
    })
}

pub fn serialize_verify_signature_result(
    _result: &VerifySignatureResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_verify_signature_result(
    _data: &[u8],
) -> Result<VerifySignatureResult, WalletError> {
    Ok(VerifySignatureResult { valid: true })
}
