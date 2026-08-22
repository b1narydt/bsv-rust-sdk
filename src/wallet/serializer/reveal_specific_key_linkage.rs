//! RevealSpecificKeyLinkage args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult};

pub fn serialize_reveal_specific_key_linkage_args(
    args: &RevealSpecificKeyLinkageArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_key_related_params(
            w,
            &KeyRelatedParams {
                protocol: args.protocol_id.clone(),
                key_id: args.key_id.clone(),
                counterparty: args.counterparty.clone(),
                privileged: args.privileged,
                privileged_reason: args.privileged_reason.clone().unwrap_or_default(),
            },
        )?;
        write_public_key(w, &args.verifier)
    })
}

pub fn deserialize_reveal_specific_key_linkage_args(
    data: &[u8],
) -> Result<RevealSpecificKeyLinkageArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let verifier = read_public_key(&mut r)?;
    Ok(RevealSpecificKeyLinkageArgs {
        counterparty: params.counterparty,
        verifier,
        protocol_id: params.protocol,
        key_id: params.key_id,
        privileged: params.privileged,
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
    })
}

pub fn serialize_reveal_specific_key_linkage_result(
    result: &RevealSpecificKeyLinkageResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_public_key(w, &result.prover)?;
        write_public_key(w, &result.verifier)?;
        write_counterparty(w, &result.counterparty)?;
        write_protocol(w, &result.protocol_id)?;
        write_bytes(w, result.key_id.as_bytes())?;
        write_bytes(w, &result.encrypted_linkage)?;
        write_bytes(w, &result.encrypted_linkage_proof)?;
        write_byte(w, result.proof_type)
    })
}

pub fn deserialize_reveal_specific_key_linkage_result(
    data: &[u8],
) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let prover = read_public_key(&mut r)?;
    let verifier = read_public_key(&mut r)?;
    let counterparty = read_counterparty(&mut r)?;
    let protocol_id = read_protocol(&mut r)?;
    let key_id_bytes = read_bytes(&mut r)?;
    let key_id =
        String::from_utf8(key_id_bytes).map_err(|e| WalletError::Internal(e.to_string()))?;
    let encrypted_linkage = read_bytes(&mut r)?;
    let encrypted_linkage_proof = read_bytes(&mut r)?;
    let proof_type = read_byte(&mut r)?;
    Ok(RevealSpecificKeyLinkageResult {
        encrypted_linkage,
        encrypted_linkage_proof,
        prover,
        verifier,
        counterparty,
        protocol_id,
        key_id,
        proof_type,
    })
}
