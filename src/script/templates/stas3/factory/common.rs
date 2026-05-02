//! Shared helpers for STAS-3 factories.
//!
//! Used by transfer, split, and redeem (and forthcoming merge / freeze /
//! confiscate). These helpers exist to keep each factory module short and
//! focused on its operation-specific shape.

use crate::script::locking_script::LockingScript;
use crate::transaction::transaction_input::TransactionInput;
use crate::wallet::interfaces::{CreateSignatureArgs, GetPublicKeyArgs, WalletInterface};

use super::super::constants::SIGHASH_DEFAULT;
use super::super::error::Stas3Error;
use super::super::key_triple::KeyTriple;
use super::types::{FundingInput, TokenInput};

/// Build a standard 25-byte P2PKH locking script.
pub fn make_p2pkh_lock(pkh: &[u8; 20]) -> LockingScript {
    let mut bytes = Vec::with_capacity(25);
    bytes.push(0x76); // OP_DUP
    bytes.push(0xa9); // OP_HASH160
    bytes.push(0x14); // PUSH20
    bytes.extend_from_slice(pkh);
    bytes.push(0x88); // OP_EQUALVERIFY
    bytes.push(0xac); // OP_CHECKSIG
    LockingScript::from_binary(&bytes)
}

/// Canonical 47-byte STAS-3 P2MPKH locking-script suffix (spec §10.2).
/// Reference assembly:
/// `OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE
///  OP_1 OP_SPLIT (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF)×5
///  OP_CHECKMULTISIG OP_ENDIF`
const P2MPKH_LOCKING_SUFFIX: [u8; 47] = [
    0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xac, 0x67,
    0x51, 0x7f, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68,
    0xae, 0x68,
];

/// Build the canonical 70-byte STAS-3 P2MPKH locking script (spec §10.2).
///
/// Layout: `[3-byte prefix OP_DUP OP_HASH160 PUSH20][20-byte MPKH][47-byte suffix]`.
/// Used for redeem outputs (the on-chain "burn-to-issuer-multisig" output)
/// — see `factory/redeem.rs`. The canonical 2,899-byte engine recognizes
/// this shape via its embedded reconstruction template (prefix `4676a914`,
/// suffix `888201218763ac...ae68`) when the input owner equals the
/// redemption_pkh and var2 is empty.
pub fn build_p2mpkh_locking_script(mpkh: &[u8; 20]) -> LockingScript {
    let mut bytes = Vec::with_capacity(70);
    bytes.push(0x76); // OP_DUP
    bytes.push(0xa9); // OP_HASH160
    bytes.push(0x14); // PUSH20
    bytes.extend_from_slice(mpkh);
    bytes.extend_from_slice(&P2MPKH_LOCKING_SUFFIX);
    LockingScript::from_binary(&bytes)
}

/// Convert a BE-hex txid (display form) into a 32-byte LE array (wire form).
pub fn funding_txid_le(hex: &str) -> Result<[u8; 32], Stas3Error> {
    let mut be = crate::primitives::utils::from_hex(hex)
        .map_err(|e| Stas3Error::InvalidScript(format!("funding txid hex: {e}")))?;
    if be.len() != 32 {
        return Err(Stas3Error::InvalidScript(format!(
            "funding txid not 32 bytes: {} bytes",
            be.len()
        )));
    }
    be.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&be);
    Ok(out)
}

/// Build a `TransactionInput` descriptor from a `TokenInput` (unsigned).
pub fn stas_input_descriptor(t: &TokenInput) -> TransactionInput {
    TransactionInput {
        source_transaction: None,
        source_txid: Some(t.txid_hex.clone()),
        source_output_index: t.vout,
        unlocking_script: None,
        sequence: 0xffffffff,
    }
}

/// Build a `TransactionInput` descriptor from a `FundingInput` (unsigned).
pub fn funding_input_descriptor(f: &FundingInput) -> TransactionInput {
    TransactionInput {
        source_transaction: None,
        source_txid: Some(f.txid_hex.clone()),
        source_output_index: f.vout,
        unlocking_script: None,
        sequence: 0xffffffff,
    }
}

/// Sign a hash via the wallet under a given Type-42 triple. Returns the DER
/// signature with the SIGHASH_ALL|SIGHASH_FORKID byte appended (P2PKH form).
pub async fn sign_via_wallet<W: WalletInterface>(
    wallet: &W,
    triple: &KeyTriple,
    hash_to_sign: Vec<u8>,
    originator: Option<&str>,
) -> Result<Vec<u8>, Stas3Error> {
    let sig_result = wallet
        .create_signature(
            CreateSignatureArgs {
                protocol_id: triple.protocol_id.clone(),
                key_id: triple.key_id.clone(),
                counterparty: triple.counterparty.clone(),
                data: None,
                hash_to_directly_sign: Some(hash_to_sign),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| Stas3Error::InvalidScript(format!("STAS input sign: {e}")))?;
    let mut sig_with_hash = sig_result.signature;
    sig_with_hash.push(SIGHASH_DEFAULT as u8);
    Ok(sig_with_hash)
}

/// Get the compressed pubkey bytes for a given Type-42 triple.
pub async fn pubkey_via_wallet<W: WalletInterface>(
    wallet: &W,
    triple: &KeyTriple,
    originator: Option<&str>,
) -> Result<Vec<u8>, Stas3Error> {
    let pk_result = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(triple.protocol_id.clone()),
                key_id: Some(triple.key_id.clone()),
                counterparty: Some(triple.counterparty.clone()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| Stas3Error::InvalidScript(format!("STAS input pubkey: {e}")))?;
    Ok(pk_result.public_key.to_der())
}
