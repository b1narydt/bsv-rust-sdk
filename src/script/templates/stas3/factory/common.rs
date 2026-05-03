//! Shared helpers for STAS-3 factories.
//!
//! Used by transfer, split, and redeem (and forthcoming merge / freeze /
//! confiscate). These helpers exist to keep each factory module short and
//! focused on its operation-specific shape.

use crate::primitives::hash::hash256;
use crate::script::locking_script::LockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_input::TransactionInput;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::{CreateSignatureArgs, GetPublicKeyArgs, WalletInterface};

use super::super::constants::{EMPTY_HASH160, SIGHASH_DEFAULT};
use super::super::error::Stas3Error;
use super::super::brc43_key_args::Brc43KeyArgs;
use super::super::unlock::AuthzWitness;
use super::types::{FundingInput, SigningKey, TokenInput};

/// Returns true if the `owner_pkh` is the `HASH160("")` sentinel — engine
/// accepts a single `OP_FALSE` in place of all auth fields. See spec §10.3.
///
/// When this returns `true`, factories MUST emit
/// [`AuthzWitness::Suppressed`] for that input rather than attempting to
/// sign — there is no key behind the sentinel hash, and any signing
/// attempt is guaranteed to derive the wrong key.
pub fn is_sentinel_owner(owner_pkh: &[u8; 20]) -> bool {
    owner_pkh == &EMPTY_HASH160
}

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

/// Build a `TransactionOutput` whose locking script is the standard 25-byte
/// P2PKH followed by `OP_FALSE OP_RETURN <minimal-push of data>`.
///
/// Used by the issuance contract tx (output 0): the bundled token-supply
/// output that carries the scheme metadata as an unspendable trailing
/// OP_RETURN annotation. The 25-byte P2PKH prefix ensures the output is
/// still spendable (the issuer redeems it in the issue tx); the trailing
/// `OP_FALSE OP_RETURN` makes everything past byte 25 unreachable script
/// (so the OP_RETURN payload doesn't affect spend authorization).
///
/// Mirrors the canonical TS form
/// `addP2PkhOutput(amount, address, [scheme.toBytes()])` from
/// `dxs-bsv-token-sdk::TransactionBuilder`.
pub fn make_p2pkh_with_op_return(
    sats: u64,
    pkh: &[u8; 20],
    data: &[u8],
) -> TransactionOutput {
    let mut bytes = Vec::with_capacity(25 + 2 + data.len() + 5);
    // P2PKH prefix
    bytes.push(0x76); // OP_DUP
    bytes.push(0xa9); // OP_HASH160
    bytes.push(0x14); // PUSH20
    bytes.extend_from_slice(pkh);
    bytes.push(0x88); // OP_EQUALVERIFY
    bytes.push(0xac); // OP_CHECKSIG
    // OP_FALSE OP_RETURN <data>
    bytes.push(0x00); // OP_FALSE (a.k.a. OP_0)
    bytes.push(0x6a); // OP_RETURN
    super::super::lock::push_data_minimal(&mut bytes, data);
    TransactionOutput {
        satoshis: Some(sats),
        locking_script: LockingScript::from_binary(&bytes),
        change: false,
    }
}

/// Compute the LE (wire-form) txid of `tx`: `hash256(tx.to_binary())`.
///
/// Returns 32 LE bytes — the form expected in funding-pointer slots and
/// in subsequent `source_outpoint.tx_hash` fields. Wraps the existing
/// `Transaction::hash()` (which already returns the LE bytes after the
/// double-SHA256 of the serialized tx).
pub fn compute_txid_le(tx: &Transaction) -> Result<[u8; 32], Stas3Error> {
    tx.hash()
        .map_err(|e| Stas3Error::InvalidScript(format!("compute txid: {e}")))
}

/// Build the canonical 70-byte STAS-3 P2MPKH locking script (spec §10.2).
///
/// Layout: `[3-byte prefix OP_DUP OP_HASH160 PUSH20][20-byte MPKH][47-byte suffix]`.
/// Used for redeem outputs (the on-chain "burn-to-issuer-multisig" output)
/// — see `factory/redeem.rs`. The canonical 2,899-byte engine recognizes
/// this shape via its embedded reconstruction template (prefix `4676a914`,
/// suffix `888201218763ac...ae68`) when the input owner equals the
/// redemption_pkh and var2 is empty.
pub fn build_p2mpkh_locking_script(mpkh: &[u8; 20]) -> LockingScript {
    // Single-sourced wire format: defer to multisig::p2mpkh_locking_script_bytes
    // so we don't carry two copies of the canonical 70-byte body.
    let bytes = super::super::multisig::p2mpkh_locking_script_bytes(*mpkh);
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
    triple: &Brc43KeyArgs,
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
    triple: &Brc43KeyArgs,
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

/// Sign the given STAS-3 input preimage under the supplied
/// [`SigningKey`] shape and return an [`AuthzWitness`] ready to plug
/// into [`super::super::unlock::UnlockParams`]. This is the single
/// entry point every factory uses to authorize a STAS-3 input — it
/// transparently covers both single-sig P2PKH owners and m-of-n
/// P2MPKH multisig owners per spec §10.2.
///
/// `owner_pkh` is the 20-byte hash on the slot we're authorizing
/// (input owner for STAS spends, freeze authority pkh for freeze /
/// unfreeze, confiscation authority pkh for confiscate, descriptor
/// `receive_addr` for swap-cancel, etc.). When it equals the spec
/// §10.3 `EMPTY_HASH160` sentinel the function short-circuits to
/// [`AuthzWitness::Suppressed`] (single `OP_FALSE`) WITHOUT touching
/// the wallet — there is no key behind the sentinel and any signing
/// attempt is guaranteed to derive the wrong key. This lets callers
/// thread "arbitrator-free" / signature-suppressed paths through the
/// same code path used for ordinary signed authorizations.
///
/// `preimage` is the BIP-143 preimage **bytes** (not the preimage
/// hash); the function applies `hash256` internally so the caller
/// doesn't have to remember which side of the hash boundary each key
/// arm expects.
///
/// `sighash_byte` is appended to each DER signature. Callers should
/// pass [`SIGHASH_DEFAULT`] (`0x41`, `SIGHASH_ALL | SIGHASH_FORKID`)
/// unless they have a specific reason to deviate.
///
/// For [`SigningKey::Multi`], the function:
///   1. Validates `triples.len() == multisig.threshold()`.
///   2. Signs the same preimage hash under each triple, in input
///      order (matching the order in which the corresponding
///      pubkeys appear in the redeem script — required by
///      `OP_CHECKMULTISIG`).
///   3. Returns `AuthzWitness::P2mpkh { sigs, redeem_script }` where
///      `redeem_script` is the canonical
///      [`super::super::multisig::MultisigScript::to_serialized_bytes`]
///      buffer.
///
/// The function does NOT verify that the multisig's pubkey set
/// actually matches the wallet-derived pubkeys for the supplied
/// triples — that invariant is the caller's responsibility (callers
/// typically derive both the redeem script and the triples from a
/// single upstream key-derivation pass, so an internal mismatch would
/// be a program bug, not a runtime error).
pub async fn sign_with_signing_key<W: WalletInterface>(
    wallet: &W,
    originator: Option<&str>,
    signing_key: &SigningKey,
    owner_pkh: &[u8; 20],
    preimage: &[u8],
    sighash_byte: u8,
) -> Result<AuthzWitness, Stas3Error> {
    // Spec §10.3: when the slot we're authorizing is the HASH160("")
    // sentinel, the engine accepts a single OP_FALSE. Skip the wallet
    // round-trip entirely — there is no key behind the sentinel.
    if is_sentinel_owner(owner_pkh) {
        return Ok(AuthzWitness::Suppressed);
    }
    signing_key.validate()?;
    let preimage_hash = hash256(preimage).to_vec();

    match signing_key {
        SigningKey::P2pkh(triple) => {
            let sig_with_hash = sign_hash_with_byte(
                wallet,
                triple,
                preimage_hash,
                originator,
                sighash_byte,
            )
            .await?;
            let pubkey = pubkey_via_wallet(wallet, triple, originator).await?;
            Ok(AuthzWitness::P2pkh {
                sig: sig_with_hash,
                pubkey,
            })
        }
        SigningKey::Multi { triples, multisig } => {
            // Sign with each triple, in the order the caller supplied
            // (which must match the corresponding pubkey order in the
            // redeem script — caller's responsibility per spec §10.2 /
            // OP_CHECKMULTISIG semantics).
            let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(triples.len());
            for triple in triples {
                let sig = sign_hash_with_byte(
                    wallet,
                    triple,
                    preimage_hash.clone(),
                    originator,
                    sighash_byte,
                )
                .await?;
                sigs.push(sig);
            }
            Ok(AuthzWitness::P2mpkh {
                sigs,
                redeem_script: multisig.to_serialized_bytes(),
            })
        }
    }
}

/// Internal: sign a hash under a triple and append the requested
/// sighash byte. Wraps `wallet.create_signature` directly so the byte
/// is always the caller-specified one (rather than unconditionally
/// `SIGHASH_DEFAULT` as in [`sign_via_wallet`]).
async fn sign_hash_with_byte<W: WalletInterface>(
    wallet: &W,
    triple: &Brc43KeyArgs,
    hash_to_sign: Vec<u8>,
    originator: Option<&str>,
    sighash_byte: u8,
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
    sig_with_hash.push(sighash_byte);
    Ok(sig_with_hash)
}
