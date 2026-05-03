//! STAS-3 merge factory (spec v0.2 §5, §8.1, §9.5).
//!
//! Builds a fully-formed (each STAS-input-signed) atomic 2-input merge
//! transaction: 2 STAS in -> 1 STAS out (new owner) + P2PKH change.
//!
//! ## Why 2-input only?
//!
//! Spec §8.1 defines `txType` (slot 18) as the merge input count N (in
//! 2..=7), and per-input trailing piece arrays carry rotation-ordered
//! fragments of the OTHER inputs' source-tx bytes. For N=2 the encoding
//! is unambiguous and engine-verifies. For N>2 the spec is silent on
//! how multiple source-tx piece groups are encoded in the single per-
//! input trailing array, and the dxs reference SDK
//! (`dxsapp/dxs-bsv-token-sdk`) explicitly limits merge to 2 STAS
//! inputs (`docs/DSTAS_CONFORMANCE_MATRIX.md`: "Merge limited to 2 STAS
//! inputs"; `BuildMergeTx` only accepts `outPoint1, outPoint2`).
//!
//! For N>2 use [`build_merge_chain`](super::build_merge_chain), which
//! mirrors the dxs `mergeStasTransactions` binary-tree pattern: pair
//! inputs 2-at-a-time and chain merged outputs across multiple
//! transactions.
//!
//! ## STAS output
//!
//! A merge produces exactly one STAS output owned by `destination_owner_pkh`,
//! carrying the SUM of both STAS input satoshis (sum-conservation per spec
//! §5.1). var2 is reset to `Passive(empty)` per spec §5.1.

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::{SIGHASH_DEFAULT, STAS3_TX_VERSION};
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::lock::{build_locking_script, LockParams};
use super::super::sighash::build_preimage;
use super::super::spend_type::{SpendType, TxType};
use super::super::unlock::{
    build_unlocking_script, ChangeWitness, FundingPointer, StasOutputWitness,
    TrailingParams, UnlockParams,
};
use super::common::{
    funding_input_descriptor, funding_txid_le, make_p2pkh_lock, sign_with_signing_key,
    stas_input_descriptor,
};
use super::pieces::{counterparty_script_from_lock, split_by_counterparty_script};
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_merge`. Each STAS input must carry its preceding-tx
/// bytes (`source_tx_bytes`) so the factory can build the trailing piece
/// array per spec §9.5.
#[derive(Clone, Debug)]
pub struct MergeRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// Exactly 2 STAS inputs to merge. Each MUST set `source_tx_bytes`.
    /// For N>2, use [`build_merge_chain`](super::build_merge_chain).
    pub stas_inputs: Vec<TokenInput>,
    pub funding_input: FundingInput,
    /// Destination owner of the merged STAS output. MUST be Type-42 derived
    /// by the caller.
    pub destination_owner_pkh: [u8; 20],
    /// Carried forward onto the merged STAS output (must match all inputs).
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    /// Optional inline note (slot 15). `None` emits OP_FALSE.
    pub note: Option<Vec<u8>>,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 atomic 2-input merge transaction.
///
/// Layout: 2 STAS inputs (each signed with its own owner key) + 1 funding
/// input -> 1 STAS output (new owner, satoshis = sum of inputs) +
/// 1 P2PKH change output. The funding input is left unsigned for the caller
/// (matches the convention of the other factory builders).
///
/// Rejects N != 2 with [`Stas3Error::InvalidScript`]. For N>2 use
/// [`build_merge_chain`](super::build_merge_chain).
pub async fn build_merge<W: WalletInterface>(
    req: MergeRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    let n = req.stas_inputs.len();
    if n != 2 {
        return Err(Stas3Error::InvalidScript(format!(
            "build_merge requires exactly 2 STAS inputs; got {n}. \
             For N>2 use build_merge_chain (mirrors dxs binary-tree merge)."
        )));
    }
    for (i, t) in req.stas_inputs.iter().enumerate() {
        if t.source_tx_bytes.is_none() {
            return Err(Stas3Error::InvalidScript(format!(
                "merge input {i} missing source_tx_bytes (required for piece array)"
            )));
        }
    }
    let total_in: u64 = req.stas_inputs.iter().map(|i| i.satoshis).sum();

    // 1. Build the merged STAS-3 lock for the destination.
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: req.destination_owner_pkh,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh: req.redemption_pkh,
        flags: req.flags,
        service_fields: req.service_fields.clone(),
        optional_data: req.optional_data.clone(),
    })?;
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // 2. Assemble the spending tx skeleton: 2 STAS inputs, 1 funding input,
    //    1 STAS output, 1 P2PKH change output.
    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    for stas in &req.stas_inputs {
        tx.inputs.push(stas_input_descriptor(stas));
    }
    tx.inputs.push(funding_input_descriptor(&req.funding_input));
    tx.outputs.push(TransactionOutput {
        satoshis: Some(total_in),
        locking_script: new_lock,
        change: false,
    });
    tx.outputs.push(TransactionOutput {
        satoshis: Some(req.change_satoshis),
        locking_script: change_lock,
        change: false,
    });

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 3. For each STAS input: compute its preimage, sign, and build its
    //    unlocking script. Per spec §9.5 + the TS reference, the merge
    //    section in input `i`'s witness references the OTHER input — its
    //    `sourceOutputIndex` (mergeVout), and pieces formed by splitting
    //    the OTHER input's source-tx bytes at every occurrence of the
    //    counterparty script (everything past `[owner_push][var2_push]`).
    //    Both tokens share the same counterparty script for a regular
    //    (non-swap) merge, so we use input 0's for both
    //    (matches `Stas3.ts::buildMergeSection`).
    let counterparty_script_shared =
        counterparty_script_from_lock(&req.stas_inputs[0].locking_script)?;

    let per_input_pieces: Vec<Vec<Vec<u8>>> = req
        .stas_inputs
        .iter()
        .map(|t| {
            let pre = t.source_tx_bytes.as_ref().expect("validated above");
            split_by_counterparty_script(pre, &counterparty_script_shared)
        })
        .collect::<Result<Vec<_>, _>>()?;

    for input_idx in 0..2 {
        let token = &req.stas_inputs[input_idx];

        let other_idx = 1 - input_idx;
        let pieces = per_input_pieces[other_idx].clone();
        let merge_vout = req.stas_inputs[other_idx].vout;

        let preimage = build_preimage(
            &tx,
            input_idx,
            token.satoshis,
            &token.locking_script,
        )?;
        let token_decoded = decode_locking_script(&token.locking_script)?;
        let authz = sign_with_signing_key(
            req.wallet,
            req.originator,
            &token.signing_key,
            &token_decoded.owner_pkh,
            &preimage,
            SIGHASH_DEFAULT as u8,
        )
        .await?;

        let unlock_bytes = build_unlocking_script(&UnlockParams {
            stas_outputs: vec![StasOutputWitness {
                satoshis: total_in,
                owner_pkh: req.destination_owner_pkh,
                var2_bytes: vec![],
            }],
            change: Some(ChangeWitness {
                satoshis: req.change_satoshis,
                owner_pkh: req.change_pkh,
            }),
            note: req.note.clone(),
            funding: Some(FundingPointer {
                vout: req.funding_input.vout,
                txid_le: txid_le_arr,
            }),
            tx_type: TxType::Merge2,
            spend_type: SpendType::Transfer,
            preimage,
            authz,
            trailing: TrailingParams::Merge {
                merge_vout,
                pieces,
            },
        })?;
        tx.inputs[input_idx].unlocking_script =
            Some(UnlockingScript::from_binary(&unlock_bytes));
    }

    Ok(tx)
}
