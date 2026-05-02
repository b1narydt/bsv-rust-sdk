//! STAS-3 merge factory (spec v0.2 §5, §8.1, §9.5).
//!
//! Builds a fully-formed (each STAS-input-signed) merge transaction:
//! 2..=7 STAS in -> 1 STAS out (new owner) + P2PKH change.
//!
//! ## Per-input txType
//!
//! `txType` (slot 18) for each STAS input encodes the **piece count** of
//! that input's trailing piece array (per spec §8.1 / Bittoku reference).
//! That piece count equals the number of STAS-shaped outputs in the
//! preceding tx of THAT input, plus one (head + N-1 gaps + tail = N pieces
//! when N-1 outputs are excised — but the engine requires N pieces for
//! txType=N, so the input's preceding tx must contain exactly N-1 STAS
//! outputs).
//!
//! In the simple/canonical case where each STAS input comes from a
//! preceding tx that contains **only that one STAS output**, each input's
//! piece count is 2 (head + tail) and the per-input txType is `Merge2`.
//! This matches the engine's per-input piece-count check in spec §9.5.
//!
//! The merge **operation** can have any input count in 2..=7; the per-input
//! `txType` is independent of the operation's input count and is determined
//! by each input's preceding-tx shape.
//!
//! ## STAS output
//!
//! A merge produces exactly one STAS output owned by `destination_owner_pkh`,
//! carrying the SUM of all STAS input satoshis (sum-conservation per spec
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
    /// 2..=7 STAS inputs to merge. Each MUST set `source_tx_bytes`.
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

/// Build a signed STAS-3 merge transaction.
///
/// Layout: N STAS inputs (each signed with its own owner key) + 1 funding
/// input -> 1 STAS output (new owner, satoshis = sum of inputs) +
/// 1 P2PKH change output. The funding input is left unsigned for the caller
/// (matches the convention of the other factory builders).
pub async fn build_merge<W: WalletInterface>(
    req: MergeRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    let n = req.stas_inputs.len();
    // Spec §5 allows 2..=7 inputs; only 2-input is currently implemented per
    // the canonical engine's per-input merge-section dispatch (the engine
    // reads the OTHER input's source-tx via the merge_vout slot — extending
    // to >2 inputs requires either a different engine ASM block or a wire
    // contract for multiple counterparty references per input).
    if n != 2 {
        return Err(Stas3Error::InvalidScript(format!(
            "merge currently supports exactly 2 STAS inputs (canonical engine \
             dispatch); got {n}"
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

    // 2. Assemble the spending tx skeleton: N STAS inputs, 1 funding input,
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
    //    For a regular (non-swap) merge both tokens have the same
    //    counterparty script, so we use input 0's counterparty script for
    //    both inputs (matches `Stas3.ts::buildMergeSection`).
    let counterparty_script_shared =
        counterparty_script_from_lock(&req.stas_inputs[0].locking_script)?;
    for input_idx in 0..n {
        let token = &req.stas_inputs[input_idx];
        let other_idx = 1 - input_idx;
        let other = &req.stas_inputs[other_idx];

        let other_preceding_tx = other
            .source_tx_bytes
            .as_ref()
            .expect("validated above");
        let pieces = split_by_counterparty_script(
            other_preceding_tx,
            &counterparty_script_shared,
        )?;
        let piece_count = pieces.len();
        let tx_type = match piece_count {
            2 => TxType::Merge2,
            3 => TxType::Merge3,
            4 => TxType::Merge4,
            5 => TxType::Merge5,
            6 => TxType::Merge6,
            7 => TxType::Merge7,
            other => {
                return Err(Stas3Error::InvalidScript(format!(
                    "merge input {input_idx}: piece count {other} not in 2..=7 \
                     (other input's source tx must contain 1..=6 occurrences of \
                      the shared counterparty script)"
                )));
            }
        };

        let preimage = build_preimage(
            &tx,
            input_idx,
            token.satoshis,
            &token.locking_script,
        )?;
        // Honor §10.3 sentinel via the input's decoded owner_pkh.
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
            tx_type,
            spend_type: SpendType::Transfer,
            preimage,
            authz,
            trailing: TrailingParams::Merge {
                merge_vout: other.vout,
                pieces,
            },
        })?;
        tx.inputs[input_idx].unlocking_script =
            Some(UnlockingScript::from_binary(&unlock_bytes));
    }

    Ok(tx)
}
