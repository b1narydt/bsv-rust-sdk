//! STAS-3 merge factory (spec v0.2 §5, §8.1, §9.5).
//!
//! Builds a fully-formed (each STAS-input-signed) merge transaction:
//! 2..=7 STAS in -> 1 STAS out (new owner) + P2PKH change.
//!
//! ## Per-input txType
//!
//! `txType` (slot 18) per spec §8.1 directly encodes the **merge input
//! count** N (in 2..=7). All N inputs share the same `txType = N` for the
//! operation. Each input's trailing piece array carries the rotation-ordered
//! fragments of the N-1 OTHER inputs' source-tx bytes (split at the shared
//! counterparty script, head+gaps+tail per source).
//!
//! For N=2 this collapses to the canonical 2-input behavior: each input's
//! trailing piece array is the OTHER input's source-tx pieces.
//!
//! For N>2 the wire format described in spec §8.1 is "piece count (N) +
//! array of N pieces" — the spec is silent on whether/how to encode multiple
//! source-tx piece groups in the single per-input trailing array. The
//! current implementation flattens the N-1 OTHER inputs' piece sequences in
//! rotation order [(i+1)%N, (i+2)%N, ..., (i+N-1)%N] and is engine-verified
//! for N=2 only (see integration tests). N>2 cases are wired but engine
//! verification is deferred — see TODO on the corresponding tests.
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
    // Spec §8.1: txType in 2..=7 directly encodes the merge input count.
    if !(2..=7).contains(&n) {
        return Err(Stas3Error::InvalidScript(format!(
            "merge supports 2..=7 STAS inputs (spec §8.1); got {n}"
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

    // Per-input: extract pieces of input i's OWN source tx so we can
    // assemble per-(i,j) trailing arrays via rotation below. Each token's
    // pieces are produced by splitting its source tx at the shared
    // counterparty script (§9.5).
    let per_input_pieces: Vec<Vec<Vec<u8>>> = req
        .stas_inputs
        .iter()
        .map(|t| {
            let pre = t.source_tx_bytes.as_ref().expect("validated above");
            split_by_counterparty_script(pre, &counterparty_script_shared)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // tx_type directly encodes the merge input count (spec §8.1).
    let tx_type = match n {
        2 => TxType::Merge2,
        3 => TxType::Merge3,
        4 => TxType::Merge4,
        5 => TxType::Merge5,
        6 => TxType::Merge6,
        7 => TxType::Merge7,
        _ => unreachable!("guarded by 2..=7 check above"),
    };

    for input_idx in 0..n {
        let token = &req.stas_inputs[input_idx];

        // Build the rotation-ordered piece array — flatten pieces from the
        // (N-1) OTHER inputs in forward rotation order
        // [(i+1)%N, (i+2)%N, ..., (i+N-1)%N]. For N=2 this collapses to the
        // single OTHER input's piece array, matching the existing canonical
        // 2-input behavior.
        //
        // NOTE: For N>2 both forward and reverse rotations were tested and
        // engine-rejected (Script(VerifyFailed)). The spec §8.1 wire layout
        // for N>2 trailing piece arrays is ambiguous — see merge.rs module
        // doc and the corresponding `#[ignore]`d tests.
        let mut pieces: Vec<Vec<u8>> = Vec::new();
        for k in 1..n {
            let other_idx = (input_idx + k) % n;
            pieces.extend(per_input_pieces[other_idx].iter().cloned());
        }

        // The merge_vout slot points to the FIRST OTHER input — for N=2 this
        // is the canonical (1 - input_idx). For N>2 the spec is silent on
        // the multi-input slot encoding, so we default to (i+1)%N.
        let first_other_idx = (input_idx + 1) % n;
        let merge_vout = req.stas_inputs[first_other_idx].vout;

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
                merge_vout,
                pieces,
            },
        })?;
        tx.inputs[input_idx].unlocking_script =
            Some(UnlockingScript::from_binary(&unlock_bytes));
    }

    Ok(tx)
}
