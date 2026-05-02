//! STAS-3 swap-execute factory (spec v0.2 §5.5 / §9.5).
//!
//! Atomic exchange of two STAS-3 tokens. Both inputs are spent in a single
//! transaction; the engine cross-validates that each input's stated swap
//! terms are satisfied by the other side via:
//! - the trailing `counterparty_script` (the OTHER input's locking script), and
//! - the trailing `piece_array` (the OTHER input's preceding tx, with its asset
//!   locking script excised so the engine can recompute its txid hash).
//!
//! Wire layout per input:
//! - `txType = 1` (AtomicSwap)
//! - `spendType = 1` (Transfer — both legs are owner spends)
//! - trailing = `<counterparty_script> <piece_count> <piece_array>`
//!
//! Output assignment per spec §5.5: requested asset goes to output matching
//! initiator's input index; given asset to opposite. In the simple symmetric
//! 2-output case, that means input 0's owner gets output 1 (their requested
//! asset) and input 1's owner gets output 0. This factory implements the
//! canonical 2-input / 2-output shape (no remainder).
//!
//! ## Status
//!
//! Marked `#[ignore]` on the engine-verify gate test. The factory builds a
//! structurally well-formed transaction (compiles, runs, populates witnesses),
//! but engine-verifying the AtomicSwap trailing piece array is the same
//! wire-format trap that blocks merge — see `pieces.rs` and
//! `test_factory_merge_2input_engine_verifies` for the parallel deferral.

use crate::primitives::hash::hash256;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::STAS3_TX_VERSION;
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::lock::{build_locking_script, LockParams};
use super::super::sighash::build_preimage;
use super::super::spend_type::{SpendType, TxType};
use super::super::unlock::{
    build_unlocking_script, AuthzWitness, ChangeWitness, FundingPointer, StasOutputWitness,
    TrailingParams, UnlockParams,
};
use super::common::{
    funding_input_descriptor, funding_txid_le, make_p2pkh_lock, pubkey_via_wallet,
    sign_via_wallet, stas_input_descriptor,
};
use super::pieces::{counterparty_script_from_lock, split_by_counterparty_script};
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_swap_execute`. Both STAS inputs MUST set `source_tx_bytes`
/// so the factory can derive each input's piece array per spec §9.5.
///
/// At least one input MUST carry a swap descriptor in `current_action_data`.
/// In the typical case both do (swap-swap); one-sided (transfer-swap) is
/// also allowed by the spec.
#[derive(Clone, Debug)]
pub struct SwapExecuteRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// Two STAS-3 inputs; both MUST set `source_tx_bytes`.
    pub stas_inputs: [TokenInput; 2],
    pub funding_input: FundingInput,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 atomic-swap-execution transaction.
///
/// Layout: 2 STAS inputs (both signed by their owners) + 1 funding input ->
/// 2 STAS outputs (asset ownership exchanged) + 1 P2PKH change. Each STAS
/// input gets its own per-input `txType=AtomicSwap` and trailing
/// `<counterparty_script> <piece_count> <piece_array>` block per spec §9.5.
///
/// The funding input is left unsigned for the caller (matches the convention
/// of the other factory builders).
pub async fn build_swap_execute<W: WalletInterface>(
    req: SwapExecuteRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // Validate at least one input carries a swap descriptor.
    let has_swap = req
        .stas_inputs
        .iter()
        .any(|t| matches!(t.current_action_data, ActionData::Swap(_)));
    if !has_swap {
        return Err(Stas3Error::InvalidState(
            "swap_execute requires at least one input with a SwapDescriptor in var2".into(),
        ));
    }
    // Validate both inputs carry source_tx_bytes (needed for piece arrays).
    for (i, t) in req.stas_inputs.iter().enumerate() {
        if t.source_tx_bytes.is_none() {
            return Err(Stas3Error::InvalidScript(format!(
                "swap_execute input {i} missing source_tx_bytes (required for piece array)"
            )));
        }
    }

    // Decode both inputs' locking scripts to recover their lock fields.
    let decoded: [_; 2] = [
        decode_locking_script(&req.stas_inputs[0].locking_script)?,
        decode_locking_script(&req.stas_inputs[1].locking_script)?,
    ];

    // Output assignment per spec §5.5 / engine validation:
    // - Output 0 carries the asset of input 1's TYPE (= input 1's lock
    //   fields), but it is owned by the recipient that input 0's swap
    //   descriptor designates (`receive_addr` in the descriptor).
    // - Output 1 mirrors: input 0's TYPE, owned by input 1's `receive_addr`.
    // - var2 resets to Passive for both (the swap is consumed).
    //
    // The `receive_addr` defaults to the input's own owner_pkh if that
    // input doesn't carry a swap descriptor (transfer-swap leg).
    let receive_a = match &decoded[0].action_data {
        ActionData::Swap(d) => d.receive_addr,
        _ => decoded[0].owner_pkh,
    };
    let receive_b = match &decoded[1].action_data {
        ActionData::Swap(d) => d.receive_addr,
        _ => decoded[1].owner_pkh,
    };
    let new_lock_for_out0 = build_locking_script(&LockParams {
        owner_pkh: receive_a,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh: decoded[1].redemption_pkh,
        flags: decoded[1].flags,
        service_fields: decoded[1].service_fields.clone(),
        optional_data: decoded[1].optional_data.clone(),
    })?;
    let new_lock_for_out1 = build_locking_script(&LockParams {
        owner_pkh: receive_b,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh: decoded[0].redemption_pkh,
        flags: decoded[0].flags,
        service_fields: decoded[0].service_fields.clone(),
        optional_data: decoded[0].optional_data.clone(),
    })?;
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // Output satoshis: input i's value flows to its requested-asset position.
    // Output 0 (asset originating from input 1) carries input 1's satoshis.
    // Output 1 (asset originating from input 0) carries input 0's satoshis.
    let out0_satoshis = req.stas_inputs[1].satoshis;
    let out1_satoshis = req.stas_inputs[0].satoshis;

    // Assemble the spending tx skeleton: 2 STAS inputs, 1 funding input,
    // 2 STAS outputs, 1 P2PKH change.
    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    for stas in req.stas_inputs.iter() {
        tx.inputs.push(stas_input_descriptor(stas));
    }
    tx.inputs.push(funding_input_descriptor(&req.funding_input));
    tx.outputs.push(TransactionOutput {
        satoshis: Some(out0_satoshis),
        locking_script: new_lock_for_out0,
        change: false,
    });
    tx.outputs.push(TransactionOutput {
        satoshis: Some(out1_satoshis),
        locking_script: new_lock_for_out1,
        change: false,
    });
    tx.outputs.push(TransactionOutput {
        satoshis: Some(req.change_satoshis),
        locking_script: change_lock,
        change: false,
    });

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // Per-input: build pieces from the OTHER input's preceding tx (split
    // at every occurrence of the OTHER input's counterparty script), sign,
    // and emit the unlock with the OTHER input's FULL locking script as the
    // `counterparty_script` parameter (per spec §9.5 / TS reference).
    for input_idx in 0..2 {
        let token = &req.stas_inputs[input_idx];
        let other_idx = 1 - input_idx;
        let other = &req.stas_inputs[other_idx];

        // Counterparty (OTHER) input's POST-var2 portion (everything past
        // `[owner_push][var2_push]` — engine bytes + redemption + flags +
        // service + optional). Per the TS reference (`Stas3Merge.ts`),
        // this is BOTH:
        //   1. the needle for splitting the OTHER input's source-tx bytes
        //      into segments, AND
        //   2. the value pushed as the "counterparty_script" witness item
        //      in the swap merge section.
        let other_counterparty_post_var2 =
            counterparty_script_from_lock(&other.locking_script)?;

        let other_preceding_tx = other
            .source_tx_bytes
            .as_ref()
            .expect("validated above");
        let pieces = split_by_counterparty_script(
            other_preceding_tx,
            &other_counterparty_post_var2,
        )?;

        let preimage = build_preimage(
            &tx,
            input_idx,
            token.satoshis,
            &token.locking_script,
        )?;
        let preimage_hash = hash256(&preimage).to_vec();
        let sig_with_hash = sign_via_wallet(
            req.wallet,
            &token.triple,
            preimage_hash,
            req.originator,
        )
        .await?;
        let pubkey_bytes =
            pubkey_via_wallet(req.wallet, &token.triple, req.originator).await?;

        // STAS outputs in the unlocking witness: per spec §7 we declare both
        // STAS outputs (positions 1-3 = output 0, 4-6 = output 1) with their
        // satoshis, owner_pkh, and var2 (Passive empty here). The engine
        // cross-checks against the actual tx outputs.
        let stas_outputs = vec![
            StasOutputWitness {
                satoshis: out0_satoshis,
                owner_pkh: decoded[0].owner_pkh,
                var2_bytes: vec![],
            },
            StasOutputWitness {
                satoshis: out1_satoshis,
                owner_pkh: decoded[1].owner_pkh,
                var2_bytes: vec![],
            },
        ];

        let unlock_bytes = build_unlocking_script(&UnlockParams {
            stas_outputs,
            change: Some(ChangeWitness {
                satoshis: req.change_satoshis,
                owner_pkh: req.change_pkh,
            }),
            note: None,
            funding: Some(FundingPointer {
                vout: req.funding_input.vout,
                txid_le: txid_le_arr,
            }),
            tx_type: TxType::AtomicSwap,
            // Per TS reference (`tests/helpers/test-driver.ts::buildSwapTx`)
            // and engine dispatch: swap-swap legs use spendingType=4
            // (SwapCancellation in our enum, but the spec re-uses "4" for
            // both swap-cancel and swap-swap leg authorization since both
            // are owner spends of a swap-marked input).
            spend_type: SpendType::SwapCancellation,
            preimage,
            authz: AuthzWitness::P2pkh {
                sig: sig_with_hash,
                pubkey: pubkey_bytes,
            },
            trailing: TrailingParams::AtomicSwap {
                merge_vout: other.vout,
                pieces,
                counterparty_script: other_counterparty_post_var2,
            },
        })?;
        tx.inputs[input_idx].unlocking_script =
            Some(UnlockingScript::from_binary(&unlock_bytes));
    }

    Ok(tx)
}
