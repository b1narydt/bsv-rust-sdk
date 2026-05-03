//! STAS-3 swap-mark factory (spec v0.2 §3.3, §5.5).
//!
//! Builds a fully-formed (STAS-input-signed) swap-mark transaction:
//! 1 STAS in (Passive/Custom) -> 1 STAS out (Swap descriptor in var2) +
//! P2PKH change.
//!
//! Marking a token for swap is structurally a regular owner spend. The
//! engine treats it as `txType=Regular, spendType=Transfer`. The only
//! semantic distinction is that the output's var2 is now a `SwapDescriptor`
//! instead of a passive payload, so a counterparty can later execute an
//! atomic swap against it (or the maker can cancel via `swap_cancel`).
//!
//! Owner, redemption_pkh, flags, service_fields, and optional_data are
//! all carried forward byte-identical to the input. Only var2 changes.

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::{ActionData, SwapDescriptor};
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
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_swap_mark`.
///
/// The output mirrors the input's owner / protoID / flags / svc / optional
/// fields, with var2 replaced by `descriptor`. Caller is responsible for
/// having Type-42-derived `descriptor.receive_addr`.
#[derive(Clone, Debug)]
pub struct SwapMarkRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Swap terms to install in var2 of the output UTXO.
    pub descriptor: SwapDescriptor,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 swap-mark transaction.
///
/// Swap-mark-shape: 1 STAS in -> 1 STAS out (var2 = SwapDescriptor, owner
/// unchanged) + P2PKH change. spendType=Transfer (1), txType=Regular (0).
/// The input owner signs (the maker is just transitioning their own UTXO
/// into the "available for swap" state).
pub async fn build_swap_mark<W: WalletInterface>(
    req: SwapMarkRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Decode input lock to recover all carry-forward fields.
    let decoded = decode_locking_script(&req.stas_input.locking_script)?;

    // 2. Build new lock — same scheme, var2 swapped to the descriptor.
    let new_action_data = ActionData::Swap(req.descriptor.clone());
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: decoded.owner_pkh,
        action_data: new_action_data.clone(),
        redemption_pkh: decoded.redemption_pkh,
        flags: decoded.flags,
        service_fields: decoded.service_fields.clone(),
        optional_data: decoded.optional_data.clone(),
    })?;
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // 3. Assemble the spending tx skeleton.
    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    tx.inputs.push(stas_input_descriptor(&req.stas_input));
    tx.inputs.push(funding_input_descriptor(&req.funding_input));
    tx.outputs.push(TransactionOutput {
        satoshis: Some(req.stas_input.satoshis),
        locking_script: new_lock,
        change: false,
    });
    tx.outputs.push(TransactionOutput {
        satoshis: Some(req.change_satoshis),
        locking_script: change_lock,
        change: false,
    });

    // 4. BIP-143 preimage for the STAS input.
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;

    // 5. Sign with the input owner's signing key (P2PKH or P2MPKH).
    let authz = sign_with_signing_key(
        req.wallet,
        req.originator,
        &req.stas_input.signing_key,
        &decoded.owner_pkh,
        &preimage,
        SIGHASH_DEFAULT as u8,
    )
    .await?;

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 6. Build the unlocking script. Single STAS triplet — var2_bytes is
    //    the encoded swap descriptor (incl. leading 0x01 action byte).
    //    spendType=Transfer (1), txType=Regular (0), no trailing params.
    let unlock_bytes = build_unlocking_script(&UnlockParams {
        stas_outputs: vec![StasOutputWitness {
            satoshis: req.stas_input.satoshis,
            owner_pkh: decoded.owner_pkh,
            var2_bytes: new_action_data.to_var2_bytes(),
        }],
        change: Some(ChangeWitness {
            satoshis: req.change_satoshis,
            owner_pkh: req.change_pkh,
        }),
        note: None,
        funding: Some(FundingPointer {
            vout: req.funding_input.vout,
            txid_le: txid_le_arr,
        }),
        tx_type: TxType::Regular,
        spend_type: SpendType::Transfer,
        preimage,
        authz,
        trailing: TrailingParams::None,
    })?;
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

    Ok(tx)
}
