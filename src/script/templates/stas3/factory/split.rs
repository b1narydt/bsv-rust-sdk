//! STAS-3 split factory.
//!
//! Builds a fully-formed (STAS-input-signed) split transaction:
//! 1 STAS in → 2..=4 STAS out + P2PKH change.
//!
//! Per spec §5.1 (Regular Spend / Split): each output STAS UTXO copies the
//! input's engine + protoID + flags + svc + optional data byte-for-byte;
//! sum of STAS output amounts MUST equal sum of STAS input amounts; var2 is
//! reset to Passive(empty) on every output.

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::{SIGHASH_DEFAULT, STAS3_TX_VERSION};
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

/// One destination of a split: an output owner PKH plus its share of the
/// total token amount. Sum of all `satoshis` MUST equal the input amount.
#[derive(Clone, Debug)]
pub struct SplitDestination {
    /// Type-42 derived by the caller.
    pub owner_pkh: [u8; 20],
    pub satoshis: u64,
}

/// Inputs to `build_split`. Carries forward the input lock's redemption PKH,
/// flags, service fields, and optional data onto every output STAS UTXO.
#[derive(Clone, Debug)]
pub struct SplitRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// 2..=4 destinations. Sum of `satoshis` MUST equal `stas_input.satoshis`.
    pub destinations: Vec<SplitDestination>,
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    pub note: Option<Vec<u8>>,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 split transaction.
///
/// Split-shape: 1 STAS input -> 2..=4 STAS outputs (each with its own owner,
/// var2 reset to passive) plus a P2PKH change output. Sums:
/// `sum(destinations.satoshis) == stas_input.satoshis`.
pub async fn build_split<W: WalletInterface>(
    req: SplitRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Validate destination count and amount conservation.
    if req.destinations.len() < 2 || req.destinations.len() > 4 {
        return Err(Stas3Error::InvalidScript(format!(
            "split requires 2..=4 destinations, got {}",
            req.destinations.len()
        )));
    }
    let total_out: u64 = req.destinations.iter().map(|d| d.satoshis).sum();
    if total_out != req.stas_input.satoshis {
        return Err(Stas3Error::AmountMismatch {
            inputs: req.stas_input.satoshis,
            outputs: total_out,
        });
    }

    // 2. Build N STAS-3 locking scripts (one per destination).
    let mut new_locks = Vec::with_capacity(req.destinations.len());
    for d in &req.destinations {
        new_locks.push(build_locking_script(&LockParams {
            owner_pkh: d.owner_pkh,
            action_data: ActionData::Passive(vec![]),
            redemption_pkh: req.redemption_pkh,
            flags: req.flags,
            service_fields: req.service_fields.clone(),
            optional_data: req.optional_data.clone(),
        })?);
    }
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // 3. Assemble the spending tx skeleton.
    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    tx.inputs.push(stas_input_descriptor(&req.stas_input));
    tx.inputs.push(funding_input_descriptor(&req.funding_input));
    for (i, lock) in new_locks.iter().enumerate() {
        tx.outputs.push(TransactionOutput {
            satoshis: Some(req.destinations[i].satoshis),
            locking_script: lock.clone(),
            change: false,
        });
    }
    tx.outputs.push(TransactionOutput {
        satoshis: Some(req.change_satoshis),
        locking_script: change_lock,
        change: false,
    });

    // 4. Sign STAS input.
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;
    let authz = sign_with_signing_key(
        req.wallet,
        req.originator,
        &req.stas_input.signing_key,
        &preimage,
        SIGHASH_DEFAULT as u8,
    )
    .await?;

    // 5. Build STAS unlocking script with N STAS output triplets.
    let stas_outputs: Vec<StasOutputWitness> = req
        .destinations
        .iter()
        .map(|d| StasOutputWitness {
            satoshis: d.satoshis,
            owner_pkh: d.owner_pkh,
            var2_bytes: vec![],
        })
        .collect();

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    let unlock_bytes = build_unlocking_script(&UnlockParams {
        stas_outputs,
        change: Some(ChangeWitness {
            satoshis: req.change_satoshis,
            owner_pkh: req.change_pkh,
        }),
        note: req.note.clone(),
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
