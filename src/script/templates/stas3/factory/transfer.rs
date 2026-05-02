//! STAS-3 transfer factory.
//!
//! Builds a fully-formed (STAS-input-signed) transfer transaction:
//! 1 STAS in → 1 STAS out (new owner) + P2PKH change.
//!
//! The factory signs only the STAS input (input 0). The funding input
//! (input 1) is left unsigned for the caller to satisfy with a standard
//! P2PKH unlock — this keeps the factory focused and lets callers reuse
//! their existing P2PKH signing infrastructure.

use crate::primitives::hash::hash256;
use crate::script::locking_script::LockingScript;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::STAS3_TX_VERSION;
use super::super::error::Stas3Error;
use super::super::lock::{build_locking_script, LockParams};
use super::super::sighash::build_preimage;
use super::super::spend_type::{SpendType, TxType};
use super::super::unlock::{
    build_unlocking_script, AuthzWitness, ChangeWitness, FundingPointer, StasOutputWitness,
    TrailingParams, UnlockParams,
};
use super::common::{
    funding_input_descriptor, funding_txid_le, make_p2pkh_lock as make_p2pkh_lock_internal,
    pubkey_via_wallet, sign_via_wallet, stas_input_descriptor,
};
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_transfer`.
///
/// Caller is responsible for Type-42 derivation of `destination_owner_pkh`
/// (the new owner's PKH). The factory carries forward the STAS-3 lock's
/// redemption PKH, flags, service fields, and optional data.
#[derive(Clone, Debug)]
pub struct TransferRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Destination owner PKH. MUST be Type-42 derived by the caller.
    pub destination_owner_pkh: [u8; 20],
    /// Carried forward from the input lock.
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    /// Optional inline note (slot 15). `None` emits OP_FALSE.
    pub note: Option<Vec<u8>>,
    /// Inline P2PKH change. The factory always emits a change output;
    /// caller decides the amount (typically `funding_input.satoshis - fee`).
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 transfer transaction.
///
/// Transfer-shape: 1 STAS input -> 1 STAS output (new owner, var2 reset to
/// passive) plus a P2PKH change output. Sums: `stas_input.satoshis ==
/// stas_output.satoshis` (transfer preserves token amount). The funding input
/// covers the fee and the change.
pub async fn build_transfer<W: WalletInterface>(
    req: TransferRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Build the new STAS-3 locking script for the destination owner.
    //    Transfer resets var2 to Passive(empty) per spec §5.1.
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: req.destination_owner_pkh,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh: req.redemption_pkh,
        flags: req.flags,
        service_fields: req.service_fields.clone(),
        optional_data: req.optional_data.clone(),
    })?;

    // 2. Standard 25-byte P2PKH change output.
    let change_lock = make_p2pkh_lock_internal(&req.change_pkh);

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

    // 4. Build the BIP-143 preimage for the STAS input.
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;
    let preimage_hash = hash256(&preimage).to_vec();

    // 5. Sign the STAS input via the wallet (Type-42).
    let sig_with_hash = sign_via_wallet(
        req.wallet,
        &req.stas_input.triple,
        preimage_hash,
        req.originator,
    )
    .await?;

    // 6. Get the matching pubkey for the same triple.
    let pubkey_bytes =
        pubkey_via_wallet(req.wallet, &req.stas_input.triple, req.originator).await?;

    // 7. Funding pointer (txid in LE bytes; tx serialization is BE-hex).
    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 8. Build the STAS unlocking script.
    let unlock_bytes = build_unlocking_script(&UnlockParams {
        stas_outputs: vec![StasOutputWitness {
            satoshis: req.stas_input.satoshis,
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
        tx_type: TxType::Regular,
        spend_type: SpendType::Transfer,
        preimage,
        authz: AuthzWitness::P2pkh {
            sig: sig_with_hash,
            pubkey: pubkey_bytes,
        },
        trailing: TrailingParams::None,
    })?;
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

    // Note: input 1 (the funding input) is left unsigned — the caller signs
    // it with whatever P2PKH machinery they prefer.
    Ok(tx)
}

/// Build a standard 25-byte P2PKH locking script. Helper for change outputs
/// (and for tests). Re-exported from `common::make_p2pkh_lock` for backward
/// compatibility with Phase 5a callers.
pub fn make_p2pkh_lock(pkh: &[u8; 20]) -> LockingScript {
    make_p2pkh_lock_internal(pkh)
}
