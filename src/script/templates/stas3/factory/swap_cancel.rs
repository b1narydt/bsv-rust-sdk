//! STAS-3 swap-cancel factory (spec v0.2 §5.4 / §9.4).
//!
//! Cancels a swap-marked UTXO by spending it back to the descriptor's
//! `receive_addr`. The maker (or whoever holds the receive_addr key)
//! reclaims the token and resets var2 to passive.
//!
//! Per spec §5.4:
//! - `spendType = 4` (SwapCancellation)
//! - Single output whose owner equals the input descriptor's `receive_addr`
//! - Authorization validates under that same `receive_addr`
//! - Input var2 must be a swap descriptor
//! - Conservation: output satoshis = input satoshis
//!
//! The `receive_addr_triple` MUST resolve to a pubkey whose HASH160 matches
//! the input descriptor's `receive_addr`. The factory does not re-derive —
//! the caller is responsible for the Type-42 derivation that produced
//! `receive_addr` in the first place.

use crate::primitives::hash::hash256;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::STAS3_TX_VERSION;
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::key_triple::KeyTriple;
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
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_swap_cancel`.
///
/// `stas_input.current_action_data` MUST be `ActionData::Swap(_)`.
/// `receive_addr_triple` MUST be the triple under which `descriptor.receive_addr`
/// was derived — its pubkey's HASH160 must match the descriptor's `receive_addr`.
#[derive(Clone, Debug)]
pub struct SwapCancelRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// Must carry a swap descriptor in `current_action_data`.
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Type-42 triple that derives a pubkey whose HASH160 = descriptor.receive_addr.
    pub receive_addr_triple: KeyTriple,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 swap-cancel transaction.
///
/// Cancel-shape: 1 STAS in (var2 = Swap) -> 1 STAS out (owner = descriptor's
/// receive_addr, var2 reset to Passive(empty), all other lock fields
/// byte-identical) + P2PKH change. spendType=SwapCancellation (4),
/// txType=Regular. Signed by the receive_addr key.
pub async fn build_swap_cancel<W: WalletInterface>(
    req: SwapCancelRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Validate the input carries a swap descriptor.
    let descriptor = match &req.stas_input.current_action_data {
        ActionData::Swap(d) => d.clone(),
        _ => {
            return Err(Stas3Error::InvalidState(
                "swap_cancel input must be swap-marked (var2 = SwapDescriptor)".into(),
            ))
        }
    };

    // 2. Decode the input lock to recover redemption_pkh / flags / svc / opt.
    let decoded = decode_locking_script(&req.stas_input.locking_script)?;

    // 3. Build new lock — owner = descriptor.receive_addr, var2 reset to passive,
    //    all other lock fields preserved.
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: descriptor.receive_addr,
        action_data: ActionData::Passive(vec![]),
        redemption_pkh: decoded.redemption_pkh,
        flags: decoded.flags,
        service_fields: decoded.service_fields.clone(),
        optional_data: decoded.optional_data.clone(),
    })?;
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // 4. Assemble the spending tx skeleton.
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

    // 5. Sign with the receive_addr_triple (NOT the input owner — receive_addr
    //    is who can cancel).
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;
    let preimage_hash = hash256(&preimage).to_vec();
    let sig_with_hash = sign_via_wallet(
        req.wallet,
        &req.receive_addr_triple,
        preimage_hash,
        req.originator,
    )
    .await?;
    let pubkey_bytes =
        pubkey_via_wallet(req.wallet, &req.receive_addr_triple, req.originator).await?;

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 6. Build the unlocking script. spendType=SwapCancellation (4),
    //    txType=Regular (0), no trailing params.
    let unlock_bytes = build_unlocking_script(&UnlockParams {
        stas_outputs: vec![StasOutputWitness {
            satoshis: req.stas_input.satoshis,
            owner_pkh: descriptor.receive_addr,
            var2_bytes: vec![],
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
        spend_type: SpendType::SwapCancellation,
        preimage,
        authz: AuthzWitness::P2pkh {
            sig: sig_with_hash,
            pubkey: pubkey_bytes,
        },
        trailing: TrailingParams::None,
    })?;
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

    Ok(tx)
}
