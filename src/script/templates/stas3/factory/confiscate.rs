//! STAS-3 confiscate factory.
//!
//! Builds a fully-formed (STAS-input-signed) confiscation transaction:
//! 1 STAS in (CONFISCATABLE) → 1 STAS out (any owner) + P2PKH change.
//!
//! Per spec §5.3: the confiscation authority key spends a confiscatable
//! STAS UTXO and reassigns it to any destination owner — typically a
//! regulator or recipient. The confiscation operation is the most
//! permissive: no var2 / owner / amount restrictions beyond the standard
//! STAS-3 lock structure being preserved (engine + protoID + flags + svc +
//! optional data byte-identical).
//!
//! Authority resolution: when CONFISCATABLE is set, its service field is
//! the HASH160 of the confiscation authority's pubkey. Position depends on
//! flags: `service_fields[0]` if CONFISCATABLE only, `service_fields[1]` if
//! both FREEZABLE and CONFISCATABLE are set (spec §5.2.2 left-to-right
//! ordering). The caller passes the matching Type-42 triple via
//! `confiscation_authority_triple`.

use crate::primitives::hash::hash256;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::STAS3_TX_VERSION;
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::flags;
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

/// Inputs to `build_confiscate`.
///
/// The `stas_input` MUST have CONFISCATABLE set in its flags byte. The
/// `confiscation_authority_triple` MUST resolve to a pubkey whose HASH160
/// matches the CONFISCATABLE service field on the input lock.
#[derive(Clone, Debug)]
pub struct ConfiscateRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Type-42 triple for the confiscation authority key — signs the spend.
    pub confiscation_authority_triple: KeyTriple,
    /// The new owner of the confiscated UTXO (typically a regulator).
    pub destination_owner_pkh: [u8; 20],
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 confiscation transaction.
///
/// Confiscation-shape: 1 STAS in -> 1 STAS out (new owner = destination,
/// var2 reset to Passive(empty)) + P2PKH change. spendType=3,
/// txType=Regular. Signed by the confiscation authority.
pub async fn build_confiscate<W: WalletInterface>(
    req: ConfiscateRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Decode the input lock.
    let decoded = decode_locking_script(&req.stas_input.locking_script)?;

    // 2. Validate CONFISCATABLE flag.
    if !flags::is_confiscatable(decoded.flags) {
        return Err(Stas3Error::ConfiscatableNotSet);
    }

    // 3. Build the new lock at the destination owner. Carry forward
    //    redemption_pkh, flags, service_fields, optional_data byte-identical;
    //    var2 reset to Passive(empty) so the confiscated UTXO is normally
    //    spendable from the destination.
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: req.destination_owner_pkh,
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

    // 5. Sign with the CONFISCATION AUTHORITY.
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;
    let preimage_hash = hash256(&preimage).to_vec();
    let sig_with_hash = sign_via_wallet(
        req.wallet,
        &req.confiscation_authority_triple,
        preimage_hash,
        req.originator,
    )
    .await?;
    let pubkey_bytes = pubkey_via_wallet(
        req.wallet,
        &req.confiscation_authority_triple,
        req.originator,
    )
    .await?;

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 6. Build the unlocking script. spendType=Confiscation (3),
    //    txType=Regular. STAS triplet for the destination output.
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
        note: None,
        funding: Some(FundingPointer {
            vout: req.funding_input.vout,
            txid_le: txid_le_arr,
        }),
        tx_type: TxType::Regular,
        spend_type: SpendType::Confiscation,
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
