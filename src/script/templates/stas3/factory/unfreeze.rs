//! STAS-3 unfreeze factory.
//!
//! Builds a fully-formed (STAS-input-signed) unfreeze transaction:
//! 1 STAS in (Frozen) → 1 STAS out (Passive) + P2PKH change. Symmetric
//! inverse of freeze.
//!
//! Per spec §5.2: the freeze authority key spends a frozen STAS UTXO and
//! transitions its var2 back to Passive. All non-var2 fields are
//! byte-identical to the input.

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::constants::{SIGHASH_DEFAULT, STAS3_TX_VERSION};
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::flags;
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
use super::types::{FundingInput, SigningKey, TokenInput};

/// Inputs to `build_unfreeze`.
///
/// The `stas_input` MUST currently be Frozen and have FREEZABLE set.
/// The `freeze_authority` SigningKey MUST resolve to a pubkey (P2PKH)
/// or MPKH (multisig) that matches the input lock's
/// `service_fields[0]`. Both single-sig and m-of-n multisig freeze
/// authorities are supported per spec §10.2.
#[derive(Clone, Debug)]
pub struct UnfreezeRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Signing key for the freeze authority — single-sig P2PKH (a
    /// `Brc43KeyArgs`, via `triple.into()`) or multisig P2MPKH
    /// (`SigningKey::Multi { triples, multisig }`).
    pub freeze_authority: SigningKey,
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 unfreeze transaction.
///
/// Unfreeze-shape: 1 STAS in (Frozen) -> 1 STAS out (Passive, all other
/// fields byte-identical) + P2PKH change. spendType=2, txType=Regular.
/// Signed by the freeze authority.
pub async fn build_unfreeze<W: WalletInterface>(
    req: UnfreezeRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. Decode the input lock.
    let decoded = decode_locking_script(&req.stas_input.locking_script)?;

    // 2. Validate FREEZABLE flag.
    if !flags::is_freezable(decoded.flags) {
        return Err(Stas3Error::FreezableNotSet);
    }

    // 3. Compute the new (unfrozen) action data per spec §6.2.
    //    Frozen(rest) → Passive(rest); anything else → reject.
    let new_action_data = match &req.stas_input.current_action_data {
        ActionData::Frozen(rest) => ActionData::Passive(rest.clone()),
        _ => {
            return Err(Stas3Error::InvalidState(
                "cannot unfreeze: input is not frozen".into(),
            ))
        }
    };

    // 4. Build the new lock — only var2 changes; all other fields preserved.
    let new_lock = build_locking_script(&LockParams {
        owner_pkh: decoded.owner_pkh,
        action_data: new_action_data.clone(),
        redemption_pkh: decoded.redemption_pkh,
        flags: decoded.flags,
        service_fields: decoded.service_fields.clone(),
        optional_data: decoded.optional_data.clone(),
    })?;
    let change_lock = make_p2pkh_lock(&req.change_pkh);

    // 5. Assemble the spending tx skeleton.
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

    // 6. Sign with the freeze authority. May be P2PKH or P2MPKH.
    let preimage = build_preimage(
        &tx,
        0,
        req.stas_input.satoshis,
        &req.stas_input.locking_script,
    )?;
    let authz = sign_with_signing_key(
        req.wallet,
        req.originator,
        &req.freeze_authority,
        &decoded.owner_pkh,
        &preimage,
        SIGHASH_DEFAULT as u8,
    )
    .await?;

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 7. Build the unlocking script. spendType=FreezeUnfreeze (2),
    //    txType=Regular. var2_bytes encodes the new (Passive) form.
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
        spend_type: SpendType::FreezeUnfreeze,
        preimage,
        authz,
        trailing: TrailingParams::None,
    })?;
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

    Ok(tx)
}
