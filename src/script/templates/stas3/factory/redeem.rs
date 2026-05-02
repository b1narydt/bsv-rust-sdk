//! STAS-3 redeem factory.
//!
//! Builds a fully-formed (STAS-input-signed) redeem transaction. Per spec
//! §5.6 ("Burn semantics"): only the issuer can redeem (= burn) by spending
//! tokens received at `protoID` to any other address. The factory enforces
//! `owner_pkh == redemption_pkh` on the input lock; otherwise it returns
//! `InvalidState`.
//!
//! ## Structural shape (canonical, per spec §10.2 + dxs conformance vectors)
//!
//! Redeem is a regular spend (txType=0, spendType=1) that satisfies two
//! preconditions: (1) the input STAS UTXO is owned by the issuer
//! (`owner_pkh == redemption_pkh`); without this, the engine would reject
//! under the precedence rules (§5.6); (2) the witness's var2 at slot 1-3
//! is empty.
//!
//! The redemption output is the canonical 70-byte **P2MPKH** locking
//! script at `redemption_destination_pkh`. The canonical 2,899-byte engine
//! recognizes this shape via its embedded reconstruction template
//! (prefix `4676a914 ...`, suffix `888201218763ac... ae68`) when the
//! triggering conditions above are met, and reconstructs `hashOutputs`
//! using the 70-byte P2MPKH template at slot 1-3 instead of the full
//! STAS-3 lock. This matches the `redeem_by_issuer_valid` conformance
//! vector and the dxs `addP2MpkhOutput` redeem path.
//!
//! Output[1] is the funding's P2PKH change.

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::WalletInterface;

use super::super::constants::{SIGHASH_DEFAULT, STAS3_TX_VERSION};
use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::sighash::build_preimage;
use super::super::spend_type::{SpendType, TxType};
use super::super::unlock::{
    build_unlocking_script, ChangeWitness, FundingPointer, StasOutputWitness,
    TrailingParams, UnlockParams,
};
use super::common::{
    build_p2mpkh_locking_script, funding_input_descriptor, funding_txid_le, make_p2pkh_lock,
    sign_with_signing_key, stas_input_descriptor,
};
use super::types::{FundingInput, TokenInput};

/// Inputs to `build_redeem`.
///
/// The `stas_input` MUST satisfy `owner_pkh == redemption_pkh` (the input
/// is at the issuer's protoID address). Otherwise, the call returns
/// `Stas3Error::InvalidState`.
#[derive(Clone, Debug)]
pub struct RedeemRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// MUST be a STAS-3 UTXO at the issuer's protoID address
    /// (`owner_pkh == redemption_pkh`).
    pub stas_input: TokenInput,
    pub funding_input: FundingInput,
    /// Type-42-derived destination MPKH that receives the redeemed satoshis
    /// at a canonical 70-byte P2MPKH locking script. Per spec §10.2 this is
    /// the "burn-to-issuer-multisig" output recognized by the engine's
    /// embedded reconstruction template.
    pub redemption_destination_pkh: [u8; 20],
    /// Inline P2PKH change for the funding input. Caller decides amount
    /// (typically `funding_input.satoshis - fee`).
    pub change_pkh: [u8; 20],
    pub change_satoshis: u64,
}

/// Build a signed STAS-3 redeem transaction.
///
/// Canonical redeem-shape per spec §10.2: 1 STAS input -> 70-byte P2MPKH
/// output at the redemption destination + P2PKH funding change. The input
/// MUST be issuer-owned (`owner_pkh == redemption_pkh`); the witness
/// var2 at slot 1-3 is empty, which together with the owner==redemption_pkh
/// condition triggers the engine's P2MPKH reconstruction branch.
pub async fn build_redeem<W: WalletInterface>(
    req: RedeemRequest<'_, W>,
) -> Result<Transaction, Stas3Error> {
    // 1. CRITICAL: validate that the input is owned by the issuer
    //    (owner_pkh == redemption_pkh) per spec §5.6.
    let decoded = decode_locking_script(&req.stas_input.locking_script)?;
    if decoded.owner_pkh != decoded.redemption_pkh {
        return Err(Stas3Error::InvalidState(format!(
            "redeem requires owner == redemption_pkh; owner={:02x?} redemption_pkh={:02x?}",
            decoded.owner_pkh, decoded.redemption_pkh
        )));
    }

    // 2. Build the canonical 70-byte P2MPKH locking script for the
    //    redemption destination (spec §10.2). The engine reconstructs
    //    hashOutputs using its embedded P2MPKH template when the witness
    //    triggers the redeem branch (owner==redemption_pkh + empty var2).
    let new_lock = build_p2mpkh_locking_script(&req.redemption_destination_pkh);
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

    // 4. Sign STAS input (Type-42 wallet derivation).
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
        &decoded.owner_pkh,
        &preimage,
        SIGHASH_DEFAULT as u8,
    )
    .await?;

    let txid_le_arr = funding_txid_le(&req.funding_input.txid_hex)?;

    // 5. Build the unlocking script. Single STAS triplet (slots 1-3) for
    //    the redemption-destination output. Change pair (slots 13-14) for
    //    the funding-fee P2PKH change.
    let unlock_bytes = build_unlocking_script(&UnlockParams {
        stas_outputs: vec![StasOutputWitness {
            satoshis: req.stas_input.satoshis,
            owner_pkh: req.redemption_destination_pkh,
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
        spend_type: SpendType::Transfer,
        preimage,
        authz,
        trailing: TrailingParams::None,
    })?;
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));

    Ok(tx)
}
