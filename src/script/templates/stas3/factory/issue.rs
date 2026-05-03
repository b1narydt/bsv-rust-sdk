//! STAS-3 issuance: 2-tx contract+issue flow (production parity).
//!
//! Mirrors the canonical TS reference
//! `dxs-bsv-token-sdk::BuildDstasIssueTxs` (see
//! `~/METAWATT/METAWATT-code/dxs-bsv-token-sdk/src/dstas-factory.ts:318-397`),
//! which splits an issuance into two chained transactions:
//!
//! 1. **Contract tx** — input 0 = the funding outpoint (signed by the
//!    funding/issuer key). Output 0 = a standard 25-byte P2PKH locked
//!    back to the issuer with `OP_FALSE OP_RETURN <scheme_bytes>`
//!    appended; sats = total token satoshis. Output 1 = P2PKH change
//!    minus fee.
//! 2. **Issue tx** — input 0 = contract_tx[0] (the bundled supply, signed
//!    by the issuer); input 1 = contract_tx[1] (the change, signed by
//!    the issuer). Outputs `0..N-1` = STAS-3 lock per destination;
//!    output `N` = P2PKH change minus fee.
//!
//! Both transactions sign every input with the same `issuer_signing_key`
//! (which MUST be `SigningKey::P2pkh` — multisig issuers are not
//! supported because the production TS path is single-sig). The
//! P2PKH-input signing path used here builds the BIP-143 preimage with
//! `Transaction::sighash_preimage` (same scope as STAS-3 spends:
//! `SIGHASH_ALL | SIGHASH_FORKID = 0x41`) then hashes it once with
//! `hash256` before passing to `wallet.create_signature`. The output
//! unlocking script is the standard `<sig+sighash> <pubkey>` two-push
//! P2PKH form.
//!
//! ## Fee policy
//!
//! Two-pass: the factory builds each tx with a placeholder change of 0,
//! measures the serialized size, and recomputes change as
//! `inputs - outputs - ceil(size * fee_rate / 1000)` before rebuilding.
//! `fee_rate_sat_per_kb` matches the TS reference
//! (`feeRate = 0.5 sat/byte → 500 sat/kB` default).
//!
//! The simple two-pass converges because adding a change output adds
//! ~34 bytes regardless of value; we don't iterate further. If you
//! find the resulting fee underpaid by a satoshi or two due to varint
//! creep on extreme tx sizes, raise `fee_rate_sat_per_kb` slightly.

use crate::primitives::hash::hash160;
use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::transaction::Transaction;
use crate::transaction::transaction_output::TransactionOutput;
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};

use super::super::action_data::ActionData;
use super::super::constants::{SIGHASH_DEFAULT, STAS3_TX_VERSION};
use super::super::error::Stas3Error;
use super::super::lock::{build_locking_script, LockParams};
use super::super::sighash::build_preimage;
use super::common::{
    compute_txid_le, funding_input_descriptor, make_p2pkh_lock,
    make_p2pkh_with_op_return,
};
use super::types::{FundingInput, SigningKey};

/// One issuance destination — receives a freshly-minted STAS-3 token
/// output in the issue tx.
#[derive(Clone, Debug)]
pub struct IssueDestination {
    /// 20-byte HASH160 of the destination owner's public key (Type-42 derived).
    pub owner_pkh: [u8; 20],
    /// var2 form on the destination output. Most issuance flows use
    /// `ActionData::Passive(vec![])`, but the spec leaves this open so
    /// callers can mint tokens in non-default initial states (e.g.
    /// pre-frozen, or pre-marked-for-swap).
    pub action_data: ActionData,
    /// Token satoshi value of this destination's STAS-3 output.
    pub satoshis: u64,
    /// Optional-data section emitted on the locking script. For EAC tokens
    /// callers pass `EacFields::to_optional_data()`; for plain STAS-3
    /// tokens this is typically empty.
    pub optional_data: Vec<Vec<u8>>,
}

/// Inputs to [`build_issue`].
#[derive(Clone, Debug)]
pub struct IssueRequest<'a, W: WalletInterface + ?Sized> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// The issuer key — signs every input of both transactions. MUST be
    /// `SigningKey::P2pkh` (multisig issuance is not supported by the
    /// production TS reference, so we don't synthesize it).
    pub issuer_signing_key: SigningKey,
    /// HASH160 of the issuer's public key. The factory verifies that
    /// this matches the wallet-derived pubkey hash; mismatches are a
    /// programmer error caught early.
    pub redemption_pkh: [u8; 20],
    /// Flags byte for the destination locks (FREEZABLE / CONFISCATABLE).
    pub flags: u8,
    /// Service fields (one per set flag bit, low-to-high), carried as-is
    /// onto every destination's lock.
    pub service_fields: Vec<Vec<u8>>,
    /// Scheme metadata bytes — written into the trailing
    /// `OP_FALSE OP_RETURN <scheme>` of the contract tx output 0.
    /// Mirrors `scheme.toBytes()` in the TS reference.
    pub scheme_bytes: Vec<u8>,
    /// The funding UTXO consumed by the contract tx input 0. The
    /// `funding_input.triple` is honored: the factory signs the funding
    /// input with the funder's own key (matching transfer/split/merge
    /// convention). The issuer key is used only for the issue tx (which
    /// spends the contract tx's two outputs — both locked to the
    /// issuer).
    ///
    /// Note: the contract tx's change output and the issue tx's change
    /// output are both still locked to `redemption_pkh` (the issuer's
    /// pkh). For mints where funder != issuer, the funder is effectively
    /// transferring the leftover (funding − token_sats − fees) to the
    /// issuer. Budget accordingly.
    pub funding_input: FundingInput,
    /// At least one destination required.
    pub destinations: Vec<IssueDestination>,
    /// Fee rate in sat/kB (TS default = 500).
    pub fee_rate_sat_per_kb: u64,
}

/// Output of [`build_issue`] — the two fully-signed transactions.
#[derive(Clone, Debug)]
pub struct IssueResult {
    pub contract_tx: Transaction,
    pub issue_tx: Transaction,
}

/// Build the production 2-tx STAS-3 issuance (contract + issue).
///
/// Both transactions are fully signed and ready to broadcast; the caller
/// is responsible for broadcasting `contract_tx` *first* (the issue tx
/// references its outputs).
///
/// See the module-level docs for the fee-calculation algorithm and
/// transaction shapes.
pub async fn build_issue<W: WalletInterface + ?Sized>(
    req: IssueRequest<'_, W>,
) -> Result<IssueResult, Stas3Error> {
    // -----------------------------------------------------------------
    // 1. Validation
    // -----------------------------------------------------------------
    if req.destinations.is_empty() {
        return Err(Stas3Error::InvalidScript(
            "issuance: at least one destination is required".into(),
        ));
    }
    let total_token_sats: u64 = req.destinations.iter().try_fold(0u64, |acc, d| {
        if d.satoshis == 0 {
            return Err(Stas3Error::InvalidScript(
                "issuance destination satoshis must be > 0".into(),
            ));
        }
        acc.checked_add(d.satoshis).ok_or_else(|| {
            Stas3Error::InvalidScript("issuance: total destination sats overflow u64".into())
        })
    })?;
    if total_token_sats >= req.funding_input.satoshis {
        return Err(Stas3Error::InvalidScript(format!(
            "issuance: funding {} sats must exceed total token sats {}",
            req.funding_input.satoshis, total_token_sats,
        )));
    }
    let issuer_triple = match &req.issuer_signing_key {
        SigningKey::P2pkh(t) => t.clone(),
        SigningKey::Multi { .. } => {
            return Err(Stas3Error::InvalidScript(
                "issuance: multisig issuer is not supported (production parity)".into(),
            ));
        }
    };

    // -----------------------------------------------------------------
    // 2. Resolve issuer pubkey + verify pkh matches redemption_pkh
    // -----------------------------------------------------------------
    let issuer_pk = req
        .wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(issuer_triple.protocol_id.clone()),
                key_id: Some(issuer_triple.key_id.clone()),
                counterparty: Some(issuer_triple.counterparty.clone()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
            req.originator,
        )
        .await
        .map_err(|e| Stas3Error::InvalidScript(format!("issuer pubkey: {e}")))?;
    let issuer_pubkey_bytes = issuer_pk.public_key.to_der();
    let issuer_pkh = hash160(&issuer_pubkey_bytes);
    if issuer_pkh != req.redemption_pkh {
        return Err(Stas3Error::InvalidScript(format!(
            "issuance: wallet-derived issuer pkh {:02x?} != redemption_pkh {:02x?}",
            issuer_pkh, req.redemption_pkh
        )));
    }

    // -----------------------------------------------------------------
    // 3. Build contract tx (two-pass for fee)
    // -----------------------------------------------------------------
    let supply_output = make_p2pkh_with_op_return(
        total_token_sats,
        &req.redemption_pkh,
        &req.scheme_bytes,
    );

    let contract_tx_pass1 = build_contract_tx_skeleton(
        &req.funding_input,
        supply_output.clone(),
        &req.redemption_pkh,
        0, // placeholder change
    );
    let pass1_size = serialized_size_with_p2pkh_unlock(&contract_tx_pass1, &[true])?;
    let contract_fee = ceil_div(pass1_size as u64 * req.fee_rate_sat_per_kb, 1000);
    let contract_change = req
        .funding_input
        .satoshis
        .checked_sub(total_token_sats)
        .and_then(|x| x.checked_sub(contract_fee))
        .ok_or_else(|| {
            Stas3Error::InvalidScript(format!(
                "contract tx fee {} would underflow change ({} - {} - fee)",
                contract_fee, req.funding_input.satoshis, total_token_sats
            ))
        })?;

    let mut contract_tx = build_contract_tx_skeleton(
        &req.funding_input,
        supply_output,
        &req.redemption_pkh,
        contract_change,
    );

    // Sign contract tx input 0 (the funding input) with the FUNDER's key
    // (from `funding_input.triple`), not the issuer key. This lets any
    // fuel UTXO bankroll a mint — issuer and funder identities are
    // independent. Matches the transfer/split/merge convention where
    // funding inputs are signed by their own owner.
    let funding_pk = req
        .wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(req.funding_input.triple.protocol_id.clone()),
                key_id: Some(req.funding_input.triple.key_id.clone()),
                counterparty: Some(req.funding_input.triple.counterparty.clone()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
            req.originator,
        )
        .await
        .map_err(|e| Stas3Error::InvalidScript(format!("funding pubkey: {e}")))?;
    let funding_pubkey_bytes = funding_pk.public_key.to_der();

    sign_p2pkh_input(
        req.wallet,
        req.originator,
        &mut contract_tx,
        0,
        req.funding_input.satoshis,
        &req.funding_input.locking_script,
        &req.funding_input.triple,
        &funding_pubkey_bytes,
    )
    .await?;

    let contract_txid_le = compute_txid_le(&contract_tx)?;

    // -----------------------------------------------------------------
    // 4. Build issue tx (two-pass for fee)
    // -----------------------------------------------------------------
    let stas_outputs: Vec<TransactionOutput> = req
        .destinations
        .iter()
        .map(|d| {
            let lock = build_locking_script(&LockParams {
                owner_pkh: d.owner_pkh,
                action_data: d.action_data.clone(),
                redemption_pkh: req.redemption_pkh,
                flags: req.flags,
                service_fields: req.service_fields.clone(),
                optional_data: d.optional_data.clone(),
            })?;
            Ok(TransactionOutput {
                satoshis: Some(d.satoshis),
                locking_script: lock,
                change: false,
            })
        })
        .collect::<Result<Vec<_>, Stas3Error>>()?;

    // Issue tx pass 1 with placeholder change.
    let issue_tx_pass1 = build_issue_tx_skeleton(
        &contract_txid_le,
        &stas_outputs,
        &req.redemption_pkh,
        0,
    );
    // Both inputs are P2PKH-unlocked.
    let issue_pass1_size = serialized_size_with_p2pkh_unlock(&issue_tx_pass1, &[true, true])?;
    let issue_fee = ceil_div(issue_pass1_size as u64 * req.fee_rate_sat_per_kb, 1000);
    let issue_change = contract_change.checked_sub(issue_fee).ok_or_else(|| {
        Stas3Error::InvalidScript(format!(
            "issue tx fee {} exceeds contract change {}",
            issue_fee, contract_change
        ))
    })?;

    let mut issue_tx = build_issue_tx_skeleton(
        &contract_txid_le,
        &stas_outputs,
        &req.redemption_pkh,
        issue_change,
    );

    // Sign both inputs of the issue tx with the issuer key.
    // Input 0 spends contract output 0 (the supply output: P2PKH+OP_RETURN).
    // Input 1 spends contract output 1 (the change: plain P2PKH).
    let supply_lock = contract_tx.outputs[0].locking_script.clone();
    let change_lock = contract_tx.outputs[1].locking_script.clone();

    sign_p2pkh_input(
        req.wallet,
        req.originator,
        &mut issue_tx,
        0,
        total_token_sats,
        &supply_lock,
        &issuer_triple,
        &issuer_pubkey_bytes,
    )
    .await?;
    sign_p2pkh_input(
        req.wallet,
        req.originator,
        &mut issue_tx,
        1,
        contract_change,
        &change_lock,
        &issuer_triple,
        &issuer_pubkey_bytes,
    )
    .await?;

    Ok(IssueResult {
        contract_tx,
        issue_tx,
    })
}

// =====================================================================
// Internal helpers
// =====================================================================

fn ceil_div(num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    (num + den - 1) / den
}

/// Build the contract-tx skeleton with no signatures.
fn build_contract_tx_skeleton(
    funding: &FundingInput,
    supply_output: TransactionOutput,
    issuer_pkh: &[u8; 20],
    change_satoshis: u64,
) -> Transaction {
    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    tx.inputs.push(funding_input_descriptor(funding));
    tx.outputs.push(supply_output);
    tx.outputs.push(TransactionOutput {
        satoshis: Some(change_satoshis),
        locking_script: make_p2pkh_lock(issuer_pkh),
        change: false,
    });
    tx
}

/// Build the issue-tx skeleton with no signatures.
fn build_issue_tx_skeleton(
    contract_txid_le: &[u8; 32],
    stas_outputs: &[TransactionOutput],
    issuer_pkh: &[u8; 20],
    issue_change_satoshis: u64,
) -> Transaction {
    use crate::primitives::utils::to_hex;
    use crate::transaction::transaction_input::TransactionInput;

    // Convert LE wire-form txid back to BE-hex display form (which is
    // what the TransactionInput holds; to_binary() reverses on the wire).
    let mut be = *contract_txid_le;
    be.reverse();
    let txid_hex = to_hex(&be);

    let mut tx = Transaction::new();
    tx.version = STAS3_TX_VERSION;
    tx.inputs.push(TransactionInput {
        source_transaction: None,
        source_txid: Some(txid_hex.clone()),
        source_output_index: 0,
        unlocking_script: None,
        sequence: 0xffffffff,
    });
    tx.inputs.push(TransactionInput {
        source_transaction: None,
        source_txid: Some(txid_hex),
        source_output_index: 1,
        unlocking_script: None,
        sequence: 0xffffffff,
    });
    for o in stas_outputs {
        tx.outputs.push(o.clone());
    }
    tx.outputs.push(TransactionOutput {
        satoshis: Some(issue_change_satoshis),
        locking_script: make_p2pkh_lock(issuer_pkh),
        change: false,
    });
    tx
}

/// Estimate serialized size assuming each input either has no unlock
/// (`false`) or a typical 108-byte P2PKH unlock (`true`).
///
/// We measure the actual bytes of the placeholder-built tx and add an
/// estimated unlock script length per "true" input. The placeholder tx
/// has `unlocking_script = None`, which `to_binary` writes as a 1-byte
/// `varint(0)` script; we account for that and also for the varint
/// inflation of swapping a 0-byte script for a 108-byte one (1→2 bytes
/// of length prefix).
fn serialized_size_with_p2pkh_unlock(
    tx: &Transaction,
    p2pkh_per_input: &[bool],
) -> Result<usize, Stas3Error> {
    let raw = tx
        .to_bytes()
        .map_err(|e| Stas3Error::InvalidScript(format!("estimate size: {e}")))?;
    let mut total = raw.len();
    for &is_p2pkh in p2pkh_per_input {
        if is_p2pkh {
            // 108 bytes typical unlock + 1 extra byte for varint(108) - varint(0).
            total += 108 + 1;
        }
    }
    Ok(total)
}

/// Sign one P2PKH input of `tx` with the issuer's wallet-resolved key
/// and install the resulting `<sig+sighash> <pubkey>` unlocking script.
#[allow(clippy::too_many_arguments)]
async fn sign_p2pkh_input<W: WalletInterface + ?Sized>(
    wallet: &W,
    originator: Option<&str>,
    tx: &mut Transaction,
    input_index: usize,
    source_satoshis: u64,
    prev_locking_script: &crate::script::locking_script::LockingScript,
    triple: &super::super::brc43_key_args::Brc43KeyArgs,
    pubkey_der: &[u8],
) -> Result<(), Stas3Error> {
    let preimage = build_preimage(tx, input_index, source_satoshis, prev_locking_script)?;
    let preimage_hash = crate::primitives::hash::hash256(&preimage).to_vec();
    let sig_with_hash = sign_via_wallet_with_byte(
        wallet,
        triple,
        preimage_hash,
        originator,
        SIGHASH_DEFAULT as u8,
    )
    .await?;
    let unlock_bytes = build_p2pkh_unlock_bytes(&sig_with_hash, pubkey_der);
    tx.inputs[input_index].unlocking_script = Some(UnlockingScript::from_binary(&unlock_bytes));
    Ok(())
}

/// Internal: sign a hash and append a specific sighash byte.
async fn sign_via_wallet_with_byte<W: WalletInterface + ?Sized>(
    wallet: &W,
    triple: &super::super::brc43_key_args::Brc43KeyArgs,
    hash_to_sign: Vec<u8>,
    originator: Option<&str>,
    sighash_byte: u8,
) -> Result<Vec<u8>, Stas3Error> {
    use crate::wallet::interfaces::CreateSignatureArgs;
    let sig_result = wallet
        .create_signature(
            CreateSignatureArgs {
                protocol_id: triple.protocol_id.clone(),
                key_id: triple.key_id.clone(),
                counterparty: triple.counterparty.clone(),
                data: None,
                hash_to_directly_sign: Some(hash_to_sign),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            originator,
        )
        .await
        .map_err(|e| Stas3Error::InvalidScript(format!("issuance P2PKH input sign: {e}")))?;
    let mut sig = sig_result.signature;
    sig.push(sighash_byte);
    Ok(sig)
}

/// Build a standard P2PKH unlocking script: `<sig+sighash> <pubkey>`.
fn build_p2pkh_unlock_bytes(sig_with_hash: &[u8], pubkey: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + sig_with_hash.len() + pubkey.len());
    // Push sig
    if sig_with_hash.len() <= 75 {
        out.push(sig_with_hash.len() as u8);
    } else {
        out.push(0x4c);
        out.push(sig_with_hash.len() as u8);
    }
    out.extend_from_slice(sig_with_hash);
    // Push pubkey
    if pubkey.len() <= 75 {
        out.push(pubkey.len() as u8);
    } else {
        out.push(0x4c);
        out.push(pubkey.len() as u8);
    }
    out.extend_from_slice(pubkey);
    out
}

