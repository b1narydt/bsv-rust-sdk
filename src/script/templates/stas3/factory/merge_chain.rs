//! STAS-3 N-input merge via chained 2-input merges (binary tree).
//!
//! Mirrors the dxs `mergeStasTransactions` pattern from
//! [`dxsapp/dxs-bsv-token-sdk`](https://github.com/dxsapp/dxs-bsv-token-sdk)
//! `src/stas-bundle-factory.ts`: pair STAS UTXOs 2-at-a-time, threading
//! each pairwise merged STAS output into the next level. Yields a
//! sequence of `Transaction`s the caller broadcasts in order.
//!
//! Why this exists: STAS-3 spec §8.1 defines per-input txType in 2..=7,
//! but the trailing-piece-array wire layout for N>2 is ambiguous and
//! unverifiable against any reference. The dxs reference SDK explicitly
//! limits a single merge tx to 2 STAS inputs
//! (`docs/DSTAS_CONFORMANCE_MATRIX.md`). We follow the same pattern:
//! atomic merge is N=2; N>2 is a chain of N-1 atomic merges.
//!
//! ## Funding model
//!
//! `build_merge_chain` is *deliberately* non-magical about funding:
//! the caller supplies one [`FundingInput`] per pairwise merge
//! (`fundings.len() == stas_inputs.len() - 1`). It does NOT auto-thread
//! a single fee UTXO across merges by spending change. If you want the
//! dxs-style auto-funding chain, build it on top of this primitive.
//!
//! ## Convergence
//!
//! All intermediate AND final merges output to a single
//! `destination_owner_pkh`. Intermediate STAS outputs are signed at
//! the next level using `destination_signing_key`. This keeps the chain
//! coherent (one converging owner) and matches dxs's `stasWallet` model.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::ActionData;
use super::super::error::Stas3Error;
use super::merge::{build_merge, MergeRequest};
use super::types::{FundingInput, SigningKey, TokenInput};

/// Inputs to [`build_merge_chain`]. See module docs for the funding and
/// convergence model.
#[derive(Clone, Debug)]
pub struct MergeChainRequest<'a, W: WalletInterface> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    /// 2..=N STAS inputs to merge into one. Each MUST set `source_tx_bytes`.
    /// N=1 is rejected; for a single passive UTXO use transfer instead.
    pub stas_inputs: Vec<TokenInput>,
    /// One funding UTXO per pairwise merge. MUST satisfy
    /// `fundings.len() == stas_inputs.len() - 1`.
    pub fundings: Vec<FundingInput>,
    /// Destination owner of every STAS output produced by the chain
    /// (intermediate AND final). Type-42 derived by the caller.
    pub destination_owner_pkh: [u8; 20],
    /// Signing-key authorization for spending intermediate STAS outputs
    /// at subsequent merge levels. Must derive to `destination_owner_pkh`.
    pub destination_signing_key: SigningKey,
    /// Token-type fields (must match all inputs). Carried forward onto
    /// every merged STAS output.
    pub redemption_pkh: [u8; 20],
    pub flags: u8,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    /// Optional inline note applied to every merge in the chain.
    pub note: Option<Vec<u8>>,
    /// One change PKH per pairwise merge. MUST satisfy
    /// `change_pkhs.len() == stas_inputs.len() - 1`.
    pub change_pkhs: Vec<[u8; 20]>,
    /// One change-satoshi value per pairwise merge. MUST satisfy
    /// `change_satoshis.len() == stas_inputs.len() - 1`.
    pub change_satoshis: Vec<u64>,
}

/// Build a chain of 2-input merges that converges N STAS UTXOs into one.
///
/// Returns transactions in broadcast order: tx[0] must confirm before
/// tx[1] can spend its merged output, etc. For N inputs the chain
/// contains exactly N-1 transactions.
///
/// For N=2 this returns a single-element vec equivalent to calling
/// [`build_merge`] directly. For N=1 it returns
/// [`Stas3Error::InvalidScript`].
pub async fn build_merge_chain<W: WalletInterface>(
    req: MergeChainRequest<'_, W>,
) -> Result<Vec<Transaction>, Stas3Error> {
    let n = req.stas_inputs.len();
    if n < 2 {
        return Err(Stas3Error::InvalidScript(format!(
            "build_merge_chain requires at least 2 STAS inputs; got {n}"
        )));
    }
    let expected_merges = n - 1;
    if req.fundings.len() != expected_merges {
        return Err(Stas3Error::InvalidScript(format!(
            "build_merge_chain: expected {expected_merges} fundings (n-1); got {}",
            req.fundings.len()
        )));
    }
    if req.change_pkhs.len() != expected_merges
        || req.change_satoshis.len() != expected_merges
    {
        return Err(Stas3Error::InvalidScript(format!(
            "build_merge_chain: expected {expected_merges} change_pkhs and \
             change_satoshis (n-1); got {} and {}",
            req.change_pkhs.len(),
            req.change_satoshis.len()
        )));
    }

    let mut current_level = req.stas_inputs;
    let mut chain: Vec<Transaction> = Vec::with_capacity(expected_merges);
    let mut funding_iter = req.fundings.into_iter();
    let mut change_pkh_iter = req.change_pkhs.into_iter();
    let mut change_sat_iter = req.change_satoshis.into_iter();

    while current_level.len() > 1 {
        let pair_count = current_level.len() / 2;
        let has_carry = current_level.len() % 2 == 1;

        let carry = if has_carry {
            Some(current_level.pop().expect("len > 1, has_carry => len odd >=3"))
        } else {
            None
        };

        let mut next_level: Vec<TokenInput> = Vec::with_capacity(pair_count + has_carry as usize);
        if let Some(c) = carry {
            next_level.push(c);
        }

        let mut iter = current_level.into_iter();
        for _ in 0..pair_count {
            let a = iter.next().expect("pair_count derived from len");
            let b = iter.next().expect("pair_count derived from len");
            let merged_satoshis = a.satoshis + b.satoshis;
            let funding = funding_iter.next().expect("funding count validated above");
            let change_pkh = change_pkh_iter.next().expect("change_pkh count validated above");
            let change_satoshis =
                change_sat_iter.next().expect("change_satoshis count validated above");

            let tx = build_merge(MergeRequest {
                wallet: req.wallet,
                originator: req.originator,
                stas_inputs: vec![a, b],
                funding_input: funding,
                destination_owner_pkh: req.destination_owner_pkh,
                redemption_pkh: req.redemption_pkh,
                flags: req.flags,
                service_fields: req.service_fields.clone(),
                optional_data: req.optional_data.clone(),
                note: req.note.clone(),
                change_pkh,
                change_satoshis,
            })
            .await?;

            // The merged STAS output is always vout 0 (per build_merge layout).
            let merged_lock = tx.outputs[0].locking_script.clone();
            let merged_txid = tx.id().map_err(|e| {
                Stas3Error::InvalidScript(format!(
                    "build_merge_chain: failed to compute merge tx id: {e:?}"
                ))
            })?;
            let merged_source_bytes = tx.to_bytes().map_err(|e| {
                Stas3Error::InvalidScript(format!(
                    "build_merge_chain: failed to serialize merge tx: {e:?}"
                ))
            })?;

            next_level.push(TokenInput {
                txid_hex: merged_txid,
                vout: 0,
                satoshis: merged_satoshis,
                locking_script: merged_lock,
                signing_key: req.destination_signing_key.clone(),
                current_action_data: ActionData::Passive(vec![]),
                source_tx_bytes: Some(merged_source_bytes),
            });

            chain.push(tx);
        }

        current_level = next_level;
    }

    Ok(chain)
}
