//! `Stas3Wallet::merge` — atomic 2-input merge.
//! `Stas3Wallet::merge_chain` — N>2 via chained 2-input merges.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::factory::merge::{build_merge, MergeRequest};
use super::super::factory::merge_chain::{build_merge_chain, MergeChainRequest};
use super::super::factory::types::{FundingInput, SigningKey, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build an atomic 2-input STAS-3 merge tx (spec §8.1, N=2). Each
    /// input must carry `source_tx_bytes` so the factory can derive the
    /// trailing piece array (spec §9.5).
    ///
    /// All inputs must be the same token type (same redemption_pkh, flags,
    /// service_fields, optional_data) — i.e. their counterparty scripts are
    /// byte-identical post-var2. The factory carries those fields forward
    /// onto the merged STAS output by copying from `tokens[0]`'s decoded
    /// lock; if any pair of tokens disagree on those fields the engine will
    /// reject the merged output.
    ///
    /// The merged STAS output is owned by `destination_owner_pkh` and
    /// carries the SUM of input satoshis (sum-conservation per spec §5.1).
    ///
    /// For N>2 use [`Self::merge_chain`].
    pub async fn merge(
        &self,
        tokens: Vec<TokenInput>,
        funding: FundingInput,
        destination_owner_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
        note: Option<Vec<u8>>,
    ) -> Result<Transaction, Stas3Error> {
        if tokens.len() != 2 {
            return Err(Stas3Error::InvalidScript(format!(
                "merge requires exactly 2 STAS inputs; got {}. \
                 For N>2 use merge_chain.",
                tokens.len()
            )));
        }
        let decoded = decode_locking_script(&tokens[0].locking_script)?;
        build_merge(MergeRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_inputs: tokens,
            funding_input: funding,
            destination_owner_pkh,
            redemption_pkh: decoded.redemption_pkh,
            flags: decoded.flags,
            service_fields: decoded.service_fields,
            optional_data: decoded.optional_data,
            note,
            change_pkh,
            change_satoshis,
        })
        .await
    }

    /// Build a chain of 2-input merges that converges N STAS UTXOs into
    /// one (mirrors the dxs `mergeStasTransactions` binary-tree pattern).
    /// Returns N-1 transactions in broadcast order: tx[0] must confirm
    /// before tx[1] can spend its merged output, etc.
    ///
    /// Caller supplies one funding UTXO + one change PKH + one change
    /// satoshi value per pairwise merge (`fundings.len() ==
    /// change_pkhs.len() == change_satoshis.len() == tokens.len() - 1`).
    /// All intermediate AND final STAS outputs land at
    /// `destination_owner_pkh`; intermediate outputs are signed at the
    /// next level using `destination_signing_key`.
    pub async fn merge_chain(
        &self,
        tokens: Vec<TokenInput>,
        fundings: Vec<FundingInput>,
        destination_owner_pkh: [u8; 20],
        destination_signing_key: SigningKey,
        change_pkhs: Vec<[u8; 20]>,
        change_satoshis: Vec<u64>,
        note: Option<Vec<u8>>,
    ) -> Result<Vec<Transaction>, Stas3Error> {
        if tokens.len() < 2 {
            return Err(Stas3Error::InvalidScript(format!(
                "merge_chain requires at least 2 STAS inputs; got {}",
                tokens.len()
            )));
        }
        let decoded = decode_locking_script(&tokens[0].locking_script)?;
        build_merge_chain(MergeChainRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_inputs: tokens,
            fundings,
            destination_owner_pkh,
            destination_signing_key,
            redemption_pkh: decoded.redemption_pkh,
            flags: decoded.flags,
            service_fields: decoded.service_fields,
            optional_data: decoded.optional_data,
            note,
            change_pkhs,
            change_satoshis,
        })
        .await
    }
}
