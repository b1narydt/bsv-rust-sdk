//! `Stas3Wallet::merge` — 2-input STAS-3 merge.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::factory::merge::{build_merge, MergeRequest};
use super::super::factory::types::{FundingInput, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a 2-input merge tx. Each input must carry `source_tx_bytes` so
    /// the factory can derive the per-input piece array (spec §9.5).
    ///
    /// Both inputs must be the same token type (same redemption_pkh, flags,
    /// service_fields, optional_data) — i.e. their counterparty scripts are
    /// byte-identical post-var2. The factory carries those fields forward
    /// onto the merged STAS output by copying from `tokens[0]`'s decoded
    /// lock; if `tokens[0]` and `tokens[1]` disagree on any of those fields
    /// the engine will reject the merged output.
    ///
    /// The merged STAS output is owned by `destination_owner_pkh` and
    /// carries the SUM of input satoshis (sum-conservation per spec §5.1).
    pub async fn merge(
        &self,
        tokens: [TokenInput; 2],
        funding: FundingInput,
        destination_owner_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
        note: Option<Vec<u8>>,
    ) -> Result<Transaction, Stas3Error> {
        let decoded = decode_locking_script(&tokens[0].locking_script)?;
        build_merge(MergeRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_inputs: tokens.to_vec(),
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
}
