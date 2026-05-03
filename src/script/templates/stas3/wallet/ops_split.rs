//! `Stas3Wallet::split` — single-input, multi-output STAS-3 split.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::factory::split::{build_split, SplitDestination, SplitRequest};
use super::super::factory::types::{FundingInput, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a split tx with explicit token + funding input.
    pub async fn split(
        &self,
        token: TokenInput,
        funding: FundingInput,
        destinations: Vec<SplitDestination>,
        change_pkh: [u8; 20],
        change_satoshis: u64,
        note: Option<Vec<u8>>,
    ) -> Result<Transaction, Stas3Error> {
        let decoded = decode_locking_script(&token.locking_script)?;
        build_split(SplitRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            destinations,
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
