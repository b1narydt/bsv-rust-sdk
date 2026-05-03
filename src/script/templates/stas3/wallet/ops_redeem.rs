//! `Stas3Wallet::redeem` — STAS-3 redemption (issuer reclaims tokens).

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::error::Stas3Error;
use super::super::factory::redeem::{build_redeem, RedeemRequest};
use super::super::factory::types::{FundingInput, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a redeem tx with explicit token + funding input. The factory
    /// validates `owner_pkh == redemption_pkh` on the input lock.
    pub async fn redeem(
        &self,
        token: TokenInput,
        funding: FundingInput,
        redemption_destination_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_redeem(RedeemRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            redemption_destination_pkh,
            change_pkh,
            change_satoshis,
        })
        .await
    }
}
