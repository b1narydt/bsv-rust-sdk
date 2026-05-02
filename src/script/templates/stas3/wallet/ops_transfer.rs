//! `Stas3Wallet::transfer` — single-input, single-output STAS-3 ownership
//! change with explicit fuel input or fuel-basket auto-pick.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::decode::decode_locking_script;
use super::super::error::Stas3Error;
use super::super::factory::transfer::{build_transfer, TransferRequest};
use super::super::factory::types::{FundingInput, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a transfer tx given an explicit token + funding input. The
    /// caller is responsible for sourcing both — useful in flows where the
    /// fuel UTXO comes from somewhere other than the basket (e.g. a
    /// just-built coinbase, or a manually-constructed test fixture).
    ///
    /// Use `transfer_with_fuel_pick` to have the wrapper select fuel from
    /// the configured basket.
    pub async fn transfer(
        &self,
        token: TokenInput,
        funding: FundingInput,
        destination_owner_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
        note: Option<Vec<u8>>,
    ) -> Result<Transaction, Stas3Error> {
        let decoded = decode_locking_script(&token.locking_script)?;
        build_transfer(TransferRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
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

    /// Like `transfer` but picks fuel from the configured fuel basket.
    pub async fn transfer_with_fuel_pick(
        &self,
        token: TokenInput,
        destination_owner_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
        note: Option<Vec<u8>>,
    ) -> Result<Transaction, Stas3Error> {
        // Fee budget: change + a small headroom. The factory does NOT compute
        // fees from the rate yet; the caller's `change_satoshis` already
        // encodes the desired post-fee change. Pick fuel large enough to
        // cover that change plus a 200-sat headroom for tx fees.
        let funding = self.pick_fuel(change_satoshis.saturating_add(200)).await?;
        self.transfer(
            token,
            funding,
            destination_owner_pkh,
            change_pkh,
            change_satoshis,
            note,
        )
        .await
    }
}
