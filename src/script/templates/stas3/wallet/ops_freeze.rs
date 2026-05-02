//! `Stas3Wallet` freeze / unfreeze / confiscate ops — authority-signed STAS-3
//! operations that suspend or seize a token without changing ownership in
//! the freeze/unfreeze case, or transferring it to a destination in the
//! confiscation case.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::error::Stas3Error;
use super::super::factory::confiscate::{build_confiscate, ConfiscateRequest};
use super::super::factory::freeze::{build_freeze, FreezeRequest};
use super::super::factory::types::{FundingInput, TokenInput};
use super::super::factory::unfreeze::{build_unfreeze, UnfreezeRequest};
use super::super::key_triple::KeyTriple;
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a freeze tx (signed by `freeze_authority_triple`).
    pub async fn freeze(
        &self,
        token: TokenInput,
        funding: FundingInput,
        freeze_authority_triple: KeyTriple,
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_freeze(FreezeRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            freeze_authority_triple,
            change_pkh,
            change_satoshis,
        })
        .await
    }

    /// Build an unfreeze tx (signed by `freeze_authority_triple`).
    pub async fn unfreeze(
        &self,
        token: TokenInput,
        funding: FundingInput,
        freeze_authority_triple: KeyTriple,
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_unfreeze(UnfreezeRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            freeze_authority_triple,
            change_pkh,
            change_satoshis,
        })
        .await
    }

    /// Build a confiscation tx (signed by `confiscation_authority_triple`).
    pub async fn confiscate(
        &self,
        token: TokenInput,
        funding: FundingInput,
        confiscation_authority_triple: KeyTriple,
        destination_owner_pkh: [u8; 20],
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_confiscate(ConfiscateRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            confiscation_authority_triple,
            destination_owner_pkh,
            change_pkh,
            change_satoshis,
        })
        .await
    }
}
