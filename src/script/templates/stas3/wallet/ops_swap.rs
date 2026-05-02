//! `Stas3Wallet` swap ops — atomic-swap mark, cancel, and execute.

use crate::transaction::transaction::Transaction;
use crate::wallet::interfaces::WalletInterface;

use super::super::action_data::SwapDescriptor;
use super::super::error::Stas3Error;
use super::super::factory::swap_cancel::{build_swap_cancel, SwapCancelRequest};
use super::super::factory::swap_execute::{build_swap_execute, SwapExecuteRequest};
use super::super::factory::swap_mark::{build_swap_mark, SwapMarkRequest};
use super::super::factory::types::{FundingInput, SigningKey, TokenInput};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a swap-mark tx (signed by the input owner) installing the
    /// supplied descriptor in var2.
    pub async fn swap_mark(
        &self,
        token: TokenInput,
        funding: FundingInput,
        descriptor: SwapDescriptor,
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_swap_mark(SwapMarkRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            descriptor,
            change_pkh,
            change_satoshis,
        })
        .await
    }

    /// Build a swap-cancel tx, signed by the descriptor's
    /// `receive_addr` key (P2PKH or P2MPKH multisig per spec §10.2).
    pub async fn swap_cancel(
        &self,
        token: TokenInput,
        funding: FundingInput,
        receive_addr_signing_key: impl Into<SigningKey>,
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_swap_cancel(SwapCancelRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_input: token,
            funding_input: funding,
            receive_addr_signing_key: receive_addr_signing_key.into(),
            change_pkh,
            change_satoshis,
        })
        .await
    }

    /// Build a 2-input atomic-swap-execution tx. Both inputs MUST carry
    /// `source_tx_bytes`, and at least one must carry a `SwapDescriptor`
    /// in its `current_action_data` (the typical case is both — swap-swap;
    /// one-sided is "transfer-swap").
    ///
    /// Per spec §5.5: each side's swap descriptor's `receive_addr` becomes
    /// the OWNER PKH of the requested-asset OUTPUT; var2 resets to Passive
    /// for both outputs (the swap is consumed). For transfer-swap legs the
    /// owner falls through to the input's own owner_pkh.
    pub async fn swap_execute(
        &self,
        tokens: [TokenInput; 2],
        funding: FundingInput,
        change_pkh: [u8; 20],
        change_satoshis: u64,
    ) -> Result<Transaction, Stas3Error> {
        build_swap_execute(SwapExecuteRequest {
            wallet: &*self.wallet,
            originator: self.config.originator.as_deref(),
            stas_inputs: tokens,
            funding_input: funding,
            change_pkh,
            change_satoshis,
        })
        .await
    }
}
