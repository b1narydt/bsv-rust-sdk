//! `Stas3Wallet<W: WalletInterface>` — high-level wallet-aware STAS-3 ops.
//!
//! Owns Type-42 derivation, fuel-basket UTXO selection, and post-broadcast
//! basket registration via `internalize_action`. Production callers (the
//! MetaWatt agent etc.) interact with this wrapper rather than the raw
//! factory functions in `super::factory` — the wrapper guarantees that every
//! key reference flows through a `KeyTriple` resolved by the wallet, never a
//! raw private key (spec §1A).
//!
//! ## Design
//!
//! - **Type-42 enforcement (spec §1A)**: every key reference is a `KeyTriple`,
//!   resolved at sign/derive time via `WalletInterface::create_signature` and
//!   `WalletInterface::get_public_key`. The wrapper never sees raw key bytes.
//! - **Fuel basket pattern (spec §8.2-8.3)**: callers fund STAS-3 spends with
//!   P2PKH UTXOs from a "fuel" basket. `pick_fuel` greedy-selects the
//!   smallest sufficient UTXO; the triple comes from `customInstructions`.
//! - **Token basket pattern**: STAS-3 outputs created by this wrapper are
//!   registered into a "tokens" basket via `internalize_action` after
//!   broadcast, with their `customInstructions` JSON carrying the owning
//!   triple — so the next spend can re-derive the signer.
//! - **`customInstructions` JSON shape (spec §1A.4)**: `{"template", "protocolID":
//!   [securityLevel, protocolName], "keyID", "counterparty", "schema"?}`. The
//!   wrapper serializes this manually to keep the wrapper available in the
//!   no-`network`-feature build (avoids the `serde_json` dependency on the
//!   crate's hot path).
//!
//! ## Module layout
//!
//! The wallet wrapper lives in this directory split across files:
//!
//! - [`custom_instructions`] — `CustomInstructions` JSON shape + parser.
//! - [`ops_transfer`] — `transfer`, `transfer_with_fuel_pick`.
//! - [`ops_split`] — `split`.
//! - [`ops_merge`] — `merge` (2-input).
//! - [`ops_redeem`] — `redeem`.
//! - [`ops_freeze`] — `freeze`, `unfreeze`, `confiscate`.
//! - [`ops_swap`] — `swap_mark`, `swap_cancel`, `swap_execute`.
//!
//! Each ops file declares its own `impl<W: WalletInterface> Stas3Wallet<W>`
//! block. Rust accepts multiple `impl` blocks across files in the same
//! module.
//!
//! ## Limitations
//!
//! - `pick_fuel` and `internalize_stas_outputs` require a wallet whose
//!   `list_outputs` / `internalize_action` are implemented — `ProtoWallet`
//!   returns `NotImplemented` for these. Production wiring against the
//!   wallet-toolbox is out of scope for this crate's tests; see Phase 9
//!   notes in the spec.
//! - "Other"-counterparty (named pubkey hex) is not yet supported on the
//!   `customInstructions` round-trip — the parser rejects unknown counterparty
//!   strings with `Stas3Error::InvalidScript`. Self / Anyone are supported.

use std::sync::Arc;

use crate::script::locking_script::LockingScript;
use crate::wallet::interfaces::{
    BasketInsertion, InternalizeActionArgs, InternalizeOutput, ListOutputsArgs, Output,
    OutputInclude, WalletInterface,
};
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

use super::constants::{BASKET_FUEL, BASKET_TOKENS};
use super::decode::decode_locking_script;
use super::error::Stas3Error;
use super::factory::types::{FundingInput, SigningKey, TokenInput};
use super::key_triple::KeyTriple;

mod custom_instructions;
mod ops_freeze;
mod ops_merge;
mod ops_mint;
mod ops_redeem;
mod ops_split;
mod ops_swap;
mod ops_transfer;

pub use custom_instructions::CustomInstructions;

// ---------------------------------------------------------------------------
// Stas3Wallet
// ---------------------------------------------------------------------------

/// Configuration for a `Stas3Wallet` instance. Defaults match spec §8.7.
#[derive(Debug, Clone)]
pub struct Stas3WalletConfig {
    pub fuel_basket: String,
    pub token_basket: String,
    /// Currently informational — the factories don't yet build fees from the
    /// rate, the caller passes the change satoshis. Reserved for a future
    /// change-amount calculator.
    pub fee_rate_sats_per_kb: u64,
    pub originator: Option<String>,
}

impl Default for Stas3WalletConfig {
    fn default() -> Self {
        Self {
            fuel_basket: BASKET_FUEL.to_string(),
            token_basket: BASKET_TOKENS.to_string(),
            fee_rate_sats_per_kb: 500,
            originator: None,
        }
    }
}

/// High-level STAS-3 wallet wrapper. See module docs for design notes.
pub struct Stas3Wallet<W: WalletInterface> {
    pub(super) wallet: Arc<W>,
    pub(super) config: Stas3WalletConfig,
}

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Build a wrapper around a wallet, using the default basket / fee /
    /// originator configuration.
    pub fn new(wallet: Arc<W>) -> Self {
        Self {
            wallet,
            config: Stas3WalletConfig::default(),
        }
    }

    /// Build a wrapper with explicit configuration.
    pub fn with_config(wallet: Arc<W>, config: Stas3WalletConfig) -> Self {
        Self { wallet, config }
    }

    /// Borrow the underlying wallet (for callers that need direct access for
    /// non-STAS-3 operations).
    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &Stas3WalletConfig {
        &self.config
    }

    /// Pick a fuel UTXO from the fuel basket whose value is at least
    /// `min_satoshis`. Greedy: smallest sufficient. Errors if none found
    /// or if the chosen UTXO's `customInstructions` can't be parsed for a
    /// triple.
    ///
    /// Requires the underlying wallet to implement `list_outputs` (the
    /// `ProtoWallet` returns `NotImplemented`; production wiring needs a
    /// real wallet-toolbox instance).
    pub async fn pick_fuel(&self, min_satoshis: u64) -> Result<FundingInput, Stas3Error> {
        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.fuel_basket.clone(),
                    tags: vec![],
                    tag_query_mode: None,
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: BooleanDefaultFalse(Some(true)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(100),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                self.config.originator.as_deref(),
            )
            .await
            .map_err(|e| {
                Stas3Error::InvalidScript(format!(
                    "list_outputs(fuel basket {:?}): {e}",
                    self.config.fuel_basket
                ))
            })?;

        // Filter to spendable UTXOs >= min_satoshis, sort by satoshis ascending,
        // pick the smallest sufficient one.
        let mut candidates: Vec<&Output> = result
            .outputs
            .iter()
            .filter(|o| o.spendable && o.satoshis >= min_satoshis)
            .collect();
        candidates.sort_by_key(|o| o.satoshis);

        let chosen = candidates.first().copied().ok_or_else(|| {
            Stas3Error::InvalidScript(format!(
                "no fuel UTXO >= {min_satoshis} sats in basket {:?}",
                self.config.fuel_basket
            ))
        })?;

        output_to_funding_input(chosen)
    }

    /// Find a STAS-3 token UTXO by its outpoint string in the token basket.
    /// Decodes its locking script to recover `current_action_data`.
    pub async fn find_token(&self, outpoint: &str) -> Result<TokenInput, Stas3Error> {
        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.token_basket.clone(),
                    tags: vec![],
                    tag_query_mode: None,
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: BooleanDefaultFalse(Some(true)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(1000),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                self.config.originator.as_deref(),
            )
            .await
            .map_err(|e| {
                Stas3Error::InvalidScript(format!(
                    "list_outputs(token basket {:?}): {e}",
                    self.config.token_basket
                ))
            })?;

        let chosen = result
            .outputs
            .iter()
            .find(|o| o.outpoint == outpoint)
            .ok_or_else(|| {
                Stas3Error::InvalidScript(format!(
                    "token outpoint {outpoint} not found in basket {:?}",
                    self.config.token_basket
                ))
            })?;

        output_to_token_input(chosen)
    }

    /// Register a freshly-built tx's STAS-3 outputs in the token basket so
    /// subsequent spends can find them. Call AFTER broadcasting the tx.
    ///
    /// `stas_output_indices` lists `(output_index, owning_triple, schema)`
    /// for each STAS-3 output to register. `schema` is an optional tag like
    /// `"EAC1"` carried in the `customInstructions` JSON.
    pub async fn internalize_stas_outputs(
        &self,
        tx_bytes: Vec<u8>,
        stas_output_indices: Vec<(u32, KeyTriple, Option<String>)>,
        description: &str,
    ) -> Result<(), Stas3Error> {
        let outputs: Vec<InternalizeOutput> = stas_output_indices
            .iter()
            .map(|(idx, triple, schema)| {
                let ci = CustomInstructions::from_triple(triple, "stas3-token", schema.clone());
                InternalizeOutput::BasketInsertion {
                    output_index: *idx,
                    insertion: BasketInsertion {
                        basket: self.config.token_basket.clone(),
                        custom_instructions: Some(ci.to_json()),
                        tags: vec![],
                    },
                }
            })
            .collect();

        self.wallet
            .internalize_action(
                InternalizeActionArgs {
                    tx: tx_bytes,
                    description: description.to_string(),
                    labels: vec!["stas3".to_string()],
                    seek_permission: BooleanDefaultTrue(Some(true)),
                    outputs,
                },
                self.config.originator.as_deref(),
            )
            .await
            .map_err(|e| Stas3Error::InvalidScript(format!("internalize_action: {e}")))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an `Output` from `list_outputs` into a `FundingInput`.
fn output_to_funding_input(o: &Output) -> Result<FundingInput, Stas3Error> {
    let triple = parse_triple_from_output(o)?;
    let locking_bytes = o.locking_script.as_ref().ok_or_else(|| {
        Stas3Error::InvalidScript(format!(
            "UTXO {} missing locking_script (need OutputInclude::LockingScripts)",
            o.outpoint
        ))
    })?;
    let locking_script = LockingScript::from_binary(locking_bytes);
    let (txid_hex, vout) = parse_outpoint(&o.outpoint)?;

    Ok(FundingInput {
        txid_hex,
        vout,
        satoshis: o.satoshis,
        locking_script,
        triple,
    })
}

/// Convert an `Output` from `list_outputs` into a `TokenInput`. Decodes the
/// STAS-3 locking script to recover `current_action_data`.
fn output_to_token_input(o: &Output) -> Result<TokenInput, Stas3Error> {
    let triple = parse_triple_from_output(o)?;
    let locking_bytes = o.locking_script.as_ref().ok_or_else(|| {
        Stas3Error::InvalidScript(format!(
            "STAS-3 UTXO {} missing locking_script (need OutputInclude::LockingScripts)",
            o.outpoint
        ))
    })?;
    let locking_script = LockingScript::from_binary(locking_bytes);
    let (txid_hex, vout) = parse_outpoint(&o.outpoint)?;
    let decoded = decode_locking_script(&locking_script)?;

    Ok(TokenInput {
        txid_hex,
        vout,
        satoshis: o.satoshis,
        locking_script,
        // Default to single-sig P2PKH ownership. Multisig-owned tokens
        // are first-class but the basket-aware path can't yet
        // distinguish them from `customInstructions` alone — callers
        // that own multisig tokens build the `TokenInput` directly via
        // `SigningKey::Multi { triples, multisig }`.
        signing_key: SigningKey::P2pkh(triple),
        current_action_data: decoded.action_data,
        // For non-merge spends, source_tx_bytes can stay None. Merge needs
        // it; we'll plumb it through a separate `find_token_with_source`
        // when we ship the wallet-aware merge wrapper.
        source_tx_bytes: None,
    })
}

fn parse_triple_from_output(o: &Output) -> Result<KeyTriple, Stas3Error> {
    let custom = o
        .custom_instructions
        .as_ref()
        .ok_or_else(|| Stas3Error::MissingKeyTriple(o.outpoint.clone()))?;
    let ci = CustomInstructions::from_json(custom)?;
    ci.to_triple()
}

/// Parse a `"txid.vout"` outpoint string into its components.
pub(crate) fn parse_outpoint(outpoint: &str) -> Result<(String, u32), Stas3Error> {
    let mut parts = outpoint.splitn(2, '.');
    let txid = parts
        .next()
        .ok_or_else(|| Stas3Error::InvalidScript(format!("bad outpoint: {outpoint}")))?
        .to_string();
    let vout_str = parts
        .next()
        .ok_or_else(|| Stas3Error::InvalidScript(format!("bad outpoint: {outpoint}")))?;
    let vout: u32 = vout_str.parse().map_err(|e| {
        Stas3Error::InvalidScript(format!("bad outpoint vout {vout_str:?}: {e}"))
    })?;
    Ok((txid, vout))
}

// ---------------------------------------------------------------------------
// Tests — wrapper config defaults + outpoint parser
// (CustomInstructions tests live in custom_instructions.rs.)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_outpoint_ok() {
        let (txid, vout) = parse_outpoint(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.7",
        )
        .unwrap();
        assert_eq!(
            txid,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(vout, 7);
    }

    #[test]
    fn test_parse_outpoint_bad() {
        assert!(parse_outpoint("nope").is_err());
        assert!(parse_outpoint("abc.notanumber").is_err());
    }

    #[test]
    fn test_default_config() {
        let cfg = Stas3WalletConfig::default();
        assert_eq!(cfg.fuel_basket, BASKET_FUEL);
        assert_eq!(cfg.token_basket, BASKET_TOKENS);
        assert_eq!(cfg.fee_rate_sats_per_kb, 500);
        assert!(cfg.originator.is_none());
    }
}
