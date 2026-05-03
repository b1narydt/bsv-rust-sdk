//! `Stas3Wallet::top_up_fuel` — provision N fuel UTXOs into the fuel basket.
//!
//! Most STAS-3 spends consume one fuel UTXO from the fuel basket via
//! `pick_fuel`. Before any STAS spend can succeed the basket must be
//! populated. `top_up_fuel` is the idiomatic way to do that: it builds a
//! single `createAction` that emits N P2PKH outputs into the configured
//! fuel basket, each owned by a Type-42-derived key under the fuel
//! protocol. The wallet's own funding logic sources the satoshis (typically
//! from its primary balance / default basket).
//!
//! Each output's `customInstructions` carries the BRC-43 derivation args
//! (protocolID, keyID, counterparty=self) so `pick_fuel` can later
//! re-derive the signing key for that UTXO without storing private keys.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::primitives::hash::hash160;
use crate::wallet::interfaces::{
    CreateActionArgs, CreateActionOutput, WalletInterface,
};

use super::super::brc43_key_args::Brc43KeyArgs;
use super::super::error::Stas3Error;
use super::super::factory::common::{make_p2pkh_lock, pubkey_via_wallet};
use super::custom_instructions::CustomInstructions;
use super::Stas3Wallet;

/// Result of a `top_up_fuel` call.
#[derive(Clone, Debug)]
pub struct TopUpFuelResult {
    /// Txid of the funding transaction (hex BE).
    pub txid: String,
    /// `"txid.vout"` outpoint of every fuel UTXO created. Same order as
    /// the outputs in the funding tx.
    pub outpoints: Vec<String>,
}

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Provision `count` P2PKH outputs into the fuel basket, each holding
    /// `satoshis_per_utxo` satoshis. Returns the funding txid + outpoints
    /// of all created fuel UTXOs.
    ///
    /// Key IDs are deterministic per call: `topup-{unix_millis}-{i}` so
    /// that re-running this method never collides with prior fuel UTXOs.
    /// The protocol is the wallet's configured `fuel_basket` name.
    ///
    /// The wallet's `create_action` decides where the input satoshis come
    /// from (typically the wallet's own primary balance). The wallet also
    /// signs the funding inputs and broadcasts.
    pub async fn top_up_fuel(
        &self,
        satoshis_per_utxo: u64,
        count: usize,
    ) -> Result<TopUpFuelResult, Stas3Error> {
        if count == 0 {
            return Err(Stas3Error::InvalidScript(
                "top_up_fuel: count must be >= 1".into(),
            ));
        }
        if satoshis_per_utxo == 0 {
            return Err(Stas3Error::InvalidScript(
                "top_up_fuel: satoshis_per_utxo must be >= 1".into(),
            ));
        }

        // Deterministic per-call key-id seed so callers can re-run without
        // collisions but the IDs within one call are stable.
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        // The fuel basket name doubles as the BRC-43 protocol name for
        // every fuel-key derivation — keeping fuel keys namespaced so they
        // can't collide with other STAS-3 key categories (token owners,
        // freeze authorities, etc.).
        let fuel_protocol = self.config.fuel_basket.clone();

        let mut outputs: Vec<CreateActionOutput> = Vec::with_capacity(count);
        for i in 0..count {
            let key_id = format!("topup-{now_ms}-{i}");
            let triple = Brc43KeyArgs::self_under(&fuel_protocol, key_id);
            let pubkey_der =
                pubkey_via_wallet(&*self.wallet, &triple, self.config.originator.as_deref())
                    .await?;
            let pkh = hash160(&pubkey_der);
            let lock = make_p2pkh_lock(&pkh);
            let custom = CustomInstructions::from_triple(&triple, "stas3-fuel", None);

            outputs.push(CreateActionOutput {
                locking_script: Some(lock.to_binary()),
                satoshis: satoshis_per_utxo,
                output_description: format!("STAS-3 fuel UTXO {i}"),
                basket: Some(self.config.fuel_basket.clone()),
                custom_instructions: Some(custom.to_json()),
                tags: vec![],
            });
        }

        let result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!("STAS-3 fuel top-up: {count} UTXOs"),
                    input_beef: None,
                    inputs: vec![],
                    outputs,
                    lock_time: None,
                    version: None,
                    labels: vec!["stas3-fuel-topup".to_string()],
                    options: None,
                    reference: None,
                },
                self.config.originator.as_deref(),
            )
            .await
            .map_err(|e| {
                Stas3Error::InvalidScript(format!("top_up_fuel create_action: {e}"))
            })?;

        let txid = result.txid.ok_or_else(|| {
            Stas3Error::InvalidScript(
                "top_up_fuel: create_action returned no txid (signableTransaction \
                 path not supported here)"
                    .into(),
            )
        })?;

        let outpoints = (0..count).map(|i| format!("{txid}.{i}")).collect();
        Ok(TopUpFuelResult { txid, outpoints })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::proto_wallet::ProtoWallet;

    use super::super::Stas3Wallet;
    use super::super::super::error::Stas3Error;

    /// Validates input guards. The actual create_action path requires a
    /// real wallet-toolbox (ProtoWallet returns NotImplemented for
    /// create_action); end-to-end coverage lives in the mainnet smoke test.
    #[tokio::test]
    async fn test_top_up_fuel_rejects_zero_count() {
        let wallet = Arc::new(ProtoWallet::new(PrivateKey::from_hex("01").unwrap()));
        let stas = Stas3Wallet::new(wallet);
        let result = stas.top_up_fuel(1_000, 0).await;
        assert!(
            matches!(result, Err(Stas3Error::InvalidScript(ref m)) if m.contains("count must be >= 1")),
            "expected InvalidScript(count must be >= 1); got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_top_up_fuel_rejects_zero_satoshis() {
        let wallet = Arc::new(ProtoWallet::new(PrivateKey::from_hex("01").unwrap()));
        let stas = Stas3Wallet::new(wallet);
        let result = stas.top_up_fuel(0, 5).await;
        assert!(
            matches!(result, Err(Stas3Error::InvalidScript(ref m)) if m.contains("satoshis_per_utxo")),
            "expected InvalidScript(satoshis_per_utxo); got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_top_up_fuel_propagates_wallet_not_implemented() {
        // ProtoWallet returns NotImplemented for create_action — the
        // wrapper must surface that as a Stas3Error::InvalidScript wrapping
        // "create_action: ..." so callers see WHERE the wallet refused.
        let wallet = Arc::new(ProtoWallet::new(PrivateKey::from_hex("01").unwrap()));
        let stas = Stas3Wallet::new(wallet);
        let result = stas.top_up_fuel(1_000, 2).await;
        assert!(
            matches!(result, Err(Stas3Error::InvalidScript(ref m)) if m.contains("create_action")),
            "expected error mentioning create_action; got {:?}",
            result.err()
        );
    }
}
