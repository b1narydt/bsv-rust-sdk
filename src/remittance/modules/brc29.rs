//! BRC-29 remittance module — P2PKH-based payment via BRC-29 key derivation.
//!
//! Implements the `RemittanceModule` trait with wire-format types that match
//! the TypeScript SDK `BasicBRC29` class exactly: same JSON field names (camelCase),
//! same optional/required fields, same config defaults.
//!
//! Plan 02 will implement `build_settlement` and `accept_settlement`. This plan
//! establishes the type system, config defaults, injectable traits, and validation
//! helpers so Plan 02 can operate against concrete types.

#![cfg(feature = "network")]

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::auth::utils::nonce::create_nonce;
use crate::primitives::public_key::PublicKey;
use crate::remittance::error::RemittanceError;
use crate::remittance::remittance_module::{
    AcceptSettlementResult, BuildSettlementResult, RemittanceModule,
};
use crate::remittance::types::{Invoice, ModuleContext, Settlement, Termination};
use crate::script::templates::p2pkh::P2PKH;
use crate::script::ScriptTemplateLock;
use crate::wallet::interfaces::WalletInterface;
use crate::wallet::types::Protocol;

// ---------------------------------------------------------------------------
// Wire-format types (BRC29-04) — match TS SDK interface shapes exactly
// ---------------------------------------------------------------------------

/// Opaque option terms produced when a payer selects BRC-29 as the payment module.
///
/// Wire format matches TS `Brc29OptionTerms` interface: camelCase fields,
/// optional fields omitted when `None`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brc29OptionTerms {
    /// Required positive payment amount in satoshis.
    pub amount_satoshis: u64,
    /// Required 66-char compressed public key hex of the payee.
    pub payee: String,
    /// Optional output index within the transaction (defaults to 0 in TS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
    /// Optional override for the BRC-29 protocol identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_id: Option<Protocol>,
    /// Optional label tags applied to the wallet action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Optional human-readable payment description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The `customInstructions` object embedded in `Brc29SettlementArtifact`.
///
/// Wire format: `{"derivationPrefix":"...","derivationSuffix":"..."}` — camelCase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brc29SettlementCustomInstructions {
    /// BRC-29 derivation prefix (base64-encoded nonce).
    pub derivation_prefix: String,
    /// BRC-29 derivation suffix (base64-encoded nonce or label).
    pub derivation_suffix: String,
}

/// Settlement artifact produced by the payer and sent to the payee.
///
/// Wire format matches TS `Brc29SettlementArtifact`: camelCase fields,
/// `transaction` serialized as a JSON number array matching TS `number[]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brc29SettlementArtifact {
    /// BRC-29 derivation metadata needed by payee to internalize the output.
    pub custom_instructions: Brc29SettlementCustomInstructions,
    /// Atomic BEEF bytes. `Vec<u8>` serializes as `[n0, n1, ...]` by default —
    /// this matches TS `number[]` with no custom serde needed.
    pub transaction: Vec<u8>,
    /// Payment amount in satoshis.
    pub amount_satoshis: u64,
    /// Output index within the transaction (optional — default 0 in TS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
}

/// Receipt data returned by the payee after accepting or rejecting a settlement.
///
/// Wire format matches TS `Brc29ReceiptData`: camelCase, all fields optional.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brc29ReceiptData {
    /// Raw result from `wallet.internalizeAction` on the payee side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internalize_result: Option<serde_json::Value>,
    /// Human-readable reason if settlement was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_reason: Option<String>,
    /// Refund token sent back when settlement was rejected but payer can reclaim funds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund: Option<Brc29RefundData>,
}

/// Refund descriptor within `Brc29ReceiptData`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Brc29RefundData {
    /// The original settlement artifact returned as a refund token.
    pub token: Brc29SettlementArtifact,
    /// Network fee consumed during the failed internalization.
    pub fee_satoshis: u64,
}

/// Private struct for the JSON string embedded in `CreateActionOutput.custom_instructions`.
///
/// NOT part of the public API — only serialized inside `build_settlement` (Plan 02).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustomInstructionsPayload<'a> {
    derivation_prefix: &'a str,
    derivation_suffix: &'a str,
    payee: &'a str,
    thread_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Injectable traits (BRC29-05)
// ---------------------------------------------------------------------------

/// Provides a nonce string for BRC-29 key derivation.
///
/// The default implementation delegates to `crate::auth::utils::nonce::create_nonce`.
/// Tests can inject a `MockNonceProvider` returning canned values.
#[async_trait]
pub trait NonceProvider: Send + Sync {
    async fn create_nonce(
        &self,
        wallet: &Arc<dyn WalletInterface>,
        originator: Option<&str>,
    ) -> Result<String, RemittanceError>;
}

/// Default `NonceProvider` using the crate's auth nonce utility.
///
/// The `create_nonce` utility always uses `Self_` counterparty and does not
/// accept an originator parameter — the `originator` argument is accepted here
/// for API consistency with the trait but ignored.
pub struct DefaultNonceProvider;

#[async_trait]
impl NonceProvider for DefaultNonceProvider {
    async fn create_nonce(
        &self,
        wallet: &Arc<dyn WalletInterface>,
        _originator: Option<&str>,
    ) -> Result<String, RemittanceError> {
        create_nonce(wallet.as_ref()).await.map_err(RemittanceError::from)
    }
}

/// Derives a P2PKH locking script from a compressed public key hex string.
///
/// The default implementation uses `P2PKH::from_public_key_hash` with the
/// RIPEMD160(SHA256(pubkey)) hash. Tests can inject a `MockLockingScriptProvider`.
#[async_trait]
pub trait LockingScriptProvider: Send + Sync {
    /// Returns a hex-encoded P2PKH locking script for the given public key.
    async fn get_locking_script(
        &self,
        public_key_hex: &str,
    ) -> Result<String, RemittanceError>;
}

/// Default `LockingScriptProvider` using the crate's P2PKH script template.
pub struct DefaultLockingScriptProvider;

#[async_trait]
impl LockingScriptProvider for DefaultLockingScriptProvider {
    async fn get_locking_script(
        &self,
        public_key_hex: &str,
    ) -> Result<String, RemittanceError> {
        let pk = PublicKey::from_string(public_key_hex)
            .map_err(|e| RemittanceError::Protocol(format!("invalid public key: {e}")))?;
        let hash_vec = pk.to_hash(); // Vec<u8>, 20 bytes
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_vec);
        let p2pkh = P2PKH::from_public_key_hash(hash);
        let lock_script = p2pkh
            .lock()
            .map_err(|e| RemittanceError::Protocol(format!("P2PKH lock error: {e}")))?;
        Ok(lock_script.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Config (BRC29-07)
// ---------------------------------------------------------------------------

/// Configuration for `Brc29RemittanceModule`.
///
/// Defaults match the TypeScript SDK `BasicBRC29` constructor defaults exactly:
/// `protocolID=[2,"3241645161d8"]`, `labels=["brc29"]`,
/// `description="BRC-29 payment"`, `outputDescription="Payment for remittance invoice"`.
pub struct Brc29RemittanceModuleConfig {
    /// BRC-29 protocol identifier. Default: `[2, "3241645161d8"]`.
    pub protocol_id: Protocol,
    /// Wallet action labels. Default: `["brc29"]`.
    pub labels: Vec<String>,
    /// Wallet action description. Default: `"BRC-29 payment"`.
    pub description: String,
    /// Output description for the payment output. Default: `"Payment for remittance invoice"`.
    pub output_description: String,
    /// Internalize protocol string. Default: `"wallet payment"`.
    pub internalize_protocol: String,
    /// Network fee estimate for refund calculations (satoshis). Default: `1000`.
    pub refund_fee_satoshis: u64,
    /// Minimum amount below which a refund is not worth building. Default: `1000`.
    pub min_refund_satoshis: u64,
    /// Nonce provider used inside `build_settlement`. Default: `DefaultNonceProvider`.
    pub nonce_provider: Arc<dyn NonceProvider>,
    /// Locking script provider used inside `build_settlement`. Default: `DefaultLockingScriptProvider`.
    pub locking_script_provider: Arc<dyn LockingScriptProvider>,
}

impl Default for Brc29RemittanceModuleConfig {
    fn default() -> Self {
        Self {
            protocol_id: Protocol {
                security_level: 2,
                protocol: "3241645161d8".to_string(),
            },
            labels: vec!["brc29".to_string()],
            description: "BRC-29 payment".to_string(),
            output_description: "Payment for remittance invoice".to_string(),
            internalize_protocol: "wallet payment".to_string(),
            refund_fee_satoshis: 1000,
            min_refund_satoshis: 1000,
            nonce_provider: Arc::new(DefaultNonceProvider),
            locking_script_provider: Arc::new(DefaultLockingScriptProvider),
        }
    }
}

// ---------------------------------------------------------------------------
// Module struct (BRC29-01)
// ---------------------------------------------------------------------------

/// BRC-29 remittance module implementing P2PKH payments with key derivation.
///
/// Providers (`nonce_provider`, `locking_script_provider`) live inside the config,
/// matching the TS pattern where providers are constructor options. Inject via
/// `Brc29RemittanceModuleConfig` fields before calling `Brc29RemittanceModule::new`.
pub struct Brc29RemittanceModule {
    config: Brc29RemittanceModuleConfig,
}

impl Brc29RemittanceModule {
    /// Create a new BRC-29 module with the given config.
    pub fn new(config: Brc29RemittanceModuleConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl RemittanceModule for Brc29RemittanceModule {
    type OptionTerms = Brc29OptionTerms;
    type SettlementArtifact = Brc29SettlementArtifact;
    type ReceiptData = Brc29ReceiptData;

    fn id(&self) -> &str {
        "brc29.p2pkh"
    }

    fn name(&self) -> &str {
        "BSV (BRC-29 derived P2PKH)"
    }

    fn allow_unsolicited_settlements(&self) -> bool {
        true
    }

    fn supports_create_option(&self) -> bool {
        // The TS SDK BasicBRC29 does NOT implement createOption.
        false
    }

    async fn create_option(
        &self,
        _thread_id: &str,
        _invoice: &Invoice,
        _ctx: &ModuleContext,
    ) -> Result<Brc29OptionTerms, RemittanceError> {
        Err(RemittanceError::Protocol(
            "BRC-29 module does not support create_option".into(),
        ))
    }

    async fn build_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _option: &Brc29OptionTerms,
        _note: Option<&str>,
        _ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<Brc29SettlementArtifact>, RemittanceError> {
        todo!("Plan 02")
    }

    async fn accept_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _settlement: &Brc29SettlementArtifact,
        _sender: &str,
        _ctx: &ModuleContext,
    ) -> Result<AcceptSettlementResult<Brc29ReceiptData>, RemittanceError> {
        todo!("Plan 02")
    }

    async fn process_receipt(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _receipt_data: &Brc29ReceiptData,
        _sender: &str,
        _ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        // TS BasicBRC29 does not implement processReceipt — no-op.
        Ok(())
    }

    async fn process_termination(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _settlement: Option<&Settlement>,
        _termination: &Termination,
        _sender: &str,
        _ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        // TS BasicBRC29 does not implement processTermination — no-op.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation helpers (BRC29-06) — match TS validation logic
// ---------------------------------------------------------------------------

/// Returns `true` if `tx` is non-empty (placeholder for future Atomic BEEF validation).
pub fn is_atomic_beef(tx: &[u8]) -> bool {
    !tx.is_empty()
}

/// Validates a `Brc29OptionTerms` before use in `build_settlement`.
///
/// Mirrors TS validation in `BasicBRC29.buildSettlement`:
/// - `amountSatoshis` must be a positive integer (> 0)
/// - `payee` must be a non-empty, non-whitespace string
pub fn ensure_valid_option(option: &Brc29OptionTerms) -> Result<(), String> {
    if option.amount_satoshis == 0 {
        return Err("BRC-29 option amount must be a positive integer".into());
    }
    if option.payee.is_empty() || option.payee.trim().is_empty() {
        return Err("BRC-29 option payee is required".into());
    }
    Ok(())
}

/// Validates a `Brc29SettlementArtifact` before use in `accept_settlement`.
///
/// Mirrors TS validation in `BasicBRC29.acceptSettlement`:
/// - `transaction` must be a non-empty byte array (is_atomic_beef check)
/// - `derivationPrefix` and `derivationSuffix` must be non-empty, non-whitespace
/// - `amountSatoshis` must be a positive integer (> 0)
pub fn ensure_valid_settlement(artifact: &Brc29SettlementArtifact) -> Result<(), String> {
    if !is_atomic_beef(&artifact.transaction) {
        return Err(
            "BRC-29 settlement transaction must be a non-empty byte array".into(),
        );
    }
    if artifact.custom_instructions.derivation_prefix.is_empty()
        || artifact.custom_instructions.derivation_prefix.trim().is_empty()
    {
        return Err("BRC-29 settlement derivation values are required".into());
    }
    if artifact.custom_instructions.derivation_suffix.is_empty()
        || artifact.custom_instructions.derivation_suffix.trim().is_empty()
    {
        return Err("BRC-29 settlement derivation values are required".into());
    }
    if artifact.amount_satoshis == 0 {
        return Err("BRC-29 settlement amount must be a positive integer".into());
    }
    Ok(())
}
