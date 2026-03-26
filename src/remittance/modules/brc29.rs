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
use crate::wallet::interfaces::{
    BasketInsertion, CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
    InternalizeActionArgs, InternalizeOutput, Payment, WalletInterface,
};
use crate::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// InternalizeProtocol enum — controls how the payee internalizes the output
// ---------------------------------------------------------------------------

/// How the wallet internalizes a received BRC-29 payment output.
///
/// Matches TS SDK `BasicBRC29` constructor option `internalizeProtocol`.
/// Serializes to the exact strings used by the TS SDK wire format.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InternalizeProtocol {
    /// Standard wallet payment (default). Serializes as `"wallet payment"`.
    #[serde(rename = "wallet payment")]
    WalletPayment,
    /// Basket insertion (advanced). Serializes as `"basket insertion"`.
    #[serde(rename = "basket insertion")]
    BasketInsertion,
}

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
    /// TS field name is `protocolID` (uppercase D) — explicit rename needed
    /// because `rename_all = "camelCase"` would produce `protocolId`.
    #[serde(rename = "protocolID", skip_serializing_if = "Option::is_none")]
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
        create_nonce(wallet.as_ref())
            .await
            .map_err(RemittanceError::from)
    }
}

/// Derives a P2PKH locking script from a compressed public key hex string.
///
/// The default implementation uses `P2PKH::from_public_key_hash` with the
/// RIPEMD160(SHA256(pubkey)) hash. Tests can inject a `MockLockingScriptProvider`.
#[async_trait]
pub trait LockingScriptProvider: Send + Sync {
    /// Returns a hex-encoded P2PKH locking script for the given public key.
    async fn get_locking_script(&self, public_key_hex: &str) -> Result<String, RemittanceError>;
}

/// Default `LockingScriptProvider` using the crate's P2PKH script template.
pub struct DefaultLockingScriptProvider;

#[async_trait]
impl LockingScriptProvider for DefaultLockingScriptProvider {
    async fn get_locking_script(&self, public_key_hex: &str) -> Result<String, RemittanceError> {
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
    /// Nonce provider used inside `build_settlement`. Default: `DefaultNonceProvider`.
    pub nonce_provider: Arc<dyn NonceProvider>,
    /// Locking script provider used inside `build_settlement`. Default: `DefaultLockingScriptProvider`.
    pub locking_script_provider: Arc<dyn LockingScriptProvider>,
    /// Fee charged on refunds, in satoshis. TS default: 1000.
    pub refund_fee_satoshis: u64,
    /// Minimum refund amount in satoshis. TS default: 1000.
    pub min_refund_satoshis: u64,
    /// How the wallet internalizes the payment. TS default: "wallet payment".
    pub internalize_protocol: InternalizeProtocol,
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
            nonce_provider: Arc::new(DefaultNonceProvider),
            locking_script_provider: Arc::new(DefaultLockingScriptProvider),
            refund_fee_satoshis: 1000,
            min_refund_satoshis: 1000,
            internalize_protocol: InternalizeProtocol::WalletPayment,
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
        thread_id: &str,
        _invoice: Option<&Invoice>,
        option: &Brc29OptionTerms,
        note: Option<&str>,
        ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<Brc29SettlementArtifact>, RemittanceError> {
        // TS buildSettlement wraps everything in try/catch and returns Terminate on any error.
        // Rust: use an inner async closure that returns Result, then map Err to Terminate.
        match self
            .build_settlement_inner(thread_id, option, note, ctx)
            .await
        {
            Ok(result) => Ok(result),
            Err(e) => Ok(BuildSettlementResult::Terminate {
                termination: Termination {
                    code: "brc29.build_failed".to_string(),
                    message: e.to_string(),
                    details: None,
                },
            }),
        }
    }

    async fn accept_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        settlement: &Brc29SettlementArtifact,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<AcceptSettlementResult<Brc29ReceiptData>, RemittanceError> {
        // Validate settlement before calling wallet
        if let Err(msg) = ensure_valid_settlement(settlement) {
            return Ok(AcceptSettlementResult::Terminate {
                termination: Termination {
                    code: "brc29.internalize_failed".to_string(),
                    message: msg,
                    details: None,
                },
            });
        }

        // Parse sender identity key
        let sender_pk = match PublicKey::from_string(sender) {
            Ok(pk) => pk,
            Err(e) => {
                return Ok(AcceptSettlementResult::Terminate {
                    termination: Termination {
                        code: "brc29.internalize_failed".to_string(),
                        message: format!("invalid sender key: {e}"),
                        details: None,
                    },
                });
            }
        };

        let output_index = settlement.output_index.unwrap_or(0);

        // Call internalize_action — catch errors, do NOT propagate via ?
        let internalize_result = ctx
            .wallet
            .internalize_action(
                InternalizeActionArgs {
                    tx: settlement.transaction.clone(),
                    description: "BRC-29 payment received".to_string(),
                    labels: self.config.labels.clone(),
                    seek_permission: BooleanDefaultTrue(Some(true)),
                    outputs: vec![match self.config.internalize_protocol {
                        InternalizeProtocol::WalletPayment => InternalizeOutput::WalletPayment {
                            output_index,
                            payment: Payment {
                                derivation_prefix: settlement
                                    .custom_instructions
                                    .derivation_prefix
                                    .as_bytes()
                                    .to_vec(),
                                derivation_suffix: settlement
                                    .custom_instructions
                                    .derivation_suffix
                                    .as_bytes()
                                    .to_vec(),
                                sender_identity_key: sender_pk,
                            },
                        },
                        InternalizeProtocol::BasketInsertion => {
                            InternalizeOutput::BasketInsertion {
                                output_index,
                                insertion: BasketInsertion {
                                    basket: "brc29".to_string(),
                                    custom_instructions: Some(format!(
                                        "prefix={},suffix={}",
                                        settlement.custom_instructions.derivation_prefix,
                                        settlement.custom_instructions.derivation_suffix,
                                    )),
                                    tags: vec![],
                                },
                            }
                        }
                    }],
                },
                ctx.originator.as_deref(),
            )
            .await;

        match internalize_result {
            Ok(result) => Ok(AcceptSettlementResult::Accept {
                receipt_data: Some(Brc29ReceiptData {
                    internalize_result: Some(
                        serde_json::to_value(&result).unwrap_or(serde_json::Value::Null),
                    ),
                    rejected_reason: None,
                    refund: None,
                }),
            }),
            Err(e) => Ok(AcceptSettlementResult::Terminate {
                termination: Termination {
                    code: "brc29.internalize_failed".to_string(),
                    message: e.to_string(),
                    details: None,
                },
            }),
        }
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
// build_settlement_inner — inner implementation called by the trait method
// ---------------------------------------------------------------------------

impl Brc29RemittanceModule {
    /// Inner implementation of build_settlement. Returns Err on any failure;
    /// the caller maps Err to Terminate with code "brc29.build_failed".
    async fn build_settlement_inner(
        &self,
        thread_id: &str,
        option: &Brc29OptionTerms,
        note: Option<&str>,
        ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<Brc29SettlementArtifact>, RemittanceError> {
        // Step 1: Validate option — return Terminate directly (not Err), matches TS behavior
        if let Err(msg) = ensure_valid_option(option) {
            return Ok(BuildSettlementResult::Terminate {
                termination: Termination {
                    code: "brc29.invalid_option".to_string(),
                    message: msg,
                    details: None,
                },
            });
        }

        // Step 2: Create two nonces (one for derivationPrefix, one for derivationSuffix)
        let derivation_prefix = self
            .config
            .nonce_provider
            .create_nonce(&ctx.wallet, ctx.originator.as_deref())
            .await?;
        let derivation_suffix = self
            .config
            .nonce_provider
            .create_nonce(&ctx.wallet, ctx.originator.as_deref())
            .await?;

        // Step 3: Determine protocol_id (option override or config default)
        let protocol_id = option
            .protocol_id
            .clone()
            .unwrap_or_else(|| self.config.protocol_id.clone());

        // Step 4: Derive payee public key and call get_public_key
        let key_id = format!("{} {}", derivation_prefix, derivation_suffix);
        let payee_pk = PublicKey::from_string(&option.payee)
            .map_err(|e| RemittanceError::Protocol(format!("invalid payee key: {e}")))?;
        let pk_result = ctx
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(protocol_id),
                    key_id: Some(key_id),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(payee_pk),
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                ctx.originator.as_deref(),
            )
            .await?;

        // Step 5: Get locking script hex from provider and decode to bytes
        let script_hex = self
            .config
            .locking_script_provider
            .get_locking_script(&pk_result.public_key.to_der_hex())
            .await?;
        let script_bytes = crate::primitives::utils::from_hex(&script_hex)
            .map_err(|e| RemittanceError::Protocol(format!("invalid locking script hex: {e}")))?;

        // Step 6: Build custom instructions JSON (camelCase, matching TS wire format)
        let custom_json = serde_json::to_string(&CustomInstructionsPayload {
            derivation_prefix: &derivation_prefix,
            derivation_suffix: &derivation_suffix,
            payee: &option.payee,
            thread_id,
            note,
        })
        .map_err(|e| RemittanceError::Protocol(format!("custom instructions JSON error: {e}")))?;

        // Step 7: Resolve description and labels (option overrides config defaults)
        let description = option
            .description
            .clone()
            .unwrap_or_else(|| self.config.description.clone());
        let labels = option
            .labels
            .clone()
            .unwrap_or_else(|| self.config.labels.clone());

        // Step 8: Call create_action with P2PKH output and randomize_outputs=false
        let action_result = ctx
            .wallet
            .create_action(
                CreateActionArgs {
                    description,
                    labels,
                    outputs: vec![CreateActionOutput {
                        locking_script: Some(script_bytes),
                        satoshis: option.amount_satoshis,
                        output_description: self.config.output_description.clone(),
                        basket: None,
                        custom_instructions: Some(custom_json),
                        tags: vec![],
                    }],
                    options: Some(CreateActionOptions {
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    input_beef: None,
                    inputs: vec![],
                    lock_time: None,
                    version: None,
                    reference: None,
                },
                ctx.originator.as_deref(),
            )
            .await?;

        // Step 9: Extract transaction bytes (tx ?? signableTransaction?.tx — matching TS)
        let tx = action_result
            .tx
            .or_else(|| action_result.signable_transaction.map(|st| st.tx));
        let tx = match tx {
            Some(tx) if is_atomic_beef(&tx) => tx,
            _ => {
                return Ok(BuildSettlementResult::Terminate {
                    termination: Termination {
                        code: "brc29.missing_tx".to_string(),
                        message: "wallet returned no transaction".to_string(),
                        details: None,
                    },
                });
            }
        };

        // Step 10: Return settlement artifact
        Ok(BuildSettlementResult::Settle {
            artifact: Brc29SettlementArtifact {
                custom_instructions: Brc29SettlementCustomInstructions {
                    derivation_prefix,
                    derivation_suffix,
                },
                transaction: tx,
                amount_satoshis: option.amount_satoshis,
                output_index: Some(option.output_index.unwrap_or(0)),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Validation helpers (BRC29-06) — match TS validation logic
// ---------------------------------------------------------------------------

/// Returns `true` if `tx` is a non-empty byte array where every byte is
/// in the valid range 0-255.
///
/// In Rust, `&[u8]` enforces the 0-255 range by type; this function therefore
/// checks non-emptiness only. This matches the TypeScript SDK `isAtomicBeef`
/// semantics where the TS version also validates each byte is an integer in
/// 0-255, which is trivially true for Rust `u8`.
pub fn is_atomic_beef(tx: &[u8]) -> bool {
    !tx.is_empty()
}

/// Validates a `Brc29OptionTerms` before use in `build_settlement`.
///
/// Mirrors TS validation in `BasicBRC29.buildSettlement` (lines 304-324):
/// - `amountSatoshis` must be a positive integer (> 0)
/// - `payee` must be a non-empty, non-whitespace string
/// - `protocolID`: if provided, the protocol string must be non-empty and non-whitespace
/// - `labels`: if provided, every label must be a non-empty, non-whitespace string
/// - `description`: if provided, must be a non-empty, non-whitespace string
///
/// Note: `outputIndex: Option<u32>` is always >= 0 by the Rust type system — no
/// runtime check is needed, matching the TS `outputIndex >= 0` check trivially.
pub fn ensure_valid_option(option: &Brc29OptionTerms) -> Result<(), String> {
    if option.amount_satoshis == 0 {
        return Err("BRC-29 option amount must be a positive integer".into());
    }
    if option.payee.is_empty() || option.payee.trim().is_empty() {
        return Err("BRC-29 option payee is required".into());
    }
    if let Some(pid) = &option.protocol_id {
        if pid.protocol.trim().is_empty() {
            return Err("BRC-29 option protocolID must have a non-empty protocol string".into());
        }
    }
    if let Some(labels) = &option.labels {
        if labels.iter().any(|l| l.trim().is_empty()) {
            return Err("BRC-29 option labels must be a list of non-empty strings".into());
        }
    }
    if let Some(desc) = &option.description {
        if desc.trim().is_empty() {
            return Err("BRC-29 option description must be a non-empty string".into());
        }
    }
    Ok(())
}

/// Validates a `Brc29SettlementArtifact` before use in `accept_settlement`.
///
/// Mirrors TS validation in `BasicBRC29.acceptSettlement`:
/// - `transaction` must be a non-empty byte array (is_atomic_beef check)
/// - `derivationPrefix` and `derivationSuffix` must be non-empty, non-whitespace
/// - `amountSatoshis` must be a positive integer (> 0)
///
/// outputIndex validation: Rust's `u32` type guarantees non-negative values,
/// matching the TS runtime check for `outputIndex >= 0`. No runtime code needed.
pub fn ensure_valid_settlement(artifact: &Brc29SettlementArtifact) -> Result<(), String> {
    if !is_atomic_beef(&artifact.transaction) {
        return Err("BRC-29 settlement transaction must be a non-empty byte array".into());
    }
    if artifact.custom_instructions.derivation_prefix.is_empty()
        || artifact
            .custom_instructions
            .derivation_prefix
            .trim()
            .is_empty()
    {
        return Err("BRC-29 settlement derivation values are required".into());
    }
    if artifact.custom_instructions.derivation_suffix.is_empty()
        || artifact
            .custom_instructions
            .derivation_suffix
            .trim()
            .is_empty()
    {
        return Err("BRC-29 settlement derivation values are required".into());
    }
    if artifact.amount_satoshis == 0 {
        return Err("BRC-29 settlement amount must be a positive integer".into());
    }
    Ok(())
}
