//! Integration tests for the BRC-29 remittance module.
//!
//! Covers: metadata (id/name/flags), wire-format serde roundtrips matching TS SDK,
//! config defaults matching TS SDK, mock provider injection, and validation helpers.
//! Plan 02 adds: build_settlement and accept_settlement integration tests.

#![cfg(feature = "network")]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bsv::primitives::public_key::PublicKey;
use bsv::remittance::modules::brc29::{
    Brc29OptionTerms, Brc29ReceiptData, Brc29RefundData, Brc29RemittanceModule,
    Brc29RemittanceModuleConfig, Brc29SettlementArtifact, Brc29SettlementCustomInstructions,
    LockingScriptProvider, NonceProvider, ensure_valid_option, ensure_valid_settlement,
    is_atomic_beef,
};
use bsv::remittance::RemittanceModule;
use bsv::remittance::RemittanceError;
use bsv::remittance::types::ModuleContext;
use bsv::wallet::types::{CounterpartyType, Protocol};
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    Certificate, CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult,
    CreateSignatureArgs, CreateSignatureResult, DecryptArgs, DecryptResult,
    DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult,
    EncryptArgs, EncryptResult, GetHeaderArgs, GetHeaderResult, GetHeightResult,
    GetNetworkResult, GetPublicKeyArgs, GetPublicKeyResult, GetVersionResult,
    InternalizeActionArgs, InternalizeActionResult, ListActionsArgs, ListActionsResult,
    ListCertificatesArgs, ListCertificatesResult, ListOutputsArgs, ListOutputsResult,
    ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
    RelinquishCertificateResult, RelinquishOutputArgs, RelinquishOutputResult,
    RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletInterface,
};

// ---------------------------------------------------------------------------
// MockWallet for provider injection tests (simple, no capturing)
// ---------------------------------------------------------------------------

struct MockWallet;

#[async_trait]
impl WalletInterface for MockWallet {
    async fn create_action(&self, _a: CreateActionArgs, _o: Option<&str>) -> Result<CreateActionResult, WalletError> { unimplemented!() }
    async fn sign_action(&self, _a: SignActionArgs, _o: Option<&str>) -> Result<SignActionResult, WalletError> { unimplemented!() }
    async fn abort_action(&self, _a: AbortActionArgs, _o: Option<&str>) -> Result<AbortActionResult, WalletError> { unimplemented!() }
    async fn list_actions(&self, _a: ListActionsArgs, _o: Option<&str>) -> Result<ListActionsResult, WalletError> { unimplemented!() }
    async fn internalize_action(&self, _a: InternalizeActionArgs, _o: Option<&str>) -> Result<InternalizeActionResult, WalletError> { unimplemented!() }
    async fn list_outputs(&self, _a: ListOutputsArgs, _o: Option<&str>) -> Result<ListOutputsResult, WalletError> { unimplemented!() }
    async fn relinquish_output(&self, _a: RelinquishOutputArgs, _o: Option<&str>) -> Result<RelinquishOutputResult, WalletError> { unimplemented!() }
    async fn get_public_key(&self, _a: GetPublicKeyArgs, _o: Option<&str>) -> Result<GetPublicKeyResult, WalletError> { unimplemented!() }
    async fn reveal_counterparty_key_linkage(&self, _a: RevealCounterpartyKeyLinkageArgs, _o: Option<&str>) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { unimplemented!() }
    async fn reveal_specific_key_linkage(&self, _a: RevealSpecificKeyLinkageArgs, _o: Option<&str>) -> Result<RevealSpecificKeyLinkageResult, WalletError> { unimplemented!() }
    async fn encrypt(&self, _a: EncryptArgs, _o: Option<&str>) -> Result<EncryptResult, WalletError> { unimplemented!() }
    async fn decrypt(&self, _a: DecryptArgs, _o: Option<&str>) -> Result<DecryptResult, WalletError> { unimplemented!() }
    async fn create_hmac(&self, _a: CreateHmacArgs, _o: Option<&str>) -> Result<CreateHmacResult, WalletError> { unimplemented!() }
    async fn verify_hmac(&self, _a: VerifyHmacArgs, _o: Option<&str>) -> Result<VerifyHmacResult, WalletError> { unimplemented!() }
    async fn create_signature(&self, _a: CreateSignatureArgs, _o: Option<&str>) -> Result<CreateSignatureResult, WalletError> { unimplemented!() }
    async fn verify_signature(&self, _a: VerifySignatureArgs, _o: Option<&str>) -> Result<VerifySignatureResult, WalletError> { unimplemented!() }
    async fn acquire_certificate(&self, _a: AcquireCertificateArgs, _o: Option<&str>) -> Result<Certificate, WalletError> { unimplemented!() }
    async fn list_certificates(&self, _a: ListCertificatesArgs, _o: Option<&str>) -> Result<ListCertificatesResult, WalletError> { unimplemented!() }
    async fn prove_certificate(&self, _a: ProveCertificateArgs, _o: Option<&str>) -> Result<ProveCertificateResult, WalletError> { unimplemented!() }
    async fn relinquish_certificate(&self, _a: RelinquishCertificateArgs, _o: Option<&str>) -> Result<RelinquishCertificateResult, WalletError> { unimplemented!() }
    async fn discover_by_identity_key(&self, _a: DiscoverByIdentityKeyArgs, _o: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
    async fn discover_by_attributes(&self, _a: DiscoverByAttributesArgs, _o: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
    async fn is_authenticated(&self, _o: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
    async fn wait_for_authentication(&self, _o: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
    async fn get_height(&self, _o: Option<&str>) -> Result<GetHeightResult, WalletError> { unimplemented!() }
    async fn get_header_for_height(&self, _a: GetHeaderArgs, _o: Option<&str>) -> Result<GetHeaderResult, WalletError> { unimplemented!() }
    async fn get_network(&self, _o: Option<&str>) -> Result<GetNetworkResult, WalletError> { unimplemented!() }
    async fn get_version(&self, _o: Option<&str>) -> Result<GetVersionResult, WalletError> { unimplemented!() }
}

// ---------------------------------------------------------------------------
// CapturingMockWallet — captures args for assertion, configurable responses
// ---------------------------------------------------------------------------

/// A mock wallet that captures calls for assertion in settlement tests.
struct CapturingMockWallet {
    /// Captured GetPublicKeyArgs calls.
    pub get_public_key_calls: Arc<Mutex<Vec<GetPublicKeyArgs>>>,
    /// Captured CreateActionArgs calls.
    pub create_action_calls: Arc<Mutex<Vec<CreateActionArgs>>>,
    /// Captured InternalizeActionArgs calls.
    pub internalize_action_calls: Arc<Mutex<Vec<InternalizeActionArgs>>>,
    /// If true, get_public_key returns an error.
    pub get_public_key_error: bool,
    /// If true, create_action returns tx=None (no signable_transaction either).
    pub create_action_no_tx: bool,
    /// If true, internalize_action returns an error.
    pub internalize_action_error: bool,
}

impl CapturingMockWallet {
    fn new() -> Self {
        Self {
            get_public_key_calls: Arc::new(Mutex::new(Vec::new())),
            create_action_calls: Arc::new(Mutex::new(Vec::new())),
            internalize_action_calls: Arc::new(Mutex::new(Vec::new())),
            get_public_key_error: false,
            create_action_no_tx: false,
            internalize_action_error: false,
        }
    }
}

/// Test public key hex (compressed secp256k1 generator point).
const TEST_PUBKEY_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// A fake Atomic BEEF — non-empty bytes recognized by is_atomic_beef placeholder.
const MOCK_TX_BYTES: &[u8] = &[0xEF, 0xBE, 0xAD, 0xDE];

#[async_trait]
impl WalletInterface for CapturingMockWallet {
    async fn get_public_key(
        &self,
        a: GetPublicKeyArgs,
        _o: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        if self.get_public_key_error {
            return Err(WalletError::InvalidParameter(
                "mock get_public_key error".to_string(),
            ));
        }
        self.get_public_key_calls.lock().unwrap().push(a);
        let pk = PublicKey::from_string(TEST_PUBKEY_HEX).unwrap();
        Ok(GetPublicKeyResult { public_key: pk })
    }

    async fn create_action(
        &self,
        a: CreateActionArgs,
        _o: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        self.create_action_calls.lock().unwrap().push(a);
        if self.create_action_no_tx {
            return Ok(CreateActionResult {
                txid: None,
                tx: None,
                no_send_change: vec![],
                send_with_results: vec![],
                signable_transaction: None,
            });
        }
        Ok(CreateActionResult {
            txid: Some("abcd1234".to_string()),
            tx: Some(MOCK_TX_BYTES.to_vec()),
            no_send_change: vec![],
            send_with_results: vec![],
            signable_transaction: None,
        })
    }

    async fn internalize_action(
        &self,
        a: InternalizeActionArgs,
        _o: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        if self.internalize_action_error {
            return Err(WalletError::InvalidParameter(
                "mock internalize error".to_string(),
            ));
        }
        self.internalize_action_calls.lock().unwrap().push(a);
        Ok(InternalizeActionResult { accepted: true })
    }

    async fn sign_action(&self, _a: SignActionArgs, _o: Option<&str>) -> Result<SignActionResult, WalletError> { unimplemented!() }
    async fn abort_action(&self, _a: AbortActionArgs, _o: Option<&str>) -> Result<AbortActionResult, WalletError> { unimplemented!() }
    async fn list_actions(&self, _a: ListActionsArgs, _o: Option<&str>) -> Result<ListActionsResult, WalletError> { unimplemented!() }
    async fn list_outputs(&self, _a: ListOutputsArgs, _o: Option<&str>) -> Result<ListOutputsResult, WalletError> { unimplemented!() }
    async fn relinquish_output(&self, _a: RelinquishOutputArgs, _o: Option<&str>) -> Result<RelinquishOutputResult, WalletError> { unimplemented!() }
    async fn reveal_counterparty_key_linkage(&self, _a: RevealCounterpartyKeyLinkageArgs, _o: Option<&str>) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { unimplemented!() }
    async fn reveal_specific_key_linkage(&self, _a: RevealSpecificKeyLinkageArgs, _o: Option<&str>) -> Result<RevealSpecificKeyLinkageResult, WalletError> { unimplemented!() }
    async fn encrypt(&self, _a: EncryptArgs, _o: Option<&str>) -> Result<EncryptResult, WalletError> { unimplemented!() }
    async fn decrypt(&self, _a: DecryptArgs, _o: Option<&str>) -> Result<DecryptResult, WalletError> { unimplemented!() }
    async fn create_hmac(&self, _a: CreateHmacArgs, _o: Option<&str>) -> Result<CreateHmacResult, WalletError> { unimplemented!() }
    async fn verify_hmac(&self, _a: VerifyHmacArgs, _o: Option<&str>) -> Result<VerifyHmacResult, WalletError> { unimplemented!() }
    async fn create_signature(&self, _a: CreateSignatureArgs, _o: Option<&str>) -> Result<CreateSignatureResult, WalletError> { unimplemented!() }
    async fn verify_signature(&self, _a: VerifySignatureArgs, _o: Option<&str>) -> Result<VerifySignatureResult, WalletError> { unimplemented!() }
    async fn acquire_certificate(&self, _a: AcquireCertificateArgs, _o: Option<&str>) -> Result<Certificate, WalletError> { unimplemented!() }
    async fn list_certificates(&self, _a: ListCertificatesArgs, _o: Option<&str>) -> Result<ListCertificatesResult, WalletError> { unimplemented!() }
    async fn prove_certificate(&self, _a: ProveCertificateArgs, _o: Option<&str>) -> Result<ProveCertificateResult, WalletError> { unimplemented!() }
    async fn relinquish_certificate(&self, _a: RelinquishCertificateArgs, _o: Option<&str>) -> Result<RelinquishCertificateResult, WalletError> { unimplemented!() }
    async fn discover_by_identity_key(&self, _a: DiscoverByIdentityKeyArgs, _o: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
    async fn discover_by_attributes(&self, _a: DiscoverByAttributesArgs, _o: Option<&str>) -> Result<DiscoverCertificatesResult, WalletError> { unimplemented!() }
    async fn is_authenticated(&self, _o: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
    async fn wait_for_authentication(&self, _o: Option<&str>) -> Result<AuthenticatedResult, WalletError> { unimplemented!() }
    async fn get_height(&self, _o: Option<&str>) -> Result<GetHeightResult, WalletError> { unimplemented!() }
    async fn get_header_for_height(&self, _a: GetHeaderArgs, _o: Option<&str>) -> Result<GetHeaderResult, WalletError> { unimplemented!() }
    async fn get_network(&self, _o: Option<&str>) -> Result<GetNetworkResult, WalletError> { unimplemented!() }
    async fn get_version(&self, _o: Option<&str>) -> Result<GetVersionResult, WalletError> { unimplemented!() }
}

// ---------------------------------------------------------------------------
// Mock providers
// ---------------------------------------------------------------------------

/// Simple nonce provider — always returns the same value.
/// Used in Plan 01 provider injection tests.
struct MockNonceProvider;

#[async_trait]
impl NonceProvider for MockNonceProvider {
    async fn create_nonce(
        &self,
        _wallet: &Arc<dyn bsv::wallet::WalletInterface>,
        _originator: Option<&str>,
    ) -> Result<String, RemittanceError> {
        Ok("mock-nonce-abc123".to_string())
    }
}

/// Incrementing nonce provider — returns "mock-nonce-1", "mock-nonce-2", etc.
/// Used in settlement tests to verify two distinct nonces are created.
struct IncrementingNonceProvider {
    counter: Arc<Mutex<u32>>,
}

impl IncrementingNonceProvider {
    fn new() -> Self {
        Self { counter: Arc::new(Mutex::new(0)) }
    }
}

#[async_trait]
impl NonceProvider for IncrementingNonceProvider {
    async fn create_nonce(
        &self,
        _wallet: &Arc<dyn bsv::wallet::WalletInterface>,
        _originator: Option<&str>,
    ) -> Result<String, RemittanceError> {
        let mut count = self.counter.lock().unwrap();
        *count += 1;
        Ok(format!("mock-nonce-{}", count))
    }
}

struct MockLockingScriptProvider;

#[async_trait]
impl LockingScriptProvider for MockLockingScriptProvider {
    async fn get_locking_script(
        &self,
        _public_key_hex: &str,
    ) -> Result<String, RemittanceError> {
        Ok("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac".to_string())
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_module() -> Brc29RemittanceModule {
    Brc29RemittanceModule::new(Brc29RemittanceModuleConfig::default())
}

fn make_module_with_mock_providers() -> Brc29RemittanceModule {
    let config = Brc29RemittanceModuleConfig {
        nonce_provider: Arc::new(MockNonceProvider),
        locking_script_provider: Arc::new(MockLockingScriptProvider),
        ..Default::default()
    };
    Brc29RemittanceModule::new(config)
}

// ---------------------------------------------------------------------------
// Metadata tests (BRC29-01)
// ---------------------------------------------------------------------------

#[test]
fn test_module_id() {
    assert_eq!(make_module().id(), "brc29.p2pkh");
}

#[test]
fn test_module_name() {
    assert_eq!(make_module().name(), "BSV (BRC-29 derived P2PKH)");
}

#[test]
fn test_allow_unsolicited_settlements() {
    assert!(make_module().allow_unsolicited_settlements());
}

#[test]
fn test_supports_create_option_is_false() {
    assert!(!make_module().supports_create_option());
}

// ---------------------------------------------------------------------------
// Wire format tests — Brc29OptionTerms (BRC29-04)
// ---------------------------------------------------------------------------

#[test]
fn test_option_terms_wire_format_minimal() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 5000,
        payee: "02abcdef".to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    };
    let json = serde_json::to_value(&opt).unwrap();
    // camelCase fields present
    assert_eq!(json["amountSatoshis"], 5000);
    assert_eq!(json["payee"], "02abcdef");
    // None fields must be absent
    assert!(json.get("outputIndex").is_none(), "outputIndex should be absent");
    assert!(json.get("protocolId").is_none(), "protocolId should be absent");
    assert!(json.get("labels").is_none(), "labels should be absent");
    assert!(json.get("description").is_none(), "description should be absent");
    // Roundtrip
    let rt: Brc29OptionTerms = serde_json::from_value(json).unwrap();
    assert_eq!(rt.amount_satoshis, 5000);
    assert_eq!(rt.payee, "02abcdef");
    assert!(rt.output_index.is_none());
}

#[test]
fn test_option_terms_wire_format_full() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 10_000,
        payee: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
        output_index: Some(1),
        protocol_id: Some(Protocol { security_level: 2, protocol: "3241645161d8".to_string() }),
        labels: Some(vec!["brc29".to_string()]),
        description: Some("test payment".to_string()),
    };
    let json = serde_json::to_value(&opt).unwrap();
    assert_eq!(json["amountSatoshis"], 10_000);
    assert_eq!(json["outputIndex"], 1);
    // Roundtrip
    let rt: Brc29OptionTerms = serde_json::from_value(json).unwrap();
    assert_eq!(rt.output_index, Some(1));
    assert_eq!(rt.labels.as_deref(), Some(["brc29".to_string()].as_ref()));
}

// ---------------------------------------------------------------------------
// Wire format tests — Brc29SettlementArtifact (BRC29-04)
// ---------------------------------------------------------------------------

#[test]
fn test_settlement_artifact_wire_format() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix-abc".to_string(),
            derivation_suffix: "suffix-xyz".to_string(),
        },
        transaction: vec![0xef, 0xbe, 0xad, 0xde],
        amount_satoshis: 5000,
        output_index: None,
    };
    let json = serde_json::to_value(&artifact).unwrap();
    // camelCase nested fields
    assert_eq!(json["customInstructions"]["derivationPrefix"], "prefix-abc");
    assert_eq!(json["customInstructions"]["derivationSuffix"], "suffix-xyz");
    // transaction as number array matching TS number[]
    assert_eq!(json["transaction"][0], 0xef);
    assert_eq!(json["transaction"][1], 0xbe);
    assert_eq!(json["amountSatoshis"], 5000);
    assert!(json.get("outputIndex").is_none(), "optional outputIndex absent when None");
    // Roundtrip
    let rt: Brc29SettlementArtifact = serde_json::from_value(json).unwrap();
    assert_eq!(rt.transaction, vec![0xef, 0xbe, 0xad, 0xde]);
    assert_eq!(rt.custom_instructions.derivation_prefix, "prefix-abc");
}

#[test]
fn test_settlement_artifact_with_output_index() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "p".to_string(),
            derivation_suffix: "s".to_string(),
        },
        transaction: vec![1, 2, 3],
        amount_satoshis: 1000,
        output_index: Some(2),
    };
    let json = serde_json::to_value(&artifact).unwrap();
    assert_eq!(json["outputIndex"], 2);
    let rt: Brc29SettlementArtifact = serde_json::from_value(json).unwrap();
    assert_eq!(rt.output_index, Some(2));
}

// ---------------------------------------------------------------------------
// Wire format tests — Brc29ReceiptData (BRC29-04)
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_data_wire_format_empty() {
    let receipt = Brc29ReceiptData {
        internalize_result: None,
        rejected_reason: None,
        refund: None,
    };
    let json = serde_json::to_value(&receipt).unwrap();
    // All fields absent when None
    assert!(json.get("internalizeResult").is_none());
    assert!(json.get("rejectedReason").is_none());
    assert!(json.get("refund").is_none());
    // Roundtrip
    let rt: Brc29ReceiptData = serde_json::from_value(json).unwrap();
    assert!(rt.internalize_result.is_none());
}

#[test]
fn test_receipt_data_wire_format_with_rejection() {
    let receipt = Brc29ReceiptData {
        internalize_result: None,
        rejected_reason: Some("invalid amount".to_string()),
        refund: None,
    };
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["rejectedReason"], "invalid amount");
    let rt: Brc29ReceiptData = serde_json::from_value(json).unwrap();
    assert_eq!(rt.rejected_reason.as_deref(), Some("invalid amount"));
}

#[test]
fn test_receipt_data_wire_format_with_refund() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "p".to_string(),
            derivation_suffix: "s".to_string(),
        },
        transaction: vec![1],
        amount_satoshis: 5000,
        output_index: None,
    };
    let receipt = Brc29ReceiptData {
        internalize_result: Some(serde_json::json!({"accepted": true})),
        rejected_reason: None,
        refund: Some(Brc29RefundData { token: artifact, fee_satoshis: 500 }),
    };
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(json["internalizeResult"]["accepted"], true);
    assert_eq!(json["refund"]["feeSatoshis"], 500);
    assert_eq!(json["refund"]["token"]["amountSatoshis"], 5000);
    let rt: Brc29ReceiptData = serde_json::from_value(json).unwrap();
    assert_eq!(rt.refund.as_ref().unwrap().fee_satoshis, 500);
}

// ---------------------------------------------------------------------------
// Config defaults tests (BRC29-07)
// ---------------------------------------------------------------------------

#[test]
fn test_config_defaults_protocol_id() {
    let cfg = Brc29RemittanceModuleConfig::default();
    assert_eq!(cfg.protocol_id.security_level, 2);
    assert_eq!(cfg.protocol_id.protocol, "3241645161d8");
}

#[test]
fn test_config_defaults_labels() {
    let cfg = Brc29RemittanceModuleConfig::default();
    assert_eq!(cfg.labels, vec!["brc29".to_string()]);
}

#[test]
fn test_config_defaults_description() {
    let cfg = Brc29RemittanceModuleConfig::default();
    assert_eq!(cfg.description, "BRC-29 payment");
}

#[test]
fn test_config_defaults_output_description() {
    let cfg = Brc29RemittanceModuleConfig::default();
    assert_eq!(cfg.output_description, "Payment for remittance invoice");
}

// ---------------------------------------------------------------------------
// Mock provider injection tests (BRC29-05)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mock_nonce_provider_injection() {
    let provider = MockNonceProvider;
    // Verify mock returns expected nonce — no wallet call needed
    let wallet: Arc<dyn WalletInterface> = Arc::new(MockWallet);
    let result = provider.create_nonce(&wallet, None).await.unwrap();
    assert_eq!(result, "mock-nonce-abc123");
}

#[tokio::test]
async fn test_mock_locking_script_provider_injection() {
    let provider = MockLockingScriptProvider;
    let result = provider.get_locking_script("02abc").await.unwrap();
    assert_eq!(result, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac");
}

#[test]
fn test_module_with_mock_providers_has_correct_metadata() {
    let m = make_module_with_mock_providers();
    assert_eq!(m.id(), "brc29.p2pkh");
    assert_eq!(m.name(), "BSV (BRC-29 derived P2PKH)");
}

// ---------------------------------------------------------------------------
// Validation helper tests (BRC29-06)
// ---------------------------------------------------------------------------

#[test]
fn test_ensure_valid_option_rejects_zero_amount() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 0,
        payee: "02abc".to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    };
    let err = ensure_valid_option(&opt).unwrap_err();
    assert!(err.contains("positive integer"), "error: {err}");
}

#[test]
fn test_ensure_valid_option_rejects_empty_payee() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 5000,
        payee: "".to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    };
    let err = ensure_valid_option(&opt).unwrap_err();
    assert!(err.contains("payee"), "error: {err}");
}

#[test]
fn test_ensure_valid_option_rejects_whitespace_payee() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 5000,
        payee: "   ".to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    };
    let err = ensure_valid_option(&opt).unwrap_err();
    assert!(err.contains("payee"), "error: {err}");
}

#[test]
fn test_ensure_valid_option_accepts_valid() {
    let opt = Brc29OptionTerms {
        amount_satoshis: 5000,
        payee: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    };
    assert!(ensure_valid_option(&opt).is_ok());
}

#[test]
fn test_ensure_valid_settlement_rejects_empty_transaction() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix".to_string(),
            derivation_suffix: "suffix".to_string(),
        },
        transaction: vec![],
        amount_satoshis: 5000,
        output_index: None,
    };
    let err = ensure_valid_settlement(&artifact).unwrap_err();
    assert!(err.contains("transaction") || err.contains("non-empty"), "error: {err}");
}

#[test]
fn test_ensure_valid_settlement_rejects_empty_derivation_prefix() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "".to_string(),
            derivation_suffix: "suffix".to_string(),
        },
        transaction: vec![1, 2, 3],
        amount_satoshis: 5000,
        output_index: None,
    };
    let err = ensure_valid_settlement(&artifact).unwrap_err();
    assert!(err.contains("derivation"), "error: {err}");
}

#[test]
fn test_ensure_valid_settlement_rejects_empty_derivation_suffix() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix".to_string(),
            derivation_suffix: "".to_string(),
        },
        transaction: vec![1, 2, 3],
        amount_satoshis: 5000,
        output_index: None,
    };
    let err = ensure_valid_settlement(&artifact).unwrap_err();
    assert!(err.contains("derivation"), "error: {err}");
}

#[test]
fn test_ensure_valid_settlement_rejects_zero_amount() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix".to_string(),
            derivation_suffix: "suffix".to_string(),
        },
        transaction: vec![1, 2, 3],
        amount_satoshis: 0,
        output_index: None,
    };
    let err = ensure_valid_settlement(&artifact).unwrap_err();
    assert!(err.contains("amount") || err.contains("positive"), "error: {err}");
}

#[test]
fn test_ensure_valid_settlement_accepts_valid() {
    let artifact = Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix-abc".to_string(),
            derivation_suffix: "suffix-xyz".to_string(),
        },
        transaction: vec![1, 2, 3, 4],
        amount_satoshis: 5000,
        output_index: None,
    };
    assert!(ensure_valid_settlement(&artifact).is_ok());
}

// ---------------------------------------------------------------------------
// is_atomic_beef tests
// ---------------------------------------------------------------------------

#[test]
fn test_is_atomic_beef_empty_is_false() {
    assert!(!is_atomic_beef(&[]));
}

#[test]
fn test_is_atomic_beef_nonempty_is_true() {
    assert!(is_atomic_beef(&[0x01, 0x02]));
}

// ---------------------------------------------------------------------------
// Helper: make a ModuleContext with a CapturingMockWallet
// ---------------------------------------------------------------------------

fn make_ctx(wallet: Arc<dyn WalletInterface>) -> ModuleContext {
    ModuleContext {
        wallet,
        originator: None,
        now: Arc::new(|| 0u64),
        logger: None,
    }
}

fn make_capturing_module(
    wallet: Arc<CapturingMockWallet>,
) -> (Brc29RemittanceModule, ModuleContext) {
    let nonce_provider = Arc::new(IncrementingNonceProvider::new());
    let locking_script_provider = Arc::new(MockLockingScriptProvider);
    let config = Brc29RemittanceModuleConfig {
        nonce_provider,
        locking_script_provider,
        ..Default::default()
    };
    let module = Brc29RemittanceModule::new(config);
    let ctx = make_ctx(wallet);
    (module, ctx)
}

fn make_valid_option() -> Brc29OptionTerms {
    Brc29OptionTerms {
        amount_satoshis: 5000,
        payee: TEST_PUBKEY_HEX.to_string(),
        output_index: None,
        protocol_id: None,
        labels: None,
        description: None,
    }
}

// ---------------------------------------------------------------------------
// build_settlement tests (Task 1 — TDD)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_build_settlement_success_creates_two_nonces() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet.clone());
    let option = make_valid_option();

    let result = module.build_settlement("thread-001", None, &option, None, &ctx)
        .await
        .unwrap();

    // Should return Settle, not Terminate
    match result {
        bsv::remittance::remittance_module::BuildSettlementResult::Settle { artifact } => {
            // Two distinct nonces stored in artifact
            assert_eq!(artifact.custom_instructions.derivation_prefix, "mock-nonce-1");
            assert_eq!(artifact.custom_instructions.derivation_suffix, "mock-nonce-2");
            // Transaction bytes match mock
            assert_eq!(artifact.transaction, MOCK_TX_BYTES);
            // Amount matches option
            assert_eq!(artifact.amount_satoshis, 5000);
        }
        other => panic!("expected Settle, got {:?}", other),
    }
}

#[tokio::test]
async fn test_build_settlement_calls_get_public_key_with_correct_args() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet.clone());
    let option = make_valid_option();

    module.build_settlement("thread-001", None, &option, None, &ctx)
        .await
        .unwrap();

    let calls = wallet.get_public_key_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "get_public_key should be called exactly once");
    let args = &calls[0];
    // identity_key must be false (derives child key, not identity key)
    assert!(!args.identity_key, "identity_key must be false");
    // key_id must be "{prefix} {suffix}"
    assert_eq!(
        args.key_id.as_deref(),
        Some("mock-nonce-1 mock-nonce-2"),
        "key_id must be '{{prefix}} {{suffix}}'"
    );
    // protocol_id must match config default
    let pid = args.protocol_id.as_ref().expect("protocol_id must be set");
    assert_eq!(pid.security_level, 2);
    assert_eq!(pid.protocol, "3241645161d8");
    // counterparty must be Other with the payee public key
    let cp = args.counterparty.as_ref().expect("counterparty must be set");
    assert_eq!(cp.counterparty_type, CounterpartyType::Other);
    let cp_pk = cp.public_key.as_ref().expect("counterparty public_key must be set");
    assert_eq!(cp_pk.to_der_hex(), TEST_PUBKEY_HEX);
}

#[tokio::test]
async fn test_build_settlement_calls_create_action_with_correct_args() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet.clone());
    let option = make_valid_option();

    module.build_settlement("thread-001", None, &option, Some("test note"), &ctx)
        .await
        .unwrap();

    let calls = wallet.create_action_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "create_action should be called exactly once");
    let args = &calls[0];

    // Outputs: exactly one output
    assert_eq!(args.outputs.len(), 1);
    let output = &args.outputs[0];
    assert_eq!(output.satoshis, 5000, "satoshis must match option.amount_satoshis");

    // custom_instructions must be valid JSON with camelCase fields
    let ci_str = output.custom_instructions.as_ref().expect("custom_instructions must be set");
    let ci: serde_json::Value = serde_json::from_str(ci_str).expect("custom_instructions must be valid JSON");
    assert_eq!(ci["derivationPrefix"], "mock-nonce-1");
    assert_eq!(ci["derivationSuffix"], "mock-nonce-2");
    assert_eq!(ci["payee"], TEST_PUBKEY_HEX);
    assert_eq!(ci["threadId"], "thread-001");
    assert_eq!(ci["note"], "test note");

    // locking_script must be present (bytes decoded from the mock hex)
    assert!(output.locking_script.is_some(), "locking_script must be set");

    // options.randomize_outputs must be false
    let opts = args.options.as_ref().expect("options must be set");
    assert_eq!(
        opts.randomize_outputs,
        bsv::wallet::types::BooleanDefaultTrue(Some(false)),
        "randomize_outputs must be explicitly false"
    );
}

#[tokio::test]
async fn test_build_settlement_returns_terminate_for_zero_amount() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet);
    let option = Brc29OptionTerms {
        amount_satoshis: 0,
        payee: TEST_PUBKEY_HEX.to_string(),
        ..make_valid_option()
    };

    let result = module.build_settlement("thread-001", None, &option, None, &ctx)
        .await
        .unwrap();

    match result {
        bsv::remittance::remittance_module::BuildSettlementResult::Terminate { termination } => {
            assert_eq!(termination.code, "brc29.invalid_option");
        }
        other => panic!("expected Terminate, got {:?}", other),
    }
}

#[tokio::test]
async fn test_build_settlement_returns_terminate_when_wallet_returns_no_tx() {
    let wallet = Arc::new(CapturingMockWallet {
        create_action_no_tx: true,
        ..CapturingMockWallet::new()
    });
    let (module, ctx) = make_capturing_module(wallet);
    let option = make_valid_option();

    let result = module.build_settlement("thread-001", None, &option, None, &ctx)
        .await
        .unwrap();

    match result {
        bsv::remittance::remittance_module::BuildSettlementResult::Terminate { termination } => {
            assert_eq!(termination.code, "brc29.missing_tx");
        }
        other => panic!("expected Terminate, got {:?}", other),
    }
}

#[tokio::test]
async fn test_build_settlement_returns_terminate_when_get_public_key_errors() {
    let wallet = Arc::new(CapturingMockWallet {
        get_public_key_error: true,
        ..CapturingMockWallet::new()
    });
    let (module, ctx) = make_capturing_module(wallet);
    let option = make_valid_option();

    let result = module.build_settlement("thread-001", None, &option, None, &ctx)
        .await
        .unwrap();

    match result {
        bsv::remittance::remittance_module::BuildSettlementResult::Terminate { termination } => {
            assert_eq!(termination.code, "brc29.build_failed");
        }
        other => panic!("expected Terminate, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// accept_settlement tests (Task 2 — TDD)
// ---------------------------------------------------------------------------

fn make_valid_artifact() -> Brc29SettlementArtifact {
    Brc29SettlementArtifact {
        custom_instructions: Brc29SettlementCustomInstructions {
            derivation_prefix: "prefix-abc".to_string(),
            derivation_suffix: "suffix-xyz".to_string(),
        },
        transaction: MOCK_TX_BYTES.to_vec(),
        amount_satoshis: 5000,
        output_index: Some(0),
    }
}

#[tokio::test]
async fn test_accept_settlement_success_calls_internalize_with_correct_args() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet.clone());
    let artifact = make_valid_artifact();

    let result = module.accept_settlement("thread-001", None, &artifact, TEST_PUBKEY_HEX, &ctx)
        .await
        .unwrap();

    // Result must be Accept
    match result {
        bsv::remittance::remittance_module::AcceptSettlementResult::Accept { receipt_data } => {
            let rd = receipt_data.expect("receipt_data must be Some");
            // internalize_result must be present and have accepted=true
            let ir = rd.internalize_result.expect("internalize_result must be set");
            assert_eq!(ir["accepted"], true);
        }
        other => panic!("expected Accept, got {:?}", other),
    }

    // Check captured internalize_action args
    let calls = wallet.internalize_action_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "internalize_action called exactly once");
    let args = &calls[0];
    assert_eq!(args.tx, MOCK_TX_BYTES);
    assert_eq!(args.description, "BRC-29 payment received");
    // labels must match config default
    assert_eq!(args.labels, vec!["brc29".to_string()]);

    // outputs: one WalletPayment
    assert_eq!(args.outputs.len(), 1);
    if let bsv::wallet::interfaces::InternalizeOutput::WalletPayment { output_index, payment } = &args.outputs[0] {
        assert_eq!(*output_index, 0);
        // derivation_prefix as bytes
        assert_eq!(payment.derivation_prefix, b"prefix-abc".to_vec());
        assert_eq!(payment.derivation_suffix, b"suffix-xyz".to_vec());
        // sender_identity_key must match TEST_PUBKEY_HEX
        assert_eq!(payment.sender_identity_key.to_der_hex(), TEST_PUBKEY_HEX);
    } else {
        panic!("expected WalletPayment variant");
    }
}

#[tokio::test]
async fn test_accept_settlement_returns_terminate_for_empty_transaction() {
    let wallet = Arc::new(CapturingMockWallet::new());
    let (module, ctx) = make_capturing_module(wallet.clone());
    let artifact = Brc29SettlementArtifact {
        transaction: vec![],  // invalid — triggers ensure_valid_settlement
        ..make_valid_artifact()
    };

    let result = module.accept_settlement("thread-001", None, &artifact, TEST_PUBKEY_HEX, &ctx)
        .await
        .unwrap();

    match result {
        bsv::remittance::remittance_module::AcceptSettlementResult::Terminate { termination } => {
            assert_eq!(termination.code, "brc29.internalize_failed");
        }
        other => panic!("expected Terminate, got {:?}", other),
    }

    // Wallet must NOT have been called (validation failed before wallet call)
    let calls = wallet.internalize_action_calls.lock().unwrap();
    assert!(calls.is_empty(), "internalize_action must not be called when validation fails");
}

#[tokio::test]
async fn test_accept_settlement_returns_terminate_when_internalize_errors() {
    let wallet = Arc::new(CapturingMockWallet {
        internalize_action_error: true,
        ..CapturingMockWallet::new()
    });
    let (module, ctx) = make_capturing_module(wallet.clone());
    let artifact = make_valid_artifact();

    // The error must be CAUGHT — result must be Ok(Terminate), NOT Err
    let result = module.accept_settlement("thread-001", None, &artifact, TEST_PUBKEY_HEX, &ctx)
        .await
        .unwrap();  // must be Ok, not Err

    match result {
        bsv::remittance::remittance_module::AcceptSettlementResult::Terminate { termination } => {
            assert_eq!(termination.code, "brc29.internalize_failed");
        }
        other => panic!("expected Terminate, got {:?}", other),
    }
}
