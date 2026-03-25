//! Integration tests for the BRC-29 remittance module.
//!
//! Covers: metadata (id/name/flags), wire-format serde roundtrips matching TS SDK,
//! config defaults matching TS SDK, mock provider injection, and validation helpers.

#![cfg(feature = "network")]

use std::sync::Arc;

use async_trait::async_trait;
use bsv::remittance::modules::brc29::{
    Brc29OptionTerms, Brc29ReceiptData, Brc29RefundData, Brc29RemittanceModule,
    Brc29RemittanceModuleConfig, Brc29SettlementArtifact, Brc29SettlementCustomInstructions,
    LockingScriptProvider, NonceProvider, ensure_valid_option, ensure_valid_settlement,
    is_atomic_beef,
};
use bsv::remittance::RemittanceModule;
use bsv::remittance::RemittanceError;
use bsv::wallet::types::Protocol;
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
// MockWallet for provider injection tests
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
// Mock providers
// ---------------------------------------------------------------------------

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
