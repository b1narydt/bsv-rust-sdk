#![cfg(feature = "network")]
//! Object-safety and behaviour tests for RemittanceModule and ErasedRemittanceModule.
//!
//! Kept as an integration test file (rather than inline #[cfg(test)]) because
//! pre-existing wallet module compilation errors prevent the lib test target from
//! building — consistent with the pattern used for remittance_traits.rs and
//! remittance_wire_format.rs.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use bsv::remittance::error::RemittanceError;
use bsv::remittance::remittance_module::{
    AcceptSettlementResult, BuildSettlementResult, RemittanceModule,
};
use bsv::remittance::types::{
    sat_unit, Amount, InstrumentBase, Invoice, ModuleContext, RemittanceKind, Settlement,
    Termination,
};
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult, Certificate,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletInterface,
};

// ---------------------------------------------------------------------------
// Minimal WalletInterface mock — all methods unimplemented
// ---------------------------------------------------------------------------

struct MockWallet;

#[async_trait]
impl WalletInterface for MockWallet {
    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        unimplemented!()
    }
    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        unimplemented!()
    }
    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        unimplemented!()
    }
    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        unimplemented!()
    }
    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        unimplemented!()
    }
    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        unimplemented!()
    }
    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        unimplemented!()
    }
    async fn get_public_key(
        &self,
        _args: GetPublicKeyArgs,
        _originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        unimplemented!()
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        unimplemented!()
    }
    async fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        unimplemented!()
    }
    async fn encrypt(
        &self,
        _args: EncryptArgs,
        _originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        unimplemented!()
    }
    async fn decrypt(
        &self,
        _args: DecryptArgs,
        _originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        unimplemented!()
    }
    async fn create_hmac(
        &self,
        _args: CreateHmacArgs,
        _originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        unimplemented!()
    }
    async fn verify_hmac(
        &self,
        _args: VerifyHmacArgs,
        _originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        unimplemented!()
    }
    async fn create_signature(
        &self,
        _args: CreateSignatureArgs,
        _originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        unimplemented!()
    }
    async fn verify_signature(
        &self,
        _args: VerifySignatureArgs,
        _originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        unimplemented!()
    }
    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        unimplemented!()
    }
    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        unimplemented!()
    }
    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        unimplemented!()
    }
    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        unimplemented!()
    }
    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        unimplemented!()
    }
    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        unimplemented!()
    }
    async fn is_authenticated(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        unimplemented!()
    }
    async fn wait_for_authentication(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        unimplemented!()
    }
    async fn get_height(&self, _originator: Option<&str>) -> Result<GetHeightResult, WalletError> {
        unimplemented!()
    }
    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        unimplemented!()
    }
    async fn get_network(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetNetworkResult, WalletError> {
        unimplemented!()
    }
    async fn get_version(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetVersionResult, WalletError> {
        unimplemented!()
    }
}

fn mock_ctx() -> ModuleContext {
    ModuleContext {
        wallet: Arc::new(MockWallet),
        originator: None,
        now: Arc::new(|| 0u64),
        logger: None,
    }
}

fn mock_invoice() -> Invoice {
    Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: None,
        options: HashMap::new(),
        base: InstrumentBase {
            thread_id: "t1".into(),
            payee: "alice".into(),
            payer: "bob".into(),
            note: None,
            line_items: vec![],
            total: Amount {
                value: "1000".into(),
                unit: sat_unit(),
            },
            invoice_number: "INV-001".into(),
            created_at: 0,
            arbitrary: None,
        },
    }
}

// ---------------------------------------------------------------------------
// MockModule — all associated types = serde_json::Value for simplicity
// ---------------------------------------------------------------------------

struct MockModule;

#[async_trait]
impl RemittanceModule for MockModule {
    type OptionTerms = serde_json::Value;
    type SettlementArtifact = serde_json::Value;
    type ReceiptData = serde_json::Value;

    fn id(&self) -> &str {
        "mock"
    }

    fn name(&self) -> &str {
        "Mock Module"
    }

    fn allow_unsolicited_settlements(&self) -> bool {
        false
    }

    async fn build_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _option: &serde_json::Value,
        _note: Option<&str>,
        _ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<serde_json::Value>, RemittanceError> {
        Ok(BuildSettlementResult::Settle {
            artifact: serde_json::json!({ "tx": "deadbeef" }),
        })
    }

    async fn accept_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _settlement: &serde_json::Value,
        _sender: &str,
        _ctx: &ModuleContext,
    ) -> Result<AcceptSettlementResult<serde_json::Value>, RemittanceError> {
        Ok(AcceptSettlementResult::Accept {
            receipt_data: Some(serde_json::json!({ "confirmed": true })),
        })
    }
}

// ---------------------------------------------------------------------------
// ErasedRemittanceModule tests
// ---------------------------------------------------------------------------

// ErasedRemittanceModule is pub(crate) so we cannot access it from integration
// tests directly. Instead we verify the public-facing behaviour: that a concrete
// RemittanceModule compiles and behaves correctly, which exercises the blanket impl.

#[test]
fn erased_module_is_object_safe() {
    // Verify the blanket impl compiles and the typed trait methods are callable.
    let module = MockModule;
    assert_eq!(module.id(), "mock");
    assert_eq!(module.name(), "Mock Module");
    assert!(!module.allow_unsolicited_settlements());
    assert!(!module.supports_create_option());
}

#[test]
fn erased_module_in_hashmap() {
    // Verify a concrete module stored behind Arc compiles in a HashMap.
    // (ErasedRemittanceModule itself is pub(crate); this tests the typed path.)
    let mut map: HashMap<
        String,
        Arc<
            dyn RemittanceModule<
                OptionTerms = serde_json::Value,
                SettlementArtifact = serde_json::Value,
                ReceiptData = serde_json::Value,
            >,
        >,
    > = HashMap::new();
    map.insert("mock".to_string(), Arc::new(MockModule));
    let retrieved = map.get("mock").unwrap();
    assert_eq!(retrieved.id(), "mock");
}

#[tokio::test]
async fn create_option_default_returns_error() {
    // MockModule does not override create_option; default should return Protocol error.
    let module = MockModule;
    let ctx = mock_ctx();
    let invoice = mock_invoice();
    let result = module.create_option("t1", &invoice, &ctx).await;
    assert!(
        matches!(result, Err(RemittanceError::Protocol(_))),
        "expected Protocol error, got {:?}",
        result
    );
}

#[test]
fn build_settlement_result_variants() {
    let settle: BuildSettlementResult<serde_json::Value> = BuildSettlementResult::Settle {
        artifact: serde_json::json!({}),
    };
    let terminate: BuildSettlementResult<serde_json::Value> = BuildSettlementResult::Terminate {
        termination: Termination {
            code: "ERR".into(),
            message: "failed".into(),
            details: None,
        },
    };
    assert!(matches!(settle, BuildSettlementResult::Settle { .. }));
    assert!(matches!(terminate, BuildSettlementResult::Terminate { .. }));
}

#[test]
fn accept_settlement_result_variants() {
    let accept: AcceptSettlementResult<serde_json::Value> = AcceptSettlementResult::Accept {
        receipt_data: Some(serde_json::json!({})),
    };
    let terminate: AcceptSettlementResult<serde_json::Value> = AcceptSettlementResult::Terminate {
        termination: Termination {
            code: "ERR".into(),
            message: "rejected".into(),
            details: None,
        },
    };
    assert!(matches!(accept, AcceptSettlementResult::Accept { .. }));
    assert!(matches!(
        terminate,
        AcceptSettlementResult::Terminate { .. }
    ));
}

#[tokio::test]
async fn process_receipt_default_is_noop() {
    let module = MockModule;
    let ctx = mock_ctx();
    let receipt_data = serde_json::json!({ "confirmed": true });
    let result = module
        .process_receipt("t1", None, &receipt_data, "alice", &ctx)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn process_termination_default_is_noop() {
    let module = MockModule;
    let ctx = mock_ctx();
    let termination = Termination {
        code: "CANCELLED".into(),
        message: "user cancelled".into(),
        details: None,
    };
    let result = module
        .process_termination("t1", None, None::<&Settlement>, &termination, "alice", &ctx)
        .await;
    assert!(result.is_ok());
}
