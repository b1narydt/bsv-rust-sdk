//! Unit tests for RemittanceManager core functionality.
//!
//! Kept as an integration test file to avoid pre-existing wallet module
//! compilation errors in the lib test target — consistent with Phase 1/2 pattern.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;

use bsv::remittance::comms_layer::CommsLayer;
use bsv::remittance::error::RemittanceError;
use bsv::remittance::identity_layer::{AssessIdentityResult, IdentityLayer, RespondToRequestResult};
use bsv::remittance::manager::{
    ComposeInvoiceInput, IdentityPhase, MessageDirection, RemittanceEvent, RemittanceManager,
    RemittanceManagerConfig, RemittanceManagerRuntimeOptions, RemittanceManagerState, Thread,
    ThreadFlags, ThreadIdentity, ThreadRole,
};
use bsv::remittance::remittance_module::{
    AcceptSettlementResult, BuildSettlementResult, RemittanceModule,
};
use bsv::remittance::types::{
    Amount, IdentityVerificationAcknowledgment, IdentityVerificationRequest,
    IdentityVerificationResponse, InstrumentBase, Invoice, ModuleContext, PeerMessage,
    RemittanceKind, RemittanceThreadState, Settlement, Termination, sat_unit,
};
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
// MockWallet — get_public_key returns a test identity key
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
    async fn get_public_key(&self, _a: GetPublicKeyArgs, _o: Option<&str>) -> Result<GetPublicKeyResult, WalletError> {
        // Return a valid compressed public key (the secp256k1 generator point in DER hex).
        // This is a well-known uncompressed point used only for testing.
        let pk = bsv::primitives::public_key::PublicKey::from_string(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ).map_err(|e| WalletError::InvalidParameter(e.to_string()))?;
        Ok(GetPublicKeyResult { public_key: pk })
    }
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
// MockComms
// ---------------------------------------------------------------------------

struct MockComms {
    sent: Arc<StdMutex<Vec<(String, String, String)>>>,
}

impl MockComms {
    fn new() -> Self {
        Self {
            sent: Arc::new(StdMutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl CommsLayer for MockComms {
    async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        _host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        self.sent.lock().unwrap().push((
            recipient.to_string(),
            message_box.to_string(),
            body.to_string(),
        ));
        Ok("mock-transport-id".to_string())
    }

    async fn list_messages(
        &self,
        _message_box: &str,
        _host: Option<&str>,
    ) -> Result<Vec<PeerMessage>, RemittanceError> {
        Ok(vec![])
    }

    async fn acknowledge_message(
        &self,
        _message_ids: &[String],
    ) -> Result<(), RemittanceError> {
        Ok(())
    }

    async fn send_live_message(
        &self,
        _recipient: &str,
        _message_box: &str,
        _body: &str,
        _host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        Ok("mock-live-id".to_string())
    }

    async fn listen_for_live_messages(
        &self,
        _message_box: &str,
        _override_host: Option<&str>,
        _on_message: Arc<dyn Fn(PeerMessage) + Send + Sync>,
    ) -> Result<(), RemittanceError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockIdentity
// ---------------------------------------------------------------------------

struct MockIdentity;

#[async_trait]
impl IdentityLayer for MockIdentity {
    async fn determine_certificates_to_request(
        &self,
        _counterparty: &str,
        thread_id: &str,
        _ctx: &ModuleContext,
    ) -> Result<IdentityVerificationRequest, RemittanceError> {
        Ok(IdentityVerificationRequest {
            kind: RemittanceKind::IdentityVerificationRequest,
            thread_id: thread_id.to_string(),
            request: bsv::remittance::types::IdentityRequest {
                types: HashMap::new(),
                certifiers: vec![],
            },
        })
    }

    async fn respond_to_request(
        &self,
        _counterparty: &str,
        thread_id: &str,
        _request: &IdentityVerificationRequest,
        _ctx: &ModuleContext,
    ) -> Result<RespondToRequestResult, RemittanceError> {
        Ok(RespondToRequestResult::Respond {
            response: IdentityVerificationResponse {
                kind: RemittanceKind::IdentityVerificationResponse,
                thread_id: thread_id.to_string(),
                certificates: vec![],
            },
        })
    }

    async fn assess_received_certificate_sufficiency(
        &self,
        _counterparty: &str,
        received: &IdentityVerificationResponse,
        _thread_id: &str,
    ) -> Result<AssessIdentityResult, RemittanceError> {
        Ok(AssessIdentityResult::Acknowledge(
            IdentityVerificationAcknowledgment {
                kind: RemittanceKind::IdentityVerificationAcknowledgment,
                thread_id: received.thread_id.clone(),
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// MockModule
// ---------------------------------------------------------------------------

struct MockModule;

#[async_trait]
impl RemittanceModule for MockModule {
    type OptionTerms = serde_json::Value;
    type SettlementArtifact = serde_json::Value;
    type ReceiptData = serde_json::Value;

    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module" }
    fn allow_unsolicited_settlements(&self) -> bool { false }

    async fn build_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _option: &serde_json::Value,
        _note: Option<&str>,
        _ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<serde_json::Value>, RemittanceError> {
        Ok(BuildSettlementResult::Settle {
            artifact: serde_json::json!({}),
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
        Ok(AcceptSettlementResult::Accept { receipt_data: None })
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_manager() -> RemittanceManager {
    make_manager_with_config(RemittanceManagerConfig {
        message_box: None,
        originator: None,
        logger: None,
        options: None,
        on_event: None,
        state_saver: None,
        state_loader: None,
        now: None,
        thread_id_factory: None,
    })
}

fn make_manager_with_config(config: RemittanceManagerConfig) -> RemittanceManager {
    RemittanceManager::new(
        config,
        Arc::new(MockWallet),
        Arc::new(MockComms::new()),
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModule)],
    )
}

fn sample_thread(thread_id: &str) -> Thread {
    Thread {
        thread_id: thread_id.to_string(),
        counterparty: "bob".to_string(),
        my_role: ThreadRole::Maker,
        their_role: ThreadRole::Taker,
        created_at: 0,
        updated_at: 0,
        state: RemittanceThreadState::New,
        state_log: vec![],
        processed_message_ids: vec![],
        protocol_log: vec![],
        identity: ThreadIdentity::default(),
        flags: ThreadFlags::default(),
        invoice: None,
        settlement: None,
        receipt: None,
        termination: None,
        last_error: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_constructor() {
    let manager = make_manager();
    // Unknown thread returns None
    let result = manager.get_thread("nonexistent").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_init_restores_state() {
    let thread = sample_thread("thread-abc");
    let thread_clone = thread.clone();

    let config = RemittanceManagerConfig {
        message_box: None,
        originator: None,
        logger: None,
        options: None,
        on_event: None,
        state_saver: None,
        state_loader: Some(Box::new(move || {
            Some(RemittanceManagerState {
                v: 1,
                threads: vec![thread_clone.clone()],
                default_payment_option_id: None,
            })
        })),
        now: Some(Box::new(|| 0u64)),
        thread_id_factory: None,
    };
    let manager = make_manager_with_config(config);
    manager.init().await.unwrap();

    let restored = manager.get_thread("thread-abc").await;
    assert!(restored.is_some());
    assert_eq!(restored.unwrap().counterparty, "bob");
}

#[tokio::test]
async fn test_save_state_envelope() {
    let thread = sample_thread("t-save");

    let config = RemittanceManagerConfig {
        message_box: None,
        originator: None,
        logger: None,
        options: None,
        on_event: None,
        state_saver: None,
        state_loader: Some(Box::new(move || {
            Some(RemittanceManagerState {
                v: 1,
                threads: vec![thread.clone()],
                default_payment_option_id: None,
            })
        })),
        now: Some(Box::new(|| 0u64)),
        thread_id_factory: None,
    };
    let manager = make_manager_with_config(config);
    manager.init().await.unwrap();

    let state = manager.save_state().await;
    assert_eq!(state.v, 1);
    assert_eq!(state.threads.len(), 1);
    assert_eq!(state.threads[0].thread_id, "t-save");

    // Roundtrip through serde_json
    let json = serde_json::to_string(&state).unwrap();
    let roundtripped: RemittanceManagerState = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtripped.v, 1);
    assert_eq!(roundtripped.threads.len(), 1);
    assert_eq!(roundtripped.threads[0].thread_id, "t-save");
}

#[tokio::test]
async fn test_state_roundtrip() {
    let state = RemittanceManagerState {
        v: 1,
        threads: vec![sample_thread("t-rt")],
        default_payment_option_id: Some("direct".to_string()),
    };

    let json = serde_json::to_string(&state).unwrap();
    let parsed: RemittanceManagerState = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.v, 1);
    assert_eq!(parsed.threads.len(), 1);
    assert_eq!(parsed.threads[0].thread_id, "t-rt");
    assert_eq!(parsed.default_payment_option_id.as_deref(), Some("direct"));
}

#[tokio::test]
async fn test_thread_serde() {
    let thread = sample_thread("camel-test");
    let json = serde_json::to_string(&thread).unwrap();

    // camelCase field names in JSON
    assert!(json.contains("\"threadId\""), "expected threadId in JSON: {}", json);
    assert!(json.contains("\"myRole\""), "expected myRole in JSON: {}", json);
    assert!(json.contains("\"stateLog\""), "expected stateLog in JSON: {}", json);
    assert!(json.contains("\"counterparty\""), "expected counterparty in JSON: {}", json);
    assert!(json.contains("\"createdAt\""), "expected createdAt in JSON: {}", json);
    assert!(json.contains("\"updatedAt\""), "expected updatedAt in JSON: {}", json);
}

#[tokio::test]
async fn test_invalid_transition() {
    let thread = sample_thread("t-inv");

    let config = RemittanceManagerConfig {
        message_box: None,
        originator: None,
        logger: None,
        options: None,
        on_event: None,
        state_saver: None,
        state_loader: Some(Box::new(move || {
            Some(RemittanceManagerState {
                v: 1,
                threads: vec![thread.clone()],
                default_payment_option_id: None,
            })
        })),
        now: Some(Box::new(|| 0u64)),
        thread_id_factory: None,
    };
    let manager = make_manager_with_config(config);
    manager.init().await.unwrap();

    // New -> Receipted is not a valid transition (New allows: IdentityRequested, Invoiced, Settled, Terminated, Errored)
    let result = manager
        .transition_thread_state("t-inv", RemittanceThreadState::Receipted, None)
        .await;

    assert!(
        matches!(result, Err(RemittanceError::InvalidStateTransition { .. })),
        "expected InvalidStateTransition, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_get_thread_or_throw() {
    let manager = make_manager();
    manager.init().await.unwrap();

    // Unknown thread should return error
    let err = manager.get_thread_or_throw("unknown-id").await;
    assert!(matches!(err, Err(RemittanceError::Protocol(_))));

    // Known thread should return Ok
    manager.insert_thread(sample_thread("known-id")).await;
    let ok = manager.get_thread_or_throw("known-id").await;
    assert!(ok.is_ok());
    assert_eq!(ok.unwrap().thread_id, "known-id");
}

#[tokio::test]
async fn test_runtime_defaults() {
    let opts = RemittanceManagerRuntimeOptions::default();
    assert!(!opts.receipt_provided);
    assert!(opts.auto_issue_receipt);
    assert_eq!(opts.invoice_expiry_seconds, 3600);
    assert_eq!(opts.identity_timeout_ms, 30_000);
    assert_eq!(opts.identity_poll_interval_ms, 1_000);
}

#[tokio::test]
async fn test_event_listener() {
    let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let events_clone = Arc::clone(&events);

    let config = RemittanceManagerConfig {
        message_box: None,
        originator: None,
        logger: None,
        options: None,
        on_event: None,
        state_saver: None,
        state_loader: None,
        now: Some(Box::new(|| 0u64)),
        thread_id_factory: None,
    };
    let manager = make_manager_with_config(config);
    manager.init().await.unwrap();

    // Register a listener that records event type names
    let listener: Arc<dyn Fn(RemittanceEvent) + Send + Sync> =
        Arc::new(move |event: RemittanceEvent| {
            let label = match &event {
                RemittanceEvent::StateChanged { .. } => "StateChanged",
                RemittanceEvent::ThreadCreated { .. } => "ThreadCreated",
                _ => "Other",
            };
            events_clone.lock().unwrap().push(label.to_string());
        });
    manager.on_event(listener).await;

    // Insert a thread in New state, then transition to IdentityRequested (valid).
    manager.insert_thread(sample_thread("evt-thread")).await;
    manager
        .transition_thread_state(
            "evt-thread",
            RemittanceThreadState::IdentityRequested,
            Some("test".to_string()),
        )
        .await
        .unwrap();

    let recorded = events.lock().unwrap().clone();
    assert!(
        recorded.contains(&"StateChanged".to_string()),
        "expected StateChanged event, got {:?}",
        recorded
    );
}
