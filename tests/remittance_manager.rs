#![cfg(feature = "network")]
//! Unit tests for RemittanceManager core functionality.
//!
//! Kept as an integration test file to avoid pre-existing wallet module
//! compilation errors in the lib test target — consistent with Phase 1/2 pattern.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use bsv::remittance::comms_layer::CommsLayer;
use bsv::remittance::error::RemittanceError;
use bsv::remittance::identity_layer::{AssessIdentityResult, IdentityLayer, RespondToRequestResult};
use bsv::remittance::manager::{
    ComposeInvoiceInput, IdentityPhase, IdentityRuntimeOptions, RemittanceEvent,
    RemittanceManager, RemittanceManagerConfig, RemittanceManagerRuntimeOptions,
    RemittanceManagerState, Thread, ThreadFlags, ThreadIdentity, ThreadRole,
};
use bsv::remittance::remittance_module::{
    AcceptSettlementResult, BuildSettlementResult, RemittanceModule,
};
use bsv::remittance::types::{
    Amount, IdentityVerificationAcknowledgment, IdentityVerificationRequest,
    IdentityVerificationResponse, InstrumentBase, Invoice, LineItem, ModuleContext, PeerMessage,
    Receipt, RemittanceEnvelope, RemittanceKind, RemittanceThreadState, Settlement, sat_unit,
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

/// Tracks all sent messages (both live and queued) as (recipient, message_box, body).
struct MockComms {
    sent: Arc<StdMutex<Vec<(String, String, String)>>>,
    /// When true, send_live_message returns an error to test queued fallback.
    fail_live: bool,
    /// Configurable list for list_messages to return.
    queued_messages: Arc<StdMutex<Vec<PeerMessage>>>,
    /// Tracks acknowledged message IDs.
    acknowledged: Arc<StdMutex<Vec<String>>>,
    /// Stored live listener callback (for verifying start_listening).
    live_callback: Arc<StdMutex<Option<Arc<dyn Fn(PeerMessage) + Send + Sync>>>>,
    /// Flag set when listen_for_live_messages is called.
    listening_flag: Arc<AtomicBool>,
}

impl MockComms {
    fn new() -> Self {
        Self {
            sent: Arc::new(StdMutex::new(Vec::new())),
            fail_live: false,
            queued_messages: Arc::new(StdMutex::new(Vec::new())),
            acknowledged: Arc::new(StdMutex::new(Vec::new())),
            live_callback: Arc::new(StdMutex::new(None)),
            listening_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    #[allow(dead_code)]
    fn new_with_fail_live() -> Self {
        let mut c = Self::new();
        c.fail_live = true;
        c
    }

    #[allow(dead_code)]
    fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Set messages to return from list_messages.
    #[allow(dead_code)]
    fn set_queued_messages(&self, msgs: Vec<PeerMessage>) {
        *self.queued_messages.lock().unwrap() = msgs;
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
        let msgs = self.queued_messages.lock().unwrap().clone();
        Ok(msgs)
    }

    async fn acknowledge_message(
        &self,
        message_ids: &[String],
    ) -> Result<(), RemittanceError> {
        let mut ack = self.acknowledged.lock().unwrap();
        for id in message_ids {
            ack.push(id.clone());
        }
        Ok(())
    }

    async fn send_live_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        _host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        if self.fail_live {
            return Err(RemittanceError::Protocol("live not supported".into()));
        }
        // Record live messages in the same vec for observability.
        self.sent.lock().unwrap().push((
            recipient.to_string(),
            message_box.to_string(),
            body.to_string(),
        ));
        Ok("mock-live-id".to_string())
    }

    async fn listen_for_live_messages(
        &self,
        _message_box: &str,
        _override_host: Option<&str>,
        on_message: Arc<dyn Fn(PeerMessage) + Send + Sync>,
    ) -> Result<(), RemittanceError> {
        self.listening_flag.store(true, Ordering::SeqCst);
        *self.live_callback.lock().unwrap() = Some(on_message);
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
// MockModuleWithOptions — supports create_option, returns fixed terms
// ---------------------------------------------------------------------------

struct MockModuleWithOptions;

#[async_trait]
impl RemittanceModule for MockModuleWithOptions {
    type OptionTerms = serde_json::Value;
    type SettlementArtifact = serde_json::Value;
    type ReceiptData = serde_json::Value;

    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module With Options" }
    fn allow_unsolicited_settlements(&self) -> bool { false }
    fn supports_create_option(&self) -> bool { true }

    async fn create_option(
        &self,
        _thread_id: &str,
        _invoice: &Invoice,
        _ctx: &ModuleContext,
    ) -> Result<serde_json::Value, RemittanceError> {
        Ok(serde_json::json!({ "minAmount": 100 }))
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
            artifact: serde_json::json!({ "tx": "mock-tx" }),
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
// MockModuleTracked — sets called_flag when build_settlement is called
// Also allows unsolicited settlements.
// ---------------------------------------------------------------------------

struct MockModuleTracked {
    called_flag: Arc<AtomicBool>,
}

#[async_trait]
impl RemittanceModule for MockModuleTracked {
    type OptionTerms = serde_json::Value;
    type SettlementArtifact = serde_json::Value;
    type ReceiptData = serde_json::Value;

    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module Tracked" }
    fn allow_unsolicited_settlements(&self) -> bool { true }
    fn supports_create_option(&self) -> bool { true }

    async fn create_option(
        &self,
        _thread_id: &str,
        _invoice: &Invoice,
        _ctx: &ModuleContext,
    ) -> Result<serde_json::Value, RemittanceError> {
        Ok(serde_json::json!({ "minAmount": 50 }))
    }

    async fn build_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _option: &serde_json::Value,
        _note: Option<&str>,
        _ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<serde_json::Value>, RemittanceError> {
        self.called_flag.store(true, Ordering::SeqCst);
        Ok(BuildSettlementResult::Settle {
            artifact: serde_json::json!({ "tx": "tracked-tx" }),
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
// MockModuleWithReceipt — accept_settlement returns receipt_data
// ---------------------------------------------------------------------------

struct MockModuleWithReceipt {
    accept_called: Arc<AtomicBool>,
}

#[async_trait]
impl RemittanceModule for MockModuleWithReceipt {
    type OptionTerms = serde_json::Value;
    type SettlementArtifact = serde_json::Value;
    type ReceiptData = serde_json::Value;

    fn id(&self) -> &str { "mock" }
    fn name(&self) -> &str { "Mock Module With Receipt" }
    fn allow_unsolicited_settlements(&self) -> bool { true }

    async fn build_settlement(
        &self,
        _thread_id: &str,
        _invoice: Option<&Invoice>,
        _option: &serde_json::Value,
        _note: Option<&str>,
        _ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<serde_json::Value>, RemittanceError> {
        Ok(BuildSettlementResult::Settle {
            artifact: serde_json::json!({ "tx": "receipt-module-tx" }),
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
        self.accept_called.store(true, Ordering::SeqCst);
        Ok(AcceptSettlementResult::Accept {
            receipt_data: Some(serde_json::json!({ "confirmed": true })),
        })
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a manager with a MockModuleWithReceipt (tracks accept_settlement calls).
fn make_manager_with_receipt_module(
    comms: Arc<MockComms>,
    accept_called: Arc<AtomicBool>,
) -> RemittanceManager {
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms;
    RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: Some(RemittanceManagerRuntimeOptions {
                auto_issue_receipt: true,
                ..Default::default()
            }),
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModuleWithReceipt { accept_called })],
    )
}

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

/// Build a manager with a specific MockComms (for observing messages).
fn make_manager_with_comms(comms: Arc<MockComms>) -> RemittanceManager {
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms;
    RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: None,
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModuleWithOptions)],
    )
}

/// Build a manager with a tracked module (supports unsolicited settlements).
fn make_manager_with_tracked_module(
    comms: Arc<MockComms>,
    called_flag: Arc<AtomicBool>,
) -> RemittanceManager {
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms;
    RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: None,
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModuleTracked { called_flag })],
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

fn sample_invoice_input() -> ComposeInvoiceInput {
    ComposeInvoiceInput {
        note: Some("test invoice".to_string()),
        line_items: vec![LineItem {
            id: None,
            description: "Widget".to_string(),
            quantity: None,
            unit_price: None,
            amount: Some(Amount {
                value: "1000".to_string(),
                unit: sat_unit(),
            }),
            metadata: None,
        }],
        total: Amount {
            value: "1000".to_string(),
            unit: sat_unit(),
        },
        invoice_number: "INV-001".to_string(),
        arbitrary: None,
        expires_at: None,
    }
}

/// Build a taker thread already in Invoiced state with a mock invoice containing module options.
fn invoiced_taker_thread(thread_id: &str) -> Thread {
    let invoice = Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: Some(2_000_000),
        options: {
            let mut map = HashMap::new();
            map.insert("mock".to_string(), serde_json::json!({ "minAmount": 50 }));
            map
        },
        base: InstrumentBase {
            thread_id: thread_id.to_string(),
            payee: "alice".to_string(),
            payer: "bob".to_string(),
            note: None,
            line_items: vec![],
            total: Amount { value: "1000".to_string(), unit: sat_unit() },
            invoice_number: "INV-001".to_string(),
            created_at: 1_000_000,
            arbitrary: None,
        },
    };
    Thread {
        thread_id: thread_id.to_string(),
        counterparty: "alice".to_string(),
        my_role: ThreadRole::Taker,
        their_role: ThreadRole::Maker,
        created_at: 0,
        updated_at: 0,
        state: RemittanceThreadState::Invoiced,
        state_log: vec![],
        processed_message_ids: vec![],
        protocol_log: vec![],
        identity: ThreadIdentity::default(),
        flags: ThreadFlags::default(),
        invoice: Some(invoice),
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
    // receipt_provided and identity_poll_interval_ms corrected to match TS SDK (PARITY-10).
    assert!(opts.receipt_provided);
    assert!(opts.auto_issue_receipt);
    assert_eq!(opts.invoice_expiry_seconds, 3600);
    assert_eq!(opts.identity_timeout_ms, 30_000);
    assert_eq!(opts.identity_poll_interval_ms, 500);
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

// ---------------------------------------------------------------------------
// Plan 02 tests — invoice lifecycle, pay, unsolicited settlement, etc.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_send_invoice_lifecycle() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    let handle = manager
        .send_invoice("counterparty", sample_invoice_input(), None)
        .await
        .expect("send_invoice should succeed");

    let thread = handle.handle.get_thread().await.unwrap();
    assert_eq!(thread.state, RemittanceThreadState::Invoiced, "thread should be Invoiced");
    assert!(thread.invoice.is_some(), "invoice should be stored on thread");
    assert!(thread.flags.has_invoiced, "has_invoiced flag should be set");

    // MockComms.send_live_message records the message; verify at least one was sent.
    let sent_count = comms.sent.lock().unwrap().len();
    assert!(sent_count >= 1, "at least one message should have been sent, got {}", sent_count);
}

#[tokio::test]
async fn test_send_invoice_for_thread() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    // Pre-insert a thread in IdentityAcknowledged state.
    let mut thread = sample_thread("existing-thread");
    thread.state = RemittanceThreadState::IdentityAcknowledged;
    thread.counterparty = "bob".to_string();
    manager.insert_thread(thread).await;

    let handle = manager
        .send_invoice_for_thread("existing-thread", sample_invoice_input(), None)
        .await
        .expect("send_invoice_for_thread should succeed");

    let thread = handle.handle.get_thread().await.unwrap();
    assert_eq!(thread.state, RemittanceThreadState::Invoiced);
    assert!(thread.invoice.is_some(), "invoice should be stored on thread");
}

#[tokio::test]
async fn test_find_invoices_payable() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    // Thread 1: taker + Invoiced — should be returned.
    let t1 = invoiced_taker_thread("t-payable");

    // Thread 2: maker + Invoiced — should NOT be returned.
    let mut t2 = invoiced_taker_thread("t-maker-invoiced");
    t2.my_role = ThreadRole::Maker;
    t2.their_role = ThreadRole::Taker;

    // Thread 3: taker + Settled — should NOT be returned.
    let mut t3 = invoiced_taker_thread("t-settled");
    t3.state = RemittanceThreadState::Settled;

    manager.insert_thread(t1).await;
    manager.insert_thread(t2).await;
    manager.insert_thread(t3).await;

    let payable = manager.find_invoices_payable(None).await;
    assert_eq!(payable.len(), 1, "only 1 thread should be payable, got {:?}", payable.len());
    assert_eq!(payable[0].handle.thread_id(), "t-payable");
}

#[tokio::test]
async fn test_pay() {
    let comms = Arc::new(MockComms::new());
    let called_flag = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_tracked_module(Arc::clone(&comms), Arc::clone(&called_flag));
    manager.init().await.unwrap();

    // Insert a taker thread in Invoiced state.
    let thread = invoiced_taker_thread("t-pay");
    manager.insert_thread(thread).await;

    let handle = manager
        .pay("t-pay", Some("mock"), None)
        .await
        .expect("pay should succeed");

    assert!(called_flag.load(Ordering::SeqCst), "build_settlement_erased should have been called");

    let thread = handle.get_thread().await.unwrap();
    assert_eq!(thread.state, RemittanceThreadState::Settled, "thread should be Settled after pay");
    assert!(thread.settlement.is_some(), "settlement should be stored on thread");
    assert!(thread.flags.has_paid, "has_paid flag should be set");

    let sent_count = comms.sent.lock().unwrap().len();
    assert!(sent_count >= 1, "at least one settlement message should have been sent");
}

#[tokio::test]
async fn test_unsolicited_settlement() {
    let comms = Arc::new(MockComms::new());
    let called_flag = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_tracked_module(Arc::clone(&comms), Arc::clone(&called_flag));
    manager.init().await.unwrap();

    let handle = manager
        .send_unsolicited_settlement("alice", "mock", "mock", serde_json::json!({"amount": 500}), None, None)
        .await
        .expect("send_unsolicited_settlement should succeed");

    let thread = handle.get_thread().await.unwrap();
    assert!(matches!(thread.my_role, ThreadRole::Taker), "thread role should be Taker");
    assert_eq!(thread.state, RemittanceThreadState::Settled, "thread should be Settled");
    assert!(thread.settlement.is_some(), "settlement should be stored");

    let sent_count = comms.sent.lock().unwrap().len();
    assert!(sent_count >= 1, "settlement message should have been sent");
}

#[tokio::test]
async fn test_identity_exchange() {
    let identity_opts = IdentityRuntimeOptions {
        maker_request_identity: Some(IdentityPhase::BeforeInvoicing),
        taker_request_identity: None,
    };
    // Use a single MockComms instance for both observation and manager.
    let comms = Arc::new(MockComms::new());
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms.clone();
    let manager = RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: Some(RemittanceManagerRuntimeOptions {
                identity_options: Some(identity_opts),
                ..Default::default()
            }),
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModuleWithOptions)],
    );
    manager.init().await.unwrap();

    // send_invoice with identity options configured — should send identity request first.
    let _handle = manager
        .send_invoice("counterparty", sample_invoice_input(), None)
        .await
        .expect("send_invoice should succeed even with identity exchange");

    let sent = comms.sent.lock().unwrap().clone();
    assert!(
        sent.len() >= 2,
        "expected at least 2 messages (identity request + invoice), got {}",
        sent.len()
    );
    // The first message should be the identity verification request.
    let first_body: serde_json::Value = serde_json::from_str(&sent[0].2).unwrap();
    assert_eq!(
        first_body.get("kind").and_then(|v| v.as_str()),
        Some("identityVerificationRequest"),
        "first message should be identityVerificationRequest, got {:?}",
        first_body.get("kind")
    );
}

#[tokio::test]
async fn test_compose_invoice_includes_module_options() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    // send_invoice to trigger compose_invoice; then inspect the stored invoice.
    let handle = manager
        .send_invoice("bob", sample_invoice_input(), None)
        .await
        .expect("send_invoice should succeed");

    let thread = handle.handle.get_thread().await.unwrap();
    let invoice = thread.invoice.expect("invoice should be stored");

    assert!(
        invoice.options.contains_key("mock"),
        "invoice.options should contain 'mock' module option, got {:?}",
        invoice.options.keys().collect::<Vec<_>>()
    );
    let option_val = &invoice.options["mock"];
    assert_eq!(
        option_val.get("minAmount").and_then(|v| v.as_u64()),
        Some(100),
        "mock option should have minAmount=100, got {:?}",
        option_val
    );
}

#[tokio::test]
async fn test_preselect_option() {
    let comms = Arc::new(MockComms::new());
    let called_flag = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_tracked_module(Arc::clone(&comms), Arc::clone(&called_flag));
    manager.init().await.unwrap();

    // Set default option.
    manager.preselect_payment_option_id("mock").await;

    // Verify it was stored.
    let default_opt = manager.get_default_payment_option_id().await;
    assert_eq!(default_opt.as_deref(), Some("mock"), "default option should be 'mock'");

    // Insert an Invoiced taker thread and pay without explicit option_id.
    manager.insert_thread(invoiced_taker_thread("t-preselect")).await;
    let handle = manager
        .pay("t-preselect", None, None)  // no explicit option_id — should use default
        .await
        .expect("pay with preselected option should succeed");

    assert!(called_flag.load(Ordering::SeqCst), "mock module should have been called via preselected option");
    let thread = handle.get_thread().await.unwrap();
    assert_eq!(thread.state, RemittanceThreadState::Settled);
}

// ---------------------------------------------------------------------------
// Plan 03 tests — sync_threads, start_listening, wait_for_receipt, dedup
// ---------------------------------------------------------------------------

/// Build a PeerMessage with the given fields.
fn make_peer_message(id: &str, sender: &str, body: &str) -> PeerMessage {
    PeerMessage {
        message_id: id.to_string(),
        sender: sender.to_string(),
        recipient: "me".to_string(),
        message_box: "remittance".to_string(),
        body: body.to_string(),
    }
}

/// Serialize a RemittanceEnvelope with Invoice kind.
fn make_invoice_envelope(thread_id: &str, invoice: Invoice) -> String {
    let payload = serde_json::to_value(&invoice).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "test-env-id".to_string(),
        kind: RemittanceKind::Invoice,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    serde_json::to_string(&env).unwrap()
}

/// Build a minimal Invoice for testing.
fn test_invoice(thread_id: &str) -> Invoice {
    Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: Some(9_999_999),
        options: {
            let mut m = HashMap::new();
            m.insert("mock".to_string(), serde_json::json!({ "minAmount": 100 }));
            m
        },
        base: InstrumentBase {
            thread_id: thread_id.to_string(),
            payee: "alice".to_string(),
            payer: "bob".to_string(),
            note: None,
            line_items: vec![],
            total: Amount { value: "1000".to_string(), unit: sat_unit() },
            invoice_number: "INV-T01".to_string(),
            created_at: 1_000_000,
            arbitrary: None,
        },
    }
}

/// Build a Settlement envelope body for an existing thread.
fn make_settlement_envelope(thread_id: &str) -> String {
    let settlement = Settlement {
        kind: RemittanceKind::Settlement,
        thread_id: thread_id.to_string(),
        module_id: "mock".to_string(),
        option_id: "mock".to_string(),
        sender: "bob".to_string(),
        created_at: 1_000_000,
        artifact: serde_json::json!({ "tx": "abc" }),
        note: None,
    };
    let payload = serde_json::to_value(&settlement).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "settle-env-id".to_string(),
        kind: RemittanceKind::Settlement,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    serde_json::to_string(&env).unwrap()
}

/// Build a Receipt envelope body for an existing thread.
fn make_receipt_envelope(thread_id: &str) -> String {
    let receipt = Receipt {
        kind: RemittanceKind::Receipt,
        thread_id: thread_id.to_string(),
        module_id: "mock".to_string(),
        option_id: "mock".to_string(),
        payee: "alice".to_string(),
        payer: "bob".to_string(),
        created_at: 1_000_000,
        receipt_data: serde_json::json!({ "confirmed": true }),
    };
    let payload = serde_json::to_value(&receipt).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "receipt-env-id".to_string(),
        kind: RemittanceKind::Receipt,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    serde_json::to_string(&env).unwrap()
}

#[tokio::test]
async fn test_sync_threads() {
    let comms = Arc::new(MockComms::new());
    let thread_id = "sync-thread-001";
    let invoice = test_invoice(thread_id);
    let body = make_invoice_envelope(thread_id, invoice);
    let msg = make_peer_message("msg-001", "alice", &body);

    // Queue one message for list_messages to return.
    comms.set_queued_messages(vec![msg]);

    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    manager.sync_threads(None).await.expect("sync_threads should succeed");

    // Thread should have been created and transitioned to Invoiced.
    let thread = manager.get_thread(thread_id).await;
    assert!(thread.is_some(), "thread should have been created by sync_threads");
    let thread = thread.unwrap();
    assert_eq!(thread.state, RemittanceThreadState::Invoiced, "thread should be Invoiced");
    assert!(thread.invoice.is_some(), "invoice should be stored");

    // Message should have been acknowledged.
    let acked = comms.acknowledged.lock().unwrap().clone();
    assert!(acked.contains(&"msg-001".to_string()), "message should have been acknowledged");
}

#[tokio::test]
async fn test_start_listening() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    manager.start_listening(None).await.expect("start_listening should succeed");

    // Verify listen_for_live_messages was called.
    assert!(
        comms.listening_flag.load(Ordering::SeqCst),
        "listening_flag should be set after start_listening"
    );
    assert!(
        comms.live_callback.lock().unwrap().is_some(),
        "live_callback should be stored after start_listening"
    );
}

#[tokio::test]
async fn test_wait_for_receipt_notify() {
    use tokio::time::{timeout, Duration};

    let comms = Arc::new(MockComms::new());
    let accept_called = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_receipt_module(Arc::clone(&comms), Arc::clone(&accept_called));
    manager.init().await.unwrap();

    // Set up an Invoiced taker thread.
    let thread_id = "wait-receipt-thread";
    manager.insert_thread(invoiced_taker_thread(thread_id)).await;

    // Transition to Settled first (so we can send receipt).
    manager
        .transition_thread_state(thread_id, RemittanceThreadState::Settled, None)
        .await
        .unwrap();

    // Queue a Receipt message via comms and trigger via sync_threads in a spawned task.
    let body = make_receipt_envelope(thread_id);
    let msg = make_peer_message("rcpt-001", "alice", &body);
    comms.set_queued_messages(vec![msg]);

    let manager_clone = manager.clone();
    tokio::spawn(async move {
        // Small delay to ensure wait_for_receipt is already waiting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Process the queued receipt message to trigger Receipted transition.
        let _ = manager_clone.sync_threads(None).await;
    });

    // Wait for receipt (with timeout to prevent hanging).
    let result = timeout(
        Duration::from_secs(2),
        manager.wait_for_receipt(thread_id, None),
    )
    .await
    .expect("wait_for_receipt should complete within 2 seconds")
    .expect("wait_for_receipt should succeed");

    let receipt = match result {
        bsv::remittance::manager::WaitReceiptResult::Receipt(r) => r,
        bsv::remittance::manager::WaitReceiptResult::Terminated(_) => {
            panic!("expected Receipt, got Terminated");
        }
    };
    assert_eq!(
        receipt.receipt_data,
        serde_json::json!({ "confirmed": true }),
        "receipt_data should match"
    );
}

#[tokio::test]
async fn test_deduplication() {
    let comms = Arc::new(MockComms::new());
    let thread_id = "dedup-thread";
    let invoice = test_invoice(thread_id);
    let body = make_invoice_envelope(thread_id, invoice);

    // Same message_id sent twice.
    let msg1 = make_peer_message("dedup-msg-001", "alice", &body);
    let msg2 = make_peer_message("dedup-msg-001", "alice", &body);

    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    // Queue both messages (same message_id) and process via sync_threads.
    // sync_threads calls handle_inbound_message internally for each message.
    comms.set_queued_messages(vec![msg1, msg2]);
    manager.sync_threads(None).await.unwrap();

    // Thread should exist and be in Invoiced (not double-transitioned).
    let thread = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(
        thread.state,
        RemittanceThreadState::Invoiced,
        "thread should be in Invoiced (not Settled or other double-transition)"
    );

    // Processed IDs should contain dedup-msg-001 exactly once.
    let count = thread
        .processed_message_ids
        .iter()
        .filter(|id| id.as_str() == "dedup-msg-001")
        .count();
    assert_eq!(count, 1, "dedup-msg-001 should appear exactly once in processed_message_ids");
}

#[tokio::test]
async fn test_thread_handle() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    let thread_id = "handle-test-thread";
    manager.insert_thread(sample_thread(thread_id)).await;

    // Get a ThreadHandle.
    let handle = manager
        .get_thread_handle(thread_id)
        .await
        .expect("get_thread_handle should succeed");

    assert_eq!(handle.thread_id(), thread_id);

    // get_thread() on handle returns the correct thread.
    let thread = handle.get_thread().await.expect("handle.get_thread should succeed");
    assert_eq!(thread.thread_id, thread_id);
    assert_eq!(thread.state, RemittanceThreadState::New);
}

#[tokio::test]
async fn test_inbound_invoice() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_comms(Arc::clone(&comms));
    manager.init().await.unwrap();

    let thread_id = "inbound-invoice-thread";
    let invoice = test_invoice(thread_id);
    let body = make_invoice_envelope(thread_id, invoice);
    let msg = make_peer_message("inv-msg-001", "alice", &body);

    comms.set_queued_messages(vec![msg]);
    manager.sync_threads(None).await.expect("sync_threads should succeed");

    let thread = manager.get_thread(thread_id).await.expect("thread should have been created");
    // We are taker (they sent the invoice as maker).
    assert!(matches!(thread.my_role, ThreadRole::Taker), "our role should be Taker");
    assert_eq!(thread.state, RemittanceThreadState::Invoiced, "thread should be Invoiced");
    assert!(thread.invoice.is_some(), "invoice should be stored on thread");
    assert!(thread.flags.has_invoiced, "has_invoiced flag should be set");
}

#[tokio::test]
async fn test_inbound_settlement_with_auto_receipt() {
    let comms = Arc::new(MockComms::new());
    let accept_called = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_receipt_module(Arc::clone(&comms), Arc::clone(&accept_called));
    manager.init().await.unwrap();

    // Pre-insert an Invoiced thread (taker sent us a settlement, so we are maker).
    let thread_id = "settle-recv-thread";
    let mut thread = sample_thread(thread_id);
    thread.my_role = ThreadRole::Maker;
    thread.their_role = ThreadRole::Taker;
    thread.state = RemittanceThreadState::Invoiced;
    thread.invoice = Some(test_invoice(thread_id));
    thread.flags.has_invoiced = true;
    manager.insert_thread(thread).await;

    let body = make_settlement_envelope(thread_id);
    let msg = make_peer_message("settle-msg-001", "bob", &body);

    comms.set_queued_messages(vec![msg]);
    manager.sync_threads(None).await.expect("sync_threads for settlement should succeed");

    // accept_settlement should have been called on the module.
    assert!(
        accept_called.load(Ordering::SeqCst),
        "module.accept_settlement should have been called"
    );

    let thread = manager.get_thread(thread_id).await.unwrap();
    // auto_issue_receipt=true → should be Receipted, not just Settled.
    assert_eq!(
        thread.state,
        RemittanceThreadState::Receipted,
        "thread should be Receipted after auto-receipt, got {:?}",
        thread.state
    );
    assert!(thread.receipt.is_some(), "receipt should be stored");

    // A receipt message should have been sent back to the counterparty.
    let sent = comms.sent.lock().unwrap();
    let receipt_sent = sent.iter().any(|(_, _, body)| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            v.get("kind").and_then(|k| k.as_str()) == Some("receipt")
        } else {
            false
        }
    });
    assert!(receipt_sent, "a receipt message should have been sent via comms");
}

// ---------------------------------------------------------------------------
// Plan 04 tests — full 7-state lifecycle (TEST-03)
// ---------------------------------------------------------------------------

/// Verifies that all 7 thread states appear in the state_log (as `to` values).
fn assert_all_seven_states_in_log(thread_id: &str, log: &[bsv::remittance::manager::StateLogEntry]) {
    use RemittanceThreadState::*;
    let expected = [
        IdentityRequested,
        IdentityResponded,
        IdentityAcknowledged,
        Invoiced,
        Settled,
        Receipted,
    ];
    for state in &expected {
        assert!(
            log.iter().any(|e| &e.to == state),
            "state_log for thread {} missing state {:?}; log: {:?}",
            thread_id,
            state,
            log
        );
    }
}

#[tokio::test]
async fn test_full_lifecycle_new_through_receipted() {
    // Build a manager with auto_issue_receipt=true and a MockModuleWithReceipt
    // so that inbound settlement auto-receipts.
    let comms = Arc::new(MockComms::new());
    let accept_called = Arc::new(AtomicBool::new(false));
    let manager = make_manager_with_receipt_module(Arc::clone(&comms), Arc::clone(&accept_called));
    manager.init().await.unwrap();

    let thread_id = "lifecycle-all-7";

    // --- Step 1: New -> IdentityRequested ---
    // Insert a fresh thread in New state and manually drive it through
    // the identity sub-states before invoice and settlement.
    let initial = sample_thread(thread_id);
    manager.insert_thread(initial).await;

    // New -> IdentityRequested (valid per allowed_transitions)
    manager
        .transition_thread_state(thread_id, RemittanceThreadState::IdentityRequested, Some("identity request sent".to_string()))
        .await
        .expect("New -> IdentityRequested must succeed");

    let t = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(t.state, RemittanceThreadState::IdentityRequested);

    // --- Step 2: IdentityRequested -> IdentityResponded ---
    manager
        .transition_thread_state(thread_id, RemittanceThreadState::IdentityResponded, Some("identity response received".to_string()))
        .await
        .expect("IdentityRequested -> IdentityResponded must succeed");

    let t = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(t.state, RemittanceThreadState::IdentityResponded);

    // --- Step 3: IdentityResponded -> IdentityAcknowledged ---
    manager
        .transition_thread_state(thread_id, RemittanceThreadState::IdentityAcknowledged, Some("identity acknowledged".to_string()))
        .await
        .expect("IdentityResponded -> IdentityAcknowledged must succeed");

    let t = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(t.state, RemittanceThreadState::IdentityAcknowledged);

    // --- Step 4: IdentityAcknowledged -> Invoiced ---
    // Attach invoice and set invoiced flag before transitioning so the thread
    // can accept an inbound settlement later.
    // Transition to Invoiced and then replace thread data via a new insert
    // (insert_thread overwrites the existing entry).
    manager
        .transition_thread_state(thread_id, RemittanceThreadState::Invoiced, Some("invoice sent".to_string()))
        .await
        .expect("IdentityAcknowledged -> Invoiced must succeed");

    let t = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(t.state, RemittanceThreadState::Invoiced);

    // --- Step 5: Invoiced -> Settled -> Receipted via inbound settlement ---
    // The thread is now Invoiced/Maker. Inject an inbound settlement message.
    // The MockModuleWithReceipt accepts it and auto_issue_receipt fires a receipt.

    // Attach invoice to thread so accept_settlement has context.
    // We do this by re-inserting the thread with invoice data preserved;
    // insert_thread replaces the entry so we rebuild with existing state.
    let invoiced_thread = {
        let snapshot = manager.get_thread(thread_id).await.unwrap();
        Thread {
            invoice: Some(test_invoice(thread_id)),
            flags: ThreadFlags { has_invoiced: true, ..snapshot.flags },
            my_role: ThreadRole::Maker,
            their_role: ThreadRole::Taker,
            ..snapshot
        }
    };
    // Preserve the state log accumulated so far by using the snapshot above
    // and then re-inserting. The state is already Invoiced so no transition needed.
    manager.insert_thread(invoiced_thread).await;

    // Verify state is still Invoiced after re-insert.
    let t = manager.get_thread(thread_id).await.unwrap();
    assert_eq!(t.state, RemittanceThreadState::Invoiced, "should still be Invoiced after re-insert");

    // Queue an inbound settlement message from the taker.
    let body = make_settlement_envelope(thread_id);
    let msg = make_peer_message("lifecycle-settle-001", "bob", &body);
    comms.set_queued_messages(vec![msg]);

    // sync_threads processes the settlement; auto-receipt fires because auto_issue_receipt=true.
    manager.sync_threads(None).await.expect("sync_threads for settlement should succeed");

    // --- Assertions ---
    assert!(accept_called.load(Ordering::SeqCst), "accept_settlement must have been called");

    let final_thread = manager.get_thread(thread_id).await.unwrap();

    // Final state must be Receipted.
    assert_eq!(
        final_thread.state,
        RemittanceThreadState::Receipted,
        "final state should be Receipted, got {:?}",
        final_thread.state
    );

    // Settlement and receipt must be stored.
    assert!(final_thread.settlement.is_some(), "settlement should be stored on thread");
    assert!(final_thread.receipt.is_some(), "receipt should be stored on thread");

    // State log must contain entries for all transitions driven (IdentityRequested
    // through Receipted — 6 transitions covering all 7 states New->Receipted).
    assert_all_seven_states_in_log(thread_id, &final_thread.state_log);

    // Verify a receipt message was sent outbound.
    let sent = comms.sent.lock().unwrap();
    let receipt_sent = sent.iter().any(|(_, _, body)| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            v.get("kind").and_then(|k| k.as_str()) == Some("receipt")
        } else {
            false
        }
    });
    assert!(receipt_sent, "a receipt message should have been sent outbound");
}

// ---------------------------------------------------------------------------
// Phase 05.1 plan 01 — PARITY-06, PARITY-07, PARITY-10 tests
// ---------------------------------------------------------------------------

/// Build a manager configured with makerRequestIdentity=BeforeSettlement.
fn make_manager_with_identity_before_settlement(comms: Arc<MockComms>) -> RemittanceManager {
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms;
    RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: Some(RemittanceManagerRuntimeOptions {
                identity_options: Some(IdentityRuntimeOptions {
                    maker_request_identity: Some(IdentityPhase::BeforeSettlement),
                    taker_request_identity: None,
                }),
                receipt_provided: true,
                auto_issue_receipt: false,
                ..Default::default()
            }),
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModule)],
    )
}

/// Build a maker thread in Invoiced state with has_identified=false.
fn invoiced_maker_thread_unidentified(thread_id: &str) -> Thread {
    let invoice = Invoice {
        kind: RemittanceKind::Invoice,
        expires_at: Some(9_999_999),
        options: {
            let mut m = HashMap::new();
            m.insert("mock".to_string(), serde_json::json!({ "minAmount": 50 }));
            m
        },
        base: InstrumentBase {
            thread_id: thread_id.to_string(),
            payee: "alice".to_string(),
            payer: "bob".to_string(),
            note: None,
            line_items: vec![],
            total: Amount { value: "1000".to_string(), unit: sat_unit() },
            invoice_number: "INV-GUARD".to_string(),
            created_at: 1_000_000,
            arbitrary: None,
        },
    };
    Thread {
        thread_id: thread_id.to_string(),
        counterparty: "bob".to_string(),
        my_role: ThreadRole::Maker,
        their_role: ThreadRole::Taker,
        created_at: 0,
        updated_at: 0,
        state: RemittanceThreadState::Invoiced,
        state_log: vec![],
        processed_message_ids: vec![],
        protocol_log: vec![],
        identity: ThreadIdentity::default(),
        flags: ThreadFlags { has_invoiced: true, has_identified: false, ..Default::default() },
        invoice: Some(invoice),
        settlement: None,
        receipt: None,
        termination: None,
        last_error: None,
    }
}

/// Build a maker thread in Invoiced state with has_identified=true.
fn invoiced_maker_thread_identified(thread_id: &str) -> Thread {
    let mut t = invoiced_maker_thread_unidentified(thread_id);
    t.flags.has_identified = true;
    t
}

/// Build a taker thread in Invoiced state with has_identified=false.
fn invoiced_taker_thread_unidentified(thread_id: &str) -> Thread {
    let mut t = invoiced_maker_thread_unidentified(thread_id);
    t.my_role = ThreadRole::Taker;
    t.their_role = ThreadRole::Maker;
    t.counterparty = "alice".to_string();
    t
}

// PARITY-06 + PARITY-12: Guard fires when maker has not identified and config requires it.
#[tokio::test]
async fn test_identity_before_settlement_guard() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_identity_before_settlement(comms.clone());

    let thread_id = "guard-test-01";
    manager.insert_thread(invoiced_maker_thread_unidentified(thread_id)).await;

    // Queue inbound settlement.
    let body = make_settlement_envelope(thread_id);
    let msg = make_peer_message("guard-msg-01", "bob", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Thread must be Terminated — settlement was blocked.
    assert_eq!(
        t.state,
        RemittanceThreadState::Terminated,
        "thread should be Terminated when identity required but not completed; got {:?}",
        t.state
    );

    // A Termination message must have been sent.
    let sent = comms.sent.lock().unwrap();
    let term_sent = sent.iter().any(|(_, _, body)| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            v.get("kind").and_then(|k| k.as_str()) == Some("termination")
        } else {
            false
        }
    });
    assert!(term_sent, "a termination message should have been sent when identity guard fires");
}

// PARITY-06 + PARITY-12: Guard does not fire when has_identified=true.
#[tokio::test]
async fn test_identity_before_settlement_guard_passes_when_identified() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_identity_before_settlement(comms.clone());

    let thread_id = "guard-test-02";
    manager.insert_thread(invoiced_maker_thread_identified(thread_id)).await;

    // Queue inbound settlement.
    let body = make_settlement_envelope(thread_id);
    let msg = make_peer_message("guard-msg-02", "bob", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Settlement was accepted — thread should be Settled (auto_issue_receipt=false).
    assert_eq!(
        t.state,
        RemittanceThreadState::Settled,
        "thread should be Settled when identity is completed; got {:?}",
        t.state
    );
}

// PARITY-12: Guard does not fire when my_role=Taker (only Maker role is guarded).
#[tokio::test]
async fn test_identity_before_settlement_guard_taker_skips() {
    let comms = Arc::new(MockComms::new());
    let manager = make_manager_with_identity_before_settlement(comms.clone());

    let thread_id = "guard-test-03";
    manager.insert_thread(invoiced_taker_thread_unidentified(thread_id)).await;

    // Queue inbound settlement (taker receiving settlement is unusual but allowed by guard logic).
    let body = make_settlement_envelope(thread_id);
    let msg = make_peer_message("guard-msg-03", "alice", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Taker is never blocked by maker identity guard — settlement proceeds.
    assert_ne!(
        t.state,
        RemittanceThreadState::Terminated,
        "taker thread should NOT be terminated by maker identity guard; got {:?}",
        t.state
    );
}

// PARITY-07: Inbound IdentityVerificationRequest on unknown thread with makerRequestIdentity set
// => creates thread with my_role=Taker (I am the responder, maker requested).
#[tokio::test]
async fn test_role_inference_identity_request() {
    let comms = Arc::new(MockComms::new());
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms.clone();
    let manager = RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: Some(RemittanceManagerRuntimeOptions {
                identity_options: Some(IdentityRuntimeOptions {
                    maker_request_identity: Some(IdentityPhase::BeforeSettlement),
                    taker_request_identity: None,
                }),
                ..Default::default()
            }),
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModule)],
    );

    let thread_id = "role-infer-req-01";
    let request = IdentityVerificationRequest {
        kind: RemittanceKind::IdentityVerificationRequest,
        thread_id: thread_id.to_string(),
        request: bsv::remittance::types::IdentityRequest { types: HashMap::new(), certifiers: vec![] },
    };
    let payload = serde_json::to_value(&request).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "role-env-01".to_string(),
        kind: RemittanceKind::IdentityVerificationRequest,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    let body = serde_json::to_string(&env).unwrap();
    let msg = make_peer_message("role-msg-01", "alice", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Maker requested identity, so inbound request means I am the responder/taker.
    assert!(
        matches!(t.my_role, ThreadRole::Taker),
        "my_role should be Taker when makerRequestIdentity is set and inbound is a Request; got {:?}",
        t.my_role
    );
}

// PARITY-07: Inbound IdentityVerificationResponse on unknown thread with makerRequestIdentity set
// => creates thread with my_role=Maker (I requested, they responded).
#[tokio::test]
async fn test_role_inference_identity_response() {
    let comms = Arc::new(MockComms::new());
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms.clone();
    let manager = RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: Some(RemittanceManagerRuntimeOptions {
                identity_options: Some(IdentityRuntimeOptions {
                    maker_request_identity: Some(IdentityPhase::BeforeSettlement),
                    taker_request_identity: None,
                }),
                ..Default::default()
            }),
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModule)],
    );

    let thread_id = "role-infer-resp-01";
    let response = IdentityVerificationResponse {
        kind: RemittanceKind::IdentityVerificationResponse,
        thread_id: thread_id.to_string(),
        certificates: vec![],
    };
    let payload = serde_json::to_value(&response).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "role-env-02".to_string(),
        kind: RemittanceKind::IdentityVerificationResponse,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    let body = serde_json::to_string(&env).unwrap();
    let msg = make_peer_message("role-msg-02", "alice", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Maker requested identity and I am the maker — inbound response means I am Maker.
    assert!(
        matches!(t.my_role, ThreadRole::Maker),
        "my_role should be Maker when makerRequestIdentity is set and inbound is a Response; got {:?}",
        t.my_role
    );
}

// PARITY-07: Inbound Receipt or Termination on unknown thread defaults to my_role=Taker.
#[tokio::test]
async fn test_role_inference_receipt_termination() {
    let comms = Arc::new(MockComms::new());
    let comms_dyn: Arc<dyn bsv::remittance::comms_layer::CommsLayer> = comms.clone();
    let manager = RemittanceManager::new(
        RemittanceManagerConfig {
            message_box: None,
            originator: None,
            logger: None,
            options: None,
            on_event: None,
            state_saver: None,
            state_loader: None,
            now: Some(Box::new(|| 1_000_000u64)),
            thread_id_factory: None,
        },
        Arc::new(MockWallet),
        comms_dyn,
        Some(Arc::new(MockIdentity)),
        vec![Box::new(MockModule)],
    );

    // Test Termination on unknown thread (Receipt is harder to test without a prior settlement).
    let thread_id = "role-infer-term-01";
    use bsv::remittance::types::Termination;
    let termination = Termination {
        code: "test".to_string(),
        message: "test termination".to_string(),
        details: None,
    };
    let payload = serde_json::to_value(&termination).unwrap();
    let env = RemittanceEnvelope {
        v: 1,
        id: "role-env-03".to_string(),
        kind: RemittanceKind::Termination,
        thread_id: thread_id.to_string(),
        created_at: 1_000_000,
        payload,
    };
    let body = serde_json::to_string(&env).unwrap();
    let msg = make_peer_message("role-msg-03", "alice", &body);
    comms.set_queued_messages(vec![msg]);

    manager.sync_threads(None).await.expect("sync should not error");

    let t = manager.get_thread(thread_id).await.unwrap();
    // Inbound Termination on unknown thread defaults to Taker.
    assert!(
        matches!(t.my_role, ThreadRole::Taker),
        "my_role should be Taker for inbound Termination on unknown thread; got {:?}",
        t.my_role
    );
}

// PARITY-10: Default options must match TypeScript SDK defaults.
#[tokio::test]
async fn test_runtime_options_defaults() {
    let opts = RemittanceManagerRuntimeOptions::default();
    assert!(
        opts.receipt_provided,
        "receipt_provided should default to true (TS SDK parity)"
    );
    assert_eq!(
        opts.identity_poll_interval_ms, 500,
        "identity_poll_interval_ms should default to 500ms (TS SDK parity)"
    );
}
