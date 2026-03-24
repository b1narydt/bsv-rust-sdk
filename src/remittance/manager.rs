//! RemittanceManager — core orchestrator for the remittance protocol.
//!
//! This file is gated behind `#[cfg(feature = "network")]` via the module
//! declaration in `mod.rs`. All types, the manager struct, and all methods
//! require the serde + tokio async runtime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::remittance::comms_layer::CommsLayer;
use crate::remittance::error::RemittanceError;
use crate::remittance::identity_layer::IdentityLayer;
use crate::remittance::remittance_module::ErasedRemittanceModule;
use crate::remittance::types::{
    IdentityVerificationAcknowledgment, IdentityVerificationRequest, IdentityVerificationResponse,
    Invoice, LineItem, LoggerLike, Amount, Receipt, RemittanceCertificate, RemittanceEnvelope,
    RemittanceThreadState, Settlement, Termination, ThreadId, UnixMillis,
};
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};

// ---------------------------------------------------------------------------
// Supporting enums
// ---------------------------------------------------------------------------

/// Role of this node in a remittance thread.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ThreadRole {
    Maker,
    Taker,
}

/// Direction of a protocol log entry relative to this node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageDirection {
    #[serde(rename = "in")]
    In,
    #[serde(rename = "out")]
    Out,
}

/// When identity verification should occur within a thread.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityPhase {
    Never,
    BeforeInvoicing,
    BeforeSettlement,
}

// ---------------------------------------------------------------------------
// Supporting structs
// ---------------------------------------------------------------------------

/// Identity-exchange status for one side of a thread.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ThreadIdentity {
    pub certs_sent: Vec<RemittanceCertificate>,
    pub certs_received: Vec<RemittanceCertificate>,
    pub request_sent: bool,
    pub response_sent: bool,
    pub acknowledgment_sent: bool,
    pub acknowledgment_received: bool,
}

/// Boolean flags summarizing the lifecycle progress of a thread.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ThreadFlags {
    pub has_identified: bool,
    pub has_invoiced: bool,
    pub has_paid: bool,
    pub has_receipted: bool,
    pub error: bool,
}

/// One entry in the state transition history of a thread.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateLogEntry {
    pub at: UnixMillis,
    pub from: RemittanceThreadState,
    pub to: RemittanceThreadState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One entry in the protocol message history of a thread.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolLogEntry {
    pub direction: MessageDirection,
    pub envelope: RemittanceEnvelope,
    pub transport_message_id: String,
}

/// An error that occurred on a thread, captured for later inspection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadError {
    pub message: String,
    pub at: UnixMillis,
}

/// Full state of one remittance thread.
///
/// Serializes to camelCase JSON to match the TypeScript wire format.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    pub thread_id: ThreadId,
    pub counterparty: String,
    pub my_role: ThreadRole,
    pub their_role: ThreadRole,
    pub created_at: UnixMillis,
    pub updated_at: UnixMillis,
    pub state: RemittanceThreadState,
    pub state_log: Vec<StateLogEntry>,
    pub processed_message_ids: Vec<String>,
    pub protocol_log: Vec<ProtocolLogEntry>,
    pub identity: ThreadIdentity,
    pub flags: ThreadFlags,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice: Option<Invoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement: Option<Settlement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub termination: Option<Termination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<ThreadError>,
}

/// Per-counterparty identity-phase configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRuntimeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maker_request_identity: Option<IdentityPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taker_request_identity: Option<IdentityPhase>,
}

/// Runtime tuning options for the manager.
///
/// All fields have sensible defaults matching the TypeScript SDK.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemittanceManagerRuntimeOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_options: Option<IdentityRuntimeOptions>,
    /// Whether the peer has indicated it will provide a receipt.
    pub receipt_provided: bool,
    /// Automatically issue a receipt after accepting settlement.
    pub auto_issue_receipt: bool,
    /// Seconds until a sent invoice expires.
    pub invoice_expiry_seconds: u64,
    /// Milliseconds to wait for an identity response before timing out.
    pub identity_timeout_ms: u64,
    /// Milliseconds between identity-polling attempts (TS compat; Rust uses Notify).
    pub identity_poll_interval_ms: u64,
}

impl Default for RemittanceManagerRuntimeOptions {
    fn default() -> Self {
        Self {
            identity_options: None,
            receipt_provided: false,
            auto_issue_receipt: true,
            invoice_expiry_seconds: 3600,
            identity_timeout_ms: 30_000,
            identity_poll_interval_ms: 1_000,
        }
    }
}

/// Input for composing an invoice message.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComposeInvoiceInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub line_items: Vec<LineItem>,
    pub total: Amount,
    pub invoice_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arbitrary: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Serializable state snapshot for persistence.
///
/// The `v` field (always 1) is the schema version sentinel for future migrations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemittanceManagerState {
    pub v: u8,
    pub threads: Vec<Thread>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_payment_option_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Event enum
// ---------------------------------------------------------------------------

/// All events emitted by the RemittanceManager.
///
/// Derived `Clone` + `Debug` only — not serialized. Deliver to all registered
/// `on_event` listeners.
#[derive(Clone, Debug)]
pub enum RemittanceEvent {
    ThreadCreated {
        thread_id: ThreadId,
        thread: Thread,
    },
    StateChanged {
        thread_id: ThreadId,
        previous: RemittanceThreadState,
        next: RemittanceThreadState,
        reason: Option<String>,
    },
    EnvelopeSent {
        thread_id: ThreadId,
        envelope: RemittanceEnvelope,
        transport_message_id: String,
    },
    EnvelopeReceived {
        thread_id: ThreadId,
        envelope: RemittanceEnvelope,
        transport_message_id: String,
    },
    IdentityRequested {
        thread_id: ThreadId,
        direction: MessageDirection,
        request: IdentityVerificationRequest,
    },
    IdentityResponded {
        thread_id: ThreadId,
        direction: MessageDirection,
        response: IdentityVerificationResponse,
    },
    IdentityAcknowledged {
        thread_id: ThreadId,
        direction: MessageDirection,
        acknowledgment: IdentityVerificationAcknowledgment,
    },
    InvoiceSent {
        thread_id: ThreadId,
        invoice: Invoice,
    },
    InvoiceReceived {
        thread_id: ThreadId,
        invoice: Invoice,
    },
    SettlementSent {
        thread_id: ThreadId,
        settlement: Settlement,
    },
    SettlementReceived {
        thread_id: ThreadId,
        settlement: Settlement,
    },
    ReceiptSent {
        thread_id: ThreadId,
        receipt: Receipt,
    },
    ReceiptReceived {
        thread_id: ThreadId,
        receipt: Receipt,
    },
    TerminationSent {
        thread_id: ThreadId,
        termination: Termination,
    },
    TerminationReceived {
        thread_id: ThreadId,
        termination: Termination,
    },
    Error {
        thread_id: ThreadId,
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Config (not Serialize/Deserialize — contains closures)
// ---------------------------------------------------------------------------

/// Construction-time configuration for RemittanceManager.
///
/// Closures must be `Send + Sync` because the manager is used across async tasks.
/// This struct intentionally does not derive Serialize/Deserialize.
pub struct RemittanceManagerConfig {
    /// Message box name for inbound messages.
    pub message_box: Option<String>,
    /// Originator string passed through to wallet calls.
    pub originator: Option<String>,
    /// Pluggable logger.
    pub logger: Option<Arc<dyn LoggerLike>>,
    /// Runtime tuning options (defaults apply when None).
    pub options: Option<RemittanceManagerRuntimeOptions>,
    /// Called for every event emitted by the manager.
    pub on_event: Option<Box<dyn Fn(RemittanceEvent) + Send + Sync>>,
    /// Called after every state change to persist the serialized state.
    pub state_saver: Option<Box<dyn Fn(RemittanceManagerState) + Send + Sync>>,
    /// Called during `init()` to restore previously persisted state.
    pub state_loader: Option<Box<dyn Fn() -> Option<RemittanceManagerState> + Send + Sync>>,
    /// Override for the current-time provider (useful in tests).
    pub now: Option<Box<dyn Fn() -> UnixMillis + Send + Sync>>,
    /// Override for thread-ID generation (useful in tests).
    pub thread_id_factory: Option<Box<dyn Fn() -> ThreadId + Send + Sync>>,
}

// ---------------------------------------------------------------------------
// Inner state
// ---------------------------------------------------------------------------

/// Mutable state owned by the manager.
///
/// Lives behind `Arc<Mutex<ManagerInner>>` so multiple clones of `RemittanceManager`
/// (e.g. passed into async tasks) share the same state safely.
struct ManagerInner {
    threads: HashMap<ThreadId, Thread>,
    default_payment_option_id: Option<String>,
    my_identity_key: Option<String>,
    event_listeners: Vec<Arc<dyn Fn(RemittanceEvent) + Send + Sync>>,
}

// ---------------------------------------------------------------------------
// RemittanceManager
// ---------------------------------------------------------------------------

/// Core orchestrator for peer-to-peer remittance protocol exchanges.
///
/// Cheaply cloneable — all mutable state is behind `Arc<Mutex<ManagerInner>>`.
/// All async methods require the tokio runtime (gated via `network` feature).
#[derive(Clone)]
pub struct RemittanceManager {
    inner: Arc<Mutex<ManagerInner>>,
    pub(crate) config: Arc<RemittanceManagerConfig>,
    wallet: Arc<dyn WalletInterface>,
    pub(crate) comms: Arc<dyn CommsLayer>,
    pub(crate) identity: Option<Arc<dyn IdentityLayer>>,
    /// Module registry keyed by module ID. Arc (not Mutex) — modules are immutable after construction.
    pub(crate) modules: Arc<HashMap<String, Box<dyn ErasedRemittanceModule>>>,
    /// Per-thread notify handles for `waitFor*` callers.
    pub(crate) notifiers: Arc<Mutex<HashMap<ThreadId, Arc<Notify>>>>,
    pub(crate) options: RemittanceManagerRuntimeOptions,
}

impl RemittanceManager {
    /// Construct a new manager with the given config and service dependencies.
    ///
    /// Modules are registered at construction time and never mutated afterwards,
    /// so they live behind `Arc<HashMap>` (no lock required on every pay/accept call).
    pub fn new(
        config: RemittanceManagerConfig,
        wallet: Arc<dyn WalletInterface>,
        comms: Arc<dyn CommsLayer>,
        identity: Option<Arc<dyn IdentityLayer>>,
        modules: Vec<Box<dyn ErasedRemittanceModule>>,
    ) -> Self {
        let options = config
            .options
            .clone()
            .unwrap_or_default();

        let module_map: HashMap<String, Box<dyn ErasedRemittanceModule>> =
            modules.into_iter().map(|m| (m.id().to_string(), m)).collect();

        let inner = ManagerInner {
            threads: HashMap::new(),
            default_payment_option_id: None,
            my_identity_key: None,
            event_listeners: Vec::new(),
        };

        let config_arc = Arc::new(config);

        let manager = Self {
            inner: Arc::new(Mutex::new(inner)),
            config: config_arc,
            wallet,
            comms,
            identity,
            modules: Arc::new(module_map),
            notifiers: Arc::new(Mutex::new(HashMap::new())),
            options,
        };

        // Register the on_event closure from config as a listener, via a forwarding Arc.
        // We do this synchronously since new() is not async.
        if manager.config.on_event.is_some() {
            let cfg = Arc::clone(&manager.config);
            let listener: Arc<dyn Fn(RemittanceEvent) + Send + Sync> =
                Arc::new(move |event: RemittanceEvent| {
                    if let Some(ref handler) = cfg.on_event {
                        handler(event);
                    }
                });
            // SAFETY: new() is called before any other async access; we can block_on or use
            // try_lock here. Since no tasks are running yet, try_lock always succeeds.
            if let Ok(mut guard) = manager.inner.try_lock() {
                guard.event_listeners.push(listener);
            }
        }

        manager
    }

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Load persisted state and refresh the identity key from the wallet.
    ///
    /// Must be called after construction and before any protocol operations.
    pub async fn init(&self) -> Result<(), RemittanceError> {
        // Restore state from persistence, if a loader was provided.
        if let Some(ref loader) = self.config.state_loader {
            if let Some(state) = loader() {
                self.load_state(state).await;
            }
        }

        // Refresh the node's own identity public key from the wallet.
        self.refresh_my_identity_key().await?;

        Ok(())
    }

    /// Fetch this node's identity public key from the wallet and cache it.
    pub(crate) async fn refresh_my_identity_key(&self) -> Result<(), RemittanceError> {
        let args = GetPublicKeyArgs {
            identity_key: true,
            protocol_id: None,
            key_id: None,
            counterparty: None,
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };
        let originator = self.config.originator.as_deref();
        let result = self.wallet.get_public_key(args, originator).await?;
        let key_hex = result.public_key.to_der_hex();

        let mut guard = self.inner.lock().await;
        guard.my_identity_key = Some(key_hex);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // State persistence
    // -----------------------------------------------------------------------

    /// Snapshot the current state as a serializable envelope.
    pub async fn save_state(&self) -> RemittanceManagerState {
        let guard = self.inner.lock().await;
        RemittanceManagerState {
            v: 1,
            threads: guard.threads.values().cloned().collect(),
            default_payment_option_id: guard.default_payment_option_id.clone(),
        }
    }

    /// Snapshot and call `state_saver` if one was configured.
    pub async fn persist_state(&self) {
        let state = self.save_state().await;
        if let Some(ref saver) = self.config.state_saver {
            saver(state);
        }
    }

    /// Replace inner thread map and options from a serialized state envelope.
    pub async fn load_state(&self, state: RemittanceManagerState) {
        let mut guard = self.inner.lock().await;
        guard.threads = state
            .threads
            .into_iter()
            .map(|t| (t.thread_id.clone(), t))
            .collect();
        guard.default_payment_option_id = state.default_payment_option_id;
    }

    // -----------------------------------------------------------------------
    // State machine
    // -----------------------------------------------------------------------

    /// Attempt to transition `thread_id` from its current state to `to`.
    ///
    /// Validates the transition, appends a `StateLogEntry`, emits `StateChanged`,
    /// notifies any `waitForState` callers, and persists the new state.
    /// Returns `RemittanceError::InvalidStateTransition` on invalid transitions.
    pub async fn transition_thread_state(
        &self,
        thread_id: &str,
        to: RemittanceThreadState,
        reason: Option<String>,
    ) -> Result<(), RemittanceError> {
        // Collect data under lock, then drop guard before calling async methods.
        let (previous, notify) = {
            let mut guard = self.inner.lock().await;
            let thread = guard
                .threads
                .get_mut(thread_id)
                .ok_or_else(|| RemittanceError::Protocol(format!("thread not found: {}", thread_id)))?;

            let current = thread.state.clone();

            if !crate::remittance::types::is_valid_transition(&current, &to) {
                return Err(RemittanceError::InvalidStateTransition {
                    from: current.to_string(),
                    to: to.to_string(),
                });
            }

            let now = self.now_internal();
            thread.state_log.push(StateLogEntry {
                at: now,
                from: current.clone(),
                to: to.clone(),
                reason: reason.clone(),
            });
            thread.state = to.clone();
            thread.updated_at = now;

            // Grab or create the Notify for this thread (outside the inner lock to avoid nesting).
            // We'll look it up from notifiers after releasing inner.
            (current, thread_id.to_string())
        };

        // Emit event (does not hold inner guard).
        let event = RemittanceEvent::StateChanged {
            thread_id: notify.clone(),
            previous,
            next: to,
            reason,
        };
        self.emit_event(event).await;

        // Wake any tokio::sync::Notify waiters for this thread.
        let notifier = {
            let mut nmap = self.notifiers.lock().await;
            nmap.entry(notify.clone())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };
        notifier.notify_waiters();

        // Persist after notifying waiters so callers see the new state.
        self.persist_state().await;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Event system
    // -----------------------------------------------------------------------

    /// Register a listener that receives every future event.
    pub async fn on_event(&self, listener: Arc<dyn Fn(RemittanceEvent) + Send + Sync>) {
        let mut guard = self.inner.lock().await;
        guard.event_listeners.push(listener);
    }

    /// Deliver `event` to all registered listeners.
    pub(crate) async fn emit_event(&self, event: RemittanceEvent) {
        // Clone the listener list so we can call outside the lock.
        let listeners: Vec<Arc<dyn Fn(RemittanceEvent) + Send + Sync>> = {
            let guard = self.inner.lock().await;
            guard.event_listeners.clone()
        };
        for listener in listeners {
            listener(event.clone());
        }
    }

    // -----------------------------------------------------------------------
    // Thread accessors
    // -----------------------------------------------------------------------

    /// Returns a clone of the thread if it exists, or `None`.
    pub async fn get_thread(&self, thread_id: &str) -> Option<Thread> {
        let guard = self.inner.lock().await;
        guard.threads.get(thread_id).cloned()
    }

    /// Returns a clone of the thread, or `RemittanceError::Protocol` if not found.
    pub async fn get_thread_or_throw(&self, thread_id: &str) -> Result<Thread, RemittanceError> {
        self.get_thread(thread_id).await.ok_or_else(|| {
            RemittanceError::Protocol(format!("thread not found: {}", thread_id))
        })
    }

    /// Returns a `ThreadHandle` for ergonomic chained access.
    pub async fn get_thread_handle(&self, thread_id: &str) -> Result<ThreadHandle, RemittanceError> {
        // Verify the thread exists before issuing a handle.
        let _ = self.get_thread_or_throw(thread_id).await?;
        Ok(ThreadHandle {
            manager: self.clone(),
            thread_id: thread_id.to_string(),
        })
    }

    /// Insert a thread into the inner map directly (used by invoice/create flows).
    pub(crate) async fn insert_thread(&self, thread: Thread) {
        let mut guard = self.inner.lock().await;
        guard.threads.insert(thread.thread_id.clone(), thread);
    }

    /// Update a thread in place using a mutable closure.
    pub(crate) async fn update_thread<F>(&self, thread_id: &str, f: F) -> Result<(), RemittanceError>
    where
        F: FnOnce(&mut Thread),
    {
        let mut guard = self.inner.lock().await;
        let thread = guard
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| RemittanceError::Protocol(format!("thread not found: {}", thread_id)))?;
        f(thread);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Payment option helpers
    // -----------------------------------------------------------------------

    /// Set the default payment option ID used when none is specified.
    pub async fn preselect_payment_option(&self, option_id: Option<String>) {
        let mut guard = self.inner.lock().await;
        guard.default_payment_option_id = option_id;
    }

    /// Get the current default payment option ID.
    pub async fn get_default_payment_option_id(&self) -> Option<String> {
        let guard = self.inner.lock().await;
        guard.default_payment_option_id.clone()
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Returns current Unix time in milliseconds, using override if configured.
    pub(crate) fn now_internal(&self) -> UnixMillis {
        if let Some(ref f) = self.config.now {
            return f();
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Returns the current time (public alias for external callers).
    pub fn now(&self) -> UnixMillis {
        self.now_internal()
    }

    /// Generates a fresh thread ID using the configured factory or getrandom.
    pub fn generate_thread_id(&self) -> ThreadId {
        if let Some(ref f) = self.config.thread_id_factory {
            return f();
        }
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{:02x}", b);
            acc
        })
    }

    /// Expose the wallet reference for use by sub-flows.
    pub(crate) fn wallet(&self) -> &Arc<dyn WalletInterface> {
        &self.wallet
    }

    /// Expose inner my_identity_key.
    pub(crate) async fn my_identity_key(&self) -> Option<String> {
        let guard = self.inner.lock().await;
        guard.my_identity_key.clone()
    }
}

// ---------------------------------------------------------------------------
// ThreadHandle / InvoiceHandle
// ---------------------------------------------------------------------------

/// Ergonomic handle to a thread with shorthand accessor methods.
pub struct ThreadHandle {
    pub manager: RemittanceManager,
    pub thread_id: ThreadId,
}

impl ThreadHandle {
    /// Returns the thread ID string.
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// Returns the current thread state, or an error if the thread has been removed.
    pub async fn get_thread(&self) -> Result<Thread, RemittanceError> {
        self.manager.get_thread_or_throw(&self.thread_id).await
    }
}

/// Handle wrapping a `ThreadHandle` for invoice-specific operations.
pub struct InvoiceHandle {
    pub handle: ThreadHandle,
}
