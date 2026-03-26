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
    Amount, IdentityVerificationAcknowledgment, IdentityVerificationRequest,
    IdentityVerificationResponse, InstrumentBase, Invoice, LineItem, LoggerLike, ModuleContext,
    PeerMessage, Receipt, RemittanceCertificate, RemittanceEnvelope, RemittanceKind,
    RemittanceThreadState, Settlement, Termination, ThreadId, UnixMillis,
};
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns true if `state` is a terminal state (no further transitions expected).
fn is_terminal_state(state: &RemittanceThreadState) -> bool {
    matches!(
        state,
        RemittanceThreadState::Receipted
            | RemittanceThreadState::Terminated
            | RemittanceThreadState::Errored
    )
}

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

/// Result of waiting for a receipt, allowing for graceful termination handling.
pub enum WaitReceiptResult {
    /// The thread reached Receipted state and a receipt was available.
    Receipt(Receipt),
    /// The counterparty terminated the thread before a receipt was issued.
    Terminated(Termination),
}

/// Result of waiting for a settlement, allowing for graceful termination handling.
pub enum WaitSettlementResult {
    /// The thread reached Settled state and a settlement was available.
    Settlement(Settlement),
    /// The counterparty terminated the thread before settlement occurred.
    Terminated(Termination),
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
            // TS SDK defaults receipt_provided=true — peer is expected to send one.
            receipt_provided: true,
            auto_issue_receipt: true,
            invoice_expiry_seconds: 3600,
            identity_timeout_ms: 30_000,
            // TS SDK uses 500ms poll interval.
            identity_poll_interval_ms: 500,
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
    event_listeners: Vec<(usize, Arc<dyn Fn(RemittanceEvent) + Send + Sync>)>,
    next_listener_id: usize,
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
        let options = config.options.clone().unwrap_or_default();

        let module_map: HashMap<String, Box<dyn ErasedRemittanceModule>> = modules
            .into_iter()
            .map(|m| (m.id().to_string(), m))
            .collect();

        let inner = ManagerInner {
            threads: HashMap::new(),
            default_payment_option_id: None,
            my_identity_key: None,
            event_listeners: Vec::new(),
            next_listener_id: 0,
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
                let id = guard.next_listener_id;
                guard.next_listener_id += 1;
                guard.event_listeners.push((id, listener));
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
            let thread = guard.threads.get_mut(thread_id).ok_or_else(|| {
                RemittanceError::Protocol(format!("thread not found: {}", thread_id))
            })?;

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
    ///
    /// Returns a listener ID that can be passed to [`remove_event_listener`] to
    /// unsubscribe — mirroring the TS SDK's `onEvent` which returns an
    /// unsubscribe function.
    pub async fn on_event(&self, listener: Arc<dyn Fn(RemittanceEvent) + Send + Sync>) -> usize {
        let mut guard = self.inner.lock().await;
        let id = guard.next_listener_id;
        guard.next_listener_id += 1;
        guard.event_listeners.push((id, listener));
        id
    }

    /// Remove a previously registered event listener by its ID.
    ///
    /// Returns `true` if a listener with the given ID was found and removed.
    pub async fn remove_event_listener(&self, listener_id: usize) -> bool {
        let mut guard = self.inner.lock().await;
        let len_before = guard.event_listeners.len();
        guard.event_listeners.retain(|(id, _)| *id != listener_id);
        guard.event_listeners.len() < len_before
    }

    /// Deliver `event` to all registered listeners.
    ///
    /// Public so that downstream code and integration tests can synthesise events.
    pub async fn emit_event(&self, event: RemittanceEvent) {
        // Clone the listener list so we can call outside the lock.
        let listeners: Vec<(usize, Arc<dyn Fn(RemittanceEvent) + Send + Sync>)> = {
            let guard = self.inner.lock().await;
            guard.event_listeners.clone()
        };
        for (_id, listener) in listeners {
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
        self.get_thread(thread_id)
            .await
            .ok_or_else(|| RemittanceError::Protocol(format!("thread not found: {}", thread_id)))
    }

    /// Returns a `ThreadHandle` for ergonomic chained access.
    pub async fn get_thread_handle(
        &self,
        thread_id: &str,
    ) -> Result<ThreadHandle, RemittanceError> {
        // Verify the thread exists before issuing a handle.
        let _ = self.get_thread_or_throw(thread_id).await?;
        Ok(ThreadHandle {
            manager: self.clone(),
            thread_id: thread_id.to_string(),
        })
    }

    /// Insert a thread into the inner map directly (used by invoice/create flows and tests).
    pub async fn insert_thread(&self, thread: Thread) {
        let mut guard = self.inner.lock().await;
        guard.threads.insert(thread.thread_id.clone(), thread);
    }

    /// Update a thread in place using a mutable closure.
    pub(crate) async fn update_thread<F>(
        &self,
        thread_id: &str,
        f: F,
    ) -> Result<(), RemittanceError>
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

    /// Set the default payment option ID used when none is specified (takes Option<String>).
    ///
    /// Use `preselect_payment_option_id` for the `&str` public API variant.
    pub async fn preselect_payment_option(&self, option_id: Option<String>) {
        let mut guard = self.inner.lock().await;
        guard.default_payment_option_id = option_id;
        drop(guard);
        self.persist_state().await;
    }

    /// Set the default payment option ID from a string slice and persist state.
    ///
    /// This is the primary public API — corresponds to the TypeScript
    /// `preselectPaymentOption(optionId: string)` method.
    pub async fn preselect_payment_option_id(&self, option_id: &str) {
        {
            let mut guard = self.inner.lock().await;
            guard.default_payment_option_id = Some(option_id.to_string());
        }
        self.persist_state().await;
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

    // -----------------------------------------------------------------------
    // ModuleContext factory
    // -----------------------------------------------------------------------

    /// Build a ModuleContext that shares the manager's clock and wallet.
    ///
    /// If `config.now` is set (e.g. for tests), modules see the same overridden
    /// clock as the manager itself.
    fn make_module_context(&self) -> ModuleContext {
        let now_fn: Arc<dyn Fn() -> u64 + Send + Sync> = match &self.config.now {
            Some(f) => {
                // Wrap the config closure in an Arc so ModuleContext can clone it.
                let cfg = Arc::clone(&self.config);
                Arc::new(move || (cfg.now.as_ref().unwrap())())
            }
            None => Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            }),
        };
        ModuleContext {
            wallet: Arc::clone(&self.wallet),
            originator: self.config.originator.clone(),
            now: now_fn,
            logger: self.config.logger.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Create a RemittanceEnvelope from its parts.
    fn make_envelope(
        kind: RemittanceKind,
        thread_id: &str,
        payload: serde_json::Value,
        now: UnixMillis,
    ) -> RemittanceEnvelope {
        // Generate a random ID for the envelope using getrandom.
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        let id = bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{:02x}", b);
            acc
        });
        RemittanceEnvelope {
            v: 1,
            id,
            kind,
            thread_id: thread_id.to_string(),
            created_at: now,
            payload,
        }
    }

    /// Serialize and send an envelope to a recipient.
    ///
    /// Tries `send_live_message` first; falls back to `send_message` on error.
    /// After sending, appends to the thread's protocol log and emits `EnvelopeSent`.
    async fn send_envelope(
        &self,
        recipient: &str,
        env: &RemittanceEnvelope,
        host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        let body = serde_json::to_string(env)?;
        let message_box = self.config.message_box.as_deref().unwrap_or("remittance");

        // Try live first; fall back to queued.
        let transport_message_id = match self
            .comms
            .send_live_message(recipient, message_box, &body, host_override)
            .await
        {
            Ok(id) => id,
            Err(_) => {
                self.comms
                    .send_message(recipient, message_box, &body, host_override)
                    .await?
            }
        };

        // Append to protocol log (under lock) without holding lock across await.
        let log_entry = ProtocolLogEntry {
            direction: MessageDirection::Out,
            envelope: env.clone(),
            transport_message_id: transport_message_id.clone(),
        };
        {
            let mut guard = self.inner.lock().await;
            if let Some(thread) = guard.threads.get_mut(&env.thread_id) {
                thread.protocol_log.push(log_entry);
            }
        }

        // Emit event (no lock held).
        self.emit_event(RemittanceEvent::EnvelopeSent {
            thread_id: env.thread_id.clone(),
            envelope: env.clone(),
            transport_message_id: transport_message_id.clone(),
        })
        .await;

        Ok(transport_message_id)
    }

    /// Compose an Invoice from ComposeInvoiceInput and module-generated options.
    ///
    /// Calls `create_option_erased` on each registered module that supports it,
    /// collecting option terms keyed by module ID.
    async fn compose_invoice(
        &self,
        thread: &Thread,
        input: &ComposeInvoiceInput,
    ) -> Result<Invoice, RemittanceError> {
        let now = self.now_internal();
        let my_key = {
            let guard = self.inner.lock().await;
            guard.my_identity_key.clone().unwrap_or_default()
        };

        let base = InstrumentBase {
            thread_id: thread.thread_id.clone(),
            payee: my_key,
            payer: thread.counterparty.clone(),
            note: input.note.clone(),
            line_items: input.line_items.clone(),
            total: input.total.clone(),
            invoice_number: input.invoice_number.clone(),
            created_at: now,
            arbitrary: input.arbitrary.clone(),
        };

        let expires_at = input
            .expires_at
            .or_else(|| Some(now + self.options.invoice_expiry_seconds * 1_000));

        // Draft invoice (without options yet) for passing to create_option_erased.
        let draft = Invoice {
            kind: RemittanceKind::Invoice,
            expires_at,
            options: HashMap::new(),
            base: base.clone(),
        };

        let ctx = self.make_module_context();
        let mut options: HashMap<String, serde_json::Value> = HashMap::new();

        // Collect options from all modules that support create_option.
        // modules is Arc<HashMap> — no lock needed.
        for (module_id, module) in self.modules.as_ref() {
            if module.supports_create_option() {
                let option_value = module
                    .create_option_erased(&thread.thread_id, &draft, &ctx)
                    .await?;
                options.insert(module_id.clone(), option_value);
            }
        }

        Ok(Invoice {
            kind: RemittanceKind::Invoice,
            expires_at,
            options,
            base,
        })
    }

    /// Perform identity exchange with the counterparty if required.
    ///
    /// Checks runtime options to decide whether identity is needed.
    /// If an identity layer is configured and the phase is not Never,
    /// sends an IdentityVerificationRequest envelope.
    async fn ensure_identity_exchange(
        &self,
        thread_id: &str,
        counterparty: &str,
    ) -> Result<(), RemittanceError> {
        let identity_layer = match &self.identity {
            Some(il) => il.clone(),
            None => return Ok(()),
        };

        // Determine whether identity is needed based on role and options.
        let should_request = match &self.options.identity_options {
            None => false,
            Some(id_opts) => {
                // Maker initiates — check maker_request_identity phase.
                let phase = id_opts.maker_request_identity.as_ref();
                matches!(
                    phase,
                    Some(IdentityPhase::BeforeInvoicing) | Some(IdentityPhase::BeforeSettlement)
                )
            }
        };

        if !should_request {
            return Ok(());
        }

        let ctx = self.make_module_context();
        let request = identity_layer
            .determine_certificates_to_request(counterparty, thread_id, &ctx)
            .await?;

        let payload = serde_json::to_value(&request)?;
        let env = Self::make_envelope(
            RemittanceKind::IdentityVerificationRequest,
            thread_id,
            payload,
            self.now_internal(),
        );

        self.send_envelope(counterparty, &env, None).await?;

        // Transition to IdentityRequested.
        self.transition_thread_state(
            thread_id,
            RemittanceThreadState::IdentityRequested,
            Some("identity exchange initiated".to_string()),
        )
        .await?;

        self.emit_event(RemittanceEvent::IdentityRequested {
            thread_id: thread_id.to_string(),
            direction: MessageDirection::Out,
            request,
        })
        .await;

        Ok(())
    }

    /// Create a new thread with the given counterparty and role.
    async fn create_thread(
        &self,
        counterparty: &str,
        my_role: ThreadRole,
    ) -> Result<Thread, RemittanceError> {
        let thread_id = self.generate_thread_id();
        let now = self.now_internal();
        let their_role = match my_role {
            ThreadRole::Maker => ThreadRole::Taker,
            ThreadRole::Taker => ThreadRole::Maker,
        };

        let thread = Thread {
            thread_id: thread_id.clone(),
            counterparty: counterparty.to_string(),
            my_role,
            their_role,
            created_at: now,
            updated_at: now,
            state: RemittanceThreadState::New,
            state_log: Vec::new(),
            processed_message_ids: Vec::new(),
            protocol_log: Vec::new(),
            identity: ThreadIdentity::default(),
            flags: ThreadFlags::default(),
            invoice: None,
            settlement: None,
            receipt: None,
            termination: None,
            last_error: None,
        };

        {
            let mut guard = self.inner.lock().await;
            guard.threads.insert(thread_id.clone(), thread.clone());
        }

        self.emit_event(RemittanceEvent::ThreadCreated {
            thread_id: thread_id.clone(),
            thread: thread.clone(),
        })
        .await;

        Ok(thread)
    }

    // -----------------------------------------------------------------------
    // Public payment flow API
    // -----------------------------------------------------------------------

    /// Create a new thread (maker), optionally run identity exchange, compose
    /// an invoice with module options, send it, and transition to Invoiced.
    pub async fn send_invoice(
        &self,
        counterparty: &str,
        input: ComposeInvoiceInput,
        host_override: Option<&str>,
    ) -> Result<InvoiceHandle, RemittanceError> {
        let thread = self.create_thread(counterparty, ThreadRole::Maker).await?;
        let thread_id = thread.thread_id.clone();

        // Identity exchange (if configured).
        self.ensure_identity_exchange(&thread_id, counterparty)
            .await?;

        // Re-fetch thread after possible identity transition.
        let thread = self.get_thread_or_throw(&thread_id).await?;
        let invoice = self.compose_invoice(&thread, &input).await?;

        let payload = serde_json::to_value(&invoice)?;
        let env = Self::make_envelope(
            RemittanceKind::Invoice,
            &thread_id,
            payload,
            self.now_internal(),
        );

        self.send_envelope(counterparty, &env, host_override)
            .await?;

        // Store invoice on thread and transition to Invoiced (lock-free across await).
        {
            let mut guard = self.inner.lock().await;
            if let Some(t) = guard.threads.get_mut(&thread_id) {
                t.invoice = Some(invoice.clone());
                t.flags.has_invoiced = true;
            }
        }

        self.transition_thread_state(
            &thread_id,
            RemittanceThreadState::Invoiced,
            Some("invoice sent".to_string()),
        )
        .await?;

        self.emit_event(RemittanceEvent::InvoiceSent {
            thread_id: thread_id.clone(),
            invoice,
        })
        .await;

        Ok(InvoiceHandle {
            handle: ThreadHandle {
                manager: self.clone(),
                thread_id,
            },
        })
    }

    /// Send an invoice on an existing thread.
    pub async fn send_invoice_for_thread(
        &self,
        thread_id: &str,
        input: ComposeInvoiceInput,
        host_override: Option<&str>,
    ) -> Result<InvoiceHandle, RemittanceError> {
        let thread = self.get_thread_or_throw(thread_id).await?;
        let counterparty = thread.counterparty.clone();

        let invoice = self.compose_invoice(&thread, &input).await?;

        let payload = serde_json::to_value(&invoice)?;
        let env = Self::make_envelope(
            RemittanceKind::Invoice,
            thread_id,
            payload,
            self.now_internal(),
        );

        self.send_envelope(&counterparty, &env, host_override)
            .await?;

        {
            let mut guard = self.inner.lock().await;
            if let Some(t) = guard.threads.get_mut(thread_id) {
                t.invoice = Some(invoice.clone());
                t.flags.has_invoiced = true;
            }
        }

        self.transition_thread_state(
            thread_id,
            RemittanceThreadState::Invoiced,
            Some("invoice sent on existing thread".to_string()),
        )
        .await?;

        self.emit_event(RemittanceEvent::InvoiceSent {
            thread_id: thread_id.to_string(),
            invoice,
        })
        .await;

        Ok(InvoiceHandle {
            handle: ThreadHandle {
                manager: self.clone(),
                thread_id: thread_id.to_string(),
            },
        })
    }

    /// Return all threads where this node is the taker and the state is Invoiced.
    ///
    /// If `counterparty` is Some, only threads with that counterparty are returned.
    pub async fn find_invoices_payable(&self, counterparty: Option<&str>) -> Vec<InvoiceHandle> {
        let guard = self.inner.lock().await;
        guard
            .threads
            .values()
            .filter(|t| {
                matches!(t.my_role, ThreadRole::Taker)
                    && t.state == RemittanceThreadState::Invoiced
                    && counterparty.map_or(true, |c| t.counterparty == c)
            })
            .map(|t| InvoiceHandle {
                handle: ThreadHandle {
                    manager: self.clone(),
                    thread_id: t.thread_id.clone(),
                },
            })
            .collect()
    }

    /// Return all threads where this node is the maker and the state is Invoiced.
    ///
    /// If `counterparty` is Some, only threads with that counterparty are returned.
    pub async fn find_receivable_invoices(&self, counterparty: Option<&str>) -> Vec<InvoiceHandle> {
        let guard = self.inner.lock().await;
        guard
            .threads
            .values()
            .filter(|t| {
                matches!(t.my_role, ThreadRole::Maker)
                    && t.state == RemittanceThreadState::Invoiced
                    && counterparty.map_or(true, |c| t.counterparty == c)
            })
            .map(|t| InvoiceHandle {
                handle: ThreadHandle {
                    manager: self.clone(),
                    thread_id: t.thread_id.clone(),
                },
            })
            .collect()
    }

    /// Pay an invoice on a thread.
    ///
    /// Selects the payment module by `option_id`, the default option ID, or the
    /// first available option in the invoice. Calls `build_settlement_erased`,
    /// sends a Settlement envelope, transitions to Settled.
    pub async fn pay(
        &self,
        thread_id: &str,
        option_id: Option<&str>,
        host_override: Option<&str>,
    ) -> Result<ThreadHandle, RemittanceError> {
        let thread = self.get_thread_or_throw(thread_id).await?;

        if thread.state != RemittanceThreadState::Invoiced {
            return Err(RemittanceError::Protocol(format!(
                "thread {} is not in Invoiced state (current: {})",
                thread_id, thread.state
            )));
        }

        let invoice = thread.invoice.as_ref().ok_or_else(|| {
            RemittanceError::Protocol(format!("thread {} has no invoice", thread_id))
        })?;

        // Reject expired invoices.
        if let Some(expires_at) = invoice.expires_at {
            if self.now_internal() > expires_at {
                return Err(RemittanceError::Protocol(format!(
                    "invoice on thread {} has expired",
                    thread_id
                )));
            }
        }

        // Determine option_id to use.
        let default_option_id = {
            let guard = self.inner.lock().await;
            guard.default_payment_option_id.clone()
        };

        let selected_option_id = option_id
            .map(|s| s.to_string())
            .or(default_option_id)
            .or_else(|| invoice.options.keys().next().cloned())
            .ok_or_else(|| {
                RemittanceError::Protocol(format!(
                    "no payment option available for thread {}",
                    thread_id
                ))
            })?;

        let option_value = invoice
            .options
            .get(&selected_option_id)
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let module = self.modules.get(&selected_option_id).ok_or_else(|| {
            RemittanceError::Protocol(format!("module not found: {}", selected_option_id))
        })?;

        let note = invoice.base.note.as_deref();
        let ctx = self.make_module_context();

        let result = module
            .build_settlement_erased(thread_id, Some(invoice), &option_value, note, &ctx)
            .await?;

        let counterparty = thread.counterparty.clone();
        let my_key = {
            let guard = self.inner.lock().await;
            guard.my_identity_key.clone().unwrap_or_default()
        };
        let now = self.now_internal();

        match result.action {
            "settle" => {
                let artifact = result.artifact.unwrap_or(serde_json::Value::Null);
                let settlement = Settlement {
                    kind: RemittanceKind::Settlement,
                    thread_id: thread_id.to_string(),
                    module_id: selected_option_id.clone(),
                    option_id: selected_option_id.clone(),
                    sender: my_key,
                    created_at: now,
                    artifact,
                    note: None,
                };

                let payload = serde_json::to_value(&settlement)?;
                let env = Self::make_envelope(RemittanceKind::Settlement, thread_id, payload, now);

                self.send_envelope(&counterparty, &env, host_override)
                    .await?;

                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.settlement = Some(settlement.clone());
                        t.flags.has_paid = true;
                    }
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::Settled,
                    Some("settlement sent".to_string()),
                )
                .await?;

                self.emit_event(RemittanceEvent::SettlementSent {
                    thread_id: thread_id.to_string(),
                    settlement,
                })
                .await;
            }
            "terminate" => {
                let termination = result.termination.unwrap_or_else(|| Termination {
                    code: "module_terminated".to_string(),
                    message: "module requested termination".to_string(),
                    details: None,
                });

                let payload = serde_json::to_value(&termination)?;
                let env = Self::make_envelope(RemittanceKind::Termination, thread_id, payload, now);

                self.send_envelope(&counterparty, &env, host_override)
                    .await?;

                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.termination = Some(termination.clone());
                    }
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::Terminated,
                    Some("module requested termination".to_string()),
                )
                .await?;

                self.emit_event(RemittanceEvent::TerminationSent {
                    thread_id: thread_id.to_string(),
                    termination,
                })
                .await;
            }
            other => {
                return Err(RemittanceError::Protocol(format!(
                    "unexpected build_settlement action: {}",
                    other
                )));
            }
        }

        Ok(ThreadHandle {
            manager: self.clone(),
            thread_id: thread_id.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Inbound message pipeline
    // -----------------------------------------------------------------------

    /// Parse an inbound PeerMessage, deduplicate, and dispatch to the correct handler.
    pub(crate) async fn handle_inbound_message(
        &self,
        msg: PeerMessage,
    ) -> Result<(), RemittanceError> {
        // Parse envelope from message body.
        let envelope: RemittanceEnvelope = serde_json::from_str(&msg.body)
            .map_err(|e| RemittanceError::Protocol(format!("invalid envelope: {}", e)))?;

        // Get or create thread for this inbound message.
        let thread_id = self
            .get_or_create_thread_from_inbound(&envelope, &msg.sender)
            .await?;

        // Deduplication: skip if already processed.
        {
            let guard = self.inner.lock().await;
            if let Some(thread) = guard.threads.get(&thread_id) {
                if thread.processed_message_ids.contains(&msg.message_id) {
                    // Already processed — acknowledge and return.
                    drop(guard);
                    let _ = self.comms.acknowledge_message(&[msg.message_id]).await;
                    return Ok(());
                }
            }
        }

        // Dispatch to kind-specific handler.
        self.apply_inbound_envelope(&thread_id, envelope.clone())
            .await?;

        // Record message ID and log entry under lock.
        let log_entry = ProtocolLogEntry {
            direction: MessageDirection::In,
            envelope: envelope.clone(),
            transport_message_id: msg.message_id.clone(),
        };
        {
            let mut guard = self.inner.lock().await;
            if let Some(thread) = guard.threads.get_mut(&thread_id) {
                thread.processed_message_ids.push(msg.message_id.clone());
                thread.protocol_log.push(log_entry);
            }
        }

        // Emit EnvelopeReceived event.
        self.emit_event(RemittanceEvent::EnvelopeReceived {
            thread_id: thread_id.clone(),
            envelope,
            transport_message_id: msg.message_id.clone(),
        })
        .await;

        // Acknowledge message transport.
        let _ = self.comms.acknowledge_message(&[msg.message_id]).await;

        // Persist updated state.
        self.persist_state().await;

        Ok(())
    }

    /// Determine the thread_id for an inbound message, creating a new thread if needed.
    async fn get_or_create_thread_from_inbound(
        &self,
        env: &RemittanceEnvelope,
        sender: &str,
    ) -> Result<ThreadId, RemittanceError> {
        // Check if thread already exists.
        {
            let guard = self.inner.lock().await;
            if guard.threads.contains_key(&env.thread_id) {
                return Ok(env.thread_id.clone());
            }
        }

        // Determine our role based on message kind.
        // Invoice → I am taker (maker is initiating).
        // Settlement (unsolicited) → I am maker (paying party sends without invoice).
        // Receipt/Termination on new thread → I am taker (default — we did not create this).
        // Identity messages → infer from config which party is the requester, then derive role.
        let my_role = match &env.kind {
            RemittanceKind::Invoice => ThreadRole::Taker,
            RemittanceKind::Settlement => ThreadRole::Maker,
            RemittanceKind::Receipt | RemittanceKind::Termination => ThreadRole::Taker,
            RemittanceKind::IdentityVerificationRequest
            | RemittanceKind::IdentityVerificationResponse
            | RemittanceKind::IdentityVerificationAcknowledgment => {
                // Determine which role is the requester per config. When only the maker is
                // configured to request, the requester_role is Maker; when only the taker is
                // configured, requester_role is Taker; otherwise default to Maker.
                let identity_opts = self.options.identity_options.as_ref();
                let maker_requests = identity_opts
                    .and_then(|o| o.maker_request_identity.as_ref())
                    .map(|p| !matches!(p, IdentityPhase::Never))
                    .unwrap_or(false);
                let taker_requests = identity_opts
                    .and_then(|o| o.taker_request_identity.as_ref())
                    .map(|p| !matches!(p, IdentityPhase::Never))
                    .unwrap_or(false);

                let requester_role = if maker_requests && !taker_requests {
                    ThreadRole::Maker
                } else if taker_requests && !maker_requests {
                    ThreadRole::Taker
                } else {
                    // Both or neither — default to Maker as requester.
                    ThreadRole::Maker
                };

                // For a Response: the requester is receiving the response (I am the requester).
                // For a Request or Acknowledgment: the other party is acting, so I am the opposite.
                match &env.kind {
                    RemittanceKind::IdentityVerificationResponse => requester_role,
                    _ => match requester_role {
                        ThreadRole::Maker => ThreadRole::Taker,
                        ThreadRole::Taker => ThreadRole::Maker,
                    },
                }
            }
        };

        let thread = self
            .create_thread_with_id(sender, my_role, &env.thread_id)
            .await?;
        Ok(thread.thread_id)
    }

    /// Create a new thread with a specific thread_id (for inbound message flows).
    async fn create_thread_with_id(
        &self,
        counterparty: &str,
        my_role: ThreadRole,
        thread_id: &str,
    ) -> Result<Thread, RemittanceError> {
        let now = self.now_internal();
        let their_role = match my_role {
            ThreadRole::Maker => ThreadRole::Taker,
            ThreadRole::Taker => ThreadRole::Maker,
        };

        let thread = Thread {
            thread_id: thread_id.to_string(),
            counterparty: counterparty.to_string(),
            my_role,
            their_role,
            created_at: now,
            updated_at: now,
            state: RemittanceThreadState::New,
            state_log: Vec::new(),
            processed_message_ids: Vec::new(),
            protocol_log: Vec::new(),
            identity: ThreadIdentity::default(),
            flags: ThreadFlags::default(),
            invoice: None,
            settlement: None,
            receipt: None,
            termination: None,
            last_error: None,
        };

        {
            let mut guard = self.inner.lock().await;
            guard.threads.insert(thread_id.to_string(), thread.clone());
        }

        self.emit_event(RemittanceEvent::ThreadCreated {
            thread_id: thread_id.to_string(),
            thread: thread.clone(),
        })
        .await;

        Ok(thread)
    }

    /// Dispatch an inbound envelope to the appropriate protocol handler by kind.
    async fn apply_inbound_envelope(
        &self,
        thread_id: &str,
        env: RemittanceEnvelope,
    ) -> Result<(), RemittanceError> {
        // Extract sender from thread (counterparty field).
        let (sender, invoice_opt, settlement_opt, my_role, has_identified) = {
            let guard = self.inner.lock().await;
            let thread = guard.threads.get(thread_id).ok_or_else(|| {
                RemittanceError::Protocol(format!("thread not found: {}", thread_id))
            })?;
            (
                thread.counterparty.clone(),
                thread.invoice.clone(),
                thread.settlement.clone(),
                thread.my_role.clone(),
                thread.flags.has_identified,
            )
        };

        match env.kind {
            RemittanceKind::IdentityVerificationRequest => {
                let request: IdentityVerificationRequest =
                    serde_json::from_value(env.payload.clone()).map_err(|e| {
                        RemittanceError::Protocol(format!("bad IdentityVerificationRequest: {}", e))
                    })?;

                let identity = match &self.identity {
                    Some(il) => il.clone(),
                    None => {
                        // No identity layer — send termination.
                        let termination = Termination {
                            code: "no_identity_layer".to_string(),
                            message: "no identity layer configured".to_string(),
                            details: None,
                        };
                        let payload = serde_json::to_value(&termination)?;
                        let term_env = Self::make_envelope(
                            RemittanceKind::Termination,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &term_env, None).await?;
                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::Terminated,
                            Some("no identity layer".to_string()),
                        )
                        .await?;
                        return Ok(());
                    }
                };

                let ctx = self.make_module_context();
                let result = identity
                    .respond_to_request(&sender, thread_id, &request, &ctx)
                    .await?;

                match result {
                    crate::remittance::identity_layer::RespondToRequestResult::Respond {
                        response,
                    } => {
                        let certs = response.certificates.clone();
                        let payload = serde_json::to_value(&response)?;
                        let resp_env = Self::make_envelope(
                            RemittanceKind::IdentityVerificationResponse,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &resp_env, None).await?;

                        {
                            let mut guard = self.inner.lock().await;
                            if let Some(t) = guard.threads.get_mut(thread_id) {
                                t.identity.response_sent = true;
                                t.identity.certs_sent = certs;
                            }
                        }

                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::IdentityResponded,
                            Some("identity response sent".to_string()),
                        )
                        .await?;

                        self.emit_event(RemittanceEvent::IdentityRequested {
                            thread_id: thread_id.to_string(),
                            direction: MessageDirection::In,
                            request,
                        })
                        .await;
                    }
                    crate::remittance::identity_layer::RespondToRequestResult::Terminate {
                        termination,
                    } => {
                        let payload = serde_json::to_value(&termination)?;
                        let term_env = Self::make_envelope(
                            RemittanceKind::Termination,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &term_env, None).await?;
                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::Terminated,
                            Some("identity terminated".to_string()),
                        )
                        .await?;
                    }
                }
            }

            RemittanceKind::IdentityVerificationResponse => {
                let response: IdentityVerificationResponse =
                    serde_json::from_value(env.payload.clone()).map_err(|e| {
                        RemittanceError::Protocol(format!(
                            "bad IdentityVerificationResponse: {}",
                            e
                        ))
                    })?;

                let identity = match &self.identity {
                    Some(il) => il.clone(),
                    None => {
                        return Err(RemittanceError::Protocol(
                            "received IdentityVerificationResponse with no identity layer"
                                .to_string(),
                        ));
                    }
                };

                let result = identity
                    .assess_received_certificate_sufficiency(&sender, &response, thread_id)
                    .await?;

                match result {
                    crate::remittance::identity_layer::AssessIdentityResult::Acknowledge(ack) => {
                        let certs_received = response.certificates.clone();
                        let payload = serde_json::to_value(&ack)?;
                        let ack_env = Self::make_envelope(
                            RemittanceKind::IdentityVerificationAcknowledgment,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &ack_env, None).await?;

                        {
                            let mut guard = self.inner.lock().await;
                            if let Some(t) = guard.threads.get_mut(thread_id) {
                                t.identity.certs_received = certs_received;
                                t.identity.acknowledgment_sent = true;
                                t.flags.has_identified = true;
                            }
                        }

                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::IdentityAcknowledged,
                            Some("identity acknowledged".to_string()),
                        )
                        .await?;

                        self.emit_event(RemittanceEvent::IdentityResponded {
                            thread_id: thread_id.to_string(),
                            direction: MessageDirection::In,
                            response,
                        })
                        .await;
                    }
                    crate::remittance::identity_layer::AssessIdentityResult::Terminate(
                        termination,
                    ) => {
                        let payload = serde_json::to_value(&termination)?;
                        let term_env = Self::make_envelope(
                            RemittanceKind::Termination,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &term_env, None).await?;
                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::Terminated,
                            Some("identity assessment terminated".to_string()),
                        )
                        .await?;
                    }
                }
            }

            RemittanceKind::IdentityVerificationAcknowledgment => {
                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.identity.acknowledgment_received = true;
                        t.flags.has_identified = true;
                    }
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::IdentityAcknowledged,
                    Some("identity acknowledgment received".to_string()),
                )
                .await?;

                let ack: IdentityVerificationAcknowledgment =
                    serde_json::from_value(env.payload.clone()).unwrap_or_else(|_| {
                        IdentityVerificationAcknowledgment {
                            kind: RemittanceKind::IdentityVerificationAcknowledgment,
                            thread_id: thread_id.to_string(),
                        }
                    });
                self.emit_event(RemittanceEvent::IdentityAcknowledged {
                    thread_id: thread_id.to_string(),
                    direction: MessageDirection::In,
                    acknowledgment: ack,
                })
                .await;
            }

            RemittanceKind::Invoice => {
                let invoice: Invoice = serde_json::from_value(env.payload.clone())
                    .map_err(|e| RemittanceError::Protocol(format!("bad Invoice: {}", e)))?;

                let invoice_clone = invoice.clone();
                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.invoice = Some(invoice.clone());
                        t.flags.has_invoiced = true;
                    }
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::Invoiced,
                    Some("invoice received".to_string()),
                )
                .await?;

                self.emit_event(RemittanceEvent::InvoiceReceived {
                    thread_id: thread_id.to_string(),
                    invoice: invoice_clone,
                })
                .await;
            }

            RemittanceKind::Settlement => {
                // PARITY-06 / PARITY-12: If the maker required identity before settlement and
                // identity has not been completed, reject the settlement with a termination.
                // Only applies when I am the Maker — the party that issued the requirement.
                let should_require_identity = matches!(my_role, ThreadRole::Maker)
                    && matches!(
                        self.options
                            .identity_options
                            .as_ref()
                            .and_then(|o| o.maker_request_identity.as_ref()),
                        Some(IdentityPhase::BeforeSettlement)
                    )
                    && !has_identified;

                if should_require_identity {
                    let termination = Termination {
                        code: "identity.required".to_string(),
                        message: "Identity verification is required before settlement".to_string(),
                        details: None,
                    };
                    let payload = serde_json::to_value(&termination)?;
                    let term_env = Self::make_envelope(
                        RemittanceKind::Termination,
                        thread_id,
                        payload,
                        self.now_internal(),
                    );
                    self.send_envelope(&sender, &term_env, None).await?;
                    self.transition_thread_state(
                        thread_id,
                        RemittanceThreadState::Terminated,
                        Some("identity required before settlement".to_string()),
                    )
                    .await?;
                    return Ok(());
                }

                let settlement: Settlement = serde_json::from_value(env.payload.clone())
                    .map_err(|e| RemittanceError::Protocol(format!("bad Settlement: {}", e)))?;

                let module_id = settlement.module_id.clone();
                let module = match self.modules.get(&module_id) {
                    Some(m) => m,
                    None => {
                        return Err(RemittanceError::Protocol(format!(
                            "no module registered for module_id: {}",
                            module_id
                        )));
                    }
                };

                let ctx = self.make_module_context();
                let result = module
                    .accept_settlement_erased(
                        thread_id,
                        invoice_opt.as_ref(),
                        &settlement.artifact,
                        &sender,
                        &ctx,
                    )
                    .await?;

                let settlement_clone = settlement.clone();
                match result.action {
                    "accept" => {
                        // Store settlement on thread.
                        {
                            let mut guard = self.inner.lock().await;
                            if let Some(t) = guard.threads.get_mut(thread_id) {
                                t.settlement = Some(settlement.clone());
                                t.flags.has_paid = true;
                            }
                        }

                        if self.options.auto_issue_receipt {
                            let receipt_data =
                                result.receipt_data.unwrap_or(serde_json::Value::Null);
                            // Build payee/payer from invoice if available, else use thread info.
                            let (payee, payer) = if let Some(ref inv) = invoice_opt {
                                (inv.base.payee.clone(), inv.base.payer.clone())
                            } else {
                                // Maker receives settlement, so maker is payee.
                                let guard = self.inner.lock().await;
                                let thread = guard.threads.get(thread_id);
                                let key = guard.my_identity_key.clone().unwrap_or_default();
                                let cp = thread.map(|t| t.counterparty.clone()).unwrap_or_default();
                                drop(guard);
                                (key, cp)
                            };
                            let receipt = Receipt {
                                kind: RemittanceKind::Receipt,
                                thread_id: thread_id.to_string(),
                                module_id: settlement.module_id.clone(),
                                option_id: settlement.option_id.clone(),
                                payee,
                                payer,
                                receipt_data,
                                created_at: self.now_internal(),
                            };
                            let receipt_clone = receipt.clone();
                            let payload = serde_json::to_value(&receipt)?;
                            let receipt_env = Self::make_envelope(
                                RemittanceKind::Receipt,
                                thread_id,
                                payload,
                                self.now_internal(),
                            );
                            self.send_envelope(&sender, &receipt_env, None).await?;

                            {
                                let mut guard = self.inner.lock().await;
                                if let Some(t) = guard.threads.get_mut(thread_id) {
                                    t.receipt = Some(receipt.clone());
                                    t.flags.has_receipted = true;
                                }
                            }

                            self.transition_thread_state(
                                thread_id,
                                RemittanceThreadState::Settled,
                                Some("settlement accepted".to_string()),
                            )
                            .await?;

                            self.transition_thread_state(
                                thread_id,
                                RemittanceThreadState::Receipted,
                                Some("receipt auto-issued".to_string()),
                            )
                            .await?;

                            self.emit_event(RemittanceEvent::ReceiptSent {
                                thread_id: thread_id.to_string(),
                                receipt: receipt_clone,
                            })
                            .await;
                        } else {
                            self.transition_thread_state(
                                thread_id,
                                RemittanceThreadState::Settled,
                                Some("settlement accepted".to_string()),
                            )
                            .await?;
                        }

                        self.emit_event(RemittanceEvent::SettlementReceived {
                            thread_id: thread_id.to_string(),
                            settlement: settlement_clone,
                        })
                        .await;
                    }
                    "terminate" => {
                        let termination = result.termination.unwrap_or_else(|| Termination {
                            code: "module_terminated".to_string(),
                            message: "module rejected settlement".to_string(),
                            details: None,
                        });
                        let payload = serde_json::to_value(&termination)?;
                        let term_env = Self::make_envelope(
                            RemittanceKind::Termination,
                            thread_id,
                            payload,
                            self.now_internal(),
                        );
                        self.send_envelope(&sender, &term_env, None).await?;
                        self.transition_thread_state(
                            thread_id,
                            RemittanceThreadState::Terminated,
                            Some("module rejected settlement".to_string()),
                        )
                        .await?;

                        self.emit_event(RemittanceEvent::SettlementReceived {
                            thread_id: thread_id.to_string(),
                            settlement: settlement_clone,
                        })
                        .await;
                    }
                    other => {
                        return Err(RemittanceError::Protocol(format!(
                            "unexpected accept_settlement action: {}",
                            other
                        )));
                    }
                }
            }

            RemittanceKind::Receipt => {
                let receipt: Receipt = serde_json::from_value(env.payload.clone())
                    .map_err(|e| RemittanceError::Protocol(format!("bad Receipt: {}", e)))?;

                let receipt_clone = receipt.clone();
                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.receipt = Some(receipt.clone());
                        t.flags.has_receipted = true;
                    }
                }

                // Call module's process_receipt_erased if available (swallow errors).
                // Use settlement's module_id (most reliable) or the receipt's module_id.
                let module_id_for_receipt = settlement_opt
                    .as_ref()
                    .map(|s| s.module_id.as_str())
                    .unwrap_or(&receipt.module_id);
                if let Some(module) = self.modules.get(module_id_for_receipt) {
                    let ctx = self.make_module_context();
                    let _ = module
                        .process_receipt_erased(
                            thread_id,
                            invoice_opt.as_ref(),
                            &receipt.receipt_data,
                            &sender,
                            &ctx,
                        )
                        .await;
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::Receipted,
                    Some("receipt received".to_string()),
                )
                .await?;

                self.emit_event(RemittanceEvent::ReceiptReceived {
                    thread_id: thread_id.to_string(),
                    receipt: receipt_clone,
                })
                .await;
            }

            RemittanceKind::Termination => {
                let termination: Termination = serde_json::from_value(env.payload.clone())
                    .map_err(|e| RemittanceError::Protocol(format!("bad Termination: {}", e)))?;

                let termination_clone = termination.clone();
                {
                    let mut guard = self.inner.lock().await;
                    if let Some(t) = guard.threads.get_mut(thread_id) {
                        t.termination = Some(termination.clone());
                        t.flags.error = true;
                    }
                }

                // Call module's process_termination_erased if available (swallow errors).
                // Use settlement's module_id if available, else try the first registered module.
                let module_for_term = if let Some(s) = settlement_opt.as_ref() {
                    self.modules.get(&s.module_id)
                } else {
                    self.modules.values().next()
                };
                if let Some(module) = module_for_term {
                    let ctx = self.make_module_context();
                    let _ = module
                        .process_termination_erased(
                            thread_id,
                            invoice_opt.as_ref(),
                            settlement_opt.as_ref(),
                            &termination,
                            &sender,
                            &ctx,
                        )
                        .await;
                }

                self.transition_thread_state(
                    thread_id,
                    RemittanceThreadState::Terminated,
                    Some(format!("termination received: {}", termination_clone.code)),
                )
                .await?;

                self.emit_event(RemittanceEvent::TerminationReceived {
                    thread_id: thread_id.to_string(),
                    termination: termination_clone,
                })
                .await;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Comms integration
    // -----------------------------------------------------------------------

    /// Fetch all pending messages from the CommsLayer and process each one.
    pub async fn sync_threads(&self, host_override: Option<&str>) -> Result<(), RemittanceError> {
        let message_box = self.config.message_box.as_deref().unwrap_or("remittance");
        let messages = self.comms.list_messages(message_box, host_override).await?;
        for msg in messages {
            // Errors on individual messages are logged, not fatal.
            if let Err(e) = self.handle_inbound_message(msg).await {
                if let Some(logger) = &self.config.logger {
                    logger.error(&[&"sync_threads: error processing message", &e.to_string()]);
                }
            }
        }
        Ok(())
    }

    /// Register a live message callback with the CommsLayer.
    ///
    /// The callback spawns a tokio task for each inbound message, so this
    /// method returns immediately after registration.
    pub async fn start_listening(
        &self,
        host_override: Option<&str>,
    ) -> Result<(), RemittanceError> {
        let message_box = self.config.message_box.as_deref().unwrap_or("remittance");
        let manager_clone = self.clone();
        let callback: Arc<dyn Fn(PeerMessage) + Send + Sync> = Arc::new(move |msg: PeerMessage| {
            let mgr = manager_clone.clone();
            tokio::spawn(async move {
                let _ = mgr.handle_inbound_message(msg).await;
            });
        });
        self.comms
            .listen_for_live_messages(message_box, host_override, callback)
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Notify-based waiters
    // -----------------------------------------------------------------------

    /// Wait until a thread reaches `target` state (or a terminal state).
    ///
    /// Uses `tokio::sync::Notify` to avoid busy-polling. The lost-wakeup
    /// prevention pattern registers the `notified()` future before re-checking
    /// state under lock. If `timeout_ms` is Some, returns `RemittanceError::Timeout`
    /// if the target state is not reached within the given duration.
    pub async fn wait_for_state(
        &self,
        thread_id: &str,
        target: RemittanceThreadState,
        timeout_ms: Option<u64>,
    ) -> Result<Thread, RemittanceError> {
        let fut = async {
            loop {
                // Register notify handle under lock, then check state.
                let notify = {
                    let mut nmap = self.notifiers.lock().await;
                    nmap.entry(thread_id.to_string())
                        .or_insert_with(|| Arc::new(Notify::new()))
                        .clone()
                };

                // CRITICAL: Create notified future before releasing any lock that
                // guards state, to prevent lost wakeups.
                let notified = notify.notified();

                // Re-check state under inner lock.
                {
                    let inner = self.inner.lock().await;
                    if let Some(thread) = inner.threads.get(thread_id) {
                        if thread.state == target || is_terminal_state(&thread.state) {
                            return Ok(thread.clone());
                        }
                    } else {
                        return Err(RemittanceError::Protocol(format!(
                            "thread not found: {}",
                            thread_id
                        )));
                    }
                }

                notified.await;
            }
        };

        if let Some(ms) = timeout_ms {
            tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
                .await
                .map_err(|_| {
                    RemittanceError::Timeout(format!(
                        "wait_for_state timed out after {}ms waiting for thread {} to reach {:?}",
                        ms, thread_id, target
                    ))
                })?
        } else {
            fut.await
        }
    }

    /// Wait until a thread reaches `Receipted` state and return the receipt.
    ///
    /// If the thread reaches `Terminated` state first, returns `WaitReceiptResult::Terminated`.
    /// If `timeout_ms` is Some, returns `RemittanceError::Timeout` on expiry.
    pub async fn wait_for_receipt(
        &self,
        thread_id: &str,
        timeout_ms: Option<u64>,
    ) -> Result<WaitReceiptResult, RemittanceError> {
        let thread = self
            .wait_for_state(thread_id, RemittanceThreadState::Receipted, timeout_ms)
            .await?;
        if thread.state == RemittanceThreadState::Terminated {
            return Ok(WaitReceiptResult::Terminated(thread.termination.unwrap_or(
                Termination {
                    code: "terminated".into(),
                    message: "counterparty terminated".into(),
                    details: None,
                },
            )));
        }
        thread
            .receipt
            .map(WaitReceiptResult::Receipt)
            .ok_or_else(|| {
                RemittanceError::Protocol(format!(
                    "thread {} reached Receipted state but has no receipt",
                    thread_id
                ))
            })
    }

    /// Wait until the thread has completed identity exchange.
    pub async fn wait_for_identity(
        &self,
        thread_id: &str,
        timeout_ms: Option<u64>,
    ) -> Result<Thread, RemittanceError> {
        self.wait_for_state(
            thread_id,
            RemittanceThreadState::IdentityAcknowledged,
            timeout_ms,
        )
        .await
    }

    /// Wait until a thread reaches `Settled` state and return the settlement.
    ///
    /// If the thread reaches `Terminated` state first, returns `WaitSettlementResult::Terminated`.
    /// If `timeout_ms` is Some, returns `RemittanceError::Timeout` on expiry.
    pub async fn wait_for_settlement(
        &self,
        thread_id: &str,
        timeout_ms: Option<u64>,
    ) -> Result<WaitSettlementResult, RemittanceError> {
        let thread = self
            .wait_for_state(thread_id, RemittanceThreadState::Settled, timeout_ms)
            .await?;
        if thread.state == RemittanceThreadState::Terminated {
            return Ok(WaitSettlementResult::Terminated(
                thread.termination.unwrap_or(Termination {
                    code: "terminated".into(),
                    message: "counterparty terminated".into(),
                    details: None,
                }),
            ));
        }
        thread
            .settlement
            .map(WaitSettlementResult::Settlement)
            .ok_or_else(|| {
                RemittanceError::Protocol(format!(
                    "thread {} reached Settled state but has no settlement",
                    thread_id
                ))
            })
    }

    /// Send a settlement without a prior invoice (unsolicited).
    ///
    /// Creates a new taker thread, verifies the module allows unsolicited
    /// settlements, calls `build_settlement_erased` with no invoice, and sends.
    ///
    /// `option` is the module-specific option data (e.g. payment terms) passed
    /// through to `build_settlement`. `note` is an optional human-readable note.
    pub async fn send_unsolicited_settlement(
        &self,
        counterparty: &str,
        module_id: &str,
        option_id: &str,
        option: serde_json::Value,
        note: Option<&str>,
        host_override: Option<&str>,
    ) -> Result<ThreadHandle, RemittanceError> {
        let thread = self.create_thread(counterparty, ThreadRole::Taker).await?;
        let thread_id = thread.thread_id.clone();

        let module = self
            .modules
            .get(module_id)
            .ok_or_else(|| RemittanceError::Protocol(format!("module not found: {}", module_id)))?;

        if !module.allow_unsolicited_settlements() {
            return Err(RemittanceError::Protocol(format!(
                "module {} does not allow unsolicited settlements",
                module_id
            )));
        }

        let ctx = self.make_module_context();
        let result = module
            .build_settlement_erased(&thread_id, None, &option, note, &ctx)
            .await?;

        let my_key = {
            let guard = self.inner.lock().await;
            guard.my_identity_key.clone().unwrap_or_default()
        };
        let now = self.now_internal();

        let artifact = result.artifact.unwrap_or(serde_json::Value::Null);
        let settlement = Settlement {
            kind: RemittanceKind::Settlement,
            thread_id: thread_id.clone(),
            module_id: module_id.to_string(),
            option_id: option_id.to_string(),
            sender: my_key,
            created_at: now,
            artifact,
            note: note.map(|s| s.to_string()),
        };

        let payload = serde_json::to_value(&settlement)?;
        let env = Self::make_envelope(RemittanceKind::Settlement, &thread_id, payload, now);
        self.send_envelope(counterparty, &env, host_override)
            .await?;

        {
            let mut guard = self.inner.lock().await;
            if let Some(t) = guard.threads.get_mut(&thread_id) {
                t.settlement = Some(settlement.clone());
                t.flags.has_paid = true;
            }
        }

        self.transition_thread_state(
            &thread_id,
            RemittanceThreadState::Settled,
            Some("unsolicited settlement sent".to_string()),
        )
        .await?;

        self.emit_event(RemittanceEvent::SettlementSent {
            thread_id: thread_id.clone(),
            settlement,
        })
        .await;

        Ok(ThreadHandle {
            manager: self.clone(),
            thread_id,
        })
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

    /// Wait until the thread reaches `state` (or a terminal state).
    pub async fn wait_for_state(
        &self,
        state: RemittanceThreadState,
        timeout_ms: Option<u64>,
    ) -> Result<Thread, RemittanceError> {
        self.manager
            .wait_for_state(&self.thread_id, state, timeout_ms)
            .await
    }

    /// Wait until the thread has completed identity exchange.
    pub async fn wait_for_identity(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<Thread, RemittanceError> {
        self.manager
            .wait_for_identity(&self.thread_id, timeout_ms)
            .await
    }

    /// Wait until the thread has a confirmed settlement.
    pub async fn wait_for_settlement(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<WaitSettlementResult, RemittanceError> {
        self.manager
            .wait_for_settlement(&self.thread_id, timeout_ms)
            .await
    }

    /// Wait until the thread has been receipted.
    pub async fn wait_for_receipt(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<WaitReceiptResult, RemittanceError> {
        self.manager
            .wait_for_receipt(&self.thread_id, timeout_ms)
            .await
    }
}

/// Handle wrapping a `ThreadHandle` for invoice-specific operations.
pub struct InvoiceHandle {
    pub handle: ThreadHandle,
}

impl InvoiceHandle {
    /// Returns the invoice stored on the thread, or an error if not present.
    pub async fn invoice(&self) -> Result<Invoice, RemittanceError> {
        let thread = self.handle.get_thread().await?;
        thread.invoice.ok_or_else(|| {
            RemittanceError::Protocol(format!("thread {} has no invoice", self.handle.thread_id))
        })
    }

    /// Pay the invoice using the given option_id (or the default/first available).
    pub async fn pay(
        &self,
        option_id: Option<&str>,
        host_override: Option<&str>,
    ) -> Result<ThreadHandle, RemittanceError> {
        self.handle
            .manager
            .pay(&self.handle.thread_id, option_id, host_override)
            .await
    }
}
