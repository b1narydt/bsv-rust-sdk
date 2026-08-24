//! Peer orchestrator for BRC-103 mutual authentication.
//!
//! The Peer manages handshakes, sessions via SessionManager, and message dispatch
//! over a Transport. It is the central protocol engine for BRC-103.
//!
//! Translated from TS SDK Peer.ts (991 lines) and Go SDK peer.go (1163 lines).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, RwLock, Semaphore};

use super::error::AuthError;
use super::session_manager::{MarkSeen, SessionManager};
use super::transports::Transport;
use super::types::{
    AuthMessage, MessageType, PeerSession, RequestedCertificateSet, AUTH_PROTOCOL_ID, AUTH_VERSION,
};
use super::utils::certificates::{get_verifiable_certificates, validate_certificates};
use super::utils::nonce::{create_nonce, verify_nonce};
use crate::auth::certificates::VerifiableCertificate;
use crate::wallet::interfaces::{
    CreateSignatureArgs, GetPublicKeyArgs, VerifySignatureArgs, WalletInterface,
};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Listener callback type
// ---------------------------------------------------------------------------

/// Callback invoked when an incoming `certificateRequest` (or an initial
/// message carrying `requestedCertificates`) is received. Registered via
/// [`Peer::listen_for_certificates_requested`].
///
/// Intentional Layer-1 divergence from TS, which awaits these callbacks: Rust's
/// callback is fire-and-forget and may change response ordering. Peer does not
/// await any async work the callback spawns. If the callback
/// needs to perform async work (e.g. reading the wallet + sending a cert
/// response) it should spawn its own task.
pub type OnCertificateRequestReceived =
    dyn Fn(String, RequestedCertificateSet) + Send + Sync + 'static;

/// Future returned by a certificate-received listener.
pub type CertificateReceivedFuture =
    Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'static>>;

/// Callback invoked after an inbound certificate set has passed validation.
///
/// Listeners are awaited sequentially in registration order, matching TS SDK
/// `Peer.listenForCertificatesReceived`. Returning an error rejects message
/// processing; for a non-empty set, TS has already committed certificate
/// validation before it invokes listeners. Each callback is cancelled after
/// 30 seconds so application code cannot stall transport dispatch forever.
pub type OnCertificatesReceived =
    dyn Fn(String, Vec<VerifiableCertificate>) -> CertificateReceivedFuture + Send + Sync + 'static;

const CERTIFICATE_WAIT_TIMEOUT: Duration = Duration::from_millis(30_000);
const CERTIFICATE_LISTENER_TIMEOUT: Duration = Duration::from_millis(30_000);
const MAX_IN_FLIGHT_GENERAL_DISPATCHES: usize = 64;
const MAX_IN_FLIGHT_CONTROL_DISPATCHES: usize = 16;
const BACKGROUND_ERROR_CHANNEL_CAPACITY: usize = 128;

struct CertificateDelivery {
    identity_key: String,
    certificates: Vec<VerifiableCertificate>,
    completion: oneshot::Sender<Result<(), AuthError>>,
}

#[derive(Default)]
struct CertificateDeliveryState {
    running: bool,
    queue: VecDeque<CertificateDelivery>,
}

struct CertificateDeliveryWorkerGuard<'a> {
    deliveries: &'a StdMutex<CertificateDeliveryState>,
    armed: bool,
}

impl Drop for CertificateDeliveryWorkerGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut deliveries = self
            .deliveries
            .lock()
            .expect("certificate deliveries lock poisoned");
        deliveries.running = false;
        for delivery in deliveries.queue.drain(..) {
            let _ = delivery
                .completion
                .send(Err(AuthError::TransportNotConnected(
                    "certificate delivery worker was cancelled".to_string(),
                )));
        }
    }
}

struct CertificateWaiterSignal {
    sender: watch::Sender<bool>,
    active_waiters: AtomicUsize,
}

type CertificateWaiterMap = HashMap<String, Arc<CertificateWaiterSignal>>;

struct HandshakeWaiter {
    id: u64,
    sender: oneshot::Sender<AuthMessage>,
}

type HandshakeWaiterMap = HashMap<String, HandshakeWaiter>;

/// Owns one nonce-keyed handshake response registration. Cancellation and
/// timeout remove only this call's entry; a later handshake cannot inherit it.
struct HandshakeWaiterRegistration {
    waiters: Arc<StdMutex<HandshakeWaiterMap>>,
    session_nonce: String,
    id: u64,
}

impl Drop for HandshakeWaiterRegistration {
    fn drop(&mut self) {
        let mut waiters = self
            .waiters
            .lock()
            .expect("handshake waiters lock poisoned");
        if waiters
            .get(&self.session_nonce)
            .is_some_and(|waiter| waiter.id == self.id)
        {
            waiters.remove(&self.session_nonce);
        }
    }
}

/// Owns exactly one waiter registration. Dropping a timeout/cancelled future
/// removes only that registration; it cannot close a signal still used by a
/// concurrent waiter on the same session.
struct CertificateWaiterRegistration {
    waiters: Arc<StdMutex<CertificateWaiterMap>>,
    session_nonce: String,
    signal: Arc<CertificateWaiterSignal>,
}

impl Drop for CertificateWaiterRegistration {
    fn drop(&mut self) {
        if self.signal.active_waiters.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let mut waiters = self
            .waiters
            .lock()
            .expect("certificate-validation waiters lock poisoned");
        if waiters
            .get(&self.session_nonce)
            .is_some_and(|current| Arc::ptr_eq(current, &self.signal))
        {
            waiters.remove(&self.session_nonce);
        }
    }
}

type EventReceiver<T> = StdMutex<Option<mpsc::Receiver<T>>>;

// ---------------------------------------------------------------------------
// Base64 helpers (self-contained, matching nonce module pattern)
// ---------------------------------------------------------------------------

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    fn char_to_val(c: u8) -> Result<u8, AuthError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(AuthError::SerializationError(format!(
                "invalid base64 char: {}",
                c as char
            ))),
        }
    }
    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            break;
        }
        let a = char_to_val(bytes[i])?;
        let b = if i + 1 < bytes.len() && bytes[i + 1] != b'=' {
            char_to_val(bytes[i + 1])?
        } else {
            0
        };
        let c = if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            char_to_val(bytes[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            char_to_val(bytes[i + 3])?
        } else {
            0
        };
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() && bytes[i + 2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() && bytes[i + 3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(result)
}

fn parse_public_key(hex: &str) -> Result<crate::primitives::public_key::PublicKey, AuthError> {
    crate::primitives::public_key::PublicKey::from_string(hex).map_err(AuthError::from)
}

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// The clock lives here (in the `network`-gated `Peer`) rather than inside the
/// pure `SessionManager`, so the session module stays wasm/no_std-friendly (the
/// timestamp is injected). `Peer` is only compiled with the `network` feature,
/// which already pulls `std` + tokio, so `SystemTime` is always available here —
/// matching the existing `iso_now()` pattern in `clients::auth_fetch`.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

/// A peer capable of performing BRC-103 mutual authentication.
///
/// Manages sessions, handles authentication handshakes, certificate requests
/// and responses, and sends/receives general messages over a Transport. The
/// transport receiver is owned by a bounded background dispatch task started
/// by [`Peer::new`]; callers never need to pump receive progress.
///
/// Generic over `W: WalletInterface` for cryptographic operations.
/// Feature-gated behind `network` since it depends on tokio and Transport.
pub struct Peer<W: WalletInterface> {
    inner: Arc<PeerInner<W>>,
}

#[doc(hidden)]
pub struct PeerInner<W: WalletInterface> {
    wallet: W,
    transport: Arc<dyn Transport>,
    /// Session store wrapped in an `Arc<RwLock>` so that the lock-free,
    /// `&self` general-message hot path (`verify_general_message`,
    /// `create_general_message`) can take concurrent read locks while the
    /// handshake path (which adds/updates sessions) takes a brief write lock.
    /// Read guards are never held across a wallet `await` — sessions are
    /// `.cloned()` out of the guard at every call site before any crypto.
    session_manager: Arc<RwLock<SessionManager>>,
    /// Certificate types to request from peers during handshake. `StdRwLock`
    /// so the `&self` setter and the `&self` handshake handlers can both touch
    /// it; it is only ever read under a brief synchronous lock (cloned out
    /// before any await), never held across `.await`.
    certificates_to_request: StdRwLock<Option<RequestedCertificateSet>>,

    // Event channels (sender side -- Peer pushes events here). `mpsc::Sender`
    // is itself `&self`-cloneable/usable, so these need no extra wrapping.
    general_message_tx: mpsc::Sender<(String, Vec<u8>)>,
    certificate_request_tx: mpsc::Sender<(String, RequestedCertificateSet)>,

    // Receiver side -- taken once by consumer. `StdMutex<Option<..>>` so the
    // `on_*` accessors can `.take()` under `&self` (they are called once,
    // before the Peer is shared, but must not require `&mut self`).
    general_message_rx: EventReceiver<(String, Vec<u8>)>,
    certificate_request_rx: StdMutex<Option<mpsc::Receiver<(String, RequestedCertificateSet)>>>,
    background_error_tx: mpsc::Sender<AuthError>,
    background_error_rx: EventReceiver<AuthError>,

    /// The receive task routes initial responses directly to the initiating
    /// call. This map never stores completed responses.
    handshake_waiters: Arc<StdMutex<HandshakeWaiterMap>>,
    handshake_waiter_id: AtomicU64,
    general_dispatch_slots: Arc<Semaphore>,
    control_dispatch_slots: Arc<Semaphore>,
    /// Kept solely so dropping the final `Peer` closes the receive task's
    /// watch receiver. The task itself owns no strong reference to this core.
    _receive_task_lifetime: watch::Sender<()>,

    // Listener callbacks for incoming certificateRequest messages.
    // Mirrors TS SDK `onCertificateRequestReceivedCallbacks`.
    //
    // `StdMutex` so registration (`listen_for_certificates_requested`) and the
    // synchronous fire path (`fire_certificate_request_listeners`) can both run
    // under `&self`. Callbacks are cloned out of the guard before invocation so
    // the lock is never held across the callback body.
    on_certificate_request_received_callbacks:
        StdMutex<BTreeMap<u64, Arc<OnCertificateRequestReceived>>>,
    /// Ordered, lossless certificate delivery. Callbacks are cloned out before
    /// awaiting so registration/removal never holds this mutex across an await.
    on_certificates_received_callbacks: StdMutex<BTreeMap<u64, Arc<OnCertificatesReceived>>>,
    /// Ordered, unbounded-by-channel certificate callback queue. The transport
    /// itself and session limits bound authenticated peers; this queue avoids
    /// the former 32-entry observer channel dropping valid deliveries while a
    /// listener is applying backpressure.
    certificate_deliveries: StdMutex<CertificateDeliveryState>,
    /// Per-session retained validation signals. `watch` avoids missed wakeups:
    /// a waiter subscribing concurrently with validation still observes `true`.
    certificate_validation_waiters: Arc<StdMutex<CertificateWaiterMap>>,
    callback_id_counter: StdMutex<u64>,
}

impl<W: WalletInterface> Clone for Peer<W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<W: WalletInterface> Deref for Peer<W> {
    type Target = PeerInner<W>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<W: WalletInterface + 'static> Peer<W> {
    /// Create a new Peer with the given wallet and transport, immediately
    /// starting its background receive task.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime because the peer-owned
    /// receive task must be spawned during construction.
    pub fn new(wallet: W, transport: Arc<dyn Transport>) -> Self {
        // General-message channel is bounded at 1024 (vs 32 for the
        // lower-traffic certificate-request observer) so that N concurrent in-flight general
        // messages on a single session never trip `try_send` drops under
        // the client dispatcher.
        let (general_tx, general_rx) = mpsc::channel(1024);
        let (cert_req_tx, cert_req_rx) = mpsc::channel(32);

        let transport_rx = transport.subscribe();
        let (background_error_tx, background_error_rx) =
            mpsc::channel(BACKGROUND_ERROR_CHANNEL_CAPACITY);
        let (receive_task_lifetime, receive_task_shutdown) = watch::channel(());

        let inner = Arc::new(PeerInner {
            wallet,
            transport,
            session_manager: Arc::new(RwLock::new(SessionManager::new())),
            certificates_to_request: StdRwLock::new(None),
            general_message_tx: general_tx,
            certificate_request_tx: cert_req_tx,
            general_message_rx: StdMutex::new(Some(general_rx)),
            certificate_request_rx: StdMutex::new(Some(cert_req_rx)),
            background_error_tx,
            background_error_rx: StdMutex::new(Some(background_error_rx)),
            handshake_waiters: Arc::new(StdMutex::new(HashMap::new())),
            handshake_waiter_id: AtomicU64::new(0),
            general_dispatch_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_GENERAL_DISPATCHES)),
            control_dispatch_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_CONTROL_DISPATCHES)),
            _receive_task_lifetime: receive_task_lifetime,
            on_certificate_request_received_callbacks: StdMutex::new(BTreeMap::new()),
            on_certificates_received_callbacks: StdMutex::new(BTreeMap::new()),
            certificate_deliveries: StdMutex::new(CertificateDeliveryState::default()),
            certificate_validation_waiters: Arc::new(StdMutex::new(HashMap::new())),
            callback_id_counter: StdMutex::new(0),
        });
        Self::spawn_receive_task(Arc::downgrade(&inner), transport_rx, receive_task_shutdown);
        Peer { inner }
    }

    fn spawn_receive_task(
        peer: Weak<PeerInner<W>>,
        mut transport_rx: mpsc::Receiver<AuthMessage>,
        mut shutdown: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    message = transport_rx.recv() => message,
                };
                let Some(message) = message else {
                    if let Some(inner) = peer.upgrade() {
                        Peer { inner }.report_background_error(AuthError::TransportNotConnected(
                            "transport receive channel closed".to_string(),
                        ));
                    }
                    break;
                };
                let Some(inner) = peer.upgrade() else {
                    break;
                };
                let peer_handle = Peer { inner };

                if message.message_type == MessageType::InitialResponse {
                    peer_handle.route_initial_response(message);
                    continue;
                }

                let (slots, lane) = if message.message_type == MessageType::General {
                    (&peer_handle.general_dispatch_slots, "general")
                } else {
                    (&peer_handle.control_dispatch_slots, "control")
                };
                // Registered Layer-1 divergence: remote-controlled task fan-out
                // is bounded. Saturated-lane frames are reported and dropped;
                // admission never blocks the receiver behind a gated frame.
                let permit = match slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        peer_handle.report_background_error(AuthError::TransportError(format!(
                            "{lane} dispatch capacity exhausted; dropped inbound {:?} frame",
                            message.message_type
                        )));
                        continue;
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = peer_handle.dispatch_message(message).await {
                        peer_handle.report_background_error(error);
                    }
                });
            }
        });
    }

    fn route_initial_response(&self, message: AuthMessage) {
        let Some(session_nonce) = message.your_nonce.as_deref() else {
            return;
        };
        let waiter = self
            .handshake_waiters
            .lock()
            .expect("handshake waiters lock poisoned")
            .remove(session_nonce);
        if let Some(waiter) = waiter {
            let _ = waiter.sender.send(message);
        }
    }

    fn report_background_error(&self, error: AuthError) {
        let _ = self.background_error_tx.try_send(error);
    }

    /// Set certificate types to request from peers during handshake.
    pub fn set_certificates_to_request(&self, requested: RequestedCertificateSet) {
        *self
            .certificates_to_request
            .write()
            .expect("certificates_to_request lock poisoned") = Some(requested);
    }

    /// Take the general message receiver. Returns None if already taken.
    pub fn on_general_message(&self) -> Option<mpsc::Receiver<(String, Vec<u8>)>> {
        self.general_message_rx
            .lock()
            .expect("general_message_rx lock poisoned")
            .take()
    }

    /// Take the receiver for asynchronous receive/dispatch failures.
    ///
    /// Background failures belong to the frame that caused them and never
    /// become session-wide state. Delivery is best-effort and bounded: if this
    /// receiver is not drained, later errors are dropped instead of blocking
    /// protocol progress.
    pub fn on_error(&self) -> Option<mpsc::Receiver<AuthError>> {
        self.background_error_rx
            .lock()
            .expect("background_error_rx lock poisoned")
            .take()
    }

    /// Register a lossless, sequentially awaited, 30-second-bounded certificate listener.
    pub fn listen_for_certificates_received(&self, callback: Arc<OnCertificatesReceived>) -> u64 {
        let id = self.next_callback_id();
        self.on_certificates_received_callbacks
            .lock()
            .expect("certificates-received callbacks lock poisoned")
            .insert(id, callback);
        id
    }

    /// Remove a previously registered certificate-received listener.
    pub fn stop_listening_for_certificates_received(&self, callback_id: u64) {
        self.on_certificates_received_callbacks
            .lock()
            .expect("certificates-received callbacks lock poisoned")
            .remove(&callback_id);
    }

    /// Take the certificate request receiver. Returns None if already taken.
    ///
    /// Exposes a pure observer channel: the receiver is notified for every
    /// incoming cert-request (and embedded cert-requests from the handshake).
    /// Taking the receiver does NOT disable the default auto-response — use
    /// [`Peer::listen_for_certificates_requested`] to override the response
    /// behaviour with an explicit handler.
    pub fn on_certificate_request(
        &self,
    ) -> Option<mpsc::Receiver<(String, RequestedCertificateSet)>> {
        self.certificate_request_rx
            .lock()
            .expect("certificate_request_rx lock poisoned")
            .take()
    }

    /// Register a handler that overrides the default certificate-request
    /// auto-response.
    ///
    /// Mirrors TS SDK `Peer.listenForCertificatesRequested`. When one or
    /// more callbacks are registered, an incoming `certificateRequest`
    /// (or a handshake message carrying `requestedCertificates`) fires each
    /// registered callback and the Peer does NOT auto-respond — the handler
    /// is expected to call [`Peer::send_certificate_response`] itself once
    /// it has resolved the verifiable certificates for the verifier.
    ///
    /// Returns a `callback_id` that can be passed to
    /// [`Peer::stop_listening_for_certificates_requested`] to remove the
    /// handler. The observer channel exposed via `on_certificate_request`
    /// continues to fire regardless of listener registration.
    pub fn listen_for_certificates_requested(
        &self,
        callback: Arc<OnCertificateRequestReceived>,
    ) -> u64 {
        let id = self.next_callback_id();
        self.on_certificate_request_received_callbacks
            .lock()
            .expect("cert-request callbacks lock poisoned")
            .insert(id, callback);
        id
    }

    fn next_callback_id(&self) -> u64 {
        let mut counter = self
            .callback_id_counter
            .lock()
            .expect("callback_id_counter lock poisoned");
        let id = *counter;
        *counter = counter.wrapping_add(1);
        id
    }

    /// Remove a previously registered certificate-request handler.
    ///
    /// Mirrors TS SDK `Peer.stopListeningForCertificatesRequested`.
    pub fn stop_listening_for_certificates_requested(&self, callback_id: u64) {
        self.on_certificate_request_received_callbacks
            .lock()
            .expect("cert-request callbacks lock poisoned")
            .remove(&callback_id);
    }

    /// Whether any cert-request listener is currently registered.
    fn has_certificate_request_listeners(&self) -> bool {
        !self
            .on_certificate_request_received_callbacks
            .lock()
            .expect("cert-request callbacks lock poisoned")
            .is_empty()
    }

    /// Fire all registered cert-request listeners with the given payload.
    ///
    /// Clones the callback `Arc`s out of the guard before invoking them so the
    /// registry lock is never held across the (synchronous) callback body —
    /// callbacks may themselves register/remove listeners without deadlocking.
    fn fire_certificate_request_listeners(
        &self,
        identity_key: &str,
        requested: &RequestedCertificateSet,
    ) {
        let callbacks: Vec<Arc<OnCertificateRequestReceived>> = self
            .on_certificate_request_received_callbacks
            .lock()
            .expect("cert-request callbacks lock poisoned")
            .values()
            .cloned()
            .collect();
        for cb in callbacks {
            (cb)(identity_key.to_string(), requested.clone());
        }
    }

    async fn fire_certificates_received_listeners(
        &self,
        identity_key: &str,
        certificates: &[VerifiableCertificate],
    ) -> Result<(), AuthError> {
        let (completion_tx, completion_rx) = oneshot::channel();
        let is_worker = {
            let mut deliveries = self
                .certificate_deliveries
                .lock()
                .expect("certificate deliveries lock poisoned");
            deliveries.queue.push_back(CertificateDelivery {
                identity_key: identity_key.to_string(),
                certificates: certificates.to_vec(),
                completion: completion_tx,
            });
            if deliveries.running {
                false
            } else {
                deliveries.running = true;
                true
            }
        };

        if is_worker {
            let mut worker_guard = CertificateDeliveryWorkerGuard {
                deliveries: &self.certificate_deliveries,
                armed: true,
            };
            loop {
                let delivery = {
                    let mut deliveries = self
                        .certificate_deliveries
                        .lock()
                        .expect("certificate deliveries lock poisoned");
                    match deliveries.queue.pop_front() {
                        Some(delivery) => delivery,
                        None => {
                            deliveries.running = false;
                            worker_guard.armed = false;
                            break;
                        }
                    }
                };
                let callbacks: Vec<Arc<OnCertificatesReceived>> = self
                    .on_certificates_received_callbacks
                    .lock()
                    .expect("certificates-received callbacks lock poisoned")
                    .values()
                    .cloned()
                    .collect();
                let mut result = Ok(());
                for callback in callbacks {
                    match tokio::time::timeout(
                        // Registered Layer-1 divergence: TS has no listener
                        // deadline; Rust bounds application backpressure.
                        CERTIFICATE_LISTENER_TIMEOUT,
                        callback(delivery.identity_key.clone(), delivery.certificates.clone()),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            result = Err(error);
                            break;
                        }
                        Err(_) => {
                            result = Err(AuthError::Timeout(format!(
                                "certificate listener timed out after {}ms for peer {}",
                                CERTIFICATE_LISTENER_TIMEOUT.as_millis(),
                                delivery.identity_key
                            )));
                            break;
                        }
                    }
                }
                let _ = delivery.completion.send(result);
            }
        }

        completion_rx.await.map_err(|_| {
            AuthError::TransportNotConnected(
                "certificate delivery worker closed before completion".to_string(),
            )
        })?
    }

    /// Wait until the session's required certificates validate, without
    /// retaining a session-manager guard across the await.
    pub async fn wait_for_certificate_validation(
        &self,
        session: &PeerSession,
    ) -> Result<(), AuthError> {
        self.wait_for_certificate_validation_with_timeout(session, CERTIFICATE_WAIT_TIMEOUT)
            .await
    }

    async fn wait_for_certificate_validation_with_timeout(
        &self,
        session: &PeerSession,
        timeout: Duration,
    ) -> Result<(), AuthError> {
        if !Self::certificate_validation_is_pending(session) {
            return Ok(());
        }
        if session.session_nonce.is_empty() {
            return Err(AuthError::CertificateValidation(
                "Session nonce is required for certificate validation".to_string(),
            ));
        }

        let (mut receiver, _registration) = {
            let mut waiters = self
                .certificate_validation_waiters
                .lock()
                .expect("certificate-validation waiters lock poisoned");
            let signal = waiters
                .entry(session.session_nonce.clone())
                .or_insert_with(|| {
                    Arc::new(CertificateWaiterSignal {
                        sender: watch::channel(false).0,
                        active_waiters: AtomicUsize::new(0),
                    })
                })
                .clone();
            signal.active_waiters.fetch_add(1, Ordering::AcqRel);
            let receiver = signal.sender.subscribe();
            let registration = CertificateWaiterRegistration {
                waiters: self.certificate_validation_waiters.clone(),
                session_nonce: session.session_nonce.clone(),
                signal,
            };
            (receiver, registration)
        };

        // Close the race where validation completed between the original
        // session clone and waiter registration.
        let current = self
            .session_manager
            .read()
            .await
            .get_session(&session.session_nonce)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!(
                    "Session not found for nonce: {}",
                    session.session_nonce
                ))
            })?;
        if !Self::certificate_validation_is_pending(&current) {
            return Ok(());
        }

        let wait = async {
            loop {
                if *receiver.borrow() {
                    let current = self
                        .session_manager
                        .read()
                        .await
                        .get_session(&session.session_nonce)
                        .cloned()
                        .ok_or_else(|| {
                            AuthError::SessionNotFound(format!(
                                "Session not found for nonce: {}",
                                session.session_nonce
                            ))
                        })?;
                    if Self::certificate_validation_is_pending(&current) {
                        continue;
                    }
                    return Ok(());
                }
                receiver.changed().await.map_err(|_| {
                    AuthError::CertificateValidation(format!(
                        "certificate validation waiter closed for peer {}",
                        session.peer_identity_key
                    ))
                })?;
            }
        };

        match tokio::time::timeout(timeout, wait).await {
            Ok(result) => result,
            Err(_) => Err(AuthError::Timeout(format!(
                "Timeout waiting for certificate validation from peer {}",
                session.peer_identity_key
            ))),
        }
    }

    /// Certificate-gate state is deliberately non-error-valued and scoped to
    /// the live session. Empty, invalid, or timed-out messages do not poison
    /// later messages or waiters; only successful validation closes the gate.
    fn certificate_validation_is_pending(session: &PeerSession) -> bool {
        session.certificates_required && !session.certificates_validated
    }

    fn resolve_certificate_validation(&self, session_nonce: &str) {
        if let Some(sender) = self
            .certificate_validation_waiters
            .lock()
            .expect("certificate-validation waiters lock poisoned")
            .remove(session_nonce)
        {
            let _ = sender.sender.send(true);
        }
    }

    async fn cleanup_reaped_sessions(&self, session_nonces: &[String]) {
        if session_nonces.is_empty() {
            return;
        }

        {
            let mut waiters = self
                .handshake_waiters
                .lock()
                .expect("handshake waiters lock poisoned");
            for session_nonce in session_nonces {
                waiters.remove(session_nonce);
            }
        }
        for session_nonce in session_nonces {
            self.resolve_certificate_validation(session_nonce);
        }
    }

    async fn finish_certificate_exchange(
        &self,
        session: &mut PeerSession,
    ) -> Result<(), AuthError> {
        session.certificates_validated = true;
        let updated = {
            let mut manager = self.session_manager.write().await;
            let updated = manager.update_session(&session.session_nonce, session.clone());
            if updated {
                manager.touch(&session.session_nonce, now_ms());
            }
            updated
        };
        self.resolve_certificate_validation(&session.session_nonce);
        if updated {
            Ok(())
        } else {
            Err(AuthError::SessionNotFound(format!(
                "session evicted during certificate validation for nonce: {}",
                session.session_nonce
            )))
        }
    }

    /// Clone the "best" session for an identifier (peer identity key or
    /// session nonce), if one exists. Takes a brief read lock and clones the
    /// session out before returning — never holds the lock across an await.
    pub async fn session_by_identifier(&self, identifier: &str) -> Option<PeerSession> {
        self.session_manager
            .read()
            .await
            .get_session_by_identifier(identifier)
            .cloned()
    }

    /// Clone all sessions tracked for a given peer identity key. Takes a brief
    /// read lock and clones the sessions out before returning.
    pub async fn sessions_for_identity(&self, identity_key: &str) -> Vec<PeerSession> {
        self.session_manager
            .read()
            .await
            .get_sessions_for_identity(identity_key)
            .into_iter()
            .cloned()
            .collect()
    }

    async fn create_general_message_from_session(
        &self,
        session: &PeerSession,
        payload: Vec<u8>,
    ) -> Result<AuthMessage, AuthError> {
        if Self::certificate_validation_is_pending(session) {
            return Err(AuthError::CertificateValidation(
                "Cannot send general message before certificate validation is complete".to_string(),
            ));
        }

        // TS parity (Peer.ts:163): outbound sends refresh session activity
        // too, so an actively-sending client never idle-expires its own
        // session while the server side stays warm. Brief synchronous write
        // lock; not held across the wallet crypto await below.
        self.session_manager
            .write()
            .await
            .touch(&session.session_nonce, now_ms());

        let request_nonce = base64_encode(&crate::primitives::random::random_bytes(32));
        let key_id = format!("{} {}", request_nonce, session.peer_nonce);

        let signature_result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(payload.clone()),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(parse_public_key(&session.peer_identity_key)?),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        let identity_key_str = self.get_identity_public_key().await?;

        Ok(AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::General,
            identity_key: identity_key_str,
            nonce: Some(request_nonce),
            initial_nonce: None,
            your_nonce: Some(session.peer_nonce.clone()),
            certificates: None,
            requested_certificates: None,
            payload: Some(payload),
            signature: Some(signature_result.signature),
        })
    }

    /// Build a signed general message for an existing authenticated session
    /// without sending it over the transport.
    ///
    /// `session_identifier` may be either the peer identity key or the local
    /// session nonce. The latter is useful for servers that need to bind the
    /// signature to the exact session that authenticated an incoming request.
    pub async fn create_general_message(
        &self,
        session_identifier: &str,
        payload: Vec<u8>,
    ) -> Result<AuthMessage, AuthError> {
        // Brief read lock: clone the session out before any wallet crypto.
        // TTL-honoring (same check as the verify path): an idle-expired
        // session must never be zombie-signed with — callers see
        // `SessionNotFound` and recover by re-handshaking.
        let now = now_ms();
        let session = self
            .session_manager
            .read()
            .await
            .get_active_session(session_identifier, now)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!(
                    "Session not found for identifier: {}",
                    session_identifier
                ))
            })?;

        if !session.is_authenticated {
            return Err(AuthError::NotAuthenticated(format!(
                "session not authenticated for identifier: {}",
                session_identifier
            )));
        }

        self.create_general_message_from_session(&session, payload)
            .await
    }

    /// Send a general message to a peer identified by their identity key.
    ///
    /// If no authenticated session exists, initiates a handshake first.
    pub async fn send_message(
        &self,
        identity_key: &str,
        payload: Vec<u8>,
    ) -> Result<(), AuthError> {
        // Find or create an authenticated session
        let session = self.get_authenticated_session(identity_key).await?;
        let general_msg = self
            .create_general_message_from_session(&session, payload)
            .await?;

        self.transport.send(general_msg).await
    }

    /// Send a certificate response to a peer.
    ///
    /// Sends a signed CertificateResponse message containing the given
    /// certificates. Initiates a handshake if no authenticated session
    /// exists with the peer.
    ///
    /// Translated from TS SDK `Peer.sendCertificateResponse` (signs the
    /// JSON-serialized certificate array with `keyID = "{requestNonce} {peerNonce}"`).
    pub async fn send_certificate_response(
        &self,
        identity_key: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<(), AuthError> {
        let session = self.get_authenticated_session(identity_key).await?;
        self.send_certificate_response_for_session(&session, certificates)
            .await
    }

    /// Inner helper: build + sign + send a CertificateResponse for an
    /// already-resolved session. Used by both the public API (which performs
    /// handshake first) and the dispatch-message auto-response paths (which
    /// already hold an authenticated session and must avoid re-entering
    /// `get_authenticated_session` to break async recursion).
    async fn send_certificate_response_for_session(
        &self,
        session: &PeerSession,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<(), AuthError> {
        // TS parity (Peer.ts:778): outbound cert responses refresh session
        // activity, same as general messages.
        self.session_manager
            .write()
            .await
            .touch(&session.session_nonce, now_ms());

        let identity_key_str = self.get_identity_public_key().await?;

        // Fresh request nonce for this outgoing message (32 random bytes,
        // base64-encoded), matching TS `Utils.toBase64(Random(32))`.
        let request_nonce = base64_encode(&crate::primitives::random::random_bytes(32));

        // Sign over the JSON-serialized certificates array, matching TS.
        let sign_data = serde_json::to_vec(&certificates).map_err(|e| {
            AuthError::SerializationError(format!(
                "failed to serialize certificates for signing: {}",
                e
            ))
        })?;
        let key_id = format!("{} {}", request_nonce, session.peer_nonce);
        let peer_pubkey = parse_public_key(&session.peer_identity_key)?;

        let sig_result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(peer_pubkey),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        let cert_response = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::CertificateResponse,
            identity_key: identity_key_str,
            nonce: Some(request_nonce),
            your_nonce: Some(session.peer_nonce.clone()),
            initial_nonce: Some(session.session_nonce.clone()),
            certificates: Some(certificates),
            requested_certificates: None,
            payload: None,
            signature: Some(sig_result.signature),
        };

        self.transport.send(cert_response).await
    }

    /// Get an authenticated session for the given identity key, initiating
    /// a handshake if necessary.
    ///
    /// Public to allow AuthFetch to trigger handshake before sending
    /// general messages (needed for certificate exchange ordering).
    pub async fn get_authenticated_session(
        &self,
        identity_key: &str,
    ) -> Result<PeerSession, AuthError> {
        // Check if we already have an authenticated, non-expired session.
        // Brief read lock: clone out before returning / before handshake await.
        // TTL-honoring (same check as the verify path): an idle-expired
        // session is treated as "no session" so we re-handshake instead of
        // reusing a session our own verify path would refuse. The expired
        // entry itself is physically evicted by `reap_idle` inside
        // `initiate_handshake`.
        {
            let now = now_ms();
            let mgr = self.session_manager.read().await;
            if let Some(session) = mgr.get_active_session(identity_key, now) {
                if session.is_authenticated {
                    return Ok(session.clone());
                }
            }
        }

        // Initiate handshake
        self.initiate_handshake(identity_key).await
    }

    /// Initiate a BRC-103 handshake with the given peer.
    ///
    /// Creates a nonce, registers a response waiter, sends an initialRequest,
    /// and awaits the receive task's nonce-correlated initialResponse.
    async fn initiate_handshake(&self, identity_key: &str) -> Result<PeerSession, AuthError> {
        let session_nonce = create_nonce(&self.wallet).await?;
        let requested_certificates = self
            .certificates_to_request
            .read()
            .expect("certificates_to_request lock poisoned")
            .clone();
        // TS normalizes an absent constructor argument to an explicit empty
        // object on both handshake envelopes. Keep the Rust-native `None`
        // internally so "no configured request" does not become a validation
        // restriction on later unsolicited certificate responses.
        let requested_certificates_on_wire =
            Some(requested_certificates.clone().unwrap_or_default());

        // Create initial session (not yet authenticated). Write lock. Touch it
        // so idle reaping has a baseline, and opportunistically reap on this
        // low-frequency handshake path (keeps the hot verify path reap-free).
        let reaped = {
            let certificates_required = requested_certificates
                .as_ref()
                .is_some_and(|requested| !requested.certifiers.is_empty());
            let mut mgr = self.session_manager.write().await;
            mgr.add_session(PeerSession {
                session_nonce: session_nonce.clone(),
                peer_identity_key: identity_key.to_string(),
                peer_nonce: String::new(),
                is_authenticated: false,
                requested_certificates: requested_certificates.clone(),
                certificates_required,
                certificates_validated: !certificates_required,
            });
            let now = now_ms();
            mgr.touch(&session_nonce, now);
            mgr.reap_idle(now)
        };
        self.cleanup_reaped_sessions(&reaped).await;

        let identity_key_str = self.get_identity_public_key().await?;

        let initial_request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: identity_key_str,
            nonce: None,
            your_nonce: None,
            initial_nonce: Some(session_nonce.clone()),
            certificates: None,
            requested_certificates: requested_certificates_on_wire,
            payload: None,
            signature: None,
        };

        // Register before sending so even an immediate response cannot race
        // ahead of its waiter. The receive task removes the entry when routing;
        // the guard removes it on cancellation, send failure, or timeout.
        let (response_tx, response_rx) = oneshot::channel();
        let waiter_id = self.handshake_waiter_id.fetch_add(1, Ordering::Relaxed);
        self.handshake_waiters
            .lock()
            .expect("handshake waiters lock poisoned")
            .insert(
                session_nonce.clone(),
                HandshakeWaiter {
                    id: waiter_id,
                    sender: response_tx,
                },
            );
        let _registration = HandshakeWaiterRegistration {
            waiters: self.handshake_waiters.clone(),
            session_nonce: session_nonce.clone(),
            id: waiter_id,
        };

        // Send the request
        self.transport.send(initial_request).await?;

        // Registered Layer-1 divergence: TS waits indefinitely; Rust bounds an
        // unanswered handshake. The background receiver remains available to
        // every other session while this call waits.
        let response = match tokio::time::timeout(Duration::from_secs(30), response_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                return Err(AuthError::TransportNotConnected(
                    "handshake response waiter closed".to_string(),
                ))
            }
            Err(_) => return Err(AuthError::Timeout("handshake timeout".to_string())),
        };
        self.complete_handshake(&session_nonce, response).await
    }

    /// Complete a handshake after receiving the initialResponse.
    async fn complete_handshake(
        &self,
        session_nonce: &str,
        response: AuthMessage,
    ) -> Result<PeerSession, AuthError> {
        // Verify the nonce was created by us
        let valid_nonce = verify_nonce(&self.wallet, session_nonce).await?;
        if !valid_nonce {
            return Err(AuthError::InvalidNonce(format!(
                "our session nonce failed verification: {}",
                session_nonce
            )));
        }

        let peer_nonce = response.initial_nonce.clone().unwrap_or_default();
        let pending_session = self
            .session_manager
            .read()
            .await
            .get_session(session_nonce)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!(
                    "Session not found for nonce: {}",
                    session_nonce
                ))
            })?;

        // Verify the response signature
        // IMPORTANT: decode each nonce separately then concatenate bytes
        let our_nonce_bytes = base64_decode(session_nonce)?;
        let peer_nonce_bytes = base64_decode(&peer_nonce)?;
        let mut verify_data = our_nonce_bytes;
        verify_data.extend_from_slice(&peer_nonce_bytes);

        let key_id = format!("{} {}", session_nonce, peer_nonce);

        let verify_result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(verify_data),
                    hash_to_directly_verify: None,
                    signature: response.signature.clone().unwrap_or_default(),
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(parse_public_key(&response.identity_key)?),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature(
                "initial response signature verification failed".to_string(),
            ));
        }

        let requested_certificates = pending_session.requested_certificates.clone();
        let certificates_required = requested_certificates
            .as_ref()
            .is_some_and(|requested| !requested.certifiers.is_empty());

        // Update session to authenticated
        let mut session = PeerSession {
            session_nonce: session_nonce.to_string(),
            peer_identity_key: response.identity_key.clone(),
            peer_nonce,
            is_authenticated: true,
            requested_certificates: requested_certificates.clone(),
            certificates_required,
            certificates_validated: !certificates_required,
        };

        // Write lock: promote the session to authenticated, refresh its activity
        // timestamp, and opportunistically reap idle sessions.
        let reaped = {
            let mut mgr = self.session_manager.write().await;
            if !mgr.update_session(session_nonce, session.clone()) {
                return Err(AuthError::SessionNotFound(format!(
                    "session evicted during handshake for nonce: {}",
                    session_nonce
                )));
            }
            let now = now_ms();
            mgr.touch(session_nonce, now);
            mgr.reap_idle(now)
        };
        self.cleanup_reaped_sessions(&reaped).await;

        if certificates_required {
            if let Some(ref certs) = response.certificates {
                if !certs.is_empty() {
                    let peer_pubkey = parse_public_key(&response.identity_key)?;
                    let certificates_valid = match validate_certificates(
                        &self.wallet,
                        certs,
                        &peer_pubkey,
                        requested_certificates.as_ref(),
                    )
                    .await
                    {
                        Ok(valid) => valid,
                        Err(error) => return Err(error),
                    };
                    if !certificates_valid {
                        let reason = format!(
                            "initialResponse certificate validation failed from: {}",
                            response.identity_key
                        );
                        return Err(AuthError::CertificateValidation(reason));
                    }

                    // TS commits validation and resolves general-message waiters
                    // before awaiting certificate listeners. Deferred messages
                    // are also released here, after validation is committed.
                    self.finish_certificate_exchange(&mut session).await?;

                    self.fire_certificates_received_listeners(&response.identity_key, certs)
                        .await?;
                }
            }
        }

        // Handle certificate requests from peer embedded in the
        // initialResponse (TS Peer.ts:653-684). Same branching as the
        // standalone certificateRequest path.
        //
        // Registered Layer-1 divergence (#23): TS releases handshake waiters
        // before answering this embedded request, allowing the caller's general
        // frame to race ahead. Rust deliberately completes and sends the proof
        // first so every conforming receiver sees certificates before the first
        // general frame and never needs to defer that frame.
        if let Some(ref requested) = response.requested_certificates {
            if !requested.certifiers.is_empty() {
                // Observer channel: non-blocking. If no one has taken the
                // receiver (or the buffer is full), drop silently rather
                // than stall dispatch.
                let _ = self
                    .certificate_request_tx
                    .try_send((response.identity_key.clone(), requested.clone()));

                if self.has_certificate_request_listeners() {
                    self.fire_certificate_request_listeners(&response.identity_key, requested);
                } else {
                    let verifier_pubkey = parse_public_key(&response.identity_key)?;
                    let verifiable =
                        get_verifiable_certificates(&self.wallet, requested, &verifier_pubkey)
                            .await?;
                    // TS suppresses this post-handshake standalone response
                    // when no certificate matched (its nonce-race guard).
                    if !verifiable.is_empty() {
                        self.send_certificate_response_for_session(&session, verifiable)
                            .await?;
                    }
                }
            }
        }

        Ok(session)
    }

    /// Dispatch an incoming message based on its type.
    /// Dispatch a single incoming auth message directly.
    ///
    /// This is useful for server middleware or tests that already own one
    /// decoded frame. Transport-delivered frames are dispatched automatically.
    pub async fn dispatch_message(&self, msg: AuthMessage) -> Result<(), AuthError> {
        if msg.version != AUTH_VERSION {
            return Err(AuthError::InvalidMessage(format!(
                "unsupported auth version: {}, expected: {}",
                msg.version, AUTH_VERSION
            )));
        }

        match msg.message_type {
            MessageType::InitialRequest => self.handle_initial_request(msg).await,
            MessageType::InitialResponse => {
                self.route_initial_response(msg);
                Ok(())
            }
            MessageType::CertificateRequest => self.process_certificate_request(msg).await,
            MessageType::CertificateResponse => self.process_certificate_response(msg).await,
            MessageType::General => self.dispatch_general_message(msg).await,
        }
    }

    /// Dispatch-path certificate gate.
    ///
    /// The background receiver schedules this frame independently and reserves
    /// separate capacity for control frames. It is therefore safe for this task
    /// to await certificate validation while the receive task accepts and
    /// dispatches the `certificateResponse` that releases it.
    async fn dispatch_general_message(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let mut session = self.resolve_general_message_session(&msg).await?;
        if !session.is_authenticated {
            return Err(AuthError::NotAuthenticated(format!(
                "session not authenticated for nonce: {}",
                session.session_nonce
            )));
        }
        if Self::certificate_validation_is_pending(&session) {
            // Authenticate before occupying a bounded wait slot. Replay state
            // is committed only after the gate opens, exactly once below.
            self.verify_general_message_signature(&msg, &session)
                .await?;
            self.wait_for_certificate_validation(&session).await?;
            session = self
                .session_manager
                .read()
                .await
                .get_session(&session.session_nonce)
                .cloned()
                .ok_or_else(|| {
                    AuthError::SessionNotFound(format!(
                        "Session not found for nonce: {}",
                        session.session_nonce
                    ))
                })?;
            self.mark_general_message_seen(&msg, &session).await?;
            return self.deliver_general_message(msg);
        }
        self.handle_general_message_with_session(msg, session).await
    }

    /// Process an inbound `certificateRequest` message.
    ///
    /// Mirrors TS SDK `Peer.processCertificateRequest`:
    /// 1. Verify `yourNonce` was created by us.
    /// 2. Look up the session for that nonce.
    /// 3. Verify the signature over `JSON.stringify(requestedCertificates)`
    ///    (counterparty = peer identity key, keyID = "{nonce} {sessionNonce}").
    /// 4. If `requestedCertificates.certifiers` is non-empty, either fire
    ///    registered listeners OR auto-respond via the wallet.
    ///
    /// The observer channel is notified in all cases (even when no certifiers
    /// are requested or when verification fails) *only* for the non-failure
    /// path, matching the existing observer semantics.
    async fn process_certificate_request(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let your_nonce = msg.your_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing yourNonce in certificateRequest".to_string())
        })?;

        // 1. Verify our nonce
        let valid_nonce = verify_nonce(&self.wallet, your_nonce).await?;
        if !valid_nonce {
            return Err(AuthError::InvalidNonce(format!(
                "certificateRequest nonce verification failed from: {}",
                msg.identity_key
            )));
        }

        // A signed, session-bound certificateRequest is replay-protected just
        // like a general message: require a per-message nonce.
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");
        if msg_nonce.is_empty() {
            return Err(AuthError::InvalidMessage(format!(
                "missing per-message nonce in certificateRequest from: {}",
                msg.identity_key
            )));
        }

        // 2. Look up session (brief read lock; clone out before crypto await).
        //    TTL-honoring so a stale/captured `yourNonce` stops resolving.
        let now = now_ms();
        let session = self
            .session_manager
            .read()
            .await
            .get_active_session(your_nonce, now)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!("Session not found for nonce: {}", your_nonce))
            })?;

        // 3. Verify signature over JSON.stringify(requestedCertificates)
        let requested = msg.requested_certificates.as_ref().ok_or_else(|| {
            AuthError::InvalidMessage("missing requestedCertificates in certificateRequest".into())
        })?;

        let sign_data = serde_json::to_vec(requested).map_err(|e| {
            AuthError::SerializationError(format!(
                "failed to serialize requestedCertificates for verification: {}",
                e
            ))
        })?;
        let key_id = format!("{} {}", msg_nonce, session.session_nonce);
        let peer_pubkey = parse_public_key(&session.peer_identity_key)?;

        let verify_result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_verify: None,
                    signature: msg.signature.clone().unwrap_or_default(),
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(peer_pubkey),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature(format!(
                "invalid signature in certificateRequest from {}",
                session.peer_identity_key
            )));
        }

        // Anti-replay gate (after signature verification, before dispatch).
        // Shares the per-session seen-set with general messages, keyed on the
        // fresh per-message nonce. Brief synchronous write lock, no `.await` held.
        match self.session_manager.write().await.mark_message_seen(
            &session.session_nonce,
            msg_nonce,
            now,
        ) {
            MarkSeen::Fresh => {}
            MarkSeen::Replay => {
                return Err(AuthError::ReplayDetected(format!(
                    "duplicate certificateRequest nonce on session from {}",
                    msg.identity_key
                )));
            }
            MarkSeen::SessionGone => {
                return Err(AuthError::SessionNotFound(format!(
                    "session evicted during verify for nonce: {}",
                    your_nonce
                )));
            }
        }

        // Observer channel: non-blocking. Separate from handler listeners;
        // fire-and-forget if no consumer / buffer full.
        let _ = self
            .certificate_request_tx
            .try_send((msg.identity_key.clone(), requested.clone()));

        // 4. Decide handler vs auto-response path
        if requested.certifiers.is_empty() {
            return Ok(());
        }

        if self.has_certificate_request_listeners() {
            // Handler mode: delegate to registered listeners and stop.
            self.fire_certificate_request_listeners(&msg.identity_key, requested);
            return Ok(());
        }

        // Auto-response path: mirror TS fallback — fetch + send. Use the
        // session we already resolved to avoid re-entering
        // `get_authenticated_session` (which would cycle through handshake).
        let verifier_pubkey = parse_public_key(&msg.identity_key)?;
        let verifiable =
            get_verifiable_certificates(&self.wallet, requested, &verifier_pubkey).await?;
        self.send_certificate_response_for_session(&session, verifiable)
            .await
    }

    /// Process an inbound `certificateResponse` message.
    ///
    /// Mirrors TS SDK `Peer.processCertificateResponse` and the sibling
    /// `process_certificate_request` path:
    /// 1. Verify `yourNonce` was created by us.
    /// 2. Look up the active session for that nonce.
    /// 3. Verify the signature over `JSON.stringify(certificates)`.
    /// 4. Apply the per-message replay gate.
    /// 5. Validate non-empty certificate sets before notifying consumers.
    async fn process_certificate_response(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let your_nonce = msg.your_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing yourNonce in certificateResponse".to_string())
        })?;

        // 1. Verify our nonce.
        let valid_nonce = verify_nonce(&self.wallet, your_nonce).await?;
        if !valid_nonce {
            return Err(AuthError::InvalidNonce(format!(
                "Unable to verify nonce for certificate response from: {}",
                msg.identity_key
            )));
        }

        // A signed, session-bound certificateResponse is replay-protected just
        // like a certificateRequest/general message: require a per-message nonce.
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");
        if msg_nonce.is_empty() {
            return Err(AuthError::InvalidMessage(format!(
                "missing per-message nonce in certificateResponse from: {}",
                msg.identity_key
            )));
        }

        // 2. Look up session (brief read lock; clone out before crypto await).
        //    TTL-honoring so a stale/captured `yourNonce` stops resolving.
        let now = now_ms();
        let mut session = self
            .session_manager
            .read()
            .await
            .get_active_session(your_nonce, now)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!("Session not found for nonce: {}", your_nonce))
            })?;

        // 3. Verify signature over JSON.stringify(certificates). TS 2.4.1
        // rejects an absent key indirectly: JSON.stringify(undefined) yields
        // `undefined`, and converting that to bytes throws. Match the rejection
        // explicitly instead of inventing an empty-byte preimage.
        let certificates = msg.certificates.as_ref().ok_or_else(|| {
            AuthError::InvalidMessage("missing certificates in certificateResponse".to_string())
        })?;
        let sign_data = serde_json::to_vec(certificates).map_err(|e| {
            AuthError::SerializationError(format!(
                "failed to serialize certificates for verification: {}",
                e
            ))
        })?;
        let key_id = format!("{} {}", msg_nonce, session.session_nonce);
        let peer_pubkey = parse_public_key(&msg.identity_key)?;

        let verify_result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_verify: None,
                    signature: msg.signature.clone().unwrap_or_default(),
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(peer_pubkey.clone()),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature(format!(
                "Unable to verify certificate response signature for peer: {}",
                msg.identity_key
            )));
        }

        // Anti-replay gate (after signature verification, before validation and
        // dispatch). Shares the per-session seen-set with general messages and
        // certificate requests.
        match self.session_manager.write().await.mark_message_seen(
            &session.session_nonce,
            msg_nonce,
            now,
        ) {
            MarkSeen::Fresh => {}
            MarkSeen::Replay => {
                return Err(AuthError::ReplayDetected(format!(
                    "duplicate certificateResponse nonce on session from {}",
                    msg.identity_key
                )));
            }
            MarkSeen::SessionGone => {
                return Err(AuthError::SessionNotFound(format!(
                    "session evicted during verify for nonce: {}",
                    your_nonce
                )));
            }
        }

        let certs = msg
            .certificates
            .expect("checked before signature verification");
        if !certs.is_empty() {
            // Validate against the exact request this session advertised. The
            // mutable Peer default may have changed since the handshake, and an
            // inbound requestedCertificates field is controlled by the sender.
            let certificates_valid = match validate_certificates(
                &self.wallet,
                &certs,
                &peer_pubkey,
                session.requested_certificates.as_ref(),
            )
            .await
            {
                Ok(valid) => valid,
                Err(error) => return Err(error),
            };
            if !certificates_valid {
                let reason = format!(
                    "certificateResponse certificate validation failed from: {}",
                    msg.identity_key
                );
                return Err(AuthError::CertificateValidation(reason));
            }
        }

        if !certs.is_empty() {
            // TS commits validation and resolves waiters before listeners run.
            // A later listener rejection therefore does not roll validation
            // back; keep that ordering for exact 2.4.1 parity.
            self.finish_certificate_exchange(&mut session).await?;
        }

        // TS notifies listeners unconditionally, including `[]`, and awaits
        // each listener sequentially. This is lossless backpressure rather than
        // a bounded channel whose receiver may never be claimed.
        self.fire_certificates_received_listeners(&msg.identity_key, &certs)
            .await?;

        Ok(())
    }

    /// Handle an incoming initialRequest message.
    ///
    /// Creates a session, signs a response, and sends the initialResponse back.
    async fn handle_initial_request(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let peer_initial_nonce = msg.initial_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing initialNonce in initialRequest".to_string())
        })?;

        if peer_initial_nonce.is_empty() {
            return Err(AuthError::InvalidMessage(
                "empty initialNonce in initialRequest".to_string(),
            ));
        }

        // Create our session nonce
        let session_nonce = create_nonce(&self.wallet).await?;
        let requested_certificates = self
            .certificates_to_request
            .read()
            .expect("certificates_to_request lock poisoned")
            .clone();
        let requested_certificates_on_wire =
            Some(requested_certificates.clone().unwrap_or_default());

        // Add session (authenticated -- responder trusts after signature
        // verification). Write lock. Touch for the idle-reaping baseline and
        // opportunistically reap idle sessions on this handshake path.
        let reaped = {
            let certificates_required = requested_certificates
                .as_ref()
                .is_some_and(|requested| !requested.certifiers.is_empty());
            let mut mgr = self.session_manager.write().await;
            mgr.add_session(PeerSession {
                session_nonce: session_nonce.clone(),
                peer_identity_key: msg.identity_key.clone(),
                peer_nonce: peer_initial_nonce.to_string(),
                is_authenticated: true,
                requested_certificates: requested_certificates.clone(),
                certificates_required,
                certificates_validated: !certificates_required,
            });
            let now = now_ms();
            mgr.touch(&session_nonce, now);
            mgr.reap_idle(now)
        };
        self.cleanup_reaped_sessions(&reaped).await;

        // If the peer requested certificates in their initialRequest, resolve
        // them here so we can embed the response in the single-round-trip
        // initialResponse (TS Peer.ts:509-528). Listener mode notifies the
        // handler and leaves `certificates_to_include` as None — the handler
        // can issue a separate certificateResponse if needed.
        let mut certificates_to_include: Option<Vec<VerifiableCertificate>> = None;
        if let Some(ref requested) = msg.requested_certificates {
            if !requested.certifiers.is_empty() {
                // Observer channel: non-blocking fire-and-forget.
                let _ = self
                    .certificate_request_tx
                    .try_send((msg.identity_key.clone(), requested.clone()));

                if self.has_certificate_request_listeners() {
                    self.fire_certificate_request_listeners(&msg.identity_key, requested);
                } else {
                    let verifier_pubkey = parse_public_key(&msg.identity_key)?;
                    let verifiable =
                        get_verifiable_certificates(&self.wallet, requested, &verifier_pubkey)
                            .await?;
                    certificates_to_include = Some(verifiable);
                }
            }
        }

        // Sign the response: data = decode(peer_nonce) ++ decode(our_nonce)
        // IMPORTANT: decode each nonce separately then concatenate bytes
        let peer_nonce_bytes = base64_decode(peer_initial_nonce)?;
        let our_nonce_bytes = base64_decode(&session_nonce)?;
        let mut sign_data = peer_nonce_bytes;
        sign_data.extend_from_slice(&our_nonce_bytes);

        let key_id = format!("{} {}", peer_initial_nonce, session_nonce);

        let identity_result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        let peer_pubkey = parse_public_key(&msg.identity_key)?;

        let sig_result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(peer_pubkey),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        let response = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialResponse,
            identity_key: identity_result.public_key.to_der_hex(),
            nonce: None,
            your_nonce: Some(peer_initial_nonce.to_string()),
            initial_nonce: Some(session_nonce),
            certificates: certificates_to_include,
            requested_certificates: requested_certificates_on_wire,
            payload: None,
            signature: Some(sig_result.signature),
        };

        self.transport.send(response).await
    }

    /// Verify an incoming general message without any side effects on the
    /// transport or event channels.
    ///
    /// This is the **lock-free, `&self` hot path** intended for the HTTP
    /// server middleware: it verifies the BRC-103 nonce + signature against the
    /// authenticated session and returns. It:
    ///
    /// - takes only a brief `session_manager.read()` lock (cloning the session
    ///   out before the wallet crypto await — the read lock is never held
    ///   across `.await`), so N concurrent verifies on one session proceed
    ///   without contention;
    /// - does **not** touch the transport receiver or handshake response map;
    /// - does **not** push to the `general_message` channel (the server path
    ///   only needs the verification result, not the decoded payload).
    ///
    /// Callable on `&Peer` (and thus on `Arc<Peer<W>>`), enabling concurrent
    /// in-flight general messages on a single authenticated session.
    async fn resolve_general_message_session(
        &self,
        msg: &AuthMessage,
    ) -> Result<PeerSession, AuthError> {
        let your_nonce = msg.your_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing yourNonce in general message".to_string())
        })?;

        // Verify the nonce was created by us
        let valid_nonce = verify_nonce(&self.wallet, your_nonce).await?;
        if !valid_nonce {
            return Err(AuthError::InvalidNonce(format!(
                "general message nonce verification failed from: {}",
                msg.identity_key
            )));
        }

        // Every honest sender mints a fresh 32-byte per-message nonce; a message
        // without one cannot be replay-protected, so reject it outright (stricter
        // than the TS reference, wire-compatible since TS always sets it).
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");
        if msg_nonce.is_empty() {
            return Err(AuthError::InvalidMessage(format!(
                "missing per-message nonce in general message from: {}",
                msg.identity_key
            )));
        }

        // Verify session exists AND is not idle-expired. Brief read lock — clone
        // out before crypto. Honoring the TTL here means a stale/captured
        // `yourNonce` stops resolving a live session once the idle window lapses.
        let now = now_ms();
        let session = self
            .session_manager
            .read()
            .await
            .get_active_session(your_nonce, now)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!("Session not found for nonce: {}", your_nonce))
            })?;

        // TS parity (Peer.processGeneralMessage verifies against
        // peerSession.peerIdentityKey): the general message must come from the
        // peer bound to THIS session during the handshake — not merely from
        // whoever the message claims to be. Without this, a captured `yourNonce`
        // could carry a message signed by a different (attacker-held) key and
        // still verify against that claimed key. Bind to the session peer, like
        // the certificate-request/response paths already do.
        if msg.identity_key != session.peer_identity_key {
            return Err(AuthError::InvalidMessage(format!(
                "general message identity_key {} does not match session peer {}",
                msg.identity_key, session.peer_identity_key
            )));
        }

        Ok(session)
    }

    pub async fn verify_general_message(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let your_nonce = msg.your_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing yourNonce in general message".to_string())
        })?;
        let session = self.resolve_general_message_session(&msg).await?;
        if !session.is_authenticated {
            return Err(AuthError::NotAuthenticated(format!(
                "session not authenticated for nonce: {}",
                your_nonce
            )));
        }

        // This public middleware path has no transport receiver capable of
        // completing the gate. Reject immediately, before signature work;
        // waiting here lets unauthenticated frames occupy a handler for 30s.
        if Self::certificate_validation_is_pending(&session) {
            return Err(AuthError::CertificateValidation(
                "Cannot verify general message before certificate validation is complete"
                    .to_string(),
            ));
        }

        self.verify_general_message_with_session(msg, &session)
            .await
    }

    async fn verify_general_message_with_session(
        &self,
        msg: AuthMessage,
        session: &PeerSession,
    ) -> Result<(), AuthError> {
        self.verify_general_message_signature(&msg, session).await?;
        self.mark_general_message_seen(&msg, session).await
    }

    async fn verify_general_message_signature(
        &self,
        msg: &AuthMessage,
        session: &PeerSession,
    ) -> Result<(), AuthError> {
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");

        // Verify signature
        let payload = msg.payload.clone().unwrap_or_default();
        let key_id = format!("{} {}", msg_nonce, session.session_nonce);

        let peer_pubkey = parse_public_key(&msg.identity_key)?;

        let verify_result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(payload.clone()),
                    hash_to_directly_verify: None,
                    signature: msg.signature.clone().unwrap_or_default(),
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id,
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(peer_pubkey),
                    },
                    for_self: None,
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature(format!(
                "invalid signature in general message from {}",
                msg.identity_key
            )));
        }

        Ok(())
    }

    async fn mark_general_message_seen(
        &self,
        msg: &AuthMessage,
        session: &PeerSession,
    ) -> Result<(), AuthError> {
        let your_nonce = msg.your_nonce.as_deref().ok_or_else(|| {
            AuthError::InvalidMessage("missing yourNonce in general message".to_string())
        })?;
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");
        let now = now_ms();

        // Anti-replay gate (AFTER signature verification, so the seen-set is
        // never poisoned by unauthenticated input; BEFORE dispatch). Brief
        // synchronous write lock — no `.await` is held while it is taken, so the
        // lock-free hot path is not serialized across crypto. The check-and-
        // insert is atomic, so concurrent verifies of the SAME captured message
        // resolve to exactly one acceptance and the rest are rejected.
        match self.session_manager.write().await.mark_message_seen(
            &session.session_nonce,
            msg_nonce,
            now,
        ) {
            MarkSeen::Fresh => {}
            MarkSeen::Replay => {
                return Err(AuthError::ReplayDetected(format!(
                    "duplicate general message nonce on session from {}",
                    msg.identity_key
                )));
            }
            MarkSeen::SessionGone => {
                return Err(AuthError::SessionNotFound(format!(
                    "session evicted during verify for nonce: {}",
                    your_nonce
                )));
            }
        }

        Ok(())
    }

    fn deliver_general_message(&self, msg: AuthMessage) -> Result<(), AuthError> {
        let identity_key = msg.identity_key;
        let payload = msg.payload.unwrap_or_default();

        // Registered Layer-1 divergence: this bounded observer channel uses
        // non-blocking delivery. At capacity a payload can be dropped after its
        // nonce entered the replay set; the charter records this API behavior.
        let _ = self.general_message_tx.try_send((identity_key, payload));
        Ok(())
    }

    /// Handle an incoming general message on the dispatch path (client side).
    ///
    /// Verifies via [`Peer::verify_general_message`], then pushes the decoded
    /// `(sender_identity_key, payload)` to the `general_message` channel so the
    /// AuthFetch dispatcher task can route the response by nonce. The server
    /// middleware does NOT use this path — it calls `verify_general_message`
    /// directly to avoid the channel push.
    async fn handle_general_message_with_session(
        &self,
        msg: AuthMessage,
        session: PeerSession,
    ) -> Result<(), AuthError> {
        // The dispatch path already resolved and gate-checked this session.
        self.verify_general_message_with_session(msg.clone(), &session)
            .await?;
        self.deliver_general_message(msg)
    }

    /// Get this peer's identity public key as a hex string.
    async fn get_identity_public_key(&self) -> Result<String, AuthError> {
        let result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await?;
        Ok(result.public_key.to_der_hex())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::certificates::certificate as cert_codec;
    use crate::auth::certificates::master::{default_get_revocation_outpoint, MasterCertificate};
    use crate::primitives::private_key::PrivateKey;
    use crate::primitives::public_key::PublicKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::types::Protocol as WalletProtocol;
    use crate::wallet::ProtoWallet;
    use async_trait::async_trait;
    use futures_util::FutureExt;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Notify;

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("peer test operation timed out")
    }

    /// Compile-time guarantee: `Peer<W>` (and thus `Arc<Peer<W>>`) is
    /// `Send + Sync` for any `Send + Sync` wallet, so it can be shared across
    /// tasks/threads without an outer `Mutex`. If a future field reintroduces a
    /// non-`Sync` member (e.g. a bare `Cell`/`RefCell`), this fails to compile.
    fn _assert_peer_send_sync<W: WalletInterface + Send + Sync>() {
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<Peer<W>>();
        is_send_sync::<std::sync::Arc<Peer<W>>>();
    }

    /// Compile-time proof for the public async paths used by spawned handlers.
    fn _assert_futures_send<W: WalletInterface + Send + Sync + 'static>(
        peer: &Peer<W>,
        message: AuthMessage,
        session: &PeerSession,
    ) {
        fn is_send<T: Send>(_: T) {}
        is_send(peer.verify_general_message(message.clone()));
        is_send(peer.dispatch_message(message));
        is_send(peer.wait_for_certificate_validation(session));
        is_send(peer.send_message("peer", Vec::new()));
        is_send(peer.create_general_message("peer", Vec::new()));
    }

    // -----------------------------------------------------------------------
    // TestWallet: WalletInterface wrapper around ProtoWallet
    // -----------------------------------------------------------------------

    struct TestWallet {
        inner: ProtoWallet,
        verify_hmac_calls: AtomicUsize,
        verify_probe: Option<Arc<VerifyProbe>>,
        certificates_to_list: Vec<CertificateResult>,
    }

    struct VerifyProbe {
        active: AtomicUsize,
        peak: AtomicUsize,
        entered: mpsc::UnboundedSender<()>,
        release: Semaphore,
    }

    struct VerifyProbeGuard<'a>(&'a AtomicUsize);

    impl Drop for VerifyProbeGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
                verify_hmac_calls: AtomicUsize::new(0),
                verify_probe: None,
                certificates_to_list: Vec::new(),
            }
        }

        fn with_verify_probe(pk: PrivateKey, verify_probe: Arc<VerifyProbe>) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
                verify_hmac_calls: AtomicUsize::new(0),
                verify_probe: Some(verify_probe),
                certificates_to_list: Vec::new(),
            }
        }

        fn with_certificate(pk: PrivateKey, certificate: Certificate) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
                verify_hmac_calls: AtomicUsize::new(0),
                verify_probe: None,
                certificates_to_list: vec![CertificateResult {
                    certificate,
                    keyring: None,
                    verifier: None,
                }],
            }
        }
    }

    macro_rules! stub_method {
        ($name:ident, $args:ty, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _args: $args,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for peer tests"))
                })
            }
        };
        ($name:ident, $ret:ty) => {
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                _originator: Option<&'life1 str>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                        + ::core::marker::Send
                        + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    unimplemented!(concat!(stringify!($name), " not needed for peer tests"))
                })
            }
        };
    }

    #[async_trait::async_trait]
    impl WalletInterface for TestWallet {
        stub_method!(create_action, CreateActionArgs, CreateActionResult);
        stub_method!(sign_action, SignActionArgs, SignActionResult);
        stub_method!(abort_action, AbortActionArgs, AbortActionResult);
        stub_method!(list_actions, ListActionsArgs, ListActionsResult);
        stub_method!(
            internalize_action,
            InternalizeActionArgs,
            InternalizeActionResult
        );
        stub_method!(list_outputs, ListOutputsArgs, ListOutputsResult);
        stub_method!(
            relinquish_output,
            RelinquishOutputArgs,
            RelinquishOutputResult
        );

        async fn get_public_key(
            &self,
            args: GetPublicKeyArgs,
            _originator: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> {
            let protocol = args.protocol_id.unwrap_or(WalletProtocol {
                security_level: 0,
                protocol: String::new(),
            });
            let key_id = args.key_id.unwrap_or_default();
            let counterparty = args.counterparty.unwrap_or(Counterparty {
                counterparty_type: CounterpartyType::Uninitialized,
                public_key: None,
            });
            let pk = self.inner.get_public_key_sync(
                &protocol,
                &key_id,
                &counterparty,
                args.for_self.unwrap_or(false),
                args.identity_key,
            )?;
            Ok(GetPublicKeyResult { public_key: pk })
        }

        stub_method!(
            reveal_counterparty_key_linkage,
            RevealCounterpartyKeyLinkageArgs,
            RevealCounterpartyKeyLinkageResult
        );
        stub_method!(
            reveal_specific_key_linkage,
            RevealSpecificKeyLinkageArgs,
            RevealSpecificKeyLinkageResult
        );

        async fn encrypt(
            &self,
            args: EncryptArgs,
            _originator: Option<&str>,
        ) -> Result<EncryptResult, WalletError> {
            let ciphertext = self.inner.encrypt_sync(
                &args.plaintext,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(EncryptResult { ciphertext })
        }

        async fn decrypt(
            &self,
            args: DecryptArgs,
            _originator: Option<&str>,
        ) -> Result<DecryptResult, WalletError> {
            let plaintext = self.inner.decrypt_sync(
                &args.ciphertext,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(DecryptResult { plaintext })
        }

        async fn create_hmac(
            &self,
            args: CreateHmacArgs,
            _originator: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            let hmac = self.inner.create_hmac_sync(
                &args.data,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateHmacResult { hmac })
        }

        async fn verify_hmac(
            &self,
            args: VerifyHmacArgs,
            _originator: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            self.verify_hmac_calls.fetch_add(1, Ordering::Relaxed);
            let valid = self.inner.verify_hmac_sync(
                &args.data,
                &args.hmac,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(VerifyHmacResult { valid })
        }

        async fn create_signature(
            &self,
            args: CreateSignatureArgs,
            _originator: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> {
            let signature = self.inner.create_signature_sync(
                args.data.as_deref(),
                args.hash_to_directly_sign.as_deref(),
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateSignatureResult { signature })
        }

        async fn verify_signature(
            &self,
            args: VerifySignatureArgs,
            _originator: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> {
            let _probe_guard = if args
                .data
                .as_deref()
                .is_some_and(|data| data.starts_with(b"dispatch-probe-"))
            {
                self.verify_probe.as_ref().map(|probe| {
                    let active = probe.active.fetch_add(1, Ordering::SeqCst) + 1;
                    probe.peak.fetch_max(active, Ordering::SeqCst);
                    let _ = probe.entered.send(());
                    VerifyProbeGuard(&probe.active)
                })
            } else {
                None
            };
            if _probe_guard.is_some() {
                self.verify_probe
                    .as_ref()
                    .expect("probe guard requires probe")
                    .release
                    .acquire()
                    .await
                    .expect("probe semaphore remains open")
                    .forget();
            }
            let valid = self.inner.verify_signature_sync(
                args.data.as_deref(),
                args.hash_to_directly_verify.as_deref(),
                &args.signature,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
                args.for_self.unwrap_or(false),
            )?;
            Ok(VerifySignatureResult { valid })
        }

        stub_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
        async fn list_certificates(
            &self,
            _args: ListCertificatesArgs,
            _originator: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> {
            Ok(ListCertificatesResult {
                total_certificates: self.certificates_to_list.len() as u32,
                certificates: self.certificates_to_list.clone(),
            })
        }
        async fn prove_certificate(
            &self,
            _args: ProveCertificateArgs,
            _originator: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> {
            Ok(ProveCertificateResult {
                keyring_for_verifier: indexmap::IndexMap::new(),
                certificate: None,
                verifier: None,
            })
        }
        stub_method!(
            relinquish_certificate,
            RelinquishCertificateArgs,
            RelinquishCertificateResult
        );
        stub_method!(
            discover_by_identity_key,
            DiscoverByIdentityKeyArgs,
            DiscoverCertificatesResult
        );
        stub_method!(
            discover_by_attributes,
            DiscoverByAttributesArgs,
            DiscoverCertificatesResult
        );
        stub_method!(is_authenticated, AuthenticatedResult);
        stub_method!(wait_for_authentication, AuthenticatedResult);
        stub_method!(get_height, GetHeightResult);
        stub_method!(get_header_for_height, GetHeaderArgs, GetHeaderResult);
        stub_method!(get_network, GetNetworkResult);
        stub_method!(get_version, GetVersionResult);
    }

    // -----------------------------------------------------------------------
    // MockTransport: in-memory transport that routes between two peers
    // -----------------------------------------------------------------------

    /// A simple mock transport that routes messages to a paired transport.
    /// Each MockTransport has its own incoming channel and sends to its peer's.
    struct MockTransport {
        /// Sender for the peer's incoming channel.
        peer_tx: mpsc::Sender<AuthMessage>,
        /// Our incoming channel receiver (taken once by subscribe()).
        incoming_rx: StdMutex<Option<mpsc::Receiver<AuthMessage>>>,
        sent_messages: StdMutex<Vec<AuthMessage>>,
    }

    /// Test transport that delivers the first send, then holds its caller at
    /// the send await until explicitly released. Later sends are unaffected.
    /// This keeps the outer initiating call suspended while background receive
    /// routes responses for two concurrent handshakes.
    struct GatedFirstSendTransport {
        inner: Arc<MockTransport>,
        sends: AtomicUsize,
        first_sent: Notify,
        release_first: Notify,
    }

    #[async_trait]
    impl Transport for GatedFirstSendTransport {
        async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
            self.inner.send(message).await?;
            if self.sends.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_sent.notify_one();
                self.release_first.notified().await;
            }
            Ok(())
        }

        fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
            self.inner.subscribe()
        }
    }

    /// Create a paired set of mock transports.
    /// Messages sent by transport_a are received by transport_b and vice versa.
    fn create_mock_transport_pair() -> (Arc<MockTransport>, Arc<MockTransport>) {
        let (tx_a, rx_a) = mpsc::channel(32);
        let (tx_b, rx_b) = mpsc::channel(32);

        let transport_a = Arc::new(MockTransport {
            peer_tx: tx_b,
            incoming_rx: StdMutex::new(Some(rx_a)),
            sent_messages: StdMutex::new(Vec::new()),
        });

        let transport_b = Arc::new(MockTransport {
            peer_tx: tx_a,
            incoming_rx: StdMutex::new(Some(rx_b)),
            sent_messages: StdMutex::new(Vec::new()),
        });

        (transport_a, transport_b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_background_receive_dispatches_without_caller_pump() {
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
        let identity_b = wallet_identity(&wallet_b).await;
        let (transport_a, transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a);
        let peer_b = Peer::new(wallet_b, transport_b);
        let mut messages = peer_b.on_general_message().expect("general receiver");

        tokio::time::timeout(
            Duration::from_secs(1),
            peer_a.send_message(&identity_b, b"background delivery".to_vec()),
        )
        .await
        .expect("background receive task must complete the handshake")
        .expect("background send succeeds");

        let (_, payload) = tokio::time::timeout(Duration::from_secs(1), messages.recv())
            .await
            .expect("background receive task must dispatch the general message")
            .expect("general message channel remains open");
        assert_eq!(payload, b"background delivery");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_background_general_dispatch_is_concurrent_and_bounded() {
        let expected_width = 64;
        assert_eq!(MAX_IN_FLIGHT_GENERAL_DISPATCHES, expected_width);
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
        let probe = Arc::new(VerifyProbe {
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            entered: entered_tx,
            release: Semaphore::new(0),
        });
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b =
            TestWallet::with_verify_probe(PrivateKey::from_random().unwrap(), probe.clone());
        let identity_b = wallet_identity(&wallet_b).await;
        let (transport_a, transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a);
        let peer_b = Peer::new(wallet_b, transport_b);
        let mut messages = peer_b.on_general_message().expect("general receiver");
        let mut errors = peer_b.on_error().expect("background error receiver");

        bounded(peer_a.send_message(&identity_b, b"setup".to_vec()))
            .await
            .unwrap();
        assert_eq!(bounded(messages.recv()).await.unwrap().1, b"setup");

        for index in 0..=expected_width {
            peer_a
                .send_message(&identity_b, format!("dispatch-probe-{index}").into_bytes())
                .await
                .unwrap();
        }

        for _ in 0..expected_width {
            bounded(entered_rx.recv())
                .await
                .expect("every admitted dispatch reaches signature verification");
        }
        let capacity_error = bounded(errors.recv())
            .await
            .expect("overflow reports a background error");
        assert!(
            matches!(&capacity_error, AuthError::TransportError(message)
                if message.contains("general dispatch capacity exhausted")),
            "unexpected capacity error: {capacity_error:?}"
        );
        assert_eq!(
            probe.peak.load(Ordering::SeqCst),
            expected_width,
            "measured peak dispatch width must equal the configured bound"
        );

        probe.release.add_permits(expected_width);
        for _ in 0..expected_width {
            bounded(messages.recv())
                .await
                .expect("every admitted dispatch completes after release");
        }
        assert_eq!(probe.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_embedded_certificate_response_precedes_first_general_frame() {
        let private_a = PrivateKey::from_random().unwrap();
        let certificate =
            issue_certificate_for_subject(&private_a.to_public_key(), CertificateType([61; 32]))
                .await;
        let requested = requested_for_certificate(&certificate);
        let wallet_a = TestWallet::with_certificate(private_a, certificate);
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
        let identity_b = wallet_identity(&wallet_b).await;
        let (transport_a, transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a.clone());
        let peer_b = Peer::new(wallet_b, transport_b);
        peer_b.set_certificates_to_request(requested);

        bounded(peer_a.send_message(&identity_b, b"first general".to_vec()))
            .await
            .unwrap();

        let order: Vec<MessageType> = transport_a
            .sent_messages
            .lock()
            .unwrap()
            .iter()
            .map(|message| message.message_type.clone())
            .collect();
        assert_eq!(
            order,
            vec![
                MessageType::InitialRequest,
                MessageType::CertificateResponse,
                MessageType::General,
            ],
            "registered #23 divergence keeps proof-first wire order"
        );
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
            self.sent_messages
                .lock()
                .expect("sent messages lock poisoned")
                .push(message.clone());
            self.peer_tx
                .send(message)
                .await
                .map_err(|e| AuthError::TransportError(format!("mock send failed: {}", e)))
        }

        fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
            self.incoming_rx
                .lock()
                .unwrap()
                .take()
                .expect("subscribe() already called on MockTransport")
        }
    }

    async fn wallet_identity(wallet: &TestWallet) -> String {
        wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .public_key
            .to_der_hex()
    }

    async fn complete_mock_handshake(
        peer_a: Peer<TestWallet>,
        _peer_b: &Peer<TestWallet>,
        identity_b: &str,
    ) -> Peer<TestWallet> {
        let identity_b = identity_b.to_string();
        let send_handle = tokio::task::spawn_local(async move {
            peer_a
                .send_message(&identity_b, b"setup".to_vec())
                .await
                .unwrap();
            peer_a
        });

        bounded(send_handle).await.unwrap()
    }

    async fn issue_certificate_for_subject(
        subject: &PublicKey,
        cert_type: CertificateType,
    ) -> Certificate {
        let certifier_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let mut fields = indexmap::IndexMap::new();
        fields.insert("name".to_string(), "Test User".to_string());
        MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            subject,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap()
        .certificate
    }

    async fn issue_verifiable_certificate(
        subject_wallet: &TestWallet,
        verifier: &PublicKey,
        cert_type: CertificateType,
    ) -> VerifiableCertificate {
        let certifier_pk = PrivateKey::from_random().unwrap();
        let certifier_wallet = TestWallet::new(certifier_pk.clone());
        let subject = parse_public_key(&wallet_identity(subject_wallet).await).unwrap();
        let mut fields = indexmap::IndexMap::new();
        fields.insert("name".to_string(), "Test User".to_string());
        let master = MasterCertificate::issue_certificate_for_subject(
            &cert_type,
            &subject,
            fields,
            &certifier_wallet,
            default_get_revocation_outpoint,
            None,
        )
        .await
        .unwrap();
        let keyring = master
            .create_keyring_for_verifier(
                verifier,
                &["name".to_string()],
                &certifier_pk.to_public_key(),
                subject_wallet,
            )
            .await
            .unwrap();
        VerifiableCertificate::new(master.certificate, keyring)
    }

    fn requested_for_certificate(cert: &Certificate) -> RequestedCertificateSet {
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(cert.certifier.to_der_hex());
        requested.insert(
            cert_codec::base64_encode(&cert.cert_type.0),
            vec!["name".to_string()],
        );
        requested
    }

    fn anyone_private_key() -> PrivateKey {
        PrivateKey::from_bytes(&{
            let mut buf = [0u8; 32];
            buf[31] = 1;
            buf
        })
        .unwrap()
    }

    async fn signed_certificate_response(
        sender_wallet: &TestWallet,
        sender_identity: String,
        receiver_identity: &str,
        receiver_session_nonce: String,
        certificates: Option<Vec<VerifiableCertificate>>,
        requested_certificates: Option<RequestedCertificateSet>,
        nonce: Option<String>,
    ) -> AuthMessage {
        let nonce =
            nonce.unwrap_or_else(|| base64_encode(&crate::primitives::random::random_bytes(32)));
        let sign_data = match certificates.as_ref() {
            Some(certs) => serde_json::to_vec(certs).unwrap(),
            None => Vec::new(),
        };
        let signature = sender_wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id: format!("{} {}", nonce, receiver_session_nonce),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(parse_public_key(receiver_identity).unwrap()),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .signature;

        AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::CertificateResponse,
            identity_key: sender_identity,
            nonce: Some(nonce),
            your_nonce: Some(receiver_session_nonce),
            initial_nonce: None,
            certificates,
            requested_certificates,
            payload: None,
            signature: Some(signature),
        }
    }

    async fn signed_initial_response(
        responder_wallet: &TestWallet,
        responder_identity: String,
        requester_identity: &str,
        requester_session_nonce: String,
        certificates: Option<Vec<VerifiableCertificate>>,
    ) -> AuthMessage {
        let responder_session_nonce = create_nonce(responder_wallet).await.unwrap();
        let requester_nonce_bytes = base64_decode(&requester_session_nonce).unwrap();
        let responder_nonce_bytes = base64_decode(&responder_session_nonce).unwrap();
        let mut sign_data = requester_nonce_bytes;
        sign_data.extend_from_slice(&responder_nonce_bytes);

        let signature = responder_wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(sign_data),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id: format!("{} {}", requester_session_nonce, responder_session_nonce),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(parse_public_key(requester_identity).unwrap()),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .signature;

        AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialResponse,
            identity_key: responder_identity,
            nonce: None,
            your_nonce: Some(requester_session_nonce),
            initial_nonce: Some(responder_session_nonce),
            certificates,
            requested_certificates: None,
            payload: None,
            signature: Some(signature),
        }
    }

    async fn add_pending_handshake_session(
        peer: &Peer<TestWallet>,
        session_nonce: &str,
        expected_identity: &str,
        requested_certificates: Option<RequestedCertificateSet>,
    ) {
        let certificates_required = requested_certificates
            .as_ref()
            .is_some_and(|requested| !requested.certifiers.is_empty());
        peer.session_manager.write().await.add_session(PeerSession {
            session_nonce: session_nonce.to_string(),
            peer_identity_key: expected_identity.to_string(),
            peer_nonce: String::new(),
            is_authenticated: false,
            requested_certificates,
            certificates_required,
            certificates_validated: !certificates_required,
        });
    }

    type CertificateEvents = Arc<StdMutex<Vec<(String, Vec<VerifiableCertificate>)>>>;

    fn record_certificate_events(peer: &Peer<TestWallet>) -> CertificateEvents {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let listener_events = events.clone();
        peer.listen_for_certificates_received(Arc::new(move |sender, certificates| {
            let listener_events = listener_events.clone();
            Box::pin(async move {
                listener_events.lock().unwrap().push((sender, certificates));
                Ok(())
            })
        }));
        events
    }

    // -----------------------------------------------------------------------
    // Integration tests
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_before_handshake_is_refused_and_not_recorded() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let pk_a = PrivateKey::from_random().unwrap();
                let pk_b = PrivateKey::from_random().unwrap();
                let wallet_a = TestWallet::new(pk_a.clone());
                let wallet_b = TestWallet::new(pk_b.clone());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let cert = issue_certificate_for_subject(
                    &parse_public_key(&identity_a).unwrap(),
                    CertificateType([45; 32]),
                )
                .await;
                let valid_b_nonce = create_nonce(&TestWallet::new(pk_b.clone())).await.unwrap();

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a.clone());
                let peer_b = Peer::new(wallet_b, transport_b);
                let cert_events = record_certificate_events(&peer_b);

                let early_response = AuthMessage {
                    version: AUTH_VERSION.to_string(),
                    message_type: MessageType::CertificateResponse,
                    identity_key: identity_a.clone(),
                    nonce: Some(base64_encode(&crate::primitives::random::random_bytes(32))),
                    your_nonce: Some(valid_b_nonce),
                    initial_nonce: None,
                    certificates: Some(vec![VerifiableCertificate::new(
                        cert,
                        indexmap::IndexMap::new(),
                    )]),
                    requested_certificates: None,
                    payload: None,
                    signature: Some(vec![1, 2, 3]),
                };

                let err = bounded(peer_b.dispatch_message(early_response))
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, AuthError::SessionNotFound(_)),
                    "expected no-session certificateResponse to be refused, got {err:?}"
                );
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "certificateResponse processed before handshake must not reach consumers"
                );

                let peer_a = complete_mock_handshake(peer_a, &peer_b, &identity_b).await;
                assert!(!peer_a.sessions_for_identity(&identity_b).await.is_empty());
                assert!(!peer_b.sessions_for_identity(&identity_a).await.is_empty());
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "normal handshake must not expose certificates from the refused early frame"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_signature_survives_json_wire_round_trip() {
        let sender = TestWallet::new(PrivateKey::from_random().unwrap());
        let receiver = TestWallet::new(PrivateKey::from_random().unwrap());
        let sender_public_key = parse_public_key(&wallet_identity(&sender).await).unwrap();
        let receiver_public_key = parse_public_key(&wallet_identity(&receiver).await).unwrap();

        let mut fields = indexmap::IndexMap::new();
        fields.insert("zeta".to_string(), "six".to_string());
        fields.insert("alpha".to_string(), "one".to_string());
        fields.insert("theta".to_string(), "five".to_string());
        fields.insert("beta".to_string(), "two".to_string());
        fields.insert("delta".to_string(), "four".to_string());
        fields.insert("gamma".to_string(), "three".to_string());

        let certificates = vec![Certificate {
            cert_type: CertificateType([7; 32]),
            serial_number: SerialNumber([8; 32]),
            subject: sender_public_key.clone(),
            certifier: sender_public_key.clone(),
            revocation_outpoint: None,
            fields: Some(fields),
            signature: Some(vec![1, 2, 3]),
        }];
        let wire_bytes = serde_json::to_vec(&certificates).unwrap();
        let key_id = "wire-order-regression".to_string();
        let protocol_id = Protocol {
            security_level: 2,
            protocol: AUTH_PROTOCOL_ID.to_string(),
        };
        let signature = sender
            .create_signature(
                CreateSignatureArgs {
                    data: Some(wire_bytes.clone()),
                    hash_to_directly_sign: None,
                    protocol_id: protocol_id.clone(),
                    key_id: key_id.clone(),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(receiver_public_key),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .signature;

        // Exercise multiple independent deserializations so the old HashMap
        // representation cannot pass by happening to choose the sender's order.
        for _ in 0..32 {
            let received: Vec<Certificate> = serde_json::from_slice(&wire_bytes).unwrap();
            let reconstructed = serde_json::to_vec(&received).unwrap();
            let result = receiver
                .verify_signature(
                    VerifySignatureArgs {
                        data: Some(reconstructed),
                        hash_to_directly_verify: None,
                        signature: signature.clone(),
                        protocol_id: protocol_id.clone(),
                        key_id: key_id.clone(),
                        counterparty: Counterparty {
                            counterparty_type: CounterpartyType::Other,
                            public_key: Some(sender_public_key.clone()),
                        },
                        for_self: None,
                        privileged: false,
                        privileged_reason: None,
                        seek_permission: None,
                    },
                    None,
                )
                .await
                .unwrap();
            assert!(
                result.valid,
                "certificate response signature changed across the JSON wire round-trip"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_with_bad_signature_is_refused() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let pk_a = PrivateKey::from_random().unwrap();
                let wallet_a = TestWallet::new(pk_a.clone());
                let wallet_b = TestWallet::new(anyone_private_key());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);
                let cert_events = record_certificate_events(&peer_b);
                let peer_a = complete_mock_handshake(peer_a, &peer_b, &identity_b).await;
                let session_b = peer_b
                    .sessions_for_identity(&identity_a)
                    .await
                    .pop()
                    .expect("receiver session for sender");

                let cert = issue_certificate_for_subject(
                    &parse_public_key(&identity_a).unwrap(),
                    CertificateType([46; 32]),
                )
                .await;
                let attacker_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
                let msg = signed_certificate_response(
                    &attacker_wallet,
                    identity_a,
                    &identity_b,
                    session_b.session_nonce,
                    Some(vec![VerifiableCertificate::new(
                        cert,
                        indexmap::IndexMap::new(),
                    )]),
                    None,
                    None,
                )
                .await;

                let err = bounded(peer_b.dispatch_message(msg)).await.unwrap_err();
                assert!(
                    matches!(err, AuthError::InvalidSignature(_)),
                    "expected bad certificateResponse signature to be refused, got {err:?}"
                );
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "badly signed certificateResponse must not reach consumers"
                );
                drop(peer_a);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_replayed_message_nonce_is_refused() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let pk_a = PrivateKey::from_random().unwrap();
                let wallet_a = TestWallet::new(pk_a.clone());
                let wallet_b = TestWallet::new(anyone_private_key());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);
                let cert_events = record_certificate_events(&peer_b);
                let peer_a = complete_mock_handshake(peer_a, &peer_b, &identity_b).await;
                let session_b = peer_b
                    .sessions_for_identity(&identity_a)
                    .await
                    .pop()
                    .expect("receiver session for sender");

                let cert = issue_verifiable_certificate(
                    &peer_a.wallet,
                    &parse_public_key(&identity_b).unwrap(),
                    CertificateType([47; 32]),
                )
                .await;
                let msg = signed_certificate_response(
                    &peer_a.wallet,
                    identity_a.clone(),
                    &identity_b,
                    session_b.session_nonce,
                    Some(vec![cert]),
                    None,
                    None,
                )
                .await;

                bounded(peer_b.dispatch_message(msg.clone())).await.unwrap();
                let (sender, certs) = cert_events.lock().unwrap()[0].clone();
                assert_eq!(sender, identity_a);
                assert_eq!(certs.len(), 1);

                let err = bounded(peer_b.dispatch_message(msg)).await.unwrap_err();
                assert!(
                    matches!(err, AuthError::ReplayDetected(_)),
                    "expected replayed certificateResponse nonce to be refused, got {err:?}"
                );
                assert!(
                    cert_events.lock().unwrap().len() == 1,
                    "replayed certificateResponse must not reach consumers"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_with_unissued_your_nonce_is_refused() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(anyone_private_key());
                let identity_a = wallet_identity(&wallet_a).await;
                let (transport_a, transport_b) = create_mock_transport_pair();
                let _peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);

                let msg = AuthMessage {
                    version: AUTH_VERSION.to_string(),
                    message_type: MessageType::CertificateResponse,
                    identity_key: identity_a,
                    nonce: Some(base64_encode(&crate::primitives::random::random_bytes(32))),
                    your_nonce: Some(base64_encode(&crate::primitives::random::random_bytes(48))),
                    initial_nonce: None,
                    certificates: Some(Vec::new()),
                    requested_certificates: None,
                    payload: None,
                    signature: Some(Vec::new()),
                };

                let err = bounded(peer_b.dispatch_message(msg)).await.unwrap_err();
                assert!(
                    matches!(err, AuthError::InvalidNonce(_)),
                    "expected unissued yourNonce to be refused before session lookup, got {err:?}"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_delivers_validated_certificates() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let pk_a = PrivateKey::from_random().unwrap();
                let wallet_a = TestWallet::new(pk_a.clone());
                let wallet_b = TestWallet::new(anyone_private_key());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);
                let cert_events = record_certificate_events(&peer_b);
                let peer_a = complete_mock_handshake(peer_a, &peer_b, &identity_b).await;
                let session_b = peer_b
                    .sessions_for_identity(&identity_a)
                    .await
                    .pop()
                    .expect("receiver session for sender");

                let cert = issue_verifiable_certificate(
                    &peer_a.wallet,
                    &parse_public_key(&identity_b).unwrap(),
                    CertificateType([48; 32]),
                )
                .await;
                let serial = cert.serial_number.clone();
                let requested = requested_for_certificate(&cert);
                let msg = signed_certificate_response(
                    &peer_a.wallet,
                    identity_a.clone(),
                    &identity_b,
                    session_b.session_nonce,
                    Some(vec![cert]),
                    Some(requested),
                    None,
                )
                .await;

                bounded(peer_b.dispatch_message(msg)).await.unwrap();
                let (sender, certs) = cert_events.lock().unwrap()[0].clone();
                assert_eq!(sender, identity_a);
                assert_eq!(certs.len(), 1);
                assert_eq!(certs[0].serial_number, serial);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_certificate_response_rejected_certificates_do_not_reach_consumers() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let pk_a = PrivateKey::from_random().unwrap();
                let wallet_a = TestWallet::new(pk_a);
                let wallet_b = TestWallet::new(anyone_private_key());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);
                let cert_events = record_certificate_events(&peer_b);
                let peer_a = complete_mock_handshake(peer_a, &peer_b, &identity_b).await;
                let mut session_b = peer_b
                    .sessions_for_identity(&identity_a)
                    .await
                    .pop()
                    .expect("receiver session for sender");
                session_b.certificates_required = true;
                session_b.certificates_validated = false;
                peer_b
                    .session_manager
                    .write()
                    .await
                    .update_session(&session_b.session_nonce, session_b.clone());

                let cert = issue_certificate_for_subject(
                    &parse_public_key(&identity_a).unwrap(),
                    CertificateType([49; 32]),
                )
                .await;
                let requested = requested_for_certificate(&cert);
                let msg = signed_certificate_response(
                    &peer_a.wallet,
                    identity_a,
                    &identity_b,
                    session_b.session_nonce.clone(),
                    Some(vec![VerifiableCertificate::new(
                        cert,
                        indexmap::IndexMap::new(),
                    )]),
                    Some(requested),
                    None,
                )
                .await;

                let err = bounded(peer_b.dispatch_message(msg)).await.unwrap_err();
                assert!(
                    matches!(err, AuthError::CertificateValidation(_)),
                    "expected invalid certificate set to be refused, got {err:?}"
                );
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "certificateResponse rejected by validate_certificates must not reach consumers"
                );
                let pending = peer_b
                    .wait_for_certificate_validation_with_timeout(
                        &session_b,
                        Duration::from_millis(20),
                    )
                    .await;
                assert!(
                    matches!(pending, Err(AuthError::Timeout(_))),
                    "a validation error belongs to its response and leaves the gate pending: {pending:?}"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_initial_response_rejected_certificates_do_not_reach_consumers() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(anyone_private_key());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let wrong_subject = PrivateKey::from_random().unwrap();
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, _transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let cert_events = record_certificate_events(&peer_a);

                let cert = issue_certificate_for_subject(
                    &wrong_subject.to_public_key(),
                    CertificateType([50; 32]),
                )
                .await;
                let requested = requested_for_certificate(&cert);
                peer_a.set_certificates_to_request(requested.clone());
                let session_nonce = create_nonce(&peer_a.wallet).await.unwrap();
                add_pending_handshake_session(
                    &peer_a,
                    &session_nonce,
                    &identity_b,
                    Some(requested),
                )
                .await;
                let response = signed_initial_response(
                    &wallet_b,
                    identity_b.clone(),
                    &identity_a,
                    session_nonce.clone(),
                    Some(vec![VerifiableCertificate::new(
                        cert,
                        indexmap::IndexMap::new(),
                    )]),
                )
                .await;

                let err = peer_a
                    .complete_handshake(&session_nonce, response)
                    .await
                    .unwrap_err();
                match err {
                    AuthError::CertificateValidation(message) => {
                        assert!(
                            message.contains("initialResponse certificate validation failed"),
                            "error should name initialResponse certificate validation, got {message}"
                        );
                        assert!(
                            message.contains(&identity_b),
                            "error should identify the verified peer, got {message}"
                        );
                    }
                    other => panic!("expected certificate validation error, got {other:?}"),
                }
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "initialResponse certificates rejected by validate_certificates must not reach consumers"
                );
                let session = peer_a
                    .sessions_for_identity(&identity_b)
                    .await
                    .pop()
                    .expect("signature-verified initialResponse still authenticates the session");
                assert!(session.is_authenticated);
                assert!(session.certificates_required);
                assert!(!session.certificates_validated);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_initial_response_delivers_validated_certificates() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(anyone_private_key());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, _transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let cert_events = record_certificate_events(&peer_a);

                let cert = issue_verifiable_certificate(
                    &wallet_b,
                    &parse_public_key(&identity_a).unwrap(),
                    CertificateType([51; 32]),
                )
                .await;
                let serial = cert.serial_number.clone();
                let requested = requested_for_certificate(&cert);
                peer_a.set_certificates_to_request(requested.clone());
                let session_nonce = create_nonce(&peer_a.wallet).await.unwrap();
                add_pending_handshake_session(
                    &peer_a,
                    &session_nonce,
                    &identity_b,
                    Some(requested),
                )
                .await;
                let response = signed_initial_response(
                    &wallet_b,
                    identity_b.clone(),
                    &identity_a,
                    session_nonce.clone(),
                    Some(vec![cert]),
                )
                .await;

                let session = peer_a
                    .complete_handshake(&session_nonce, response)
                    .await
                    .unwrap();
                assert_eq!(session.peer_identity_key, identity_b);
                assert!(session.is_authenticated);
                assert!(session.certificates_required);
                assert!(session.certificates_validated);

                let (sender, certs) = cert_events.lock().unwrap()[0].clone();
                assert_eq!(sender, identity_b);
                assert_eq!(certs.len(), 1);
                assert_eq!(certs[0].serial_number, serial);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_initial_response_ignores_certificates_when_none_requested() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let wrong_subject = PrivateKey::from_random().unwrap();
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, _transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let cert_events = record_certificate_events(&peer_a);

                let cert = issue_certificate_for_subject(
                    &wrong_subject.to_public_key(),
                    CertificateType([52; 32]),
                )
                .await;
                let session_nonce = create_nonce(&peer_a.wallet).await.unwrap();
                add_pending_handshake_session(&peer_a, &session_nonce, &identity_b, None).await;
                let response = signed_initial_response(
                    &wallet_b,
                    identity_b.clone(),
                    &identity_a,
                    session_nonce.clone(),
                    Some(vec![VerifiableCertificate::new(
                        cert,
                        indexmap::IndexMap::new(),
                    )]),
                )
                .await;

                let session = peer_a
                    .complete_handshake(&session_nonce, response)
                    .await
                    .unwrap();
                assert_eq!(session.peer_identity_key, identity_b);
                assert!(session.is_authenticated);
                assert!(!session.certificates_required);
                assert!(session.certificates_validated);
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "initialResponse certificates must not be delivered when none were requested"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_initial_response_empty_certificates_leave_gate_pending() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let identity_a = wallet_identity(&wallet_a).await;
                let identity_b = wallet_identity(&wallet_b).await;

                let (transport_a, _transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let cert_events = record_certificate_events(&peer_a);

                let requested_cert = issue_certificate_for_subject(
                    &parse_public_key(&identity_b).unwrap(),
                    CertificateType([53; 32]),
                )
                .await;
                let requested = requested_for_certificate(&requested_cert);
                peer_a.set_certificates_to_request(requested.clone());
                let session_nonce = create_nonce(&peer_a.wallet).await.unwrap();
                add_pending_handshake_session(
                    &peer_a,
                    &session_nonce,
                    &identity_b,
                    Some(requested),
                )
                .await;
                let response = signed_initial_response(
                    &wallet_b,
                    identity_b.clone(),
                    &identity_a,
                    session_nonce.clone(),
                    Some(Vec::new()),
                )
                .await;

                let session = peer_a
                    .complete_handshake(&session_nonce, response)
                    .await
                    .unwrap();
                assert_eq!(session.peer_identity_key, identity_b);
                assert!(session.is_authenticated);
                assert!(session.certificates_required);
                assert!(!session.certificates_validated);
                assert!(
                    cert_events.lock().unwrap().is_empty(),
                    "TS's initialResponse length guard ignores empty certificate arrays"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_full_handshake_and_message_exchange() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // Create two wallets
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

                // Get identity keys
                let identity_a = wallet_a
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                // Create transport pair
                let (transport_a, transport_b) = create_mock_transport_pair();

                // Create peers
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);

                // Set up message receivers before starting
                let mut msg_rx_b = peer_b.on_general_message().unwrap();

                // Peer A sends; both peers' background receive tasks drive the
                // handshake and dispatch the trailing general frame.
                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"Hello from Peer A!".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });

                let peer_a = bounded(send_handle).await.unwrap();
                let (sender_key, received_payload) = bounded(msg_rx_b.recv())
                    .await
                    .expect("background-dispatched general message");
                assert_eq!(sender_key, identity_a);
                assert_eq!(received_payload, b"Hello from Peer A!");

                // Verify both peers have authenticated sessions
                let sessions_a = peer_a.sessions_for_identity(&identity_b).await;
                assert!(
                    !sessions_a.is_empty(),
                    "Peer A should have a session for Peer B"
                );
                assert!(
                    sessions_a[0].is_authenticated,
                    "Peer A session should be authenticated"
                );

                let sessions_b = peer_b.sessions_for_identity(&identity_a).await;
                assert!(
                    !sessions_b.is_empty(),
                    "Peer B should have a session for Peer A"
                );
                assert!(
                    sessions_b[0].is_authenticated,
                    "Peer B session should be authenticated"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cert_request_listener_fires_on_handshake_requested_certs() {
        // When peer A asks peer B for certificates (via
        // set_certificates_to_request -> initialRequest.requestedCertificates),
        // peer B's handle_initial_request fires any registered listener
        // instead of attempting to fetch+include certs itself.
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);

                // Peer A requests a certificate type from peer B.
                let mut requested = RequestedCertificateSet::default();
                requested.certifiers.push("certifier-key-1".to_string());
                requested.insert("dGVzdA==".to_string(), vec!["name".to_string()]);
                peer_a.set_certificates_to_request(requested);

                // Register a listener on peer B that records invocations.
                let seen = Arc::new(StdMutex::new(
                    Vec::<(String, RequestedCertificateSet)>::new(),
                ));
                let seen_cb = seen.clone();
                peer_b.listen_for_certificates_requested(Arc::new(move |key, req| {
                    seen_cb.lock().unwrap().push((key, req));
                }));

                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    let result = peer_a.get_authenticated_session(&identity_b_clone).await;
                    (peer_a, result)
                });

                let (_peer_a, session) = bounded(send_handle).await.unwrap();
                let session = session.expect("transport handshake completes");
                assert!(session.is_authenticated);
                assert!(session.certificates_required);
                assert!(!session.certificates_validated);

                let recorded = seen.lock().unwrap();
                assert_eq!(
                    recorded.len(),
                    1,
                    "listener on peer B should fire exactly once during handshake"
                );
                assert_eq!(recorded[0].1.certifiers, vec!["certifier-key-1"]);
                assert!(recorded[0].1.types.contains_key("dGVzdA=="));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stop_listening_removes_only_targeted_callback() {
        // Verify stop_listening_for_certificates_requested removes only the
        // named callback. Register two listeners, stop one, handshake with
        // a cert request, and assert only the non-removed listener fires.
        // (This avoids exercising the auto-response path whose wallet
        // stubs would otherwise panic inside background dispatch.)
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);

                let mut requested = RequestedCertificateSet::default();
                requested.certifiers.push("certifier-key-1".to_string());
                requested.insert("dGVzdA==".to_string(), vec!["name".to_string()]);
                peer_a.set_certificates_to_request(requested);

                let hits_removed = Arc::new(StdMutex::new(0u32));
                let hits_kept = Arc::new(StdMutex::new(0u32));
                let hr = hits_removed.clone();
                let hk = hits_kept.clone();

                let id_removed =
                    peer_b.listen_for_certificates_requested(Arc::new(move |_k, _r| {
                        *hr.lock().unwrap() += 1;
                    }));
                peer_b.listen_for_certificates_requested(Arc::new(move |_k, _r| {
                    *hk.lock().unwrap() += 1;
                }));
                peer_b.stop_listening_for_certificates_requested(id_removed);

                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    let result = peer_a.get_authenticated_session(&identity_b_clone).await;
                    (peer_a, result)
                });

                let (_peer_a, session) = bounded(send_handle).await.unwrap();
                let session = session.expect("transport handshake completes");
                assert!(session.is_authenticated);
                assert!(session.certificates_required);
                assert!(!session.certificates_validated);

                assert_eq!(
                    *hits_removed.lock().unwrap(),
                    0,
                    "removed listener must not fire"
                );
                assert_eq!(
                    *hits_kept.lock().unwrap(),
                    1,
                    "remaining listener must still fire"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cert_request_listener_receives_with_empty_certifiers_skipped() {
        // Guard: TS Peer.ts:512-515 only branches into listener/auto-response
        // when certifiers.len() > 0. Rust must match — otherwise a peer
        // advertising empty certifiers could trigger spurious listener
        // fires. Verified here by sending handshake with empty certifiers
        // and asserting the listener does not fire.
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a);
                let peer_b = Peer::new(wallet_b, transport_b);

                // Empty certifiers means "no cert request" per TS parity.
                let requested = RequestedCertificateSet::default();
                peer_a.set_certificates_to_request(requested);

                let seen = Arc::new(StdMutex::new(0u32));
                let seen_cb = seen.clone();
                peer_b.listen_for_certificates_requested(Arc::new(move |_k, _r| {
                    *seen_cb.lock().unwrap() += 1;
                }));

                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"hello".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });

                let _ = bounded(send_handle).await.unwrap();

                assert_eq!(
                    *seen.lock().unwrap(),
                    0,
                    "listener must not fire when certifiers is empty (TS parity)"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_send_certificate_response_is_signed() {
        // Regression guard for the TS-parity signing fix: outgoing
        // CertificateResponse must carry a non-empty `signature`.
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
                let identity_a = parse_public_key(&wallet_identity(&wallet_a).await).unwrap();

                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                // Build a one-way transport that captures what peer A sends
                // so we can inspect the CertificateResponse wire message.
                let (transport_a, transport_b) = create_mock_transport_pair();
                let peer_a = Peer::new(wallet_a, transport_a.clone());
                let _peer_b = Peer::new(wallet_b, transport_b);

                // Handshake via send_message so both sides end up with
                // authenticated sessions.
                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"setup".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });
                let peer_a = bounded(send_handle).await.unwrap();

                let certificate = Certificate {
                    cert_type: CertificateType([0x21; 32]),
                    serial_number: SerialNumber([0x22; 32]),
                    subject: identity_a.clone(),
                    certifier: identity_a,
                    revocation_outpoint: None,
                    fields: None,
                    signature: None,
                };
                let mut keyring = indexmap::IndexMap::new();
                keyring.insert("name".to_string(), "a2V5cmluZw==".to_string());

                // Now peer A explicitly sends a verifier-ready response to B.
                peer_a
                    .send_certificate_response(
                        &identity_b,
                        vec![VerifiableCertificate::new(certificate, keyring)],
                    )
                    .await
                    .unwrap();

                // Inspect the sender-side wire record; the receiver is owned
                // permanently by peer B's background task.
                let msg = transport_a
                    .sent_messages
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|message| message.message_type == MessageType::CertificateResponse)
                    .cloned()
                    .expect("signed certificateResponse was sent");

                assert_eq!(msg.message_type, MessageType::CertificateResponse);
                assert!(msg.nonce.is_some(), "request nonce must be populated");
                assert_eq!(
                    msg.certificates.as_ref().unwrap()[0].keyring["name"],
                    "a2V5cmluZw=="
                );
                assert!(
                    msg.signature
                        .as_ref()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false),
                    "CertificateResponse must carry a non-empty signature (TS parity)"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_handshake_creates_sessions_for_both_peers() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
                let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

                let identity_b = wallet_b
                    .get_public_key(
                        GetPublicKeyArgs {
                            identity_key: true,
                            protocol_id: None,
                            key_id: None,
                            counterparty: None,
                            privileged: false,
                            privileged_reason: None,
                            for_self: None,
                            seek_permission: None,
                        },
                        None,
                    )
                    .await
                    .unwrap()
                    .public_key
                    .to_der_hex();

                let (transport_a, transport_b) = create_mock_transport_pair();

                let peer_a = Peer::new(wallet_a, transport_a);
                let _peer_b = Peer::new(wallet_b, transport_b);

                // Background-driven handshake
                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"test".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });

                let peer_a = bounded(send_handle).await.unwrap();

                // Peer A should have a session for Peer B
                assert!(
                    peer_a.session_by_identifier(&identity_b).await.is_some(),
                    "Peer A should track Peer B session"
                );
            })
            .await;
    }

    /// Concurrency regression: N general messages on ONE authenticated session
    /// must all verify via the lock-free `&self` hot path on an `Arc<Peer>`,
    /// concurrently, without touching the transport receiver.
    ///
    /// This is the server-middleware shape: the responder (peer B) holds an
    /// `Arc<Peer>` and fans out `verify_general_message` across many in-flight
    /// requests bound to the same session. Proves SessionManager's `RwLock`
    /// allows concurrent reads and that verify has no `&mut self` requirement.
    #[tokio::test]
    async fn test_outbound_general_omits_initial_nonce_like_typescript() {
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());
        let identity_b = wallet_identity(&wallet_b).await;
        let (transport_a, _transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a);
        let session_nonce = "rust-general-session".to_string();

        peer_a
            .session_manager
            .write()
            .await
            .add_session(PeerSession {
                session_nonce: session_nonce.clone(),
                peer_identity_key: identity_b,
                peer_nonce: "peer-general-session".to_string(),
                is_authenticated: true,
                requested_certificates: Some(RequestedCertificateSet::default()),
                certificates_required: false,
                certificates_validated: true,
            });

        let message = tokio::time::timeout(
            Duration::from_secs(2),
            peer_a.create_general_message(&session_nonce, b"wire-shape".to_vec()),
        )
        .await
        .expect("general-message creation is time-bounded")
        .expect("general-message creation succeeds");

        assert!(
            message.initial_nonce.is_none(),
            "TS Peer.send omits initialNonce from general messages"
        );
        assert!(!serde_json::to_string(&message)
            .unwrap()
            .contains("initialNonce"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_general_message_verify_one_session() {
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

        let identity_b = wallet_b
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .public_key
            .to_der_hex();

        let (transport_a, transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a);
        let peer_b = Peer::new(wallet_b, transport_b);

        // Drive the handshake A -> B; background receive owns progress.
        let identity_b_clone = identity_b.clone();
        let send_handle = tokio::spawn(async move {
            peer_a
                .get_authenticated_session(&identity_b_clone)
                .await
                .unwrap();
            peer_a
        });

        let peer_a = bounded(send_handle).await.unwrap();

        // Build N signed general messages from A bound to the same session.
        // Each carries your_nonce = B's session_nonce, which B verifies
        // against on the inbound hot path.
        let n = 16usize;
        let mut messages = Vec::with_capacity(n);
        for i in 0..n {
            let payload = format!("concurrent-msg-{i}").into_bytes();
            let msg = peer_a
                .create_general_message(&identity_b, payload)
                .await
                .expect("create_general_message");
            messages.push(msg);
        }

        // Wrap B in Arc and verify all N concurrently via the &self hot path.
        let peer_b_arc = Arc::new(peer_b);
        let mut handles = Vec::with_capacity(n);
        for msg in messages {
            let pb = peer_b_arc.clone();
            handles.push(tokio::spawn(
                async move { pb.verify_general_message(msg).await },
            ));
        }

        for h in handles {
            h.await.unwrap().expect("concurrent verify must succeed");
        }
    }

    /// Full interior-mutability proof: a SINGLE `Arc<Peer>` services a live
    /// handshake (responder-side background dispatch driving
    /// `handle_initial_request`, which takes a `SessionManager` write lock)
    /// AND, interleaved on the very same
    /// `Arc`, a fan-out of concurrent `verify_general_message` calls (lock-free
    /// against the handshake mutex, `SessionManager` *read* lock only) — all
    /// WITHOUT any outer `Mutex<Peer>`.
    ///
    /// This is the server-middleware shape end-to-end. To interleave a genuine
    /// B-side handshake-handler invocation with the verifies on ONE Arc, the
    /// client A sends another live frame right as the verify fan-out launches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_handshake_and_concurrent_verify_on_one_arc_peer() {
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

        let identity_b = wallet_b
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .public_key
            .to_der_hex();

        let (transport_a, transport_b) = create_mock_transport_pair();
        // A is wrapped in an Arc<Peer> too, proving send_message is &self.
        let peer_a = Arc::new(Peer::new(wallet_a, transport_a));
        let peer_b = Arc::new(Peer::new(wallet_b, transport_b));

        // 1. Establish A -> B session without caller-driven progress.
        let pa = peer_a.clone();
        let id_b = identity_b.clone();
        let send_handle =
            tokio::spawn(async move { pa.send_message(&id_b, b"handshake".to_vec()).await });
        bounded(send_handle).await.unwrap().unwrap();

        // 2. Build N signed general messages from A bound to B's session.
        let n = 16usize;
        let mut messages = Vec::with_capacity(n);
        for i in 0..n {
            let payload = format!("interleaved-msg-{i}").into_bytes();
            let msg = peer_a
                .create_general_message(&identity_b, payload)
                .await
                .expect("create_general_message");
            messages.push(msg);
        }

        // 3. Send another live background-dispatched frame while the direct
        //    verification fan-out uses the same Arc<Peer>.
        let pa2 = peer_a.clone();
        let id_b2 = identity_b.clone();
        let second_handshake = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                pa2.send_message(&id_b2, b"handshake-2".to_vec()),
            )
            .await;
        });

        // 4. Direct verification and background dispatch share the same peer.
        let mut handles = Vec::with_capacity(n);
        for msg in messages {
            let pb = peer_b.clone();
            handles.push(tokio::spawn(
                async move { pb.verify_general_message(msg).await },
            ));
        }

        for h in handles {
            h.await
                .unwrap()
                .expect("concurrent verify must succeed during a live handshake");
        }

        bounded(second_handshake).await.unwrap();

        // Sanity: A still tracks its (first) authenticated session to B after
        // all the interleaved activity.
        let session = peer_a.session_by_identifier(&identity_b).await;
        assert!(
            session.map(|s| s.is_authenticated).unwrap_or(false),
            "A must still hold an authenticated session to B after interleaving"
        );
    }

    /// Drive an A -> B handshake and return `(peer_a, Arc<peer_b>, identity_b)`
    /// with B holding an authenticated session for A. Shared setup for the
    /// anti-replay tests.
    async fn authenticated_pair() -> (Peer<TestWallet>, Arc<Peer<TestWallet>>, String) {
        let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
        let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

        let identity_b = wallet_b
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .public_key
            .to_der_hex();

        let (transport_a, transport_b) = create_mock_transport_pair();
        let peer_a = Peer::new(wallet_a, transport_a);
        let peer_b = Peer::new(wallet_b, transport_b);

        let identity_b_clone = identity_b.clone();
        let send_handle = tokio::spawn(async move {
            peer_a
                .get_authenticated_session(&identity_b_clone)
                .await
                .unwrap();
            peer_a
        });

        let peer_a = bounded(send_handle).await.unwrap();

        (peer_a, Arc::new(peer_b), identity_b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_outbound_general_message_is_blocked_until_certificates_validate() {
        let (peer_a, _peer_b, identity_b) = authenticated_pair().await;
        let session_nonce = peer_a
            .session_by_identifier(&identity_b)
            .await
            .expect("authenticated session")
            .session_nonce;
        let session = {
            let mut sessions = peer_a.session_manager.write().await;
            let session = sessions
                .get_session_mut(&session_nonce)
                .expect("session by nonce");
            session.certificates_required = true;
            session.certificates_validated = false;
            session.clone()
        };

        let result = peer_a
            .create_general_message_from_session(&session, b"must wait".to_vec())
            .await;

        assert!(
            matches!(&result, Err(AuthError::CertificateValidation(message))
                if message == "Cannot send general message before certificate validation is complete"),
            "general message was created before certificate validation: {result:?}"
        );

        let result = peer_a
            .send_message(&identity_b, b"must fail immediately".to_vec())
            .now_or_never()
            .expect("TS rejects an outbound send synchronously at the certificate gate");
        assert!(
            matches!(result, Err(AuthError::CertificateValidation(_))),
            "send_message must expose the same immediate gate error: {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_public_outbound_apis_reject_the_same_pending_gate_immediately() {
        let (peer_a, _peer_b, identity_b) = authenticated_pair().await;
        let mut session = peer_a.session_by_identifier(&identity_b).await.unwrap();
        session.certificates_required = true;
        session.certificates_validated = false;
        peer_a
            .session_manager
            .write()
            .await
            .update_session(&session.session_nonce, session.clone());

        let create = peer_a
            .create_general_message(&identity_b, b"create".to_vec())
            .now_or_never()
            .expect("create_general_message must not pump a pending certificate gate");
        assert!(
            matches!(create, Err(AuthError::CertificateValidation(_))),
            "create_general_message must reject the pending gate: {create:?}"
        );
        let send = peer_a
            .send_message(&identity_b, b"send".to_vec())
            .now_or_never()
            .expect("send_message must not pump a pending certificate gate");
        assert!(
            matches!(send, Err(AuthError::CertificateValidation(_))),
            "send_message must reject the pending gate: {send:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_inbound_general_message_waits_in_its_dispatch_task() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut messages = peer_b.on_general_message().expect("general receiver");
        while messages.try_recv().is_ok() {}
        let message = peer_a
            .create_general_message(&identity_b, b"must wait".to_vec())
            .await
            .expect("sender can create general message");
        let session_nonce = message.your_nonce.clone().expect("receiver session nonce");
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions
                .get_session_mut(&session_nonce)
                .expect("receiver session");
            session.certificates_required = true;
            session.certificates_validated = false;
        }

        let mut dispatch = Box::pin(peer_b.dispatch_message(message));
        assert!(
            dispatch.as_mut().now_or_never().is_none(),
            "the independent dispatch task must wait at the certificate gate"
        );
        assert!(
            messages.try_recv().is_err(),
            "a gated payload must not be delivered before validation"
        );

        {
            let mut sessions = peer_b.session_manager.write().await;
            sessions
                .get_session_mut(&session_nonce)
                .unwrap()
                .certificates_validated = true;
        }
        peer_b.resolve_certificate_validation(&session_nonce);
        bounded(dispatch)
            .await
            .expect("dispatch releases after validation");
        assert_eq!(bounded(messages.recv()).await.unwrap().1, b"must wait");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unverified_gated_general_message_fails_before_waiting() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut message = peer_a
            .create_general_message(&identity_b, b"forged".to_vec())
            .await
            .unwrap();
        let session_nonce = message.your_nonce.clone().unwrap();
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
        }
        let last = message.signature.as_ref().unwrap().len() - 1;
        message.signature.as_mut().unwrap()[last] ^= 0x01;

        let error = bounded(peer_b.dispatch_message(message))
            .await
            .expect_err("an invalid pending frame is rejected before gate wait");
        assert!(matches!(error, AuthError::InvalidSignature(_)));
        assert!(!peer_b
            .certificate_validation_waiters
            .lock()
            .unwrap()
            .contains_key(&session_nonce));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_direct_general_verification_rejects_pending_gate_immediately() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut message = peer_a
            .create_general_message(&identity_b, b"verify gate".to_vec())
            .await
            .unwrap();
        let session_nonce = message.your_nonce.clone().unwrap();
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
        }

        let last = message.signature.as_ref().unwrap().len() - 1;
        message.signature.as_mut().unwrap()[last] ^= 0x01;
        let verification = peer_b
            .verify_general_message(message)
            .now_or_never()
            .expect("pending-gate middleware verification must return immediately");
        assert!(
            matches!(verification, Err(AuthError::CertificateValidation(_))),
            "the gate must reject before forged-signature work: {verification:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dispatch_general_resolves_nonce_once() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut messages = peer_b.on_general_message().unwrap();
        while messages.try_recv().is_ok() {}
        let message = peer_a
            .create_general_message(&identity_b, b"one nonce check".to_vec())
            .await
            .unwrap();
        peer_b.wallet.verify_hmac_calls.store(0, Ordering::Relaxed);

        bounded(peer_b.dispatch_message(message)).await.unwrap();

        assert_eq!(
            peer_b.wallet.verify_hmac_calls.load(Ordering::Relaxed),
            1,
            "dispatch must thread its resolved session into general verification"
        );
        assert_eq!(
            bounded(messages.recv()).await.unwrap().1,
            b"one nonce check"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_background_dispatch_isolates_one_message_failure_and_continues() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut messages = peer_b.on_general_message().unwrap();
        let mut errors = peer_b.on_error().unwrap();
        while messages.try_recv().is_ok() {}
        let valid = peer_a
            .create_general_message(&identity_b, b"survives".to_vec())
            .await
            .unwrap();
        let mut invalid = valid.clone();
        invalid.version = "hostile-version".to_string();
        peer_a.transport.send(invalid).await.unwrap();
        peer_a.transport.send(valid).await.unwrap();

        assert!(matches!(
            bounded(errors.recv()).await.unwrap(),
            AuthError::InvalidMessage(_)
        ));
        assert_eq!(bounded(messages.recv()).await.unwrap().1, b"survives");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_background_dispatch_reports_the_frames_error() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let mut errors = peer_b.on_error().unwrap();
        let mut invalid = peer_a
            .create_general_message(&identity_b, b"invalid version".to_vec())
            .await
            .unwrap();
        invalid.version = "hostile-version".to_string();
        peer_a.transport.send(invalid).await.unwrap();

        let error = bounded(errors.recv())
            .await
            .expect("background error channel remains open");

        assert!(matches!(error, AuthError::InvalidMessage(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_background_errors_do_not_cross_peer_boundaries() {
        let (peer_a1, peer_b1, identity_b1) = authenticated_pair().await;
        let (peer_a2, peer_b2, identity_b2) = authenticated_pair().await;
        let mut errors_b1 = peer_b1.on_error().unwrap();
        let mut errors_b2 = peer_b2.on_error().unwrap();
        let mut messages_b2 = peer_b2.on_general_message().unwrap();

        let mut invalid = peer_a1
            .create_general_message(&identity_b1, b"peer one failure".to_vec())
            .await
            .unwrap();
        invalid.version = "hostile-version".to_string();
        peer_a1.transport.send(invalid).await.unwrap();
        peer_a2
            .send_message(&identity_b2, b"peer two success".to_vec())
            .await
            .unwrap();

        assert!(matches!(
            bounded(errors_b1.recv()).await.unwrap(),
            AuthError::InvalidMessage(_)
        ));
        assert_eq!(
            bounded(messages_b2.recv()).await.unwrap().1,
            b"peer two success"
        );
        assert!(matches!(
            errors_b2.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_hostile_general_before_certificate_response_does_not_block_drain() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let mut messages = peer_b.on_general_message().expect("general receiver");
        while messages.try_recv().is_ok() {}
        let general = peer_a
            .create_general_message(&identity_b, b"ordered payload".to_vec())
            .await
            .unwrap();
        let session_nonce = general.your_nonce.clone().unwrap();
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
        }
        let certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([56; 32]),
        )
        .await;
        let requested = requested_for_certificate(&certificate);
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a,
            &identity_b,
            session_nonce,
            Some(vec![certificate]),
            Some(requested),
            None,
        )
        .await;
        peer_a.transport.send(general).await.unwrap();
        peer_a.transport.send(response).await.unwrap();

        assert_eq!(
            bounded(messages.recv()).await.unwrap().1,
            b"ordered payload"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_gated_general_dispatch_has_an_independent_timeout() {
        assert_eq!(CERTIFICATE_WAIT_TIMEOUT, Duration::from_secs(30));
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let message = peer_a
            .create_general_message(&identity_b, b"expire me".to_vec())
            .await
            .unwrap();
        let session_nonce = message.your_nonce.clone().unwrap();
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
        }

        let dispatch = {
            let peer_b = peer_b.clone();
            tokio::spawn(async move { peer_b.dispatch_message(message).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if peer_b
                    .certificate_validation_waiters
                    .lock()
                    .unwrap()
                    .contains_key(&session_nonce)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gated dispatch waiter registered");
        tokio::time::advance(CERTIFICATE_WAIT_TIMEOUT).await;
        let result = dispatch.await.unwrap();
        assert!(matches!(result, Err(AuthError::Timeout(_))));
        let session = peer_b
            .session_by_identifier(&session_nonce)
            .await
            .expect("expired session remains inspectable");
        assert!(
            session.certificates_required && !session.certificates_validated,
            "one dispatch timeout must leave the session gate pending"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_gated_duplicate_is_marked_seen_exactly_once_after_release() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let mut messages = peer_b.on_general_message().unwrap();
        while messages.try_recv().is_ok() {}
        let captured = peer_a
            .create_general_message(&identity_b, b"gated once".to_vec())
            .await
            .unwrap();
        let session_nonce = captured.your_nonce.clone().unwrap();
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
        }

        let first = {
            let peer_b = peer_b.clone();
            let message = captured.clone();
            tokio::spawn(async move { peer_b.dispatch_message(message).await })
        };
        let duplicate = {
            let peer_b = peer_b.clone();
            let message = captured.clone();
            tokio::spawn(async move { peer_b.dispatch_message(message).await })
        };

        let certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([57; 32]),
        )
        .await;
        let requested = requested_for_certificate(&certificate);
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a,
            &identity_b,
            session_nonce,
            Some(vec![certificate]),
            Some(requested),
            None,
        )
        .await;
        bounded(peer_b.dispatch_message(response)).await.unwrap();
        let first = bounded(first).await.unwrap();
        let duplicate = bounded(duplicate).await.unwrap();
        assert!(
            (first.is_ok() && matches!(duplicate, Err(AuthError::ReplayDetected(_))))
                || (duplicate.is_ok() && matches!(first, Err(AuthError::ReplayDetected(_)))),
            "exactly one duplicate dispatch must commit replay state"
        );
        assert_eq!(bounded(messages.recv()).await.unwrap().1, b"gated once");

        let replay = peer_b.verify_general_message(captured).await;
        assert!(
            matches!(replay, Err(AuthError::ReplayDetected(_))),
            "re-dispatch must mark the message exactly once in the ordinary replay set"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_evicted_certificate_exchange_still_wakes_waiters() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .unwrap()
            .session_nonce;
        let mut session = peer_b.session_by_identifier(&session_nonce).await.unwrap();
        session.certificates_required = true;
        session.certificates_validated = false;
        let (sender, receiver) = watch::channel(false);
        peer_b
            .certificate_validation_waiters
            .lock()
            .unwrap()
            .insert(
                session_nonce.clone(),
                Arc::new(CertificateWaiterSignal {
                    sender,
                    active_waiters: AtomicUsize::new(0),
                }),
            );
        peer_b
            .session_manager
            .write()
            .await
            .remove_session(&session_nonce);

        let result = peer_b.finish_certificate_exchange(&mut session).await;
        assert!(matches!(result, Err(AuthError::SessionNotFound(_))));
        assert!(
            *receiver.borrow(),
            "session eviction must still wake certificate waiters"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_session_reap_cleans_all_peer_owned_nonce_state() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .unwrap()
            .session_nonce;
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions.get_session_mut(&session_nonce).unwrap();
            session.certificates_required = true;
            session.certificates_validated = false;
            sessions.touch(&session_nonce, 0);
        }
        let (handshake_tx, _handshake_rx) = oneshot::channel();
        peer_b.handshake_waiters.lock().unwrap().insert(
            session_nonce.clone(),
            HandshakeWaiter {
                id: 7,
                sender: handshake_tx,
            },
        );
        let (sender, receiver) = watch::channel(false);
        peer_b
            .certificate_validation_waiters
            .lock()
            .unwrap()
            .insert(
                session_nonce.clone(),
                Arc::new(CertificateWaiterSignal {
                    sender,
                    active_waiters: AtomicUsize::new(0),
                }),
            );

        let request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: wallet_identity(&peer_a.wallet).await,
            nonce: None,
            your_nonce: None,
            initial_nonce: Some(create_nonce(&peer_a.wallet).await.unwrap()),
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        };
        bounded(peer_b.handle_initial_request(request))
            .await
            .expect("new handshake triggers idle reap");

        assert!(peer_b.session_by_identifier(&session_nonce).await.is_none());
        assert!(!peer_b
            .handshake_waiters
            .lock()
            .unwrap()
            .contains_key(&session_nonce));
        assert!(!peer_b
            .certificate_validation_waiters
            .lock()
            .unwrap()
            .contains_key(&session_nonce));
        assert!(*receiver.borrow(), "reap must wake an active waiter");
    }

    #[tokio::test(start_paused = true)]
    async fn test_certificate_validation_wait_times_out() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let mut session = peer_b
            .session_by_identifier(&identity_a)
            .await
            .expect("authenticated receiver session");
        session.certificates_required = true;
        session.certificates_validated = false;
        peer_b
            .session_manager
            .write()
            .await
            .update_session(&session.session_nonce, session.clone());

        let result = peer_b.wait_for_certificate_validation(&session).await;

        assert!(
            matches!(&result, Err(AuthError::Timeout(message))
                if message.contains("Timeout waiting for certificate validation from peer")),
            "expected certificate-validation timeout, got {result:?}"
        );
        let still_pending = peer_b
            .session_by_identifier(&session.session_nonce)
            .await
            .expect("timed-out session remains recorded");
        assert!(
            still_pending.certificates_required && !still_pending.certificates_validated,
            "a waiter's deadline must not mutate shared session state"
        );
        let later_waiter = peer_b
            .wait_for_certificate_validation_with_timeout(&still_pending, Duration::ZERO)
            .await;
        assert!(
            matches!(later_waiter, Err(AuthError::Timeout(_))),
            "a later waiter owns a fresh deadline instead of inheriting an error: {later_waiter:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_concurrent_certificate_waiters_have_independent_deadlines() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let mut session = peer_b.session_by_identifier(&identity_a).await.unwrap();
        session.certificates_required = true;
        session.certificates_validated = false;
        peer_b
            .session_manager
            .write()
            .await
            .update_session(&session.session_nonce, session.clone());

        let first = {
            let peer_b = peer_b.clone();
            let session = session.clone();
            tokio::spawn(async move { peer_b.wait_for_certificate_validation(&session).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let ready = peer_b
                    .certificate_validation_waiters
                    .lock()
                    .unwrap()
                    .get(&session.session_nonce)
                    .is_some_and(|signal| signal.sender.receiver_count() == 1);
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first certificate waiter never registered");
        tokio::time::advance(Duration::from_secs(25)).await;
        let mut second = {
            let peer_b = peer_b.clone();
            let session = session.clone();
            tokio::spawn(async move { peer_b.wait_for_certificate_validation(&session).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let ready = peer_b
                    .certificate_validation_waiters
                    .lock()
                    .unwrap()
                    .get(&session.session_nonce)
                    .is_some_and(|signal| signal.sender.receiver_count() == 2);
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second certificate waiter never registered");

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(first.await.unwrap(), Err(AuthError::Timeout(_))));
        assert!(
            (&mut second).now_or_never().is_none(),
            "waiter two still owns 25 seconds of its independent deadline"
        );
        peer_b
            .session_manager
            .write()
            .await
            .get_session_mut(&session.session_nonce)
            .unwrap()
            .certificates_validated = true;
        peer_b.resolve_certificate_validation(&session.session_nonce);
        assert!(
            second.await.unwrap().is_ok(),
            "the first public wait timeout must not close the second waiter's signal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cancelled_certificate_waiter_removes_its_registration() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let mut session = peer_b.session_by_identifier(&identity_a).await.unwrap();
        session.certificates_required = true;
        session.certificates_validated = false;
        peer_b
            .session_manager
            .write()
            .await
            .update_session(&session.session_nonce, session.clone());
        let waiter = {
            let peer_b = peer_b.clone();
            let session = session.clone();
            tokio::spawn(async move { peer_b.wait_for_certificate_validation(&session).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if peer_b
                    .certificate_validation_waiters
                    .lock()
                    .unwrap()
                    .contains_key(&session.session_nonce)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled certificate waiter never registered");
        waiter.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("aborted certificate waiter did not stop");
        tokio::task::yield_now().await;

        assert!(
            !peer_b
                .certificate_validation_waiters
                .lock()
                .unwrap()
                .contains_key(&session.session_nonce),
            "dropping a waiter future must not orphan the session entry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_certificate_listeners_are_awaited_in_registration_order() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let (transport, _other) = create_mock_transport_pair();
        let peer = Arc::new(Peer::new(wallet, transport));
        let order = Arc::new(StdMutex::new(Vec::new()));
        let first_started = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let first_order = order.clone();
        let listener_started = first_started.clone();
        let listener_release = release_first.clone();
        peer.listen_for_certificates_received(Arc::new(move |_, _| {
            let first_order = first_order.clone();
            let listener_started = listener_started.clone();
            let listener_release = listener_release.clone();
            Box::pin(async move {
                listener_started.notify_one();
                listener_release.notified().await;
                first_order.lock().unwrap().push(1);
                Ok(())
            })
        }));
        let second_order = order.clone();
        peer.listen_for_certificates_received(Arc::new(move |_, _| {
            let second_order = second_order.clone();
            Box::pin(async move {
                second_order.lock().unwrap().push(2);
                Ok(())
            })
        }));

        let delivery = {
            let peer = peer.clone();
            tokio::spawn(async move {
                peer.fire_certificates_received_listeners("sender", &[])
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), first_started.notified())
            .await
            .expect("first certificate listener never started");
        assert!(
            order.lock().unwrap().is_empty(),
            "a later listener ran before the first listener completed"
        );
        release_first.notify_one();
        delivery
            .await
            .expect("delivery task")
            .expect("listeners succeed");
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_certificate_delivery_has_no_bounded_channel_limit() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let (transport, _other) = create_mock_transport_pair();
        let peer = Arc::new(Peer::new(wallet, transport));
        let deliveries = Arc::new(StdMutex::new(Vec::<usize>::new()));
        let first_started = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let listener_deliveries = deliveries.clone();
        let listener_started = first_started.clone();
        let listener_release = release_first.clone();
        peer.listen_for_certificates_received(Arc::new(move |sender, _| {
            let listener_deliveries = listener_deliveries.clone();
            let listener_started = listener_started.clone();
            let listener_release = listener_release.clone();
            Box::pin(async move {
                let index = sender.parse::<usize>().unwrap();
                if index == 0 {
                    listener_started.notify_one();
                    listener_release.notified().await;
                }
                listener_deliveries.lock().unwrap().push(index);
                Ok(())
            })
        }));

        let first = {
            let peer = peer.clone();
            tokio::spawn(async move { peer.fire_certificates_received_listeners("0", &[]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), first_started.notified())
            .await
            .expect("first certificate delivery listener never started");

        let mut backlog = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            for index in 1..=64 {
                let delivery_peer = peer.clone();
                backlog.push(tokio::spawn(async move {
                    delivery_peer
                        .fire_certificates_received_listeners(&index.to_string(), &[])
                        .await
                }));
                loop {
                    if peer.certificate_deliveries.lock().unwrap().queue.len() == index {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        })
        .await
        .expect("certificate delivery backlog did not fill");
        release_first.notify_one();
        first.await.unwrap().unwrap();
        for delivery in backlog {
            delivery.await.unwrap().unwrap();
        }

        assert_eq!(
            *deliveries.lock().unwrap(),
            (0..=64).collect::<Vec<_>>(),
            ">32 arrivals must remain lossless and ordered while the listener is blocked"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_empty_certificate_response_reaches_consumers() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let identity_b = wallet_identity(&peer_b.wallet).await;
        let receiver_session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .expect("receiver session")
            .session_nonce;
        let mut waiting_session = peer_b
            .session_by_identifier(&receiver_session_nonce)
            .await
            .unwrap();
        waiting_session.certificates_required = true;
        waiting_session.certificates_validated = false;
        peer_b
            .session_manager
            .write()
            .await
            .update_session(&receiver_session_nonce, waiting_session.clone());
        let certificate_events = record_certificate_events(&peer_b);
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a.clone(),
            &identity_b,
            receiver_session_nonce,
            Some(Vec::new()),
            None,
            None,
        )
        .await;

        bounded(peer_b.dispatch_message(response))
            .await
            .expect("empty signed response is valid");

        let (sender, received) = certificate_events.lock().unwrap()[0].clone();
        assert_eq!(sender, identity_a);
        assert!(received.is_empty());
        let pending = peer_b
            .wait_for_certificate_validation_with_timeout(
                &waiting_session,
                Duration::from_millis(20),
            )
            .await;
        assert!(
            matches!(pending, Err(AuthError::Timeout(_))),
            "TS leaves the gate pending after an authenticated empty response: {pending:?}"
        );

        let certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([66; 32]),
        )
        .await;
        let later_response = signed_certificate_response(
            &peer_a.wallet,
            identity_a,
            &identity_b,
            waiting_session.session_nonce.clone(),
            Some(vec![certificate]),
            None,
            None,
        )
        .await;
        bounded(peer_b.dispatch_message(later_response))
            .await
            .expect("a later valid response must still validate the live session");
        let validated = peer_b
            .session_by_identifier(&waiting_session.session_nonce)
            .await
            .unwrap();
        assert!(validated.certificates_validated);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_certificate_response_without_certificates_key_is_rejected() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let identity_b = wallet_identity(&peer_b.wallet).await;
        let receiver_session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .unwrap()
            .session_nonce;
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a,
            &identity_b,
            receiver_session_nonce,
            None,
            None,
            None,
        )
        .await;

        let result = bounded(peer_b.dispatch_message(response)).await;
        assert!(
            matches!(&result, Err(AuthError::InvalidMessage(message)) if message.contains("missing certificates")),
            "TS rejects certificateResponse without a certificates key: {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_certificate_request_auto_responds_with_empty_set() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let certificate_events = record_certificate_events(&peer_a);
        let receiver_session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .expect("receiver session")
            .session_nonce;
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        requested.insert(
            cert_codec::base64_encode(&[55; 32]),
            vec!["name".to_string()],
        );
        let nonce = base64_encode(&crate::primitives::random::random_bytes(32));
        let signature = peer_a
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(serde_json::to_vec(&requested).unwrap()),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol {
                        security_level: 2,
                        protocol: AUTH_PROTOCOL_ID.to_string(),
                    },
                    key_id: format!("{} {}", nonce, receiver_session_nonce),
                    counterparty: Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(parse_public_key(&identity_b).unwrap()),
                    },
                    privileged: false,
                    privileged_reason: None,
                    seek_permission: None,
                },
                None,
            )
            .await
            .unwrap()
            .signature;
        let request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::CertificateRequest,
            identity_key: identity_a,
            nonce: Some(nonce),
            your_nonce: Some(receiver_session_nonce),
            initial_nonce: None,
            certificates: None,
            requested_certificates: Some(requested),
            payload: None,
            signature: Some(signature),
        };

        bounded(peer_b.dispatch_message(request))
            .await
            .expect("valid certificate request");
        bounded(async {
            loop {
                if !certificate_events.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(certificate_events.lock().unwrap().len(), 1);
        assert!(certificate_events.lock().unwrap()[0].1.is_empty());
        assert!(
            peer_a
                .session_by_identifier(&identity_b)
                .await
                .unwrap()
                .certificates_validated,
            "an unsolicited empty response must not downgrade a session with no pending request"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_certificate_listener_failure_propagates_after_validation_commit() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let identity_b = wallet_identity(&peer_b.wallet).await;
        let receiver_session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .expect("receiver session")
            .session_nonce;
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions
                .get_session_mut(&receiver_session_nonce)
                .expect("receiver session by nonce");
            session.certificates_required = true;
            session.certificates_validated = false;
        }
        peer_b.listen_for_certificates_received(Arc::new(|_, _| {
            Box::pin(async {
                Err(AuthError::TransportError(
                    "certificate listener failed".to_string(),
                ))
            })
        }));
        let certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([54; 32]),
        )
        .await;
        let requested = requested_for_certificate(&certificate);
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a.clone(),
            &identity_b,
            receiver_session_nonce.clone(),
            Some(vec![certificate]),
            Some(requested),
            None,
        )
        .await;

        let result = bounded(peer_b.dispatch_message(response)).await;
        let session = peer_b
            .session_by_identifier(&receiver_session_nonce)
            .await
            .expect("receiver session remains");

        assert!(
            matches!(result, Err(AuthError::TransportError(message))
                if message == "certificate listener failed"),
            "failed certificate listener was not propagated"
        );
        assert!(
            session.certificates_validated,
            "TS commits validation before invoking certificate listeners"
        );
    }

    /// Item 1: a captured authenticated message replays are REJECTED (the
    /// verified defect at 0.2.87), while a genuinely fresh message still passes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_general_message_replay_is_rejected() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;

        // Capture ONE signed general message (fixed per-message nonce).
        let captured = peer_a
            .create_general_message(&identity_b, b"transfer 100".to_vec())
            .await
            .expect("create_general_message");

        // First delivery: accepted.
        peer_b
            .verify_general_message(captured.clone())
            .await
            .expect("first (fresh) delivery must be accepted");

        // Replay of the identical captured bytes: rejected as a replay.
        let replay = peer_b.verify_general_message(captured.clone()).await;
        assert!(
            matches!(replay, Err(AuthError::ReplayDetected(_))),
            "captured message replay must be rejected, got: {:?}",
            replay
        );

        // A genuinely fresh message (new per-message nonce) still passes — the
        // happy path is preserved.
        let fresh = peer_a
            .create_general_message(&identity_b, b"transfer 100".to_vec())
            .await
            .expect("create_general_message");
        peer_b
            .verify_general_message(fresh)
            .await
            .expect("a fresh-nonce message must still be accepted");
    }

    /// TS parity (Peer.processGeneralMessage binds verification to
    /// `peerSession.peerIdentityKey`): a general message whose claimed
    /// `identity_key` differs from the session's handshake-bound peer must be
    /// rejected on the identity mismatch — before signature verification — so a
    /// captured `yourNonce` cannot carry a message from a different key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_general_message_identity_must_match_session_peer() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;

        // A valid general message from A over the A–B session (correct yourNonce).
        let mut msg = peer_a
            .create_general_message(&identity_b, b"hello".to_vec())
            .await
            .expect("create_general_message");

        // Swap only the claimed sender identity to a different key; yourNonce still
        // resolves the A–B session, but the sender no longer matches the bound peer.
        let attacker_identity = format!("02{}", "11".repeat(32));
        assert_ne!(
            attacker_identity, msg.identity_key,
            "attacker key must differ"
        );
        msg.identity_key = attacker_identity;

        let res = peer_b.verify_general_message(msg).await;
        assert!(
            matches!(&res, Err(AuthError::InvalidMessage(m)) if m.contains("does not match session peer")),
            "identity_key != session peer must be rejected on the binding check, got: {res:?}"
        );
    }

    /// An idle-expired session is refused by the REUSE path
    /// (`create_general_message`), not just the verify path, and
    /// `get_authenticated_session` treats it as "no session" and self-heals by
    /// re-handshaking to a fresh session — no zombie-signing (TS parity: an
    /// unauthenticated/absent session always triggers `initiateHandshake`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_expired_session_refused_on_reuse_and_rehandshake_recovers() {
        let (peer_a, _peer_b, identity_b) = authenticated_pair().await;

        let old_nonce = peer_a
            .session_by_identifier(&identity_b)
            .await
            .expect("A must hold a session for B")
            .session_nonce;

        // Backdate A's session activity far past the 15-min idle TTL.
        peer_a.session_manager.write().await.touch(&old_nonce, 1);

        // Reuse path: signing with the expired session must be refused with
        // the same outcome the verify path would produce (SessionNotFound),
        // instead of zombie-signing a session our own verify path rejects.
        let err = peer_a
            .create_general_message(&identity_b, b"zombie".to_vec())
            .await
            .expect_err("expired session must not be signed with");
        assert!(
            matches!(err, AuthError::SessionNotFound(_)),
            "expected SessionNotFound for expired session, got: {:?}",
            err
        );

        // Recovery: background receive completes a fresh handshake.
        let fresh = peer_a
            .get_authenticated_session(&identity_b)
            .await
            .expect("re-handshake must succeed");
        assert!(fresh.is_authenticated);
        assert_ne!(
            fresh.session_nonce, old_nonce,
            "recovery must mint a NEW session, not resurrect the expired one"
        );

        // The expired session was physically reaped by the handshake path.
        assert!(
            peer_a.session_by_identifier(&old_nonce).await.is_none(),
            "expired session must have been reaped"
        );

        // And the fresh session signs successfully.
        peer_a
            .create_general_message(&identity_b, b"alive".to_vec())
            .await
            .expect("fresh session must sign");
    }

    /// Outbound sends refresh `last_used_ms` (TS Peer.ts:163 parity), so an
    /// actively-sending client never idle-expires its own session even if it
    /// receives nothing back for a while.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_outbound_send_refreshes_session_activity() {
        use crate::auth::session_manager::DEFAULT_SESSION_IDLE_TTL_MS;

        let (peer_a, _peer_b, identity_b) = authenticated_pair().await;
        let nonce = peer_a
            .session_by_identifier(&identity_b)
            .await
            .unwrap()
            .session_nonce;

        // Backdate activity to 1 minute before the TTL boundary — still live.
        let now = now_ms();
        let backdated = now - (DEFAULT_SESSION_IDLE_TTL_MS - 60_000);
        peer_a
            .session_manager
            .write()
            .await
            .touch(&nonce, backdated);

        // Outbound sign refreshes activity to ~now.
        peer_a
            .create_general_message(&identity_b, b"ping".to_vec())
            .await
            .expect("session is within TTL and must sign");

        // Probe just past the point where the BACKDATED timestamp would have
        // expired: without the outbound refresh this would be expired; with
        // it, the session is still live.
        let probe = now + 61_000;
        assert!(
            !peer_a
                .session_manager
                .read()
                .await
                .is_expired(&nonce, probe),
            "outbound send must refresh last_used_ms"
        );
    }

    /// The SessionNotFound message must match TS casing exactly
    /// (`Session not found for nonce`, Peer.ts:870) — TS AuthFetch's
    /// stale-session detection is a case-sensitive `includes`
    /// (AuthFetch.ts:269), so cross-stack self-healing depends on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_session_not_found_message_matches_ts_casing() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;

        let captured = peer_a
            .create_general_message(&identity_b, b"hello".to_vec())
            .await
            .expect("create_general_message");

        // Evict B's session so the verify path takes the not-found branch.
        let b_nonce = captured.your_nonce.clone().unwrap();
        peer_b
            .session_manager
            .write()
            .await
            .remove_session(&b_nonce);

        let err = peer_b
            .verify_general_message(captured)
            .await
            .expect_err("verify must fail once the session is gone");
        assert!(
            err.to_string().contains("Session not found for nonce"),
            "error must carry the exact TS casing, got: {}",
            err
        );
    }

    /// Item 4: N concurrent verifies of the SAME captured message must not
    /// deadlock or serialize, and the atomic check-and-insert must admit exactly
    /// ONE and reject the other N-1 as replays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_identical_replays_admit_exactly_one() {
        let (peer_a, peer_b, identity_b) = authenticated_pair().await;

        let captured = peer_a
            .create_general_message(&identity_b, b"double-spend me".to_vec())
            .await
            .expect("create_general_message");

        let n = 16usize;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let pb = peer_b.clone();
            let msg = captured.clone();
            handles.push(tokio::spawn(
                async move { pb.verify_general_message(msg).await },
            ));
        }

        let mut accepted = 0usize;
        let mut replayed = 0usize;
        for h in handles {
            match h.await.expect("verify task must not panic/deadlock") {
                Ok(()) => accepted += 1,
                Err(AuthError::ReplayDetected(_)) => replayed += 1,
                Err(other) => panic!("unexpected error under concurrent replay: {:?}", other),
            }
        }

        assert_eq!(
            accepted, 1,
            "exactly one concurrent delivery must be accepted"
        );
        assert_eq!(
            replayed,
            n - 1,
            "all other concurrent deliveries must be replays"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_hung_certificate_listener_is_time_bounded() {
        let wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let (transport, _other) = create_mock_transport_pair();
        let peer = Peer::new(wallet, transport);
        peer.listen_for_certificates_received(Arc::new(|_, _| Box::pin(std::future::pending())));

        let outer = tokio::time::timeout(
            Duration::from_secs(31),
            peer.fire_certificates_received_listeners("sender", &[]),
        )
        .await;

        assert!(
            matches!(outer, Ok(Err(AuthError::Timeout(ref message))) if message.contains("certificate listener")),
            "the listener must be cancelled by Peer before the outer test timeout: {outer:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_listener_nested_handshake_routes_each_initial_response_by_nonce() {
        let requester_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let outer_responder_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let nested_responder_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requester_identity = wallet_identity(&requester_wallet).await;
        let outer_identity = wallet_identity(&outer_responder_wallet).await;
        let nested_identity = wallet_identity(&nested_responder_wallet).await;
        let (requester_transport, responder_transport) = create_mock_transport_pair();
        let mut responder_rx = responder_transport.subscribe();
        let requester_transport = Arc::new(GatedFirstSendTransport {
            inner: requester_transport,
            sends: AtomicUsize::new(0),
            first_sent: Notify::new(),
            release_first: Notify::new(),
        });
        let peer = Arc::new(Peer::new(requester_wallet, requester_transport.clone()));

        let outer_handshake = {
            let peer = peer.clone();
            let outer_identity = outer_identity.clone();
            tokio::spawn(async move { peer.get_authenticated_session(&outer_identity).await })
        };
        let outer_request = tokio::time::timeout(Duration::from_secs(1), responder_rx.recv())
            .await
            .expect("outer initialRequest timeout")
            .expect("outer initialRequest");
        requester_transport.first_sent.notified().await;

        let weak_peer = Arc::downgrade(&peer);
        let listener_nested_identity = nested_identity.clone();
        peer.listen_for_certificates_received(Arc::new(move |_, _| {
            let peer = weak_peer.upgrade().expect("peer lives through listener");
            let nested_identity = listener_nested_identity.clone();
            Box::pin(async move {
                peer.send_message(&nested_identity, b"nested".to_vec())
                    .await
            })
        }));
        let delivery = {
            let peer = peer.clone();
            tokio::spawn(async move {
                peer.fire_certificates_received_listeners("sender", &[])
                    .await
            })
        };
        let nested_request = tokio::time::timeout(Duration::from_secs(1), responder_rx.recv())
            .await
            .expect("nested initialRequest timeout")
            .expect("nested initialRequest");

        let outer_response = signed_initial_response(
            &outer_responder_wallet,
            outer_identity,
            &requester_identity,
            outer_request.initial_nonce.unwrap(),
            None,
        )
        .await;
        responder_transport.send(outer_response).await.unwrap();
        let nested_response = signed_initial_response(
            &nested_responder_wallet,
            nested_identity,
            &requester_identity,
            nested_request.initial_nonce.unwrap(),
            None,
        )
        .await;
        responder_transport.send(nested_response).await.unwrap();

        let nested_general = tokio::time::timeout(Duration::from_secs(1), responder_rx.recv())
            .await
            .expect("nested general-message timeout")
            .expect("nested general message");
        assert_eq!(nested_general.message_type, MessageType::General);
        tokio::time::timeout(Duration::from_secs(1), delivery)
            .await
            .expect("listener delivery timed out")
            .expect("listener delivery task")
            .expect("nested send succeeds");
        requester_transport.release_first.notify_one();
        let outer_session = tokio::time::timeout(Duration::from_secs(1), outer_handshake)
            .await
            .expect("outer handshake lost its InitialResponse")
            .expect("outer handshake task")
            .expect("outer handshake succeeds");
        assert!(outer_session.is_authenticated);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_handshake_validates_against_advertised_snapshot_after_reconfigure() {
        let requester_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let responder_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requester_identity = wallet_identity(&requester_wallet).await;
        let responder_identity = wallet_identity(&responder_wallet).await;
        let requester_public_key = parse_public_key(&requester_identity).unwrap();
        let certificate = issue_verifiable_certificate(
            &responder_wallet,
            &requester_public_key,
            CertificateType([61; 32]),
        )
        .await;
        let advertised = requested_for_certificate(&certificate);
        let (requester_transport, responder_transport) = create_mock_transport_pair();
        let mut responder_rx = responder_transport.subscribe();
        let peer = Arc::new(Peer::new(requester_wallet, requester_transport));
        peer.set_certificates_to_request(advertised.clone());

        let handshake = {
            let peer = peer.clone();
            let responder_identity = responder_identity.clone();
            tokio::spawn(async move { peer.get_authenticated_session(&responder_identity).await })
        };
        let request = tokio::time::timeout(Duration::from_secs(1), responder_rx.recv())
            .await
            .expect("initialRequest timeout")
            .expect("initialRequest");
        assert_eq!(
            request.requested_certificates.unwrap().types,
            advertised.types
        );

        let mut reconfigured = RequestedCertificateSet::default();
        reconfigured.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        reconfigured.insert(base64_encode(&[62; 32]), vec!["other".to_string()]);
        peer.set_certificates_to_request(reconfigured);
        let response = signed_initial_response(
            &responder_wallet,
            responder_identity,
            &requester_identity,
            request.initial_nonce.unwrap(),
            Some(vec![certificate]),
        )
        .await;
        responder_transport.send(response).await.unwrap();

        let session = tokio::time::timeout(Duration::from_secs(1), handshake)
            .await
            .expect("handshake timeout")
            .expect("handshake task")
            .expect("the advertised certificate must remain accepted");
        assert!(session.certificates_validated);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_initial_response_emits_empty_certificates_array_for_empty_match() {
        let requester_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let responder_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requester_identity = wallet_identity(&requester_wallet).await;
        let initial_nonce = create_nonce(&requester_wallet).await.unwrap();
        let (observer_transport, responder_transport) = create_mock_transport_pair();
        let mut observer_rx = observer_transport.subscribe();
        let peer = Peer::new(responder_wallet, responder_transport);
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        requested.insert(base64_encode(&[63; 32]), vec!["name".to_string()]);
        let request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: requester_identity,
            nonce: None,
            your_nonce: None,
            initial_nonce: Some(initial_nonce),
            certificates: None,
            requested_certificates: Some(requested),
            payload: None,
            signature: None,
        };

        tokio::time::timeout(Duration::from_secs(1), peer.handle_initial_request(request))
            .await
            .expect("initialRequest dispatch timeout")
            .expect("initialRequest succeeds");
        let response = tokio::time::timeout(Duration::from_secs(1), observer_rx.recv())
            .await
            .expect("initialResponse timeout")
            .expect("initialResponse");

        assert!(
            response.certificates.as_ref().is_some_and(Vec::is_empty),
            "TS 2.4.1 emits certificates: [] when the embedded request has no matches"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_initial_response_embedded_request_suppresses_empty_response() {
        let requester_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let responder_wallet = TestWallet::new(PrivateKey::from_random().unwrap());
        let requester_identity = wallet_identity(&requester_wallet).await;
        let responder_identity = wallet_identity(&responder_wallet).await;
        let (requester_transport, responder_transport) = create_mock_transport_pair();
        let mut responder_rx = responder_transport.subscribe();
        let peer = Arc::new(Peer::new(requester_wallet, requester_transport));

        let handshake = {
            let peer = peer.clone();
            let responder_identity = responder_identity.clone();
            tokio::spawn(async move { peer.get_authenticated_session(&responder_identity).await })
        };
        let request = tokio::time::timeout(Duration::from_secs(1), responder_rx.recv())
            .await
            .expect("initialRequest timeout")
            .expect("initialRequest");
        let mut requested = RequestedCertificateSet::default();
        requested.certifiers.push(
            PrivateKey::from_random()
                .unwrap()
                .to_public_key()
                .to_der_hex(),
        );
        requested.insert(base64_encode(&[67; 32]), vec!["name".to_string()]);
        let mut response = signed_initial_response(
            &responder_wallet,
            responder_identity,
            &requester_identity,
            request.initial_nonce.unwrap(),
            None,
        )
        .await;
        response.requested_certificates = Some(requested);
        responder_transport.send(response).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), handshake)
            .await
            .expect("handshake timeout")
            .expect("handshake task")
            .expect("handshake succeeds");
        assert!(
            matches!(
                responder_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "TS suppresses this post-handshake empty response because it can race a later request"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_certificate_response_cannot_relabel_the_session_request() {
        let (peer_a, peer_b, _identity_b) = authenticated_pair().await;
        let identity_a = wallet_identity(&peer_a.wallet).await;
        let identity_b = wallet_identity(&peer_b.wallet).await;
        let receiver_session_nonce = peer_b
            .session_by_identifier(&identity_a)
            .await
            .unwrap()
            .session_nonce;
        let advertised_certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([64; 32]),
        )
        .await;
        let advertised = requested_for_certificate(&advertised_certificate);
        let unadvertised_certificate = issue_verifiable_certificate(
            &peer_a.wallet,
            &parse_public_key(&identity_b).unwrap(),
            CertificateType([65; 32]),
        )
        .await;
        let sender_relabel = requested_for_certificate(&unadvertised_certificate);
        {
            let mut sessions = peer_b.session_manager.write().await;
            let session = sessions
                .get_session_mut(&receiver_session_nonce)
                .expect("receiver session");
            session.requested_certificates = Some(advertised);
            session.certificates_required = true;
            session.certificates_validated = false;
        }
        let response = signed_certificate_response(
            &peer_a.wallet,
            identity_a,
            &identity_b,
            receiver_session_nonce,
            Some(vec![unadvertised_certificate]),
            Some(sender_relabel),
            None,
        )
        .await;

        let result =
            tokio::time::timeout(Duration::from_secs(1), peer_b.dispatch_message(response))
                .await
                .expect("certificateResponse dispatch timeout");

        assert!(
            matches!(result, Err(AuthError::CertificateValidation(_))),
            "the sender must not replace the request snapshot carried by the session: {result:?}"
        );
    }
}
