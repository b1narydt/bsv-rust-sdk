//! AuthFetch: high-level HTTP client for BRC-31 authenticated requests.
//!
//! Manages per-base-URL Peer instances, automatically performs the auth
//! handshake on first request to a new server, and serializes HTTP requests
//! as general messages over the BRC-31 protocol.
//!
//! Translated from TS SDK AuthFetch.ts (924 lines) and Go SDK authhttp.go (782 lines).

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use crate::auth::certificates::master::MasterCertificate;
use crate::auth::error::AuthError;
use crate::auth::peer::Peer;
use crate::auth::transports::Transport;
use crate::auth::types::RequestedCertificateSet;
use crate::auth::utils::certificates::get_verifiable_certificates;
use crate::wallet::interfaces::{Certificate, WalletInterface};

/// Maximum time `fetch` will wait for in-flight certificate exchanges to
/// complete before sending the general message. Matches TS SDK's
/// `CERTIFICATE_WAIT_TIMEOUT_MS` in `AuthFetch.ts`.
const CERTIFICATE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for the pending-certificate-requests queue
/// to drain. Matches TS SDK's `CHECK_INTERVAL_MS`.
const CERTIFICATE_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Post-send grace window: after the client sends its CertificateResponse,
/// wait this long before releasing the queue entry so the server has time
/// to ingest the certificates before the next general message arrives.
/// Matches the 500ms `setTimeout` inside the TS listener's `finally` block.
const CERTIFICATE_POST_SEND_GRACE: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Payment constants and public types (TS SDK AuthFetch.ts parity)
// ---------------------------------------------------------------------------

/// BSV payment protocol version. Server's `x-bsv-payment-version` header must
/// equal this value.  Matches `PAYMENT_VERSION` in TS SDK AuthFetch.ts:58.
pub const PAYMENT_VERSION: &str = "1.0";

/// Default maximum 402-retry attempts when none is specified in `FetchOptions`.
const DEFAULT_PAYMENT_RETRY_ATTEMPTS: u32 = 3;

/// Per-call options for `fetch_with_options`.
#[derive(Clone, Debug, Default)]
pub struct FetchOptions {
    /// Maximum 402-retry attempts.  Defaults to [`DEFAULT_PAYMENT_RETRY_ATTEMPTS`]
    /// when `None`.  Values < 1 are treated as 1.
    pub payment_retry_attempts: Option<u32>,
}

/// Single error entry captured during a 402 retry sequence.
///
/// Mirrors the `PaymentErrorLogEntry` interface in TS SDK AuthFetch.ts:32-37.
#[derive(Clone, Debug)]
pub struct PaymentErrorLogEntry {
    /// The attempt number (1-based) on which this error occurred.
    pub attempt: u32,
    /// RFC 3339 timestamp of the error.
    pub timestamp: String,
    /// Human-readable error message.
    pub message: String,
}

/// Per-attempt payment state carried through the 402 retry loop.
///
/// ## Intentional divergence from TS SDK
///
/// The TS SDK can reuse an existing `PaymentRetryContext` across retries via
/// `isPaymentContextCompatible` (AuthFetch.ts:625-636), which means the **same
/// transaction** is re-broadcast on a second 402 — a latent double-spend risk.
///
/// Rust implementation: we **never** reuse a `PaymentRetryContext` across
/// retries.  `create_payment_context` is called fresh on every loop iteration,
/// producing a distinct transaction each time.  This struct records the most
/// recently created context for logging / error surfacing only.
#[derive(Clone, Debug)]
pub struct PaymentRetryContext {
    /// Satoshis required by the server on the last 402 response.
    pub satoshis_required: u64,
    /// Base64-encoded signed transaction.
    pub transaction_base64: String,
    /// Derivation prefix from the server's response header.
    pub derivation_prefix: String,
    /// Derivation suffix generated locally for this attempt.
    pub derivation_suffix: String,
    /// Server's identity key (hex).
    pub server_identity_key: String,
    /// Client's identity key (hex).  Used in failure logging.
    pub client_identity_key: String,
    /// Number of attempts completed so far (0-based before first retry).
    pub attempts: u32,
    /// Maximum attempts permitted.
    pub max_attempts: u32,
    /// Log of errors accumulated during this retry sequence.
    pub errors: Vec<PaymentErrorLogEntry>,
}

// ---------------------------------------------------------------------------
// AuthFetchResponse
// ---------------------------------------------------------------------------

/// Response from an authenticated HTTP request.
#[derive(Clone, Debug)]
pub struct AuthFetchResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AuthPeer (internal)
// ---------------------------------------------------------------------------

/// Internal tracking struct for a peer associated with a base URL.
struct AuthPeer<W: WalletInterface> {
    peer: Arc<Mutex<Peer<W>>>,
    identity_key: Option<String>,
    #[allow(clippy::type_complexity)]
    general_rx: Arc<Mutex<mpsc::Receiver<(String, Vec<u8>)>>>,
    /// Tracks in-flight certificate exchanges for this peer. Each inbound
    /// `certificateRequest` (or handshake-embedded cert request) pushes an
    /// entry; the listener task shifts it 500ms after sending the response.
    /// `fetch` blocks before sending its general message until this is empty,
    /// mirroring TS `pendingCertificateRequests` semantics in `AuthFetch.ts`.
    pending_certificate_requests: Arc<StdMutex<Vec<bool>>>,
}

// ---------------------------------------------------------------------------
// AuthFetch
// ---------------------------------------------------------------------------

/// High-level HTTP client for BRC-31 mutually authenticated requests.
///
/// AuthFetch manages per-base-URL Peer instances. When `fetch()` is called,
/// it creates a SimplifiedHTTPTransport + Peer for new servers, performs the
/// BRC-31 handshake automatically, then sends the serialized HTTP request as
/// a general message and awaits the response.
///
/// # Generic Parameters
///
/// * `W` - A WalletInterface implementation for cryptographic operations.
///
/// # Feature Gate
///
/// This struct is only available when the `network` feature is enabled.
pub struct AuthFetch<W: WalletInterface + Clone + 'static> {
    wallet: W,
    certificates_to_include: Vec<MasterCertificate>,
    certificates_to_request: Option<RequestedCertificateSet>,
    peers: HashMap<String, AuthPeer<W>>,
}

impl<W: WalletInterface + Clone + 'static> AuthFetch<W> {
    /// Create a new AuthFetch instance with the given wallet.
    pub fn new(wallet: W) -> Self {
        AuthFetch {
            wallet,
            certificates_to_include: Vec::new(),
            certificates_to_request: None,
            peers: HashMap::new(),
        }
    }

    /// Set certificates to include in handshake exchanges.
    pub fn set_certificates(&mut self, certs: Vec<MasterCertificate>) {
        self.certificates_to_include = certs;
    }

    /// Set certificate types to request from servers during handshake.
    pub fn set_requested_certificates(&mut self, requested: RequestedCertificateSet) {
        self.certificates_to_request = Some(requested);
    }

    /// Send an authenticated HTTP request to the given URL.
    ///
    /// Equivalent to `fetch_with_options(url, method, body, headers, FetchOptions::default())`.
    /// Automatically handles 402 Payment Required by creating and attaching a BSV payment
    /// transaction, then retrying up to [`DEFAULT_PAYMENT_RETRY_ATTEMPTS`] times.
    pub async fn fetch(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<AuthFetchResponse, AuthError> {
        self.fetch_with_options(url, method, body, headers, FetchOptions::default())
            .await
    }

    /// Send an authenticated HTTP request with explicit per-call options.
    ///
    /// Performs the BRC-31 handshake on the first request to a base URL, then
    /// sends the serialized HTTP request as a general message.  If the server
    /// responds with 402 Payment Required, enters the payment retry loop
    /// governed by `options.payment_retry_attempts`.
    pub async fn fetch_with_options(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        options: FetchOptions,
    ) -> Result<AuthFetchResponse, AuthError> {
        let response = self
            .do_fetch_once(url, method, body.clone(), headers.clone())
            .await?;

        if response.status == 402 {
            return self
                .handle_402_and_retry(url, method, body, headers, response, options)
                .await;
        }

        Ok(response)
    }

    // -----------------------------------------------------------------------
    // Internal: single authenticated fetch (no 402 handling)
    // -----------------------------------------------------------------------

    /// Perform one authenticated request without any 402 retry logic.
    ///
    /// This is the core transport layer: establish/reuse the peer session,
    /// wait for cert exchanges, serialize and send the request, then await
    /// and deserialize the response.
    async fn do_fetch_once(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<AuthFetchResponse, AuthError> {
        let base_url = extract_base_url(url)?;
        let path = extract_path(url);
        let query = extract_query(url);
        let headers = headers.unwrap_or_default();

        // Get or create peer for this base URL
        self.ensure_peer(&base_url).await?;

        // Trigger handshake first (if not already authenticated).
        {
            let auth_peer = self.peers.get(&base_url).ok_or_else(|| {
                AuthError::TransportNotConnected(format!("no peer for base URL: {}", base_url))
            })?;
            let cached_identity = auth_peer.identity_key.as_deref().unwrap_or("").to_string();
            let mut peer = auth_peer.peer.lock().await;
            let session = peer.get_authenticated_session(&cached_identity).await?;
            drop(peer);
            if let Some(ap) = self.peers.get_mut(&base_url) {
                ap.identity_key = Some(session.peer_identity_key.clone());
            }
        }

        // Block until any in-flight certificate exchanges complete.
        {
            let auth_peer = self.peers.get(&base_url).ok_or_else(|| {
                AuthError::TransportNotConnected(format!("no peer for base URL: {}", base_url))
            })?;
            let pending = auth_peer.pending_certificate_requests.clone();
            let start = tokio::time::Instant::now();
            loop {
                let empty = pending
                    .lock()
                    .expect("pending queue mutex poisoned")
                    .is_empty();
                if empty {
                    break;
                }
                if tokio::time::Instant::now() - start > CERTIFICATE_WAIT_TIMEOUT {
                    return Err(AuthError::Timeout(
                        "timeout waiting for certificate request to complete".to_string(),
                    ));
                }
                tokio::time::sleep(CERTIFICATE_WAIT_POLL_INTERVAL).await;
            }
        }

        // Serialize the request payload
        let request_nonce = crate::primitives::random::random_bytes(32);
        let payload = serialize_request(&request_nonce, method, &path, &query, &headers, &body);
        let request_nonce_b64 = b64_encode(&request_nonce);

        // Send the general message via the peer
        let auth_peer = self.peers.get(&base_url).ok_or_else(|| {
            AuthError::TransportNotConnected(format!("no peer for base URL: {}", base_url))
        })?;

        let identity_key = auth_peer.identity_key.clone().unwrap_or_default();
        let general_rx = auth_peer.general_rx.clone();

        {
            let mut peer = auth_peer.peer.lock().await;
            peer.send_message(&identity_key, payload).await?;
        }

        // Process any pending incoming messages
        {
            let mut peer = auth_peer.peer.lock().await;
            peer.process_pending().await?;
        }

        // Wait for the response matching our nonce
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(AuthError::Timeout(
                    "auth fetch response timeout".to_string(),
                ));
            }

            let msg = {
                let mut rx = general_rx.lock().await;
                match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        return Err(AuthError::TransportNotConnected(
                            "peer general message channel closed".to_string(),
                        ))
                    }
                    Err(_) => continue,
                }
            };

            let (sender_key, response_payload) = msg;

            if !sender_key.is_empty() {
                if let Some(auth_peer) = self.peers.get_mut(&base_url) {
                    auth_peer.identity_key = Some(sender_key);
                }
            }

            if response_payload.len() < 32 {
                continue;
            }

            let response_nonce_b64 = b64_encode(&response_payload[..32]);
            if response_nonce_b64 != request_nonce_b64 {
                continue;
            }

            return deserialize_response(&response_payload[32..]);
        }
    }

    // -----------------------------------------------------------------------
    // 402 Payment Required handling
    // -----------------------------------------------------------------------

    /// Handle a 402 Payment Required response by building a BSV payment and
    /// retrying the request.
    ///
    /// ## Intentional divergence from TS SDK
    ///
    /// The TS SDK `handlePaymentAndRetry` (AuthFetch.ts:514-623) contains a
    /// latent bug: when `isPaymentContextCompatible` returns `true` (same
    /// satoshis / server key / prefix on the second 402), it re-broadcasts the
    /// **same transaction**, risking a double-spend.  This implementation
    /// **always calls `create_payment_context` afresh on every loop iteration**,
    /// ensuring a fresh transaction and derivation suffix each time.
    async fn handle_402_and_retry(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        original_headers: Option<HashMap<String, String>>,
        first_402: AuthFetchResponse,
        options: FetchOptions,
    ) -> Result<AuthFetchResponse, AuthError> {
        let base_url = extract_base_url(url)?;
        let max_attempts = options
            .payment_retry_attempts
            .unwrap_or(DEFAULT_PAYMENT_RETRY_ATTEMPTS)
            .max(1);

        // The server identity key is cached from the handshake.
        let server_identity_key = self
            .peers
            .get(&base_url)
            .and_then(|p| p.identity_key.clone())
            .ok_or_else(|| {
                AuthError::Payment("no server identity key cached for base URL".to_string())
            })?;

        let mut errors: Vec<PaymentErrorLogEntry> = Vec::new();
        // The 402 response we will parse payment headers from on each loop iteration.
        let mut last_402 = first_402;

        for attempt in 1..=max_attempts {
            // Validate payment version header (must equal PAYMENT_VERSION).
            validate_payment_version(&last_402)?;
            let satoshis = parse_satoshis_required(&last_402)?;
            let derivation_prefix = parse_derivation_prefix(&last_402)?;

            // Always create a fresh context — never reuse a transaction.
            let ctx_result = self
                .create_payment_context(
                    url,
                    satoshis,
                    &server_identity_key,
                    &derivation_prefix,
                    attempt,
                    max_attempts,
                )
                .await;

            let ctx = match ctx_result {
                Ok(c) => c,
                Err(e) => {
                    let entry = make_error_entry(attempt, &e.to_string());
                    errors.push(entry);
                    if attempt == max_attempts {
                        return Err(build_payment_failure(url, attempt, max_attempts, &errors));
                    }
                    tokio::time::sleep(payment_retry_delay(attempt)).await;
                    continue;
                }
            };

            // Assemble x-bsv-payment header (camelCase keys — must match TS wire format).
            let pay_json = serde_json::json!({
                "derivationPrefix": ctx.derivation_prefix,
                "derivationSuffix": ctx.derivation_suffix,
                "transaction": ctx.transaction_base64,
            })
            .to_string();

            let mut retry_headers = original_headers.clone().unwrap_or_default();
            retry_headers.insert("x-bsv-payment".to_string(), pay_json);

            // Retry the request with the payment header attached.
            match self
                .do_fetch_once(url, method, body.clone(), Some(retry_headers))
                .await
            {
                Ok(r) if r.status != 402 => {
                    // Success (or a non-402 error code — pass through to caller).
                    return Ok(r);
                }
                Ok(r_402) => {
                    // Server returned 402 again.
                    errors.push(make_error_entry(
                        attempt,
                        "server returned 402 again after payment",
                    ));
                    last_402 = r_402;
                    if attempt == max_attempts {
                        return Err(build_payment_failure(url, attempt, max_attempts, &errors));
                    }
                    tokio::time::sleep(payment_retry_delay(attempt)).await;
                }
                Err(e) => {
                    errors.push(make_error_entry(attempt, &e.to_string()));
                    if attempt == max_attempts {
                        return Err(build_payment_failure(url, attempt, max_attempts, &errors));
                    }
                    tokio::time::sleep(payment_retry_delay(attempt)).await;
                }
            }
        }

        // Unreachable: every loop branch either returns or continues until max_attempts,
        // and the last iteration always returns. The compiler cannot see this, so provide
        // a defensive fallback rather than `unreachable!()`.
        Err(build_payment_failure(
            url,
            max_attempts,
            max_attempts,
            &errors,
        ))
    }

    /// Build a `PaymentRetryContext` for a single payment attempt.
    ///
    /// Mirrors `createPaymentContext` in TS SDK AuthFetch.ts:638-681.
    async fn create_payment_context(
        &mut self,
        url: &str,
        satoshis_required: u64,
        server_identity_key: &str,
        derivation_prefix: &str,
        attempt: u32,
        max_attempts: u32,
    ) -> Result<PaymentRetryContext, AuthError> {
        use crate::auth::utils::nonce::create_nonce;
        use crate::script::templates::ScriptTemplateLock;
        use crate::wallet::interfaces::{
            CreateActionArgs, CreateActionOptions, CreateActionOutput, GetPublicKeyArgs,
        };
        use crate::wallet::types::{BooleanDefaultTrue, Counterparty, CounterpartyType, Protocol};

        // 1. Create a fresh derivation suffix nonce.
        let derivation_suffix = create_nonce(&self.wallet).await?;

        // 2. Derive the payment public key.
        //    protocolID: [2, "3241645161d8"],  keyID: "{prefix} {suffix}",
        //    counterparty: serverIdentityKey
        //    (mirrors TS getPublicKey call at AuthFetch.ts:647-651)
        let server_pubkey =
            crate::primitives::public_key::PublicKey::from_string(server_identity_key)
                .map_err(AuthError::from)?;

        let derived_pubkey_result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol {
                        security_level: 2,
                        protocol: "3241645161d8".to_string(),
                    }),
                    key_id: Some(format!("{} {}", derivation_prefix, derivation_suffix)),
                    counterparty: Some(Counterparty {
                        counterparty_type: CounterpartyType::Other,
                        public_key: Some(server_pubkey),
                    }),
                    privileged: false,
                    privileged_reason: None,
                    for_self: None,
                    seek_permission: None,
                },
                None, // originator
            )
            .await
            .map_err(AuthError::from)?;

        let derived_pubkey = derived_pubkey_result.public_key;

        // 3. Build P2PKH locking script bytes from the derived public key.
        //    TS: new P2PKH().lock(PublicKey.fromString(derivedPublicKey).toAddress()).toHex()
        //    Rust: build from pubkey hash → raw bytes (serde hex-encodes on the wire).
        let hash_vec = derived_pubkey.to_hash();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_vec);
        let p2pkh = crate::script::templates::p2pkh::P2PKH::from_public_key_hash(hash);
        let lock_script = p2pkh
            .lock()
            .map_err(|e| AuthError::Payment(format!("P2PKH lock failed: {}", e)))?;
        let locking_script_bytes = lock_script.to_binary(); // Vec<u8>

        // 4. Build customInstructions JSON (camelCase, must match TS wire shape).
        let custom_instructions = serde_json::json!({
            "derivationPrefix": derivation_prefix,
            "derivationSuffix": derivation_suffix,
            "payee": server_identity_key,
        })
        .to_string();

        // 5. Create the payment action via the wallet.
        //    description mirrors TS `Payment for request to ${new URL(url).origin}`.
        let description = format!("Payment for request to {}", extract_base_url(url)?);

        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description,
                    input_beef: None,
                    inputs: Vec::new(),
                    outputs: vec![CreateActionOutput {
                        locking_script: Some(locking_script_bytes),
                        satoshis: satoshis_required,
                        output_description: "HTTP request payment".to_string(),
                        basket: None,
                        custom_instructions: Some(custom_instructions),
                        tags: Vec::new(),
                    }],
                    lock_time: None,
                    version: None,
                    labels: Vec::new(),
                    options: Some(CreateActionOptions {
                        // randomizeOutputs: false — must match TS to get deterministic TXID
                        randomize_outputs: BooleanDefaultTrue(Some(false)),
                        ..Default::default()
                    }),
                    reference: None,
                },
                None, // originator
            )
            .await
            .map_err(AuthError::from)?;

        let tx_bytes = create_result.tx.ok_or_else(|| {
            AuthError::Payment(
                "wallet.create_action returned no tx (sign_and_process may have returned early)"
                    .to_string(),
            )
        })?;

        let transaction_base64 = b64_encode(&tx_bytes);

        // 6. Get client identity key for logging / error surfacing.
        let client_identity_key_result = self
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
                None, // originator
            )
            .await
            .map_err(AuthError::from)?;
        let client_identity_key = client_identity_key_result.public_key.to_der_hex();

        Ok(PaymentRetryContext {
            satoshis_required,
            transaction_base64,
            derivation_prefix: derivation_prefix.to_string(),
            derivation_suffix,
            server_identity_key: server_identity_key.to_string(),
            client_identity_key,
            attempts: attempt,
            max_attempts,
            errors: Vec::new(),
        })
    }

    /// Ensure a peer exists for the given base URL, creating one if needed.
    ///
    /// Registers a certificate-request listener on the new Peer that mirrors
    /// TS SDK `AuthFetch` behaviour: pushes a marker onto the pending queue,
    /// fetches verifiable certificates from the wallet, sends the response,
    /// sleeps 500ms, then shifts the queue to release the gate on `fetch`.
    async fn ensure_peer(&mut self, base_url: &str) -> Result<(), AuthError> {
        if self.peers.contains_key(base_url) {
            return Ok(());
        }

        // Create a new SimplifiedHTTPTransport for this base URL
        let transport = create_http_transport(base_url)?;

        // Create a new Peer
        let mut peer = Peer::new(self.wallet.clone(), transport);

        // Configure certificates
        if !self.certificates_to_include.is_empty() {
            peer.set_certificates_to_include(self.certificates_to_include.clone());
        }
        if let Some(ref requested) = self.certificates_to_request {
            peer.set_certificates_to_request(requested.clone());
        }

        // Take the general message receiver before wrapping in Arc<Mutex>
        let general_rx = peer.on_general_message().ok_or_else(|| {
            AuthError::InvalidMessage("general message receiver already taken".to_string())
        })?;

        let peer_arc = Arc::new(Mutex::new(peer));
        let pending = Arc::new(StdMutex::new(Vec::<bool>::new()));

        // Register the cert-request listener. Captures Arc<Peer>, wallet,
        // and the pending queue. Fires synchronously inside dispatch, then
        // spawns an async task that waits for dispatch to release the lock
        // before sending the response.
        {
            let peer_cb = peer_arc.clone();
            let pending_cb = pending.clone();
            let wallet = self.wallet.clone();
            let listener: Arc<crate::auth::peer::OnCertificateRequestReceived> = Arc::new(
                move |verifier_key: String, requested: RequestedCertificateSet| {
                    // Push marker synchronously so `fetch` sees a non-empty
                    // queue before it starts its polling wait.
                    pending_cb
                        .lock()
                        .expect("pending queue mutex poisoned")
                        .push(true);

                    let peer_arc = peer_cb.clone();
                    let pending = pending_cb.clone();
                    let wallet = wallet.clone();
                    tokio::spawn(async move {
                        // Mirror TS listener: fetch + send inside a
                        // try-block; on success or failure, still run the
                        // 500ms grace + shift in the finally. Errors are
                        // swallowed — fire-and-forget, matching TS which
                        // calls the callback without awaiting its result.
                        let _result: Result<(), AuthError> = async {
                            let verifier_pubkey =
                                crate::primitives::public_key::PublicKey::from_string(
                                    &verifier_key,
                                )
                                .map_err(AuthError::from)?;
                            let verifiable =
                                get_verifiable_certificates(&wallet, &requested, &verifier_pubkey)
                                    .await?;
                            if !verifiable.is_empty() {
                                let certs: Vec<Certificate> =
                                    verifiable.into_iter().map(|vc| vc.certificate).collect();
                                let mut peer = peer_arc.lock().await;
                                peer.send_certificate_response(&verifier_key, certs).await?;
                            }
                            Ok(())
                        }
                        .await;

                        // Release the queue entry 500ms after the send (or
                        // the failure path) so the server has time to
                        // ingest the certificates before the general
                        // message arrives — mirrors TS listener finally.
                        tokio::time::sleep(CERTIFICATE_POST_SEND_GRACE).await;
                        let mut queue = pending.lock().expect("pending queue mutex poisoned");
                        if !queue.is_empty() {
                            queue.remove(0);
                        }
                    });
                },
            );

            peer_arc
                .lock()
                .await
                .listen_for_certificates_requested(listener);
        }

        let auth_peer = AuthPeer {
            peer: peer_arc,
            identity_key: None,
            general_rx: Arc::new(Mutex::new(general_rx)),
            pending_certificate_requests: pending,
        };

        self.peers.insert(base_url.to_string(), auth_peer);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 402 header parsing helpers
// ---------------------------------------------------------------------------

/// Validate `x-bsv-payment-version` header equals `PAYMENT_VERSION`.
///
/// Mirrors TS AuthFetch.ts:519-522.
fn validate_payment_version(response: &AuthFetchResponse) -> Result<(), AuthError> {
    let version = get_header_ci(response, "x-bsv-payment-version").ok_or_else(|| {
        AuthError::Payment(format!(
            "missing x-bsv-payment-version header (expected \"{}\")",
            PAYMENT_VERSION
        ))
    })?;
    if version != PAYMENT_VERSION {
        return Err(AuthError::Payment(format!(
            "unsupported x-bsv-payment-version: got \"{}\", client supports \"{}\"",
            version, PAYMENT_VERSION
        )));
    }
    Ok(())
}

/// Parse `x-bsv-payment-satoshis-required` header as a positive integer.
///
/// Mirrors TS AuthFetch.ts:524-531.
fn parse_satoshis_required(response: &AuthFetchResponse) -> Result<u64, AuthError> {
    let raw = get_header_ci(response, "x-bsv-payment-satoshis-required").ok_or_else(|| {
        AuthError::Payment("missing x-bsv-payment-satoshis-required header".to_string())
    })?;
    let satoshis: u64 = raw.trim().parse().map_err(|_| {
        AuthError::Payment(format!(
            "invalid x-bsv-payment-satoshis-required value: \"{}\"",
            raw
        ))
    })?;
    if satoshis == 0 {
        return Err(AuthError::Payment(
            "x-bsv-payment-satoshis-required must be > 0".to_string(),
        ));
    }
    Ok(satoshis)
}

/// Parse `x-bsv-payment-derivation-prefix` header as a non-empty string.
///
/// Mirrors TS AuthFetch.ts:538-541.
fn parse_derivation_prefix(response: &AuthFetchResponse) -> Result<String, AuthError> {
    let prefix = get_header_ci(response, "x-bsv-payment-derivation-prefix").ok_or_else(|| {
        AuthError::Payment("missing x-bsv-payment-derivation-prefix header".to_string())
    })?;
    if prefix.is_empty() {
        return Err(AuthError::Payment(
            "x-bsv-payment-derivation-prefix must not be empty".to_string(),
        ));
    }
    Ok(prefix)
}

/// Case-insensitive header lookup.
fn get_header_ci(response: &AuthFetchResponse, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    response
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name_lower)
        .map(|(_, v)| v.clone())
}

// ---------------------------------------------------------------------------
// Payment retry helpers
// ---------------------------------------------------------------------------

/// Compute the back-off delay for a given attempt number.
///
/// Linear schedule: `250ms * min(attempt, 5)`.
/// Attempt 1 → 250ms, 2 → 500ms, 3 → 750ms, 4 → 1000ms, ≥5 → 1250ms.
///
/// Mirrors `getPaymentRetryDelay` in TS SDK AuthFetch.ts:821-825.
fn payment_retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(250 * u64::from(attempt.min(5)))
}

/// Build a timestamped error log entry.
fn make_error_entry(attempt: u32, message: &str) -> PaymentErrorLogEntry {
    PaymentErrorLogEntry {
        attempt,
        timestamp: iso_now(),
        message: message.to_string(),
    }
}

/// Return the current UTC time as an RFC 3339 string.
///
/// Uses `std::time::SystemTime`; no external crate dependency.
fn iso_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Produce a minimal RFC 3339 / ISO 8601 UTC string.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Approximate Gregorian calendar (good enough for log timestamps).
    let year_start = 1970u64;
    let mut remaining = days;
    let mut year = year_start;
    loop {
        // Clippy wants is_multiple_of but that's unstable; use explicit arithmetic.
        #[allow(clippy::manual_is_multiple_of)]
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let dy = if leap { 366 } else { 365 };
        if remaining < dy {
            break;
        }
        remaining -= dy;
        year += 1;
    }
    #[allow(clippy::manual_is_multiple_of)]
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    let mut day = remaining + 1;
    for &md in &month_days {
        if day <= md {
            break;
        }
        day -= md;
        month += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

/// Build the terminal `AuthError::PaymentFailed` after exhausting all attempts.
fn build_payment_failure(
    url: &str,
    attempts: u32,
    max_attempts: u32,
    errors: &[PaymentErrorLogEntry],
) -> AuthError {
    let last_msg = errors
        .last()
        .map(|e| e.message.as_str())
        .unwrap_or("unknown error");
    AuthError::PaymentFailed {
        attempts,
        max_attempts,
        message: format!(
            "paid request to {} failed after {}/{} attempts; last error: {}",
            url, attempts, max_attempts, last_msg
        ),
    }
}

// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

/// Extract the base URL (scheme + host + port) from a full URL.
///
/// For example, `"https://example.com:8080/api/data?q=1"` -> `"https://example.com:8080"`
pub fn extract_base_url(url: &str) -> Result<String, AuthError> {
    // Find the scheme
    let scheme_end = url
        .find("://")
        .ok_or_else(|| AuthError::InvalidMessage(format!("invalid URL, no scheme: {}", url)))?;
    let after_scheme = &url[scheme_end + 3..];

    // Find the end of the host+port (first / or end of string)
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let base = &url[..scheme_end + 3 + host_end];

    Ok(base.to_string())
}

/// Extract the path component from a URL.
fn extract_path(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            let path_and_query = &after_scheme[slash_pos..];
            if let Some(q_pos) = path_and_query.find('?') {
                return path_and_query[..q_pos].to_string();
            }
            return path_and_query.to_string();
        }
    }
    "/".to_string()
}

/// Extract the query string component from a URL (including the ?).
fn extract_query(url: &str) -> String {
    if let Some(q_pos) = url.find('?') {
        url[q_pos..].to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Request/Response serialization
// ---------------------------------------------------------------------------

/// Serialize an HTTP request into the BRC-31 general message payload format.
///
/// Format (matching TS SDK AuthFetch.serializeRequest):
/// - 32 bytes: request nonce
/// - varint + bytes: method
/// - varint + bytes: path (or varint(-1) if empty)
/// - varint + bytes: query (or varint(-1) if empty)
/// - varint: number of headers
/// - for each header: varint + key bytes, varint + value bytes
/// - varint + bytes: body (or varint(-1) if no body)
fn serialize_request(
    nonce: &[u8],
    method: &str,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
    body: &Option<Vec<u8>>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Request nonce (32 bytes)
    buf.extend_from_slice(nonce);

    // Method
    let method_bytes = method.as_bytes();
    write_varint_num(&mut buf, method_bytes.len() as i64);
    buf.extend_from_slice(method_bytes);

    // Path
    if !path.is_empty() {
        let path_bytes = path.as_bytes();
        write_varint_num(&mut buf, path_bytes.len() as i64);
        buf.extend_from_slice(path_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Query
    if !query.is_empty() {
        let query_bytes = query.as_bytes();
        write_varint_num(&mut buf, query_bytes.len() as i64);
        buf.extend_from_slice(query_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Headers -- normalize and sort by key for consistent signing.
    // Content-type is normalized by stripping parameters (e.g. "; charset=utf-8")
    // to match the TS SDK behavior in both AuthFetch and middleware.
    let mut sorted_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            let key = k.to_lowercase();
            let value = if key == "content-type" {
                v.split(';').next().unwrap_or("").trim().to_string()
            } else {
                v.clone()
            };
            (key, value)
        })
        .collect();
    sorted_headers.sort_by(|(a, _), (b, _)| a.cmp(b));

    write_varint_num(&mut buf, sorted_headers.len() as i64);
    for (key, value) in &sorted_headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);

        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    // Body
    match body {
        Some(b) => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        None => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

/// Deserialize a response payload from the BRC-31 general message format.
///
/// Format (matching TS SDK AuthFetch response deserialization):
/// - varint: status code
/// - varint: number of headers
/// - for each header: varint + key bytes, varint + value bytes
/// - varint: body length
/// - body bytes
fn deserialize_response(data: &[u8]) -> Result<AuthFetchResponse, AuthError> {
    let mut pos = 0;

    // Status code
    let status = read_varint_num(data, &mut pos)? as u16;

    // Headers
    let num_headers = read_varint_num(data, &mut pos)?;
    let mut headers = HashMap::new();
    for _ in 0..num_headers {
        let key_len = read_varint_num(data, &mut pos)? as usize;
        if pos + key_len > data.len() {
            return Err(AuthError::SerializationError(
                "response header key extends past data".to_string(),
            ));
        }
        let key = String::from_utf8_lossy(&data[pos..pos + key_len]).to_string();
        pos += key_len;

        let val_len = read_varint_num(data, &mut pos)? as usize;
        if pos + val_len > data.len() {
            return Err(AuthError::SerializationError(
                "response header value extends past data".to_string(),
            ));
        }
        let value = String::from_utf8_lossy(&data[pos..pos + val_len]).to_string();
        pos += val_len;

        headers.insert(key, value);
    }

    // Body
    let body_len = read_varint_num(data, &mut pos)?;
    let body = if body_len > 0 {
        let body_len = body_len as usize;
        if pos + body_len > data.len() {
            return Err(AuthError::SerializationError(
                "response body extends past data".to_string(),
            ));
        }
        data[pos..pos + body_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(AuthFetchResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Varint helpers (signed, matching TS SDK Writer.writeVarIntNum / Reader.readVarIntNum)
// ---------------------------------------------------------------------------

/// Write a signed varint matching TS SDK Writer.writeVarIntNum behavior.
///
/// Negative values are encoded as their two's complement unsigned 64-bit
/// representation. For -1 this gives `0xFFFFFFFFFFFFFFFF`, encoded as
/// `0xFF` prefix + 8 LE bytes = 9 bytes total.
fn write_varint_num(buf: &mut Vec<u8>, val: i64) {
    if val < 0 {
        // Reinterpret as u64 (two's complement), matching TS SDK which does
        // `bn.add(2^64)` for negative BigNumber values in varIntBn.
        let uval = val as u64;
        buf.push(0xff);
        buf.extend_from_slice(&uval.to_le_bytes());
        return;
    }
    let val = val as u64;
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a varint from data at the given position. Advances pos.
fn read_varint_num(data: &[u8], pos: &mut usize) -> Result<i64, AuthError> {
    if *pos >= data.len() {
        return Err(AuthError::SerializationError(
            "unexpected end of response data reading varint".to_string(),
        ));
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0xfd => {
            if *pos + 2 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 2-byte value truncated".to_string(),
                ));
            }
            let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(val as i64)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 4-byte value truncated".to_string(),
                ));
            }
            let val =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(val as i64)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 8-byte value truncated".to_string(),
                ));
            }
            let val = u64::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(val as i64)
        }
        _ => Ok(first as i64),
    }
}

// ---------------------------------------------------------------------------
// Transport factory (creates SimplifiedHTTPTransport stub)
// ---------------------------------------------------------------------------

/// Create an HTTP transport for the given base URL.
fn create_http_transport(base_url: &str) -> Result<Arc<dyn Transport>, AuthError> {
    Ok(Arc::new(
        crate::auth::transports::http::SimplifiedHTTPTransport::new(base_url),
    ))
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

fn b64_encode(data: &[u8]) -> String {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pre-existing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("https://example.com/api/data?q=1").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            extract_base_url("http://localhost:3000/path").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            extract_base_url("https://api.example.com:8443/v1/resource").unwrap(),
            "https://api.example.com:8443"
        );
        assert_eq!(
            extract_base_url("https://example.com").unwrap(),
            "https://example.com"
        );
        assert!(extract_base_url("not-a-url").is_err());
    }

    #[test]
    fn test_extract_path() {
        assert_eq!(
            extract_path("https://example.com/api/data?q=1"),
            "/api/data"
        );
        assert_eq!(extract_path("https://example.com/path"), "/path");
        assert_eq!(extract_path("https://example.com"), "/");
    }

    #[test]
    fn test_extract_query() {
        assert_eq!(
            extract_query("https://example.com/api?q=hello&page=1"),
            "?q=hello&page=1"
        );
        assert_eq!(extract_query("https://example.com/api"), "");
    }

    #[test]
    fn test_serialize_deserialize_request() {
        let nonce = [42u8; 32];
        let method = "POST";
        let path = "/api/data";
        let query = "?page=1";
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let body = Some(b"{\"key\":\"value\"}".to_vec());

        let payload = serialize_request(&nonce, method, path, query, &headers, &body);

        // Verify the nonce is at the start
        assert_eq!(&payload[..32], &nonce);
        // Payload should be non-trivially long
        assert!(payload.len() > 50);
    }

    #[test]
    fn test_deserialize_response() {
        // Build a response payload manually
        let mut data = Vec::new();
        // Status: 200
        write_varint_num(&mut data, 200);
        // 1 header
        write_varint_num(&mut data, 1);
        // Header key: "content-type"
        let key = b"content-type";
        write_varint_num(&mut data, key.len() as i64);
        data.extend_from_slice(key);
        // Header value: "application/json"
        let val = b"application/json";
        write_varint_num(&mut data, val.len() as i64);
        data.extend_from_slice(val);
        // Body
        let body = b"hello world";
        write_varint_num(&mut data, body.len() as i64);
        data.extend_from_slice(body);

        let response = deserialize_response(&data).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(response.body, b"hello world");
    }

    #[test]
    fn test_auth_fetch_response_struct() {
        let response = AuthFetchResponse {
            status: 404,
            headers: HashMap::new(),
            body: b"not found".to_vec(),
        };
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"not found");
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values: Vec<i64> = vec![0, 1, 127, 252, 253, 1000, 70000, 200];
        for val in test_values {
            let mut buf = Vec::new();
            write_varint_num(&mut buf, val);
            let mut pos = 0;
            let decoded = read_varint_num(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
            assert_eq!(pos, buf.len());
        }
    }

    // -----------------------------------------------------------------------
    // New tests: 402 payment retry logic
    // -----------------------------------------------------------------------

    /// payment_retry_delay: verify linear schedule mirrors TS SDK
    /// `getPaymentRetryDelay` (AuthFetch.ts:821-825).
    #[test]
    fn test_payment_retry_delay_schedule() {
        assert_eq!(payment_retry_delay(1), Duration::from_millis(250));
        assert_eq!(payment_retry_delay(2), Duration::from_millis(500));
        assert_eq!(payment_retry_delay(3), Duration::from_millis(750));
        assert_eq!(payment_retry_delay(4), Duration::from_millis(1000));
        assert_eq!(payment_retry_delay(5), Duration::from_millis(1250));
        // cap at min(attempt, 5) → any attempt ≥ 5 returns 1250ms
        assert_eq!(payment_retry_delay(100), Duration::from_millis(1250));
        assert_eq!(payment_retry_delay(0), Duration::from_millis(0));
    }

    /// Header parsing: all required 402 headers present and valid → Ok.
    #[test]
    fn test_parse_payment_headers_valid() {
        let mut headers = HashMap::new();
        headers.insert("x-bsv-payment-version".to_string(), "1.0".to_string());
        headers.insert(
            "x-bsv-payment-satoshis-required".to_string(),
            "1000".to_string(),
        );
        headers.insert(
            "x-bsv-payment-derivation-prefix".to_string(),
            "some-prefix".to_string(),
        );
        let resp = AuthFetchResponse {
            status: 402,
            headers,
            body: Vec::new(),
        };

        assert!(validate_payment_version(&resp).is_ok());
        assert_eq!(parse_satoshis_required(&resp).unwrap(), 1000u64);
        assert_eq!(
            parse_derivation_prefix(&resp).unwrap(),
            "some-prefix".to_string()
        );
    }

    /// Header parsing: wrong payment version → Err.
    #[test]
    fn test_parse_payment_headers_invalid_version() {
        let mut headers = HashMap::new();
        headers.insert("x-bsv-payment-version".to_string(), "2.0".to_string());
        let resp = AuthFetchResponse {
            status: 402,
            headers,
            body: Vec::new(),
        };
        let err = validate_payment_version(&resp).unwrap_err();
        assert!(
            matches!(err, AuthError::Payment(_)),
            "expected Payment error, got {:?}",
            err
        );
        assert!(err.to_string().contains("2.0"));
    }

    /// Header parsing: missing satoshis header → Err.
    #[test]
    fn test_parse_payment_headers_missing_satoshis() {
        let resp = AuthFetchResponse {
            status: 402,
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let err = parse_satoshis_required(&resp).unwrap_err();
        assert!(matches!(err, AuthError::Payment(_)));
    }

    /// Header parsing: satoshis = 0 is invalid.
    #[test]
    fn test_parse_payment_headers_zero_satoshis() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-bsv-payment-satoshis-required".to_string(),
            "0".to_string(),
        );
        let resp = AuthFetchResponse {
            status: 402,
            headers,
            body: Vec::new(),
        };
        let err = parse_satoshis_required(&resp).unwrap_err();
        assert!(matches!(err, AuthError::Payment(_)));
    }

    /// FetchOptions defaults: None → 3 attempts; explicit values preserved.
    #[test]
    fn test_fetch_options_default_retry_attempts() {
        let default_opts = FetchOptions::default();
        let effective = default_opts
            .payment_retry_attempts
            .unwrap_or(DEFAULT_PAYMENT_RETRY_ATTEMPTS);
        assert_eq!(effective, 3);

        let explicit_opts = FetchOptions {
            payment_retry_attempts: Some(7),
        };
        assert_eq!(explicit_opts.payment_retry_attempts.unwrap(), 7);
    }

    /// x-bsv-payment JSON shape: camelCase keys, exact TS wire format.
    #[test]
    fn test_x_bsv_payment_json_shape() {
        let prefix = "pfx123";
        let suffix = "sfx456";
        let tx_b64 = "AAAA";
        let json_str = serde_json::json!({
            "derivationPrefix": prefix,
            "derivationSuffix": suffix,
            "transaction": tx_b64,
        })
        .to_string();

        // Must be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["derivationPrefix"], prefix);
        assert_eq!(parsed["derivationSuffix"], suffix);
        assert_eq!(parsed["transaction"], tx_b64);

        // Must NOT use snake_case keys (TS wire parity)
        assert!(!json_str.contains("derivation_prefix"));
        assert!(!json_str.contains("derivation_suffix"));
    }

    /// Header lookup is case-insensitive (server may use any casing).
    #[test]
    fn test_get_header_ci() {
        let mut headers = HashMap::new();
        headers.insert("X-BSV-Payment-Version".to_string(), "1.0".to_string());
        let resp = AuthFetchResponse {
            status: 402,
            headers,
            body: Vec::new(),
        };
        assert_eq!(
            get_header_ci(&resp, "x-bsv-payment-version"),
            Some("1.0".to_string())
        );
        assert_eq!(
            get_header_ci(&resp, "X-BSV-PAYMENT-VERSION"),
            Some("1.0".to_string())
        );
    }

    /// `payment_retry_attempts: Some(0)` must clamp to 1 via `.max(1)`,
    /// guaranteeing at least one attempt even when misconfigured.
    #[test]
    fn test_max_attempts_clamp_zero_becomes_one() {
        let clamped = FetchOptions {
            payment_retry_attempts: Some(0),
        }
        .payment_retry_attempts
        .unwrap_or(DEFAULT_PAYMENT_RETRY_ATTEMPTS)
        .max(1);
        assert_eq!(clamped, 1, "zero attempts must clamp to at least 1");

        // None → default (3), not clamped below 3.
        let none_case = FetchOptions::default()
            .payment_retry_attempts
            .unwrap_or(DEFAULT_PAYMENT_RETRY_ATTEMPTS)
            .max(1);
        assert_eq!(none_case, 3);

        // Explicit high value preserved.
        let high = FetchOptions {
            payment_retry_attempts: Some(10),
        }
        .payment_retry_attempts
        .unwrap_or(DEFAULT_PAYMENT_RETRY_ATTEMPTS)
        .max(1);
        assert_eq!(high, 10);
    }

    /// customInstructions JSON shape: camelCase keys exactly matching TS
    /// `{ derivationPrefix, derivationSuffix, payee }`. Server-side payment
    /// derivation breaks silently if key names drift.
    #[test]
    fn test_custom_instructions_json_shape() {
        let prefix = "pfx";
        let suffix = "sfx";
        let server_key = "02abcdef";
        let json_str = serde_json::json!({
            "derivationPrefix": prefix,
            "derivationSuffix": suffix,
            "payee": server_key,
        })
        .to_string();

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["derivationPrefix"], prefix);
        assert_eq!(parsed["derivationSuffix"], suffix);
        assert_eq!(parsed["payee"], server_key);

        // TS wire parity: no snake_case.
        assert!(!json_str.contains("derivation_prefix"));
        assert!(!json_str.contains("derivation_suffix"));
        assert!(!json_str.contains("server_identity_key"));
    }

    /// iso_now produces a non-empty, roughly ISO-shaped string.
    #[test]
    fn test_iso_now_format() {
        let ts = iso_now();
        // minimal: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars
        assert!(ts.len() >= 20, "timestamp too short: {}", ts);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }
}
