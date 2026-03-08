//! Peer orchestrator for BRC-31 mutual authentication.
//!
//! The Peer manages handshakes, sessions via SessionManager, and message dispatch
//! over a Transport. It is the central protocol engine for BRC-31 Authrite.
//!
//! Translated from TS SDK Peer.ts (991 lines) and Go SDK peer.go (1163 lines).

use std::sync::Arc;

use tokio::sync::mpsc;

use super::certificates::master::MasterCertificate;
use super::error::AuthError;
use super::session_manager::SessionManager;
use super::transports::Transport;
use super::types::{
    AuthMessage, MessageType, PeerSession, RequestedCertificateSet, AUTH_PROTOCOL_ID, AUTH_VERSION,
};
use super::utils::nonce::{create_nonce, verify_nonce};
use crate::wallet::interfaces::{
    Certificate, CreateSignatureArgs, GetPublicKeyArgs, VerifySignatureArgs, WalletInterface,
};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

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

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

/// A peer capable of performing BRC-31 mutual authentication.
///
/// Manages sessions, handles authentication handshakes, certificate requests
/// and responses, and sends/receives general messages over a Transport.
///
/// Generic over `W: WalletInterface` for cryptographic operations.
/// Feature-gated behind `network` since it depends on tokio and Transport.
pub struct Peer<W: WalletInterface> {
    wallet: W,
    transport: Arc<dyn Transport>,
    session_manager: SessionManager,
    #[allow(dead_code)]
    certificates_to_include: Vec<MasterCertificate>,
    certificates_to_request: Option<RequestedCertificateSet>,

    // Event channels (sender side -- Peer pushes events here)
    general_message_tx: mpsc::Sender<(String, Vec<u8>)>,
    certificate_tx: mpsc::Sender<(String, Vec<Certificate>)>,
    certificate_request_tx: mpsc::Sender<(String, RequestedCertificateSet)>,

    // Receiver side -- taken once by consumer
    general_message_rx: Option<mpsc::Receiver<(String, Vec<u8>)>>,
    certificate_rx: Option<mpsc::Receiver<(String, Vec<Certificate>)>>,
    certificate_request_rx: Option<mpsc::Receiver<(String, RequestedCertificateSet)>>,

    // Transport incoming message receiver
    transport_rx: Option<mpsc::Receiver<AuthMessage>>,
}

impl<W: WalletInterface> Peer<W> {
    /// Create a new Peer with the given wallet and transport.
    pub fn new(wallet: W, transport: Arc<dyn Transport>) -> Self {
        let (general_tx, general_rx) = mpsc::channel(32);
        let (cert_tx, cert_rx) = mpsc::channel(32);
        let (cert_req_tx, cert_req_rx) = mpsc::channel(32);

        let transport_rx = transport.subscribe();

        Peer {
            wallet,
            transport,
            session_manager: SessionManager::new(),
            certificates_to_include: Vec::new(),
            certificates_to_request: None,
            general_message_tx: general_tx,
            certificate_tx: cert_tx,
            certificate_request_tx: cert_req_tx,
            general_message_rx: Some(general_rx),
            certificate_rx: Some(cert_rx),
            certificate_request_rx: Some(cert_req_rx),
            transport_rx: Some(transport_rx),
        }
    }

    /// Set certificates to include in handshake responses.
    pub fn set_certificates_to_include(&mut self, certs: Vec<MasterCertificate>) {
        self.certificates_to_include = certs;
    }

    /// Set certificate types to request from peers during handshake.
    pub fn set_certificates_to_request(&mut self, requested: RequestedCertificateSet) {
        self.certificates_to_request = Some(requested);
    }

    /// Take the general message receiver. Returns None if already taken.
    pub fn on_general_message(&mut self) -> Option<mpsc::Receiver<(String, Vec<u8>)>> {
        self.general_message_rx.take()
    }

    /// Take the certificates receiver. Returns None if already taken.
    pub fn on_certificates(&mut self) -> Option<mpsc::Receiver<(String, Vec<Certificate>)>> {
        self.certificate_rx.take()
    }

    /// Take the certificate request receiver. Returns None if already taken.
    pub fn on_certificate_request(
        &mut self,
    ) -> Option<mpsc::Receiver<(String, RequestedCertificateSet)>> {
        self.certificate_request_rx.take()
    }

    /// Get a reference to the session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Process one incoming message from the transport.
    ///
    /// Returns `Ok(true)` if a message was processed, `Ok(false)` if no message
    /// was available (channel empty/closed).
    pub async fn process_next(&mut self) -> Result<bool, AuthError> {
        let rx = match self.transport_rx.as_mut() {
            Some(rx) => rx,
            None => return Ok(false),
        };

        match rx.try_recv() {
            Ok(msg) => {
                self.dispatch_message(msg).await?;
                Ok(true)
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(false),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(false),
        }
    }

    /// Process all pending incoming messages from the transport.
    ///
    /// Drains the transport receive buffer and dispatches each message.
    pub async fn process_pending(&mut self) -> Result<usize, AuthError> {
        let mut count = 0;
        while self.process_next().await? {
            count += 1;
        }
        Ok(count)
    }

    /// Send a general message to a peer identified by their identity key.
    ///
    /// If no authenticated session exists, initiates a handshake first.
    pub async fn send_message(
        &mut self,
        identity_key: &str,
        payload: Vec<u8>,
    ) -> Result<(), AuthError> {
        // Find or create an authenticated session
        let session = self.get_authenticated_session(identity_key).await?;

        // Build the general message
        let request_nonce = base64_encode(&crate::primitives::random::random_bytes(32));
        let key_id = format!("{} {}", request_nonce, session.peer_nonce);

        let signature_result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: payload.clone(),
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

        let general_msg = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::General,
            identity_key: identity_key_str,
            nonce: Some(request_nonce),
            your_nonce: Some(session.peer_nonce.clone()),
            initial_nonce: Some(session.session_nonce.clone()),
            certificates: None,
            requested_certificates: None,
            payload: Some(payload),
            signature: Some(signature_result.signature),
        };

        self.transport.send(general_msg).await
    }

    /// Send a certificate response to a peer.
    ///
    /// Sends a CertificateResponse message containing the given certificates.
    /// The peer must already have an authenticated session.
    ///
    /// Translated from TS SDK Peer.sendCertificateResponse().
    pub async fn send_certificate_response(
        &mut self,
        identity_key: &str,
        certificates: Vec<Certificate>,
    ) -> Result<(), AuthError> {
        let session = self.get_authenticated_session(identity_key).await?;
        let identity_key_str = self.get_identity_public_key().await?;

        let cert_response = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::CertificateResponse,
            identity_key: identity_key_str,
            nonce: None,
            your_nonce: Some(session.peer_nonce.clone()),
            initial_nonce: Some(session.session_nonce.clone()),
            certificates: Some(certificates),
            requested_certificates: None,
            payload: None,
            signature: None,
        };

        self.transport.send(cert_response).await
    }

    /// Get an authenticated session for the given identity key, initiating
    /// a handshake if necessary.
    ///
    /// Public to allow AuthFetch to trigger handshake before sending
    /// general messages (needed for certificate exchange ordering).
    pub async fn get_authenticated_session(
        &mut self,
        identity_key: &str,
    ) -> Result<PeerSession, AuthError> {
        // Check if we already have an authenticated session
        if let Some(session) = self.session_manager.get_session_by_identifier(identity_key) {
            if session.is_authenticated {
                return Ok(session.clone());
            }
        }

        // Initiate handshake
        self.initiate_handshake(identity_key).await
    }

    /// Initiate a BRC-31 handshake with the given peer.
    ///
    /// Creates a nonce, sends an initialRequest, waits for the
    /// initialResponse (polling the transport), and completes the handshake.
    async fn initiate_handshake(&mut self, identity_key: &str) -> Result<PeerSession, AuthError> {
        let session_nonce = create_nonce(&self.wallet).await?;

        // Create initial session (not yet authenticated)
        self.session_manager.add_session(PeerSession {
            session_nonce: session_nonce.clone(),
            peer_identity_key: identity_key.to_string(),
            peer_nonce: String::new(),
            is_authenticated: false,
        });

        let identity_key_str = self.get_identity_public_key().await?;

        let initial_request = AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: identity_key_str,
            nonce: None,
            your_nonce: None,
            initial_nonce: Some(session_nonce.clone()),
            certificates: None,
            requested_certificates: self.certificates_to_request.clone(),
            payload: None,
            signature: None,
        };

        // Send the request
        self.transport.send(initial_request).await?;

        // Wait for the response by polling the transport
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(AuthError::Timeout("handshake timeout".to_string()));
            }

            let msg = {
                let rx = self.transport_rx.as_mut().ok_or_else(|| {
                    AuthError::TransportNotConnected("no transport rx".to_string())
                })?;
                match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        return Err(AuthError::TransportNotConnected(
                            "transport closed".to_string(),
                        ))
                    }
                    Err(_) => continue, // timeout, retry
                }
            };

            // If this is the initialResponse we're waiting for, process it
            if msg.message_type == MessageType::InitialResponse {
                if let Some(ref your_nonce) = msg.your_nonce {
                    if your_nonce == &session_nonce {
                        return self.complete_handshake(&session_nonce, msg).await;
                    }
                }
            }

            // Otherwise dispatch the message normally
            self.dispatch_message(msg).await?;
        }
    }

    /// Complete a handshake after receiving the initialResponse.
    async fn complete_handshake(
        &mut self,
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
                    data: verify_data,
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

        // Update session to authenticated
        let session = PeerSession {
            session_nonce: session_nonce.to_string(),
            peer_identity_key: response.identity_key.clone(),
            peer_nonce,
            is_authenticated: true,
        };

        self.session_manager
            .update_session(session_nonce, session.clone());

        // Push certificates to channel if any
        if let Some(certs) = response.certificates {
            if !certs.is_empty() {
                let _ = self
                    .certificate_tx
                    .send((response.identity_key.clone(), certs))
                    .await;
            }
        }

        // Handle certificate requests from peer
        if let Some(ref requested) = response.requested_certificates {
            let _ = self
                .certificate_request_tx
                .send((response.identity_key.clone(), requested.clone()))
                .await;
        }

        Ok(session)
    }

    /// Dispatch an incoming message based on its type.
    async fn dispatch_message(&mut self, msg: AuthMessage) -> Result<(), AuthError> {
        if msg.version != AUTH_VERSION {
            return Err(AuthError::InvalidMessage(format!(
                "unsupported auth version: {}, expected: {}",
                msg.version, AUTH_VERSION
            )));
        }

        match msg.message_type {
            MessageType::InitialRequest => self.handle_initial_request(msg).await,
            MessageType::InitialResponse => {
                // InitialResponse should be handled by initiate_handshake polling.
                // If we get one here unexpectedly, ignore it.
                Ok(())
            }
            MessageType::CertificateRequest => {
                if let Some(ref requested) = msg.requested_certificates {
                    let _ = self
                        .certificate_request_tx
                        .send((msg.identity_key.clone(), requested.clone()))
                        .await;
                }
                Ok(())
            }
            MessageType::CertificateResponse => {
                if let Some(certs) = msg.certificates {
                    if !certs.is_empty() {
                        let _ = self
                            .certificate_tx
                            .send((msg.identity_key.clone(), certs))
                            .await;
                    }
                }
                Ok(())
            }
            MessageType::General => self.handle_general_message(msg).await,
        }
    }

    /// Handle an incoming initialRequest message.
    ///
    /// Creates a session, signs a response, and sends the initialResponse back.
    async fn handle_initial_request(&mut self, msg: AuthMessage) -> Result<(), AuthError> {
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

        // Add session (authenticated -- responder trusts after signature verification)
        self.session_manager.add_session(PeerSession {
            session_nonce: session_nonce.clone(),
            peer_identity_key: msg.identity_key.clone(),
            peer_nonce: peer_initial_nonce.to_string(),
            is_authenticated: true,
        });

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
                    data: sign_data,
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
            certificates: None,
            requested_certificates: self.certificates_to_request.clone(),
            payload: None,
            signature: Some(sig_result.signature),
        };

        self.transport.send(response).await
    }

    /// Handle an incoming general message.
    ///
    /// Verifies the session exists and the signature is valid, then pushes
    /// the message payload to the general_message channel.
    async fn handle_general_message(&mut self, msg: AuthMessage) -> Result<(), AuthError> {
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

        // Verify session exists
        let session = self
            .session_manager
            .get_session_by_identifier(your_nonce)
            .cloned()
            .ok_or_else(|| {
                AuthError::SessionNotFound(format!("session not found for nonce: {}", your_nonce))
            })?;

        // Verify signature
        let payload = msg.payload.clone().unwrap_or_default();
        let msg_nonce = msg.nonce.as_deref().unwrap_or("");
        let key_id = format!("{} {}", msg_nonce, session.session_nonce);

        let peer_pubkey = parse_public_key(&msg.identity_key)?;

        let verify_result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: payload.clone(),
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

        // Push to general message channel
        let _ = self
            .general_message_tx
            .send((msg.identity_key.clone(), payload))
            .await;

        Ok(())
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
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::error::WalletError;
    use crate::wallet::interfaces::*;
    use crate::wallet::types::Protocol as WalletProtocol;
    use crate::wallet::ProtoWallet;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    // -----------------------------------------------------------------------
    // TestWallet: WalletInterface wrapper around ProtoWallet
    // -----------------------------------------------------------------------

    struct TestWallet {
        inner: ProtoWallet,
    }

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet {
                inner: ProtoWallet::new(pk),
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
            let pk = self.inner.get_public_key(
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
            let ciphertext = self.inner.encrypt(
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
            let plaintext = self.inner.decrypt(
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
            let hmac = self.inner.create_hmac(
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
            let valid = self.inner.verify_hmac(
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
            let signature = self.inner.create_signature(
                &args.data,
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
            let valid = self.inner.verify_signature(
                &args.data,
                &args.signature,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
                args.for_self.unwrap_or(false),
            )?;
            Ok(VerifySignatureResult { valid })
        }

        stub_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
        stub_method!(
            list_certificates,
            ListCertificatesArgs,
            ListCertificatesResult
        );
        stub_method!(
            prove_certificate,
            ProveCertificateArgs,
            ProveCertificateResult
        );
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
    }

    /// Create a paired set of mock transports.
    /// Messages sent by transport_a are received by transport_b and vice versa.
    fn create_mock_transport_pair() -> (Arc<MockTransport>, Arc<MockTransport>) {
        let (tx_a, rx_a) = mpsc::channel(32);
        let (tx_b, rx_b) = mpsc::channel(32);

        let transport_a = Arc::new(MockTransport {
            peer_tx: tx_b,
            incoming_rx: StdMutex::new(Some(rx_a)),
        });

        let transport_b = Arc::new(MockTransport {
            peer_tx: tx_a,
            incoming_rx: StdMutex::new(Some(rx_b)),
        });

        (transport_a, transport_b)
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
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

    // -----------------------------------------------------------------------
    // Integration tests
    // -----------------------------------------------------------------------

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
                let mut peer_a = Peer::new(wallet_a, transport_a);
                let mut peer_b = Peer::new(wallet_b, transport_b);

                // Set up message receivers before starting
                let mut msg_rx_b = peer_b.on_general_message().unwrap();

                // Step 1: Peer A starts sending (will block waiting for handshake response)
                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"Hello from Peer A!".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });

                // Step 2: Give Peer A time to send the initialRequest
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Step 3: Peer B processes the initialRequest (sends initialResponse)
                let processed = peer_b.process_pending().await.unwrap();
                assert!(
                    processed > 0,
                    "Peer B should have received the initialRequest"
                );

                // Step 4: Give time for Peer A to receive and process initialResponse
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Step 5: Get Peer A back (handshake done, general msg sent)
                let peer_a = send_handle.await.unwrap();

                // Step 6: Peer B processes the general message
                let processed = peer_b.process_pending().await.unwrap();
                assert!(
                    processed > 0,
                    "Peer B should have received the general message"
                );

                // Peer B should have received the message on the channel
                let (sender_key, received_payload) = msg_rx_b.try_recv().unwrap();
                assert_eq!(sender_key, identity_a);
                assert_eq!(received_payload, b"Hello from Peer A!");

                // Verify both peers have authenticated sessions
                let sessions_a = peer_a
                    .session_manager()
                    .get_sessions_for_identity(&identity_b);
                assert!(
                    !sessions_a.is_empty(),
                    "Peer A should have a session for Peer B"
                );
                assert!(
                    sessions_a[0].is_authenticated,
                    "Peer A session should be authenticated"
                );

                let sessions_b = peer_b
                    .session_manager()
                    .get_sessions_for_identity(&identity_a);
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

                let mut peer_a = Peer::new(wallet_a, transport_a);
                let mut peer_b = Peer::new(wallet_b, transport_b);

                // Interleaved handshake
                let identity_b_clone = identity_b.clone();
                let send_handle = tokio::task::spawn_local(async move {
                    peer_a
                        .send_message(&identity_b_clone, b"test".to_vec())
                        .await
                        .unwrap();
                    peer_a
                });

                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                peer_b.process_pending().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                let peer_a = send_handle.await.unwrap();

                // Peer A should have a session for Peer B
                assert!(
                    peer_a
                        .session_manager()
                        .get_session_by_identifier(&identity_b)
                        .is_some(),
                    "Peer A should track Peer B session"
                );
            })
            .await;
    }
}
