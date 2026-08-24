//! Official BRC-103 authentication schema and HTTP-behaviour corpus.
//!
//! These vectors are not byte-level cryptographic fixtures. The assertions
//! below exercise real Rust constructors, serde boundaries, key parsing, and
//! HTTP transport behavior. Middleware/Socket.IO server behavior is recorded
//! as governed skips owned by the repositories that implement those servers.

#![cfg(feature = "network")]

mod conformance_harness;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bsv::auth::transports::http::{HEADER_AUTH_VERSION, HEADER_REQUEST_ID};
use bsv::auth::transports::{SimplifiedHTTPTransport, Transport};
use bsv::auth::{
    AuthError, AuthMessage, MessageType, Peer, PeerSession, RequestedCertificateSet, AUTH_VERSION,
};
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::proto_wallet::ProtoWallet;
use conformance_harness::{ensure, run_corpora, Corpus, GovernedSkip, KnownDivergence, Vector};
use futures_util::FutureExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use wiremock::{Mock, MockServer, ResponseTemplate};

const BRC103_HTTP: &str = include_str!("../conformance/vectors/auth/brc31-handshake.json");
const AUTH_SOCKET: &str = include_str!("../conformance/vectors/messaging/authsocket.json");

const CORPORA: &[Corpus<'_>] = &[
    Corpus {
        category: "brc103-http",
        json: BRC103_HTTP,
        expected_count: 16,
    },
    Corpus {
        category: "authsocket",
        json: AUTH_SOCKET,
        expected_count: 12,
    },
];

const EXPRESS: &str =
    "owned by packages/middleware/auth-express-middleware: this crate has no Express HTTP server";
const AUTH_SOCKET_SERVER: &str =
    "owned by packages/messaging/authsocket: this crate has no Socket.IO AuthSocket server";

const GOVERNED_SKIPS: &[GovernedSkip<'_>] = &[
    GovernedSkip { id: "auth.brc31-handshake.2", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.3", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.4", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.5", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.6", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.7", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.8", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.9", reason: EXPRESS },
    GovernedSkip {
        id: "auth.brc31-handshake.10",
        reason: "owned by packages/middleware/auth-express-middleware: it maps the 30-second certificate gate to HTTP 408; this crate's gate timing is asserted separately",
    },
    GovernedSkip { id: "auth.brc31-handshake.11", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.14", reason: EXPRESS },
    GovernedSkip { id: "auth.brc31-handshake.16", reason: EXPRESS },
    GovernedSkip { id: "messaging.authsocket.1", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.2", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.3", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.5", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.6", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.7", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.9", reason: AUTH_SOCKET_SERVER },
    GovernedSkip { id: "messaging.authsocket.10", reason: AUTH_SOCKET_SERVER },
];

const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[KnownDivergence {
    id: "auth.brc31-handshake.1",
    reason: "the corpus request example carries nonce/payload/signature, while real Rust and TS 2.4.1 Peer constructors do not",
    evidence: "initialRequest JSON shape mismatch: expected keys {\"identityKey\", \"initialNonce\", \"messageType\", \"nonce\", \"payload\", \"signature\", \"version\"}, got {\"identityKey\", \"initialNonce\", \"messageType\", \"requestedCertificates\", \"version\"}",
}];

struct CaptureTransport {
    sent: mpsc::Sender<AuthMessage>,
    incoming: Mutex<Option<mpsc::Receiver<AuthMessage>>>,
}

#[async_trait]
impl Transport for CaptureTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        self.sent
            .send(message)
            .await
            .map_err(|error| AuthError::TransportError(error.to_string()))
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming
            .lock()
            .expect("capture transport mutex poisoned")
            .take()
            .expect("capture transport subscribed twice")
    }
}

fn capture_transport() -> (Arc<CaptureTransport>, mpsc::Receiver<AuthMessage>) {
    let (sent_tx, sent_rx) = mpsc::channel(8);
    let (_incoming_tx, incoming_rx) = mpsc::channel(8);
    (
        Arc::new(CaptureTransport {
            sent: sent_tx,
            incoming: Mutex::new(Some(incoming_rx)),
        }),
        sent_rx,
    )
}

async fn emitted_initial_request() -> Result<AuthMessage, String> {
    let wallet = ProtoWallet::new(PrivateKey::from_random().map_err(|error| error.to_string())?);
    let target = PrivateKey::from_random()
        .map_err(|error| error.to_string())?
        .to_public_key()
        .to_der_hex();
    let (transport, mut sent) = capture_transport();
    let peer = Arc::new(Peer::new(wallet, transport));
    let handshake = {
        let peer = peer.clone();
        tokio::spawn(async move { peer.get_authenticated_session(&target).await })
    };
    let message = tokio::time::timeout(std::time::Duration::from_secs(1), sent.recv())
        .await
        .map_err(|_| "timed out waiting for real initialRequest".to_string())?
        .ok_or("capture transport closed before initialRequest")?;
    handshake.abort();
    let _ = handshake.await;
    Ok(message)
}

async fn emitted_initial_response_with_request() -> Result<
    (
        Arc<Peer<ProtoWallet>>,
        AuthMessage,
        String,
        RequestedCertificateSet,
        String,
    ),
    String,
> {
    let responder = ProtoWallet::new(PrivateKey::from_random().map_err(|error| error.to_string())?);
    let requester_key = PrivateKey::from_random().map_err(|error| error.to_string())?;
    let requester_identity = requester_key.to_public_key().to_der_hex();
    let requester_wallet = ProtoWallet::new(requester_key);
    let requester_nonce = bsv::auth::utils::create_nonce(&requester_wallet)
        .await
        .map_err(|error| error.to_string())?;
    let (transport, mut sent) = capture_transport();
    let peer = Arc::new(Peer::new(responder, transport));
    let mut requested = RequestedCertificateSet::default();
    requested.certifiers.push(requester_identity.clone());
    requested.insert(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        vec!["name".to_string()],
    );
    peer.set_certificates_to_request(requested.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        peer.dispatch_message(AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: requester_identity.clone(),
            nonce: None,
            your_nonce: None,
            initial_nonce: Some(requester_nonce.clone()),
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        }),
    )
    .await
    .map_err(|_| "timed out dispatching real initialRequest".to_string())?
    .map_err(|error| error.to_string())?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), sent.recv())
        .await
        .map_err(|_| "timed out waiting for real initialResponse".to_string())?
        .ok_or("capture transport closed before initialResponse")?;
    Ok((
        peer,
        response,
        requester_nonce,
        requested,
        requester_identity,
    ))
}

async fn emitted_request_id() -> Result<String, String> {
    use wiremock::matchers::{method, path};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(HEADER_AUTH_VERSION, AUTH_VERSION)
                .set_body_bytes(Vec::new()),
        )
        .mount(&server)
        .await;
    let transport = SimplifiedHTTPTransport::new(&server.uri());
    let mut payload = bsv::primitives::random::random_bytes(32);
    payload.extend_from_slice(&[3, b'G', b'E', b'T']);
    payload.extend_from_slice(&[13]);
    payload.extend_from_slice(b"/api/resource");
    payload.extend_from_slice(&[0xff]);
    payload.extend_from_slice(&u64::MAX.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0xff]);
    payload.extend_from_slice(&u64::MAX.to_le_bytes());
    transport
        .send(AuthMessage {
            version: AUTH_VERSION.to_string(),
            message_type: MessageType::General,
            identity_key: PrivateKey::from_random()
                .map_err(|error| error.to_string())?
                .to_public_key()
                .to_der_hex(),
            nonce: Some("nonce".to_string()),
            your_nonce: Some("yourNonce".to_string()),
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: Some(payload),
            signature: Some(vec![0x30]),
        })
        .await
        .map_err(|error| error.to_string())?;
    let requests = server
        .received_requests()
        .await
        .ok_or("wiremock request recording is disabled")?;
    let request = requests.first().ok_or("HTTP transport sent no request")?;
    request
        .headers
        .get(HEADER_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| "real HTTP request omitted x-bsv-auth-request-id".to_string())
}

fn decoded_base64_len(encoded: &str) -> Option<usize> {
    if !encoded.len().is_multiple_of(4)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    let padding = encoded
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'=')
        .count();
    (padding <= 2).then_some(encoded.len() / 4 * 3 - padding)
}

fn string_array<'a>(value: &'a Value, key: &str) -> Result<Vec<&'a str>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {key} array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("non-string {key} item"))
        })
        .collect()
}

fn assert_required_fields(vector: &Vector, actual: &Value) -> Result<(), String> {
    let fields = string_array(&vector.input, "required_fields")
        .or_else(|_| string_array(&vector.expected, "required_fields"))?;
    for field in fields {
        ensure(actual.get(field).is_some(), || {
            format!("real AuthMessage omitted required field {field}")
        })?;
        let mut missing = actual.clone();
        missing
            .as_object_mut()
            .ok_or("real AuthMessage did not serialize as an object")?
            .remove(field);
        ensure(
            serde_json::from_value::<AuthMessage>(missing).is_err(),
            || format!("AuthMessage accepted missing required field {field}"),
        )?;
    }
    Ok(())
}

fn assert_message_types(vector: &Vector) -> Result<(), String> {
    let types = string_array(&vector.expected, "enum")
        .or_else(|_| string_array(&vector.expected, "valid_message_types"))?;
    for message_type in types {
        let parsed = serde_json::from_value::<AuthMessage>(json!({
            "version": AUTH_VERSION,
            "messageType": message_type,
            "identityKey": PrivateKey::from_random()
                .map_err(|error| error.to_string())?
                .to_public_key()
                .to_der_hex()
        }));
        ensure(parsed.is_ok(), || {
            format!("real AuthMessage rejected declared messageType {message_type}")
        })?;
    }
    Ok(())
}

fn assert_public_keys(vector: &Vector) -> Result<(), String> {
    for key in string_array(&vector.input, "valid_examples")? {
        ensure(PublicKey::from_string(key).is_ok(), || {
            format!("real public-key parser rejected valid PubKeyHex {key}")
        })?;
    }
    if let Ok(invalid) = string_array(&vector.input, "invalid_examples") {
        for key in invalid {
            ensure(PublicKey::from_string(key).is_err(), || {
                format!("real public-key parser accepted invalid PubKeyHex {key}")
            })?;
        }
    }
    Ok(())
}

struct Observations {
    initial_request: Value,
    initial_response: Value,
    request_id: String,
}

fn dispatch(vector: &Vector, observed: &Observations) -> Result<(), String> {
    match vector.id.as_str() {
        "auth.brc31-handshake.1" => {
            let expected = vector
                .input
                .get("body")
                .ok_or("vector has no initialRequest body")?;
            let expected_object = expected
                .as_object()
                .ok_or("vector initialRequest body is not an object")?;
            let actual_object = observed
                .initial_request
                .as_object()
                .ok_or("real initialRequest is not an object")?;
            let expected_keys: BTreeSet<&str> =
                expected_object.keys().map(String::as_str).collect();
            let actual_keys: BTreeSet<&str> = actual_object.keys().map(String::as_str).collect();
            ensure(
                actual_object.get("messageType") == expected_object.get("messageType")
                    && actual_object.get("version") == expected_object.get("version"),
                || "real initialRequest changed messageType or version".to_string(),
            )?;
            ensure(
                expected_object.get("nonce") == expected_object.get("initialNonce"),
                || "corpus initialRequest nonce did not equal initialNonce".to_string(),
            )?;
            ensure(actual_keys == expected_keys, || {
                format!(
                    "initialRequest JSON shape mismatch: expected keys {expected_keys:?}, got {actual_keys:?}"
                )
            })
        }
        "auth.brc31-handshake.12" => {
            assert_required_fields(vector, &observed.initial_request)?;
            assert_message_types(vector)
        }
        "auth.brc31-handshake.13" => {
            let expected_chars = vector
                .expected
                .get("requestId_base64_length")
                .and_then(Value::as_u64)
                .ok_or("missing requestId_base64_length")?
                as usize;
            let expected_bytes = vector
                .input
                .get("requestId_length_bytes")
                .and_then(Value::as_u64)
                .ok_or("missing requestId_length_bytes")? as usize;
            ensure(observed.request_id.len() == expected_chars, || {
                format!("real requestId was {} chars", observed.request_id.len())
            })?;
            ensure(
                decoded_base64_len(&observed.request_id) == Some(expected_bytes),
                || format!("real requestId did not decode to {expected_bytes} bytes"),
            )
        }
        "auth.brc31-handshake.15" | "messaging.authsocket.12" => assert_public_keys(vector),
        "messaging.authsocket.4" => assert_message_types(vector),
        "messaging.authsocket.8" => ensure(
            observed
                .initial_response
                .get("requestedCertificates")
                .is_some(),
            || "real initialResponse omitted requestedCertificates".to_string(),
        ),
        "messaging.authsocket.11" => assert_required_fields(vector, &observed.initial_request),
        _ => Err(format!("unhandled asserted auth vector {}", vector.id)),
    }
}

#[tokio::test]
async fn official_auth_conformance() {
    let initial_request = emitted_initial_request()
        .await
        .and_then(|message| serde_json::to_value(message).map_err(|error| error.to_string()))
        .expect("capture real initialRequest");
    let (_, initial_response, _, _, _) = emitted_initial_response_with_request()
        .await
        .expect("capture real initialResponse");
    let initial_response =
        serde_json::to_value(initial_response).expect("serialize real initialResponse");
    let request_id = emitted_request_id().await.expect("capture real requestId");
    let observed = Observations {
        initial_request,
        initial_response,
        request_id,
    };
    let asserted = run_corpora(CORPORA, GOVERNED_SKIPS, KNOWN_DIVERGENCES, |_, vector| {
        dispatch(vector, &observed)
    });
    assert_eq!(
        asserted, 8,
        "the auth conformance asserted-vector count must not silently erode"
    );
}

#[tokio::test(start_paused = true)]
async fn certificate_gate_matches_vector_ten_30_second_timeout() {
    let (peer, response, requester_nonce, requested, requester_identity) =
        emitted_initial_response_with_request()
            .await
            .expect("establish certificate-gated responder session");
    let session = PeerSession {
        session_nonce: response
            .initial_nonce
            .expect("initialResponse carries responder session nonce"),
        peer_identity_key: requester_identity,
        peer_nonce: requester_nonce,
        is_authenticated: true,
        requested_certificates: Some(requested),
        certificates_required: true,
        certificates_validated: false,
    };
    let mut wait = Box::pin(peer.wait_for_certificate_validation(&session));
    assert!(wait.as_mut().now_or_never().is_none());
    tokio::time::advance(std::time::Duration::from_millis(29_999)).await;
    assert!(
        wait.as_mut().now_or_never().is_none(),
        "certificate gate timed out before 30 seconds"
    );
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    let outcome = wait
        .as_mut()
        .now_or_never()
        .expect("certificate gate did not time out at 30 seconds");
    assert!(
        matches!(outcome, Err(AuthError::Timeout(ref message)) if message.contains("Timeout waiting for certificate validation")),
        "certificate gate returned the wrong terminal result: {outcome:?}"
    );
}
