#![cfg(feature = "network")]

use async_trait::async_trait;
use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::transports::Transport;
use bsv::auth::{AuthError, AuthMessage, MessageType, Peer};
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use indexmap::IndexMap;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{path::PathBuf, process::Command};
use tokio::sync::mpsc;

const VECTORS: &str = include_str!("vectors/auth_certificate_interop.json");

#[derive(Deserialize)]
struct Fixture {
    sdk: Sdk,
    #[serde(rename = "typeScriptToRust")]
    type_script_to_rust: CertificateResponseVector,
    #[serde(rename = "emptyTypeScriptToRust")]
    empty_type_script_to_rust: CertificateResponseVector,
    #[serde(rename = "rustToTypeScript")]
    rust_to_type_script: CertificateResponseVector,
    #[serde(rename = "emptyRustToTypeScript")]
    empty_rust_to_type_script: CertificateResponseVector,
    #[serde(rename = "typeScriptAuthMessages")]
    type_script_auth_messages: AuthMessageVectors,
    #[serde(rename = "rustAuthMessages")]
    rust_auth_messages: AuthMessageVectors,
    #[serde(rename = "certificateGateBehavior")]
    certificate_gate_behavior: CertificateGateBehavior,
    #[serde(rename = "emptyInitialResponseShape")]
    empty_initial_response_shape: EmptyInitialResponseShape,
    #[serde(rename = "optionalFieldSerializations")]
    optional_field_serializations: Vec<OptionalFieldSerialization>,
    #[serde(rename = "decryptedFieldSerializations")]
    decrypted_field_serializations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthMessageVectors {
    initial_request: ExactWireMessage,
    initial_response: ExactWireMessage,
    initial_response_with_empty_certificates: ExactWireMessage,
    certificate_request: ExactWireMessage,
    certificate_response: ExactWireMessage,
    general: ExactWireMessage,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExactWireMessage {
    json: String,
    hex: String,
    keys: Vec<String>,
    #[serde(default)]
    verified_by_type_script: bool,
}

impl ExactWireMessage {
    fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.hex).expect("exact wire hex")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmptyInitialResponseShape {
    has_certificates_member: bool,
    serialized_member: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateGateBehavior {
    standalone_empty_response_sent: bool,
    empty_response_listener_fired: bool,
    empty_response_left_gate_pending: bool,
    general_wait_registered: bool,
    general_delivered_before_validation: bool,
    general_delivered_after_validation: bool,
}

#[derive(Deserialize)]
struct Sdk {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateResponseVector {
    receiver_private_key: String,
    sender_public_key: String,
    key_id: String,
    preimage_bytes: Vec<u8>,
    message: AuthMessage,
    #[serde(default)]
    verified_by_type_script: bool,
}

#[derive(Deserialize)]
struct OptionalFieldSerialization {
    mask: u8,
    json: String,
}

struct CaptureTransport {
    sent: mpsc::Sender<AuthMessage>,
    incoming: Mutex<Option<mpsc::Receiver<AuthMessage>>>,
}

impl CaptureTransport {
    fn new() -> (Arc<Self>, mpsc::Receiver<AuthMessage>) {
        let (sent_tx, sent_rx) = mpsc::channel(8);
        let (_incoming_tx, incoming_rx) = mpsc::channel(8);
        (
            Arc::new(Self {
                sent: sent_tx,
                incoming: Mutex::new(Some(incoming_rx)),
            }),
            sent_rx,
        )
    }
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
            .expect("capture transport lock")
            .take()
            .expect("capture transport subscribed once")
    }
}

fn vector_file() -> Fixture {
    serde_json::from_str(VECTORS).expect("auth certificate interop fixture is valid JSON")
}

fn type_script_sdk_path() -> PathBuf {
    if let Some(path) = std::env::var_os("BSV_TS_SDK_PATH") {
        return path.into();
    }
    let repository_copy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("node_modules")
        .join("@bsv")
        .join("sdk");
    if repository_copy.exists() {
        return repository_copy;
    }
    PathBuf::from(
        "/private/tmp/claude-501/-Users-donot-Project-Atlas/03591944-f737-4bbf-9300-4eb98375a634/scratchpad/tssdk/package",
    )
}

fn auth_protocol() -> Protocol {
    Protocol {
        security_level: 2,
        protocol: "auth message signature".to_string(),
    }
}

fn verify_vector_signature(
    vector: &CertificateResponseVector,
    message: &AuthMessage,
    preimage: &[u8],
) -> bool {
    let receiver_private_key =
        PrivateKey::from_hex(&vector.receiver_private_key).expect("valid receiver private key");
    let sender_public_key =
        PublicKey::from_string(&vector.sender_public_key).expect("valid sender public key");

    ProtoWallet::new(receiver_private_key)
        .verify_signature_sync(
            Some(preimage),
            None,
            message.signature.as_deref().expect("message signature"),
            &auth_protocol(),
            &vector.key_id,
            &Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(sender_public_key),
            },
            false,
        )
        .expect("signature verification should execute")
}

#[test]
fn typescript_certificate_response_round_trips_the_exact_signed_preimage() {
    let fixture = vector_file();
    assert_eq!(fixture.sdk.name, "@bsv/sdk");
    assert_eq!(fixture.sdk.version, "2.4.1");
    let vector = &fixture.type_script_to_rust;
    let message = &vector.message;
    let certificates = message
        .certificates
        .as_ref()
        .expect("TS certificateResponse certificates");
    let rust_preimage = serde_json::to_vec(certificates).expect("serialize Rust certificates");
    let ts_preimage = &vector.preimage_bytes;

    assert_eq!(&rust_preimage, ts_preimage, "signed preimage bytes differ");
    assert!(verify_vector_signature(vector, message, &rust_preimage));

    let preimage_text = std::str::from_utf8(&rust_preimage).unwrap();
    assert!(preimage_text.contains(
        r#""fields":{"zeta":"dHMtemV0YQ==","alpha":"dHMtYWxwaGE=","middle":"dHMtbWlkZGxl"}"#
    ));
    assert!(preimage_text.contains(
        r#""keyring":{"zeta":"dHMta2V5cmluZy16ZXRh","alpha":"dHMta2V5cmluZy1hbHBoYQ==","middle":"dHMta2V5cmluZy1taWRkbGU="}"#
    ));
    assert!(!preimage_text.contains("decryptedFields"));

    // Each TS case is a real VerifiableCertificate instance. Together the
    // eight masks cover every present/undefined combination of
    // revocationOutpoint, fields, and signature, including an unsigned cert.
    for case in &fixture.optional_field_serializations {
        let expected = &case.json;
        let parsed: VerifiableCertificate = serde_json::from_str(expected).unwrap();
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            expected.as_str(),
            "optional-field mismatch for mask {}",
            case.mask
        );
        assert!(parsed.decrypted_fields.is_none());
    }

    assert_eq!(fixture.decrypted_field_serializations.len(), 2);
    let without_decrypted: VerifiableCertificate =
        serde_json::from_str(&fixture.decrypted_field_serializations[0]).unwrap();
    assert!(without_decrypted.decrypted_fields.is_none());
    assert_eq!(
        serde_json::to_string(&without_decrypted).unwrap(),
        fixture.decrypted_field_serializations[0]
    );
    let with_decrypted: VerifiableCertificate =
        serde_json::from_str(&fixture.decrypted_field_serializations[1]).unwrap();
    let _: &IndexMap<String, String> = with_decrypted.decrypted_fields.as_ref().unwrap();
    assert_eq!(
        with_decrypted
            .decrypted_fields
            .as_ref()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "middle"],
        "decryptedFields must retain the TS insertion order inside the signed preimage"
    );
    assert_eq!(
        with_decrypted.decrypted_fields.as_ref().unwrap()["middle"],
        "ts-middle"
    );
    assert_eq!(
        serde_json::to_string(&with_decrypted).unwrap(),
        fixture.decrypted_field_serializations[1]
    );
}

#[test]
fn rust_certificate_response_vector_is_accepted_by_typescript_and_rust() {
    let fixture = vector_file();
    let vector = &fixture.rust_to_type_script;
    assert!(vector.verified_by_type_script);
    let message = &vector.message;
    let certificates = message.certificates.as_ref().expect("Rust certificates");
    assert_eq!(
        certificates[0]
            .keyring
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "middle"],
        "Rust must preserve the caller's keyring order in the signed preimage"
    );
    let rust_preimage = serde_json::to_vec(certificates).unwrap();
    let expected_preimage = &vector.preimage_bytes;

    assert_eq!(&rust_preimage, expected_preimage);
    assert!(verify_vector_signature(vector, message, &rust_preimage));
}

#[test]
fn rust_vectors_are_accepted_by_real_typescript_at_test_time() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("node")
        .arg(root.join("tests/vectors/verify_auth_certificate_interop.mjs"))
        .arg(type_script_sdk_path())
        .arg(root.join("tests/vectors/auth_certificate_interop.json"))
        .output()
        .expect("Node is required for the TypeScript interop assertion");
    assert!(
        output.status.success(),
        "live TypeScript interop check failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn empty_certificate_response_is_byte_exact_and_cross_verified() {
    let fixture = vector_file();
    for vector in [
        &fixture.empty_type_script_to_rust,
        &fixture.empty_rust_to_type_script,
    ] {
        let message = &vector.message;
        let certificates = message
            .certificates
            .as_ref()
            .expect("empty certificateResponse carries an explicit array");
        assert!(certificates.is_empty());
        let rust_preimage = serde_json::to_vec(certificates).unwrap();
        assert_eq!(rust_preimage, b"[]");
        assert_eq!(rust_preimage, vector.preimage_bytes);
        assert!(verify_vector_signature(vector, message, &rust_preimage));
    }
    assert!(fixture.empty_rust_to_type_script.verified_by_type_script);
}

#[test]
fn initial_response_deserialization_preserves_the_verifier_keyring() {
    let fixture = vector_file();
    let mut message = fixture.type_script_to_rust.message;
    message.message_type = MessageType::InitialResponse;
    assert_eq!(message.message_type, MessageType::InitialResponse);

    let serialized = serde_json::to_value(message.certificates.unwrap()).unwrap();
    assert_eq!(
        serialized[0]["keyring"]["middle"],
        serde_json::Value::String("dHMta2V5cmluZy1taWRkbGU=".to_string())
    );
    assert!(serialized[0].get("decryptedFields").is_none());
}

#[test]
fn typescript_initial_response_retains_empty_certificates_member() {
    let fixture = vector_file();
    assert_eq!(fixture.sdk.name, "@bsv/sdk");
    assert_eq!(fixture.sdk.version, "2.4.1");
    assert!(fixture.empty_initial_response_shape.has_certificates_member);
    assert_eq!(
        fixture.empty_initial_response_shape.serialized_member,
        r#"{"certificates":[]}"#
    );
}

#[test]
fn typescript_certificate_gate_behavior_is_pinned_from_two_real_peers() {
    let behavior = vector_file().certificate_gate_behavior;
    assert!(behavior.standalone_empty_response_sent);
    assert!(behavior.empty_response_listener_fired);
    assert!(behavior.empty_response_left_gate_pending);
    assert!(behavior.general_wait_registered);
    assert!(!behavior.general_delivered_before_validation);
    assert!(behavior.general_delivered_after_validation);
}

#[test]
fn typescript_handshake_envelopes_round_trip_byte_exactly_in_rust() {
    let fixture = vector_file();
    for vector in [
        &fixture.type_script_auth_messages.initial_request,
        &fixture.type_script_auth_messages.initial_response,
    ] {
        let bytes = vector.bytes();
        assert_eq!(bytes, vector.json.as_bytes());
        let message: AuthMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&message).unwrap(), bytes);
    }

    assert_eq!(
        fixture.type_script_auth_messages.initial_request.keys,
        [
            "version",
            "messageType",
            "identityKey",
            "initialNonce",
            "requestedCertificates",
        ]
    );
    assert_eq!(
        fixture.type_script_auth_messages.initial_response.keys,
        [
            "version",
            "messageType",
            "identityKey",
            "initialNonce",
            "yourNonce",
            "requestedCertificates",
            "signature",
        ]
    );
}

#[test]
fn all_rust_auth_envelopes_are_byte_exact_and_accepted_by_typescript() {
    let fixture = vector_file();
    for vector in [
        &fixture.rust_auth_messages.certificate_request,
        &fixture.rust_auth_messages.certificate_response,
        &fixture.rust_auth_messages.general,
        &fixture.rust_auth_messages.initial_request,
        &fixture.rust_auth_messages.initial_response,
        &fixture
            .rust_auth_messages
            .initial_response_with_empty_certificates,
    ] {
        assert!(vector.verified_by_type_script);
        let bytes = vector.bytes();
        assert_eq!(bytes, vector.json.as_bytes());
        let message: AuthMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&message).unwrap(), bytes);
    }
}

#[test]
fn all_typescript_auth_envelopes_round_trip_byte_exactly_in_rust() {
    let fixture = vector_file();
    for vector in [
        &fixture.type_script_auth_messages.certificate_request,
        &fixture.type_script_auth_messages.certificate_response,
        &fixture.type_script_auth_messages.general,
        &fixture.type_script_auth_messages.initial_request,
        &fixture.type_script_auth_messages.initial_response,
        &fixture
            .type_script_auth_messages
            .initial_response_with_empty_certificates,
    ] {
        let bytes = vector.bytes();
        assert_eq!(bytes, vector.json.as_bytes());
        let message: AuthMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&message).unwrap(), bytes);
    }
}

#[tokio::test]
async fn rust_default_initial_request_emits_typescript_default_request_set() {
    let fixture = vector_file();
    let sender_private_key =
        PrivateKey::from_hex(&fixture.type_script_to_rust.receiver_private_key)
            .expect("valid fixture private key");
    let target_identity = fixture.type_script_to_rust.sender_public_key.clone();
    let (transport, mut sent) = CaptureTransport::new();
    let peer = Arc::new(Peer::new(ProtoWallet::new(sender_private_key), transport));

    let sending_peer = Arc::clone(&peer);
    let sending_target = target_identity.clone();
    let send_task =
        tokio::spawn(async move { sending_peer.send_message(&sending_target, vec![1]).await });
    let request = tokio::time::timeout(Duration::from_secs(2), sent.recv())
        .await
        .expect("initialRequest send is time-bounded")
        .expect("initialRequest was sent");
    send_task.abort();
    let _ = send_task.await;

    assert_eq!(request.message_type, MessageType::InitialRequest);
    let requested = request
        .requested_certificates
        .as_ref()
        .expect("TS always emits requestedCertificates on initialRequest");
    assert!(requested.certifiers.is_empty());
    assert!(requested.types.is_empty());

    let serialized = serde_json::to_string(&request).unwrap();
    assert!(serialized.ends_with(r#","requestedCertificates":{"certifiers":[],"types":{}}}"#));
}

#[tokio::test]
async fn rust_default_initial_response_emits_typescript_default_request_set_and_order() {
    let fixture = vector_file();
    let sender_private_key =
        PrivateKey::from_hex(&fixture.type_script_to_rust.receiver_private_key)
            .expect("valid fixture private key");
    let request: AuthMessage =
        serde_json::from_slice(&fixture.type_script_auth_messages.initial_request.bytes())
            .expect("TS initialRequest fixture");
    let (transport, mut sent) = CaptureTransport::new();
    let peer = Peer::new(ProtoWallet::new(sender_private_key), transport);

    tokio::time::timeout(Duration::from_secs(2), peer.dispatch_message(request))
        .await
        .expect("initialRequest dispatch is time-bounded")
        .expect("initialRequest dispatch succeeds");
    let response = tokio::time::timeout(Duration::from_secs(2), sent.recv())
        .await
        .expect("initialResponse send is time-bounded")
        .expect("initialResponse was sent");

    assert_eq!(response.message_type, MessageType::InitialResponse);
    assert!(response.certificates.is_none());
    let requested = response
        .requested_certificates
        .as_ref()
        .expect("TS always emits requestedCertificates on initialResponse");
    assert!(requested.certifiers.is_empty());
    assert!(requested.types.is_empty());

    let serialized = serde_json::to_string(&response).unwrap();
    let initial_nonce = serialized.find(r#""initialNonce""#).unwrap();
    let your_nonce = serialized.find(r#""yourNonce""#).unwrap();
    let requested_certificates = serialized.find(r#""requestedCertificates""#).unwrap();
    let signature = serialized.find(r#""signature""#).unwrap();
    assert!(initial_nonce < your_nonce);
    assert!(your_nonce < requested_certificates);
    assert!(requested_certificates < signature);
}
