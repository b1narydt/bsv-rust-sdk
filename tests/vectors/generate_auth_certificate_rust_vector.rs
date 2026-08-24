//! Fixture generator helper invoked by `gen_auth_certificate_interop.mjs`.
//!
//! This is an example target rather than a test so the committed golden vectors
//! remain hermetic at test time. It emits one certificateResponse signed by the
//! Rust SDK; the Node generator verifies that signature with @bsv/sdk 2.4.1.

use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::{AuthMessage, MessageType, RequestedCertificateSet};
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{Certificate, CertificateType, SerialNumber};
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use indexmap::IndexMap;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RustVector {
    producer: String,
    sender_private_key: String,
    sender_public_key: String,
    receiver_private_key: String,
    receiver_public_key: String,
    key_id: String,
    preimage_bytes: Vec<u8>,
    preimage_utf8: String,
    message: AuthMessage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExactWireMessage {
    json: String,
    hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RustAuthMessages {
    initial_request: ExactWireMessage,
    initial_response: ExactWireMessage,
    initial_response_with_empty_certificates: ExactWireMessage,
    certificate_request: ExactWireMessage,
    certificate_response: ExactWireMessage,
    general: ExactWireMessage,
}

fn exact_wire_message(message: AuthMessage) -> ExactWireMessage {
    let bytes = serde_json::to_vec(&message).unwrap();
    ExactWireMessage {
        json: String::from_utf8(bytes.clone()).unwrap(),
        hex: hex::encode(bytes),
    }
}

fn rust_auth_messages(sender_public_key: &str) -> RustAuthMessages {
    let requested = Some(RequestedCertificateSet::default());
    RustAuthMessages {
        initial_request: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: sender_public_key.to_string(),
            nonce: None,
            initial_nonce: Some("cnVzdC1pbml0aWFsLXJlcXVlc3Q=".to_string()),
            your_nonce: None,
            certificates: None,
            requested_certificates: requested.clone(),
            payload: None,
            signature: None,
        }),
        initial_response: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::InitialResponse,
            identity_key: sender_public_key.to_string(),
            nonce: None,
            initial_nonce: Some("cnVzdC1pbml0aWFsLXJlc3BvbnNl".to_string()),
            your_nonce: Some("cnVzdC1pbml0aWFsLXJlcXVlc3Q=".to_string()),
            certificates: None,
            requested_certificates: requested.clone(),
            payload: None,
            signature: Some(vec![48, 1, 1]),
        }),
        initial_response_with_empty_certificates: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::InitialResponse,
            identity_key: sender_public_key.to_string(),
            nonce: None,
            initial_nonce: Some("cnVzdC1pbml0aWFsLXJlc3BvbnNl".to_string()),
            your_nonce: Some("cnVzdC1pbml0aWFsLXJlcXVlc3Q=".to_string()),
            certificates: Some(vec![]),
            requested_certificates: requested,
            payload: None,
            signature: Some(vec![48, 1, 1]),
        }),
        certificate_request: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::CertificateRequest,
            identity_key: sender_public_key.to_string(),
            nonce: Some("cnVzdC1jZXJ0aWZpY2F0ZS1yZXF1ZXN0".to_string()),
            initial_nonce: Some("cnVzdC1pbml0aWFsLXJlcXVlc3Q=".to_string()),
            your_nonce: Some("cnVzdC1wZWVyLW5vbmNl".to_string()),
            certificates: None,
            requested_certificates: Some(RequestedCertificateSet::default()),
            payload: None,
            signature: Some(vec![48, 1, 2]),
        }),
        certificate_response: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::CertificateResponse,
            identity_key: sender_public_key.to_string(),
            nonce: Some("cnVzdC1jZXJ0aWZpY2F0ZS1yZXNwb25zZQ==".to_string()),
            initial_nonce: Some("cnVzdC1pbml0aWFsLXJlcXVlc3Q=".to_string()),
            your_nonce: Some("cnVzdC1wZWVyLW5vbmNl".to_string()),
            certificates: Some(vec![]),
            requested_certificates: None,
            payload: None,
            signature: Some(vec![48, 1, 3]),
        }),
        general: exact_wire_message(AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::General,
            identity_key: sender_public_key.to_string(),
            nonce: Some("cnVzdC1nZW5lcmFsLW5vbmNl".to_string()),
            initial_nonce: None,
            your_nonce: Some("cnVzdC1wZWVyLW5vbmNl".to_string()),
            certificates: None,
            requested_certificates: None,
            payload: Some(vec![9, 8, 7]),
            signature: Some(vec![48, 1, 4]),
        }),
    }
}

fn main() {
    let empty = std::env::args().any(|arg| arg == "--empty");
    let sender_private_key = PrivateKey::from_hex(&format!("{:064x}", 4)).unwrap();
    let receiver_private_key = PrivateKey::from_hex(&format!("{:064x}", 5)).unwrap();
    let certifier_private_key = PrivateKey::from_hex(&format!("{:064x}", 6)).unwrap();
    let sender_public_key = sender_private_key.to_public_key();
    let receiver_public_key = receiver_private_key.to_public_key();

    if std::env::args().any(|arg| arg == "--handshake") {
        println!(
            "{}",
            serde_json::to_string(&rust_auth_messages(&sender_public_key.to_der_hex())).unwrap()
        );
        return;
    }

    let mut fields = IndexMap::new();
    fields.insert("zeta".to_string(), "cnVzdC16ZXRh".to_string());
    fields.insert("alpha".to_string(), "cnVzdC1hbHBoYQ==".to_string());
    fields.insert("middle".to_string(), "cnVzdC1taWRkbGU=".to_string());

    let certificate = Certificate {
        cert_type: CertificateType([0x31; 32]),
        serial_number: SerialNumber([0x42; 32]),
        subject: sender_public_key.clone(),
        certifier: certifier_private_key.to_public_key(),
        revocation_outpoint: Some(format!("{}.9", "ab".repeat(32))),
        fields: Some(fields),
        // This fixture is about the auth-message signature. The TS-produced
        // direction separately carries a valid certificate signature.
        signature: None,
    };
    let mut keyring = IndexMap::new();
    keyring.insert("zeta".to_string(), "cnVzdC1rZXlyaW5nLXpldGE=".to_string());
    keyring.insert("alpha".to_string(), "cnVzdC1rZXlyaW5nLWFscGhh".to_string());
    keyring.insert(
        "middle".to_string(),
        "cnVzdC1rZXlyaW5nLW1pZGRsZQ==".to_string(),
    );
    let certificates = if empty {
        Vec::new()
    } else {
        vec![VerifiableCertificate::new(certificate, keyring)]
    };
    let preimage = serde_json::to_vec(&certificates).unwrap();

    let nonce = "REVFREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
    let session_nonce = "cnVzdC1zZXNzaW9uLW5vbmNlLTAwMDAwMDA=";
    let key_id = format!("{nonce} {session_nonce}");
    let protocol = Protocol {
        security_level: 2,
        protocol: "auth message signature".to_string(),
    };
    let signature = ProtoWallet::new(sender_private_key.clone())
        .create_signature_sync(
            Some(&preimage),
            None,
            &protocol,
            &key_id,
            &Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(receiver_public_key.clone()),
            },
        )
        .unwrap();

    let vector = RustVector {
        producer: "bsv-sdk Rust".to_string(),
        sender_private_key: sender_private_key.to_hex(),
        sender_public_key: sender_public_key.to_der_hex(),
        receiver_private_key: receiver_private_key.to_hex(),
        receiver_public_key: receiver_public_key.to_der_hex(),
        key_id,
        preimage_utf8: String::from_utf8(preimage.clone()).unwrap(),
        preimage_bytes: preimage,
        message: AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::CertificateResponse,
            identity_key: sender_public_key.to_der_hex(),
            nonce: Some(nonce.to_string()),
            initial_nonce: Some("cnVzdC1pbml0aWFsLW5vbmNlLTAwMDAwMA==".to_string()),
            your_nonce: Some(session_nonce.to_string()),
            certificates: Some(certificates),
            requested_certificates: None,
            payload: None,
            signature: Some(signature),
        },
    };
    println!("{}", serde_json::to_string(&vector).unwrap());
}
