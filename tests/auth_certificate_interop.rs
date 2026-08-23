#![cfg(feature = "network")]

use bsv::auth::certificates::VerifiableCertificate;
use bsv::auth::{AuthMessage, MessageType};
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use serde::Deserialize;

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
    #[serde(rename = "optionalFieldSerializations")]
    optional_field_serializations: Vec<OptionalFieldSerialization>,
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

fn vector_file() -> Fixture {
    serde_json::from_str(VECTORS).expect("auth certificate interop fixture is valid JSON")
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
}

#[test]
fn rust_certificate_response_vector_is_accepted_by_typescript_and_rust() {
    let fixture = vector_file();
    let vector = &fixture.rust_to_type_script;
    assert!(vector.verified_by_type_script);
    let message = &vector.message;
    let certificates = message.certificates.as_ref().expect("Rust certificates");
    let rust_preimage = serde_json::to_vec(certificates).unwrap();
    let expected_preimage = &vector.preimage_bytes;

    assert_eq!(&rust_preimage, expected_preimage);
    assert!(verify_vector_signature(vector, message, &rust_preimage));
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
