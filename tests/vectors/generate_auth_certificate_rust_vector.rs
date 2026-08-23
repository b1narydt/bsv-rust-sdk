//! Fixture generator helper invoked by `gen_auth_certificate_interop.mjs`.
//!
//! This is an example target rather than a test so the committed golden vectors
//! remain hermetic at test time. It emits one certificateResponse signed by the
//! Rust SDK; the Node generator verifies that signature with @bsv/sdk 2.4.1.

use std::collections::HashMap;

use bsv::auth::certificates::VerifiableCertificate;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::{Certificate, CertificateType, SerialNumber};
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use indexmap::IndexMap;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RustMessage {
    version: String,
    message_type: String,
    identity_key: String,
    nonce: String,
    your_nonce: String,
    initial_nonce: String,
    certificates: Vec<VerifiableCertificate>,
    signature: Vec<u8>,
}

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
    message: RustMessage,
}

fn main() {
    let sender_private_key = PrivateKey::from_hex(&format!("{:064x}", 4)).unwrap();
    let receiver_private_key = PrivateKey::from_hex(&format!("{:064x}", 5)).unwrap();
    let certifier_private_key = PrivateKey::from_hex(&format!("{:064x}", 6)).unwrap();
    let sender_public_key = sender_private_key.to_public_key();
    let receiver_public_key = receiver_private_key.to_public_key();

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
    let mut keyring = HashMap::new();
    keyring.insert("middle".to_string(), "cnVzdC1rZXlyaW5n".to_string());
    let certificates = vec![VerifiableCertificate::new(certificate, keyring)];
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
        message: RustMessage {
            version: "0.1".to_string(),
            message_type: "certificateResponse".to_string(),
            identity_key: sender_public_key.to_der_hex(),
            nonce: nonce.to_string(),
            your_nonce: session_nonce.to_string(),
            initial_nonce: "cnVzdC1pbml0aWFsLW5vbmNlLTAwMDAwMA==".to_string(),
            certificates,
            signature,
        },
    };
    println!("{}", serde_json::to_string(&vector).unwrap());
}
