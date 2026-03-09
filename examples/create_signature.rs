//! Create a digital signature with ProtoWallet and verify it.
//!
//! Run: `cargo run --example create_signature`

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use bsv::wallet::ProtoWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Create Signature ===\n");

    // Create a ProtoWallet from a known key
    let key =
        PrivateKey::from_hex("e6bd9c2f3e1b0460e919b6b4a6e6c8b3f5a7d9c2e4b6a8d0f1e3c5b7a9d1f3e5")?;
    let wallet = ProtoWallet::new(key);

    // Message to sign
    let message = b"Hello, BSV SDK!";
    println!("Message:   \"{}\"", std::str::from_utf8(message).unwrap());

    // Define a protocol and key ID for derivation
    let protocol = Protocol {
        protocol: "example signing".to_string(),
        security_level: 2,
    };
    let key_id = "message-signing-1";
    let counterparty = Counterparty {
        counterparty_type: CounterpartyType::Anyone,
        public_key: None,
    };

    // Sign the message
    let signature = wallet.create_signature_sync(message, &protocol, key_id, &counterparty)?;
    println!(
        "Signature: {}",
        signature
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // Verify the signature
    let valid = wallet.verify_signature_sync(
        message,
        &signature,
        &protocol,
        key_id,
        &counterparty,
        true,
    )?;
    println!("Verified:  {}", valid);
    assert!(valid, "Signature verification must succeed");

    // Tamper with the message and verify again
    let tampered = b"Hello, BSV SDK?";
    let invalid = wallet.verify_signature_sync(
        tampered,
        &signature,
        &protocol,
        key_id,
        &counterparty,
        true,
    )?;
    println!("Tampered:  {} (expected false)", invalid);
    assert!(!invalid, "Tampered signature must fail verification");

    println!("\nSignature create + verify succeeded.");
    Ok(())
}
