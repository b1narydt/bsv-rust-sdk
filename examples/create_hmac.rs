//! Create and verify an HMAC using ProtoWallet.
//!
//! Run: `cargo run --example create_hmac`

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use bsv::wallet::ProtoWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Create HMAC ===\n");

    // Create a ProtoWallet from a known key
    let key =
        PrivateKey::from_hex("b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4")?;
    let wallet = ProtoWallet::new(key);

    // Data to authenticate
    let data = b"Important message requiring integrity";
    println!("Data:     \"{}\"", std::str::from_utf8(data).unwrap());

    // Define protocol and key ID
    let protocol = Protocol {
        protocol: "message authentication".to_string(),
        security_level: 2,
    };
    let key_id = "hmac-key-1";
    let counterparty = Counterparty {
        counterparty_type: CounterpartyType::Self_,
        public_key: None,
    };

    // Create HMAC
    let hmac = wallet.create_hmac_sync(data, &protocol, key_id, &counterparty)?;
    println!(
        "HMAC:     {}",
        hmac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!("Length:   {} bytes", hmac.len());

    // Verify HMAC
    let valid = wallet.verify_hmac_sync(data, &hmac, &protocol, key_id, &counterparty)?;
    println!("Valid:    {}", valid);
    assert!(valid, "HMAC verification must succeed");

    // Verify with tampered data
    let tampered = b"Tampered message requiring integrity";
    let invalid = wallet.verify_hmac_sync(tampered, &hmac, &protocol, key_id, &counterparty)?;
    println!("Tampered: {} (expected false)", invalid);
    assert!(!invalid, "Tampered HMAC must fail verification");

    println!("\nHMAC create + verify succeeded.");
    Ok(())
}
