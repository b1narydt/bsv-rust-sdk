//! Encrypt and decrypt a message using ProtoWallet (AES-GCM via Type-42 derived key).
//!
//! Run: `cargo run --example encrypt_decrypt`

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};
use bsv::wallet::ProtoWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Encrypt / Decrypt ===\n");

    // Create a ProtoWallet from a known key
    let key =
        PrivateKey::from_hex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")?;
    let wallet = ProtoWallet::new(key);

    // Plaintext to encrypt
    let plaintext = b"Confidential BSV transaction data";
    println!(
        "Plaintext:  \"{}\"",
        std::str::from_utf8(plaintext).unwrap()
    );

    // Define protocol and key ID for symmetric key derivation
    let protocol = Protocol {
        protocol: "data encryption".to_string(),
        security_level: 2,
    };
    let key_id = "vault-key-1";
    let counterparty = Counterparty {
        counterparty_type: CounterpartyType::Self_,
        public_key: None,
    };

    // Encrypt
    let ciphertext = wallet.encrypt_sync(plaintext, &protocol, key_id, &counterparty)?;
    println!(
        "Ciphertext: {} ({} bytes)",
        ciphertext
            .iter()
            .take(32)
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
            + "...",
        ciphertext.len()
    );

    // Decrypt
    let decrypted = wallet.decrypt_sync(&ciphertext, &protocol, key_id, &counterparty)?;
    let decrypted_text = std::str::from_utf8(&decrypted)?;
    println!("Decrypted:  \"{}\"", decrypted_text);

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("\nEncrypt + decrypt round-trip succeeded.");

    Ok(())
}
