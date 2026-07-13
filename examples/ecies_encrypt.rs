//! ECIES (Elliptic Curve Integrated Encryption Scheme) encrypt and decrypt.
//!
//! Demonstrates both Electrum (BIE1) and Bitcore variants.
//!
//! Run: `cargo run --example ecies_encrypt`

use bsv::compat::ecies::ECIES;
use bsv::primitives::private_key::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ECIES Encrypt / Decrypt ===\n");

    // Generate a recipient key pair
    let recipient_key =
        PrivateKey::from_hex("d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6")?;
    let recipient_pub = recipient_key.to_public_key();
    println!("Recipient pubkey: {}", recipient_pub.to_der_hex());

    let plaintext = b"Secret message via ECIES";
    println!(
        "Plaintext:        \"{}\"",
        std::str::from_utf8(plaintext).unwrap()
    );

    // --- Electrum variant (BIE1) ---
    println!("\n--- Electrum ECIES (BIE1) ---");

    let electrum_ct = ECIES::electrum_encrypt(plaintext, &recipient_pub, None)?;
    println!(
        "Ciphertext:       {} ({} bytes)",
        electrum_ct
            .iter()
            .take(20)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + "...",
        electrum_ct.len()
    );

    let electrum_pt = ECIES::electrum_decrypt(&electrum_ct, &recipient_key)?;
    let electrum_text = std::str::from_utf8(&electrum_pt)?;
    println!("Decrypted:        \"{electrum_text}\"");
    assert_eq!(plaintext.as_slice(), electrum_pt.as_slice());
    println!("Electrum round-trip verified.");

    // --- Bitcore variant ---
    println!("\n--- Bitcore ECIES ---");

    let bitcore_ct = ECIES::bitcore_encrypt(plaintext, &recipient_pub, None)?;
    println!(
        "Ciphertext:       {} ({} bytes)",
        bitcore_ct
            .iter()
            .take(20)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + "...",
        bitcore_ct.len()
    );

    let bitcore_pt = ECIES::bitcore_decrypt(&bitcore_ct, &recipient_key)?;
    let bitcore_text = std::str::from_utf8(&bitcore_pt)?;
    println!("Decrypted:        \"{bitcore_text}\"");
    assert_eq!(plaintext.as_slice(), bitcore_pt.as_slice());
    println!("Bitcore round-trip verified.");

    Ok(())
}
