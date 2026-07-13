//! Import a WIF private key, derive the public key, and compute the P2PKH address.
//!
//! Run: `cargo run --example address_from_wif`

use bsv::primitives::private_key::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Address from WIF ===\n");

    // Create a key from hex, export as WIF, then re-import.
    // This demonstrates the full WIF round-trip.
    let original =
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?;
    let wif = original.to_wif(&[0x80]);
    println!("WIF:        {wif}");

    // Import the private key from WIF
    let private_key = PrivateKey::from_wif(&wif)?;
    println!("Private key (hex): {}", private_key.to_hex());

    // Derive the public key
    let public_key = private_key.to_public_key();
    println!("Public key (hex):  {}", public_key.to_der_hex());

    // Compute the P2PKH address (mainnet prefix 0x00)
    let address = public_key.to_address(&[0x00]);
    println!("Address:    {address}");

    // Verify WIF round-trip
    let wif_roundtrip = private_key.to_wif(&[0x80]);
    assert_eq!(wif, wif_roundtrip);
    println!("\nWIF round-trip verified.");

    Ok(())
}
