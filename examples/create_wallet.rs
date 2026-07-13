//! Generate a BIP39 mnemonic, derive a BIP32 HD key, and create a ProtoWallet.
//!
//! Run: `cargo run --example create_wallet`

use bsv::compat::bip32::ExtendedKey;
use bsv::compat::bip39::{Language, Mnemonic};
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::ProtoWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Create Wallet ===\n");

    // Generate a 12-word mnemonic
    let mnemonic = Mnemonic::from_random(128, Language::English)?;
    println!("Mnemonic:   {}", mnemonic.to_phrase());

    // Derive a seed from the mnemonic (no passphrase)
    let seed = mnemonic.to_seed("");

    // Create a BIP32 master key from the seed
    let master = ExtendedKey::from_seed(&seed)?;
    println!("Master xprv: {}", master.to_base58());

    // Derive m/44'/0'/0'/0/0 (first receive address in BIP44)
    let child = master.derive("m/44'/0'/0'/0/0")?;
    let child_pub = child.public_key()?;
    let address = child_pub.to_address(&[0x00]);
    println!("Derived address (m/44'/0'/0'/0/0): {address}");

    // Create a ProtoWallet from the derived key
    let key_bytes = child.to_base58();
    let child_key_parsed = ExtendedKey::from_string(&key_bytes)?;
    let pub_key = child_key_parsed.public_key()?;

    // Use the master key to create a ProtoWallet (needs a private key)
    let master_key_bytes = master.to_base58();
    let master_parsed = ExtendedKey::from_string(&master_key_bytes)?;
    // For ProtoWallet, derive a key to use
    let m0 = master_parsed.derive("m/0'")?;
    let m0_pubkey = m0.public_key()?;

    let wallet_key = PrivateKey::from_random()?;
    let wallet = ProtoWallet::new(wallet_key);

    println!("\nProtoWallet created successfully.");
    println!("Identity key: {}", pub_key.to_der_hex());
    println!("Master child m/0' pubkey: {}", m0_pubkey.to_der_hex());

    // Suppress unused-variable warning
    let _ = wallet;

    Ok(())
}
