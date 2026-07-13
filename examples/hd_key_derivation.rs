//! BIP32 Hierarchical Deterministic key derivation example.
//!
//! Run: `cargo run --example hd_key_derivation`

use bsv::compat::bip32::ExtendedKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BIP32 HD Key Derivation ===\n");

    // Use a deterministic seed for reproducible output
    let seed: Vec<u8> = (0..64).collect();

    // Create master key from seed
    let master = ExtendedKey::from_seed(&seed)?;
    let master_xprv = master.to_base58();
    let master_xpub = master.to_public()?.to_base58();
    println!("Master xprv: {master_xprv}");
    println!("Master xpub: {master_xpub}");

    // Derive hardened child: m/44'/0'/0'
    let account = master.derive("m/44'/0'/0'")?;
    let account_xprv = account.to_base58();
    let account_xpub = account.to_public()?.to_base58();
    println!("\nm/44'/0'/0' (account):");
    println!("  xprv: {account_xprv}");
    println!("  xpub: {account_xpub}");
    println!("  depth: {}", account.depth());

    // Derive normal children: m/44'/0'/0'/0/0 through m/44'/0'/0'/0/4
    println!("\nDerived addresses (m/44'/0'/0'/0/i):");
    let external = account.derive("0")?; // m/44'/0'/0'/0
    for i in 0..5 {
        let child = external.derive_child(i)?;
        let pubkey = child.public_key()?;
        let address = pubkey.to_address(&[0x00]);
        println!("  m/44'/0'/0'/0/{i}: {address}");
    }

    // Demonstrate xprv round-trip
    let parsed = ExtendedKey::from_string(&master_xprv)?;
    assert_eq!(
        parsed.to_base58(),
        master_xprv,
        "xprv round-trip must match"
    );
    println!("\nxprv Base58 round-trip verified.");

    Ok(())
}
