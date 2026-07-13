//! Split a private key into shares using Shamir's Secret Sharing and reconstruct it.
//!
//! Run: `cargo run --example keyshares_backup`

use bsv::primitives::key_shares::KeyShares;
use bsv::primitives::private_key::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Key Shares Backup (Shamir's Secret Sharing) ===\n");

    // Create a private key to split
    let original_key =
        PrivateKey::from_hex("c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5")?;
    println!("Original key:      {}", original_key.to_hex());

    // Split into 5 shares with threshold 3
    let threshold = 3;
    let total = 5;
    let shares = KeyShares::split(&original_key, threshold, total)?;
    println!("Total shares:      {total}");
    println!("Threshold:         {threshold}");
    println!("Integrity hash:    {}", shares.integrity);

    // Display share backup strings
    let backup = shares.to_backup_format();
    for (i, share) in backup.iter().enumerate() {
        println!(
            "  Share {}: {}...{}",
            i + 1,
            &share[..20],
            &share[share.len() - 8..]
        );
    }

    // Reconstruct from any 3 of the 5 shares
    println!("\nReconstructing from shares 1, 3, 5...");
    let subset_backup = vec![backup[0].clone(), backup[2].clone(), backup[4].clone()];
    let subset_shares = KeyShares::from_backup_format(&subset_backup)?;
    let reconstructed = KeyShares::reconstruct(&subset_shares)?;

    println!("Reconstructed key: {}", reconstructed.to_hex());

    assert_eq!(
        original_key.to_hex(),
        reconstructed.to_hex(),
        "Reconstructed key must match original"
    );
    println!("\nKey reconstruction verified -- original and reconstructed match.");

    Ok(())
}
