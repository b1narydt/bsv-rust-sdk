//! BEEF Deserialization and Verification Example
//!
//! Demonstrates creating a transaction, wrapping it in BEEF V1 format,
//! serializing to bytes, deserializing back, and verifying the round-trip
//! produces identical data.
//!
//! BEEF (Background Evaluation Extended Format, BRC-62) packages
//! transactions with their SPV proofs (Merkle paths) for compact
//! verification without requiring a full node.
//!
//! Run with: `cargo run --example verify_beef`

use std::io::Cursor;

use bsv::primitives::private_key::PrivateKey;
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::beef::{Beef, BEEF_V1};
use bsv::transaction::beef_tx::BeefTx;
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Build a simple transaction to wrap in BEEF
    // -----------------------------------------------------------------------
    let sender_key = PrivateKey::from_hex("1")?;
    let sender_p2pkh = P2PKH::from_private_key(sender_key.clone());
    let source_locking_script = sender_p2pkh.lock()?;
    let source_satoshis: u64 = 100_000;

    let mut tx = Transaction::new();

    let input = TransactionInput {
        source_txid: Some(
            "d477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
        ),
        source_output_index: 0,
        sequence: 0xFFFFFFFF,
        ..Default::default()
    };
    tx.add_input(input);

    let lock_script = sender_p2pkh.lock()?;
    tx.add_output(TransactionOutput {
        satoshis: Some(99_500),
        locking_script: lock_script,
        change: false,
    });

    // Sign the transaction
    let sighash_type = 0x41;
    tx.sign(
        0,
        &sender_p2pkh,
        sighash_type,
        source_satoshis,
        &source_locking_script,
    )?;

    let original_txid = tx.id()?;
    println!("Original transaction ID: {original_txid}");

    // -----------------------------------------------------------------------
    // 2. Wrap in BEEF V1 format (no merkle path -- new/unconfirmed tx)
    // -----------------------------------------------------------------------
    let beef_tx = BeefTx::from_tx(tx, None)?;
    let mut beef = Beef::new(BEEF_V1);
    beef.txs.push(beef_tx);

    // -----------------------------------------------------------------------
    // 3. Serialize BEEF to bytes
    // -----------------------------------------------------------------------
    let mut beef_bytes = Vec::new();
    beef.to_binary(&mut beef_bytes)?;

    println!("BEEF bytes length: {}", beef_bytes.len());
    println!(
        "BEEF hex: {}",
        beef_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!();

    // -----------------------------------------------------------------------
    // 4. Deserialize BEEF back from bytes
    // -----------------------------------------------------------------------
    let mut cursor = Cursor::new(&beef_bytes);
    let decoded_beef = Beef::from_binary(&mut cursor)?;

    println!("Decoded BEEF version: {}", decoded_beef.version);
    println!("Decoded BEEF bump count: {}", decoded_beef.bumps.len());
    println!("Decoded BEEF tx count: {}", decoded_beef.txs.len());

    // -----------------------------------------------------------------------
    // 5. Verify round-trip: compare txids
    // -----------------------------------------------------------------------
    let decoded_txid = &decoded_beef.txs[0].txid;
    println!();
    println!("Original txid:     {original_txid}");
    println!("Decoded BEEF txid: {decoded_txid}");

    if original_txid == *decoded_txid {
        println!();
        println!("BEEF round-trip verification PASSED: txids match.");
    } else {
        eprintln!();
        eprintln!("BEEF round-trip verification FAILED: txids do not match!");
        std::process::exit(1);
    }

    // -----------------------------------------------------------------------
    // 6. Verify byte-level round-trip
    // -----------------------------------------------------------------------
    let mut re_serialized = Vec::new();
    decoded_beef.to_binary(&mut re_serialized)?;

    if beef_bytes == re_serialized {
        println!("Byte-level round-trip verification PASSED: identical bytes.");
    } else {
        eprintln!("Byte-level round-trip verification FAILED: bytes differ!");
        eprintln!("  Original:     {} bytes", beef_bytes.len());
        eprintln!("  Re-serialized: {} bytes", re_serialized.len());
        std::process::exit(1);
    }

    Ok(())
}
