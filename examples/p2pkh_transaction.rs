//! P2PKH Transaction Example
//!
//! Demonstrates building, signing, and serializing a standard
//! Pay-to-Public-Key-Hash (P2PKH) transaction using the BSV SDK.
//!
//! This example shows the complete workflow:
//!   key -> address -> locking script -> transaction -> sign -> serialize
//!
//! Run with: `cargo run --example p2pkh_transaction`

use bsv::primitives::private_key::PrivateKey;
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Create sender and recipient keys
    // -----------------------------------------------------------------------
    // Use well-known private keys for this example.
    // Key 1: the generator point private key (smallest valid key).
    let sender_key = PrivateKey::from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")?;
    let sender_pubkey = sender_key.to_public_key();
    let sender_address = sender_pubkey.to_address(&[0x00]); // mainnet prefix

    // Key 2: derived from hex for a different address.
    let recipient_key = PrivateKey::from_hex("ff")?;
    let recipient_pubkey = recipient_key.to_public_key();
    let recipient_address = recipient_pubkey.to_address(&[0x00]);

    println!("Sender address:    {sender_address}");
    println!("Recipient address: {recipient_address}");
    println!();

    // -----------------------------------------------------------------------
    // 2. Create the P2PKH locking script for the sender (simulated UTXO)
    // -----------------------------------------------------------------------
    let sender_p2pkh = P2PKH::from_private_key(sender_key.clone());
    let source_locking_script = sender_p2pkh.lock()?;
    let source_satoshis: u64 = 100_000; // 0.001 BSV

    println!(
        "Source locking script (hex): {}",
        source_locking_script.to_hex()
    );
    println!("Source satoshis: {source_satoshis}");
    println!();

    // -----------------------------------------------------------------------
    // 3. Build the new transaction
    // -----------------------------------------------------------------------
    let mut tx = Transaction::new();

    // Add input spending the simulated UTXO
    let input = TransactionInput {
        source_txid: Some(
            "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
        ),
        source_output_index: 0,
        sequence: 0xFFFFFFFF,
        ..Default::default()
    };
    tx.add_input(input);

    // Add P2PKH output to recipient (50,000 satoshis)
    let recipient_p2pkh = P2PKH::from_address(&recipient_address)?;
    let recipient_lock_script = recipient_p2pkh.lock()?;
    tx.add_output(TransactionOutput {
        satoshis: Some(50_000),
        locking_script: recipient_lock_script,
        change: false,
    });

    // Add change output back to sender (49,500 satoshis, leaving 500 for fee)
    let change_lock_script = sender_p2pkh.lock()?;
    tx.add_output(TransactionOutput {
        satoshis: Some(49_500),
        locking_script: change_lock_script,
        change: true,
    });

    // -----------------------------------------------------------------------
    // 4. Sign the transaction input
    // -----------------------------------------------------------------------
    let sighash_type = 0x41; // SIGHASH_ALL | SIGHASH_FORKID
    tx.sign(
        0,
        &sender_p2pkh,
        sighash_type,
        source_satoshis,
        &source_locking_script,
    )?;

    // -----------------------------------------------------------------------
    // 5. Serialize and display results
    // -----------------------------------------------------------------------
    let tx_hex = tx.to_hex()?;
    let txid = tx.id()?;

    println!("Transaction ID: {txid}");
    println!("Transaction hex ({} bytes):", tx_hex.len() / 2);
    println!("{tx_hex}");
    println!();
    println!("P2PKH transaction built, signed, and serialized successfully.");

    Ok(())
}
