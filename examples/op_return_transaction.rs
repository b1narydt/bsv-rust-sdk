//! OP_RETURN Data Embedding Example
//!
//! Demonstrates building a transaction with an OP_RETURN output
//! containing arbitrary data. OP_RETURN outputs are provably
//! unspendable and commonly used for on-chain data storage.
//!
//! Run with: `cargo run --example op_return_transaction`

use bsv::primitives::private_key::PrivateKey;
use bsv::script::inscriptions::op_return_data;
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Set up the sender key and simulated funding UTXO
    // -----------------------------------------------------------------------
    let sender_key = PrivateKey::from_hex("1")?;
    let sender_p2pkh = P2PKH::from_private_key(sender_key.clone());
    let source_locking_script = sender_p2pkh.lock()?;
    let source_satoshis: u64 = 50_000;

    println!(
        "Sender address: {}",
        sender_key.to_public_key().to_address(&[0x00])
    );
    println!();

    // -----------------------------------------------------------------------
    // 2. Create OP_RETURN output with embedded data
    // -----------------------------------------------------------------------
    let message = b"Hello from the BSV Rust SDK! On-chain data storage example.";
    let op_return_script = op_return_data(message);

    println!("Embedded data: {}", String::from_utf8_lossy(message));
    println!("OP_RETURN script (hex): {}", op_return_script.to_hex());
    println!("OP_RETURN script (ASM): {}", op_return_script.to_asm());
    println!();

    // -----------------------------------------------------------------------
    // 3. Build the transaction
    // -----------------------------------------------------------------------
    let mut tx = Transaction::new();

    // Input spending from a simulated UTXO
    let input = TransactionInput {
        source_txid: Some(
            "b477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
        ),
        source_output_index: 0,
        sequence: 0xFFFFFFFF,
        ..Default::default()
    };
    tx.add_input(input);

    // OP_RETURN output (0 satoshis -- unspendable)
    tx.add_output(TransactionOutput {
        satoshis: Some(0),
        locking_script: op_return_script,
        change: false,
    });

    // Change output back to sender (minus fee)
    let change_script = sender_p2pkh.lock()?;
    tx.add_output(TransactionOutput {
        satoshis: Some(49_500),
        locking_script: change_script,
        change: true,
    });

    // -----------------------------------------------------------------------
    // 4. Sign the input
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
    // 5. Serialize and display
    // -----------------------------------------------------------------------
    let tx_hex = tx.to_hex()?;
    let txid = tx.id()?;

    println!("Transaction ID: {txid}");
    println!("Transaction hex ({} bytes):", tx_hex.len() / 2);
    println!("{tx_hex}");
    println!();
    println!("OP_RETURN transaction built and serialized successfully.");

    Ok(())
}
