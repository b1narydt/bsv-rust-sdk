//! Inscription Transaction Example
//!
//! Demonstrates building a transaction with an inscription using the
//! OP_FALSE OP_RETURN format. This is the safe data carrier pattern
//! used for on-chain inscriptions in BSV -- the output is provably
//! unspendable, preventing accidental fund locking.
//!
//! Run with: `cargo run --example inscription_transaction`

use bsv::primitives::private_key::PrivateKey;
use bsv::script::inscriptions::Inscription;
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
    // 2. Create an inscription with content type and data
    // -----------------------------------------------------------------------
    let content_type = "text/plain";
    let inscription_data = b"BSV Rust SDK inscription example -- stored on-chain forever.";

    let inscription = Inscription::new(content_type, inscription_data.to_vec());
    let inscription_script = inscription.to_script();

    println!("Content type: {content_type}");
    println!(
        "Inscription data: {}",
        String::from_utf8_lossy(inscription_data)
    );
    println!("Inscription script (hex): {}", inscription_script.to_hex());
    println!("Inscription script (ASM): {}", inscription_script.to_asm());
    println!();

    // -----------------------------------------------------------------------
    // 3. Build the transaction
    // -----------------------------------------------------------------------
    let mut tx = Transaction::new();

    // Input spending from a simulated UTXO
    let input = TransactionInput {
        source_txid: Some(
            "c477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458".to_string(),
        ),
        source_output_index: 0,
        sequence: 0xFFFFFFFF,
        ..Default::default()
    };
    tx.add_input(input);

    // Inscription output (0 satoshis -- unspendable OP_FALSE OP_RETURN)
    tx.add_output(TransactionOutput {
        satoshis: Some(0),
        locking_script: inscription_script,
        change: false,
    });

    // Change output back to sender
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
    println!("Inscription transaction built and serialized successfully.");
    println!("Format: OP_FALSE OP_RETURN <content_type> <data>");

    Ok(())
}
