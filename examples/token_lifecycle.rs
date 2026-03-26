//! Token Lifecycle Example
//!
//! Demonstrates a complete token lifecycle using the BRC-100 wallet JSON API:
//!   1. Create a token (event ticket) in a basket
//!   2. List tokens in the basket
//!   3. Redeem (spend) a token from the basket
//!
//! This example requires a running BRC-100 wallet service endpoint.
//! By default it connects to http://localhost:3321 (JSON API).
//!
//! Run with: `cargo run --example token_lifecycle --features network`
//!
//! To specify a custom wallet endpoint:
//!   WALLET_URL=http://myhost:3321 cargo run --example token_lifecycle --features network

use bsv::script::Script;
use bsv::wallet::interfaces::{
    CreateActionArgs, CreateActionInput, CreateActionOutput, ListOutputsArgs, OutputInclude,
};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use bsv::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};
use bsv::wallet::WalletInterface;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        eprintln!();
        eprintln!("This example requires a running BRC-100 wallet service.");
        eprintln!("Ensure it is listening on http://localhost:3321 (or set WALLET_URL).");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_url =
        std::env::var("WALLET_URL").unwrap_or_else(|_| "http://localhost:3321".to_string());
    let wallet = HttpWalletJson::new("token-lifecycle-example", &wallet_url);
    println!("Connected to wallet JSON API at: {}", wallet_url);
    println!();

    // -----------------------------------------------------------------------
    // Step 1: Create a token (event ticket)
    // -----------------------------------------------------------------------
    println!("Step 1: Creating an event ticket token...");

    let nop_script = Script::from_asm("OP_NOP");
    let create_result = wallet
        .create_action(
            CreateActionArgs {
                description: "create an event ticket".to_string(),
                input_beef: None,
                inputs: Vec::new(),
                outputs: vec![CreateActionOutput {
                    locking_script: Some(nop_script.to_binary()),
                    satoshis: 1,
                    output_description: "event ticket".to_string(),
                    basket: Some("event tickets".to_string()),
                    custom_instructions: None,
                    tags: Vec::new(),
                }],
                lock_time: None,
                version: None,
                labels: Vec::new(),
                options: None,
                reference: None,
            },
            None,
        )
        .await?;

    println!("  Token created successfully.");
    if let Some(ref txid) = create_result.txid {
        println!("  TXID: {}", txid);
    }
    println!();

    // -----------------------------------------------------------------------
    // Step 2: List tokens in the basket
    // -----------------------------------------------------------------------
    println!("Step 2: Listing event ticket tokens...");

    let list_result = wallet
        .list_outputs(
            ListOutputsArgs {
                basket: "event tickets".to_string(),
                tags: Vec::new(),
                tag_query_mode: None,
                include: Some(OutputInclude::EntireTransactions),
                include_custom_instructions: BooleanDefaultFalse(None),
                include_tags: BooleanDefaultFalse(None),
                include_labels: BooleanDefaultFalse(None),
                limit: None,
                offset: None,
                seek_permission: BooleanDefaultTrue(None),
            },
            None,
        )
        .await?;

    println!("  Total outputs: {}", list_result.total_outputs);
    for (i, output) in list_result.outputs.iter().enumerate() {
        println!(
            "  [{}] outpoint: {}  satoshis: {}  spendable: {}",
            i, output.outpoint, output.satoshis, output.spendable
        );
    }
    if let Some(ref beef) = list_result.beef {
        println!("  BEEF: {} bytes", beef.len());
    }
    println!();

    // -----------------------------------------------------------------------
    // Step 3: Redeem a token
    // -----------------------------------------------------------------------
    println!("Step 3: Redeeming an event ticket token...");

    if list_result.outputs.is_empty() {
        println!("  No tokens available to redeem.");
        return Ok(());
    }

    // Use the last output (most recently created token)
    let last = list_result.outputs.last().unwrap();
    let outpoint = &last.outpoint;
    println!("  Redeeming outpoint: {}", outpoint);

    let op_true_script = Script::from_asm("OP_TRUE");

    let redeem_result = wallet
        .create_action(
            CreateActionArgs {
                description: "redeem an event ticket".to_string(),
                input_beef: list_result.beef,
                inputs: vec![CreateActionInput {
                    outpoint: outpoint.clone(),
                    input_description: "event ticket".to_string(),
                    unlocking_script: Some(op_true_script.to_binary()),
                    unlocking_script_length: None,
                    sequence_number: None,
                }],
                outputs: Vec::new(),
                lock_time: None,
                version: None,
                labels: Vec::new(),
                options: None,
                reference: None,
            },
            None,
        )
        .await?;

    println!("  Token redeemed successfully.");
    if let Some(ref txid) = redeem_result.txid {
        println!("  TXID: {}", txid);
    }
    println!();

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    println!("Token lifecycle complete:");
    println!("  1. Created event ticket token");
    println!(
        "  2. Listed {} token(s) in basket",
        list_result.total_outputs
    );
    println!("  3. Redeemed token at outpoint {}", outpoint);

    Ok(())
}
