//! WalletClient Multi-Operation Example
//!
//! Demonstrates the core BRC-100 wallet workflow using the JSON API:
//!   1. getPublicKey  -- get the wallet's identity key
//!   2. createAction  -- create an action with an OP_RETURN output
//!   3. signAction    -- sign the created action
//!
//! This example requires a running BRC-100 wallet service endpoint.
//! By default it connects to http://localhost:3321 (JSON API).
//!
//! Run with: `cargo run --example wallet_client_action --features network`
//!
//! To specify a custom wallet endpoint:
//!   WALLET_URL=http://myhost:3321 cargo run --example wallet_client_action --features network
//!
//! NOTE: If no wallet service is available, the example will print a
//! descriptive error message explaining what is needed.

use std::collections::HashMap;

use bsv::script::inscriptions::op_return_data;
use bsv::wallet::interfaces::{
    CreateActionArgs, CreateActionOutput, GetPublicKeyArgs, SignActionArgs,
};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use bsv::wallet::WalletInterface;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        eprintln!();
        eprintln!("This example requires a running BRC-100 wallet service.");
        eprintln!("To set up a wallet service:");
        eprintln!("  1. Install and run a BRC-100 compatible wallet server");
        eprintln!("  2. Ensure it is listening on the expected endpoint");
        eprintln!("  3. Set WALLET_URL environment variable if not localhost:3321");
        eprintln!();
        eprintln!("Example: WALLET_URL=http://localhost:3321 cargo run --example wallet_client_action --features network");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. Connect to wallet service via JSON API
    // -----------------------------------------------------------------------
    let wallet_url =
        std::env::var("WALLET_URL").unwrap_or_else(|_| "http://localhost:3321".to_string());
    println!("Connecting to wallet JSON API at: {}", wallet_url);
    println!();

    let wallet = HttpWalletJson::new("bsv-sdk-example", &wallet_url);

    // -----------------------------------------------------------------------
    // 2. Get the wallet's identity public key
    // -----------------------------------------------------------------------
    println!("Step 1: getPublicKey -- retrieving wallet identity key...");
    let pubkey_result = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                privileged: false,
                privileged_reason: None,
                for_self: None,
                seek_permission: None,
            },
            None,
        )
        .await?;

    let identity_key = pubkey_result.public_key;
    println!("  Identity key: {}", identity_key.to_der_hex());
    println!();

    // -----------------------------------------------------------------------
    // 3. Create an action with an OP_RETURN output
    // -----------------------------------------------------------------------
    println!("Step 2: createAction -- creating action with OP_RETURN data...");

    // Build an OP_RETURN locking script with a message
    let message = b"Hello from BSV Rust SDK WalletClient!";
    let op_return_script = op_return_data(message);
    let script_bytes = op_return_script.to_binary();

    let create_result = wallet
        .create_action(
            CreateActionArgs {
                description: "BSV SDK example action".to_string(),
                input_beef: None,
                inputs: Some(Vec::new()),
                outputs: Some(vec![CreateActionOutput {
                    locking_script: Some(script_bytes),
                    satoshis: 0,
                    output_description: "OP_RETURN data output".to_string(),
                    basket: None,
                    custom_instructions: None,
                    tags: Some(Vec::new()),
                }]),
                lock_time: None,
                version: None,
                labels: Some(Vec::new()),
                options: None,
                reference: None,
            },
            None,
        )
        .await?;

    println!("  Action created successfully.");
    if let Some(ref txid) = create_result.txid {
        println!("  TXID: {}", txid);
    }

    // If the wallet returns a signable transaction, we can sign it.
    // Otherwise the action was completed directly (no signing needed).
    let signable = create_result.signable_transaction;
    if let Some(ref st) = signable {
        println!("  Reference: {} bytes", st.reference.len());
    }
    println!();

    // -----------------------------------------------------------------------
    // 4. Sign the action (if required)
    // -----------------------------------------------------------------------
    let sign_result = if let Some(st) = signable {
        println!("Step 3: signAction -- signing the created action...");

        let result = wallet
            .sign_action(
                SignActionArgs {
                    reference: st.reference,
                    spends: HashMap::new(),
                    options: None,
                },
                None,
            )
            .await?;
        Some(result)
    } else {
        println!("Step 3: signAction -- skipped (action completed without signing).");
        None
    };

    if let Some(ref result) = sign_result {
        println!("  Action signed successfully.");
        if let Some(ref txid) = result.txid {
            println!("  Final TXID: {}", txid);
        }
    }
    println!();

    // -----------------------------------------------------------------------
    // 5. Summary
    // -----------------------------------------------------------------------
    println!("BRC-100 wallet workflow completed:");
    println!("  1. Retrieved identity key: {}", identity_key.to_der_hex());
    println!(
        "  2. Created action with OP_RETURN data: \"{}\"",
        String::from_utf8_lossy(message)
    );
    println!("  3. Signed the action for broadcast");

    Ok(())
}
