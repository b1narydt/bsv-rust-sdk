//! STAS-3 mainnet smoke test — exercises `Stas3Wallet` end-to-end against
//! a live BRC-100 wallet.
//!
//! This is the dogfood test the SDK has not yet had: until now every stas3
//! integration test ran against `ProtoWallet` (which returns `NotImplemented`
//! for `create_action` / `list_outputs` / `internalize_action`), so the
//! wallet-aware wrapper code paths in `Stas3Wallet` were untouched on a
//! real wallet store. This example runs them through one.
//!
//! # SAFETY
//!
//! Defaults to **dry-run**. Without `SMOKE_BROADCAST=1` the example builds
//! the request args but does NOT call the wallet. Set `SMOKE_BROADCAST=1`
//! to actually mutate state on chain.
//!
//! # Phases
//!
//! Only the `connect` phase runs by default. Set `SMOKE_PHASE` to opt in:
//!
//! - `connect` — ping the wallet, fetch identity key, list current fuel basket
//! - `topup`   — connect + provision N fresh fuel UTXOs via `top_up_fuel`,
//!               then re-list to confirm they appear
//!
//! Future phases (`mint`, `transfer`, etc.) layer on top of `topup` and will
//! be added once the topup phase has been verified on chain.
//!
//! # Configuration (env vars)
//!
//! - `WALLET_URL`         — BRC-100 wallet JSON endpoint (default `http://localhost:3321`)
//! - `ORIGINATOR`         — originator string passed to the wallet (default `stas3-smoke`)
//! - `SMOKE_PHASE`        — `connect` (default) | `topup`
//! - `SMOKE_BROADCAST`    — `1` to actually broadcast; anything else (default) is dry-run
//! - `SMOKE_FUEL_SATS`    — satoshis per fuel UTXO (default `2000`)
//! - `SMOKE_FUEL_COUNT`   — how many fuel UTXOs to provision (default `2`)
//! - `SMOKE_FUEL_BASKET`  — basket name override (default uses Stas3Wallet's default)
//!
//! # Running
//!
//! ```bash
//! # dry-run, just check we can reach the wallet:
//! cargo run --example stas3_mainnet_smoke --features network
//!
//! # actually top up 2 × 2000-sat fuel UTXOs (mainnet — real money):
//! SMOKE_PHASE=topup SMOKE_BROADCAST=1 \
//!   WALLET_URL=http://localhost:3321 \
//!   cargo run --example stas3_mainnet_smoke --features network
//! ```

use std::env;
use std::sync::Arc;

use bsv::script::templates::stas3::{Stas3Wallet, Stas3WalletConfig};
use bsv::wallet::interfaces::{
    GetPublicKeyArgs, ListOutputsArgs, OutputInclude, WalletInterface,
};
use bsv::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;

const DEFAULT_WALLET_URL: &str = "http://localhost:3321";
const DEFAULT_ORIGINATOR: &str = "stas3-smoke";
const DEFAULT_FUEL_SATS: u64 = 2_000;
const DEFAULT_FUEL_COUNT: usize = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_url = env::var("WALLET_URL").unwrap_or_else(|_| DEFAULT_WALLET_URL.into());
    let originator = env::var("ORIGINATOR").unwrap_or_else(|_| DEFAULT_ORIGINATOR.into());
    let phase = env::var("SMOKE_PHASE").unwrap_or_else(|_| "connect".into());
    let broadcast = env::var("SMOKE_BROADCAST")
        .map(|v| v == "1")
        .unwrap_or(false);
    let fuel_sats = env::var("SMOKE_FUEL_SATS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_FUEL_SATS);
    let fuel_count = env::var("SMOKE_FUEL_COUNT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_FUEL_COUNT);

    println!("== STAS-3 mainnet smoke test ==");
    println!("  WALLET_URL         = {wallet_url}");
    println!("  ORIGINATOR         = {originator}");
    println!("  SMOKE_PHASE        = {phase}");
    println!(
        "  SMOKE_BROADCAST    = {} {}",
        broadcast,
        if broadcast { "(LIVE)" } else { "(dry-run)" }
    );

    // -------------------------------------------------------------------
    // Phase: connect (always runs)
    // -------------------------------------------------------------------
    println!("\n[1/?] Connecting to wallet...");
    let wallet = Arc::new(HttpWalletJson::new(&originator, &wallet_url));

    println!("[2/?] Fetching identity key...");
    let id = wallet
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
            Some(&originator),
        )
        .await?;
    println!("       identity key: {}", id.public_key.to_der_hex());

    let stas = Stas3Wallet::with_config(
        wallet.clone(),
        Stas3WalletConfig {
            originator: Some(originator.clone()),
            ..Default::default()
        },
    );

    println!("[3/?] Listing current fuel basket...");
    let fuel_basket = stas.config().fuel_basket.clone();
    let before = list_basket(&*wallet, &fuel_basket, &originator).await?;
    println!(
        "       basket {fuel_basket:?}: {} UTXO(s), total {} sats",
        before.len(),
        before.iter().map(|o| o.satoshis).sum::<u64>()
    );

    if phase == "connect" {
        println!("\n✓ connect phase complete (set SMOKE_PHASE=topup to provision fuel)");
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: topup
    // -------------------------------------------------------------------
    if phase != "topup" {
        return Err(format!("unknown SMOKE_PHASE={phase} (expected: connect | topup)").into());
    }

    println!(
        "\n[4/?] Topping up fuel: {fuel_count} × {fuel_sats} sats \
         ({} sats total + fees)",
        fuel_sats * fuel_count as u64
    );

    if !broadcast {
        println!("       SKIPPED (dry-run — set SMOKE_BROADCAST=1 to actually broadcast)");
        println!("\n✓ topup dry-run complete");
        return Ok(());
    }

    let topup = stas.top_up_fuel(fuel_sats, fuel_count).await?;
    println!("       broadcast txid: {}", topup.txid);
    for op in &topup.outpoints {
        println!("       new fuel UTXO:  {op}");
    }

    println!("[5/?] Re-listing fuel basket to confirm...");
    let after = list_basket(&*wallet, &fuel_basket, &originator).await?;
    let delta = after.len().saturating_sub(before.len());
    println!(
        "       basket {fuel_basket:?}: {} UTXO(s) (delta = +{delta}), total {} sats",
        after.len(),
        after.iter().map(|o| o.satoshis).sum::<u64>()
    );

    if delta < fuel_count {
        return Err(format!(
            "fuel basket gained only {delta} UTXOs after broadcasting {fuel_count} top-up outputs \
             — wallet may have rejected some, or list_outputs is not yet reflecting the new tx"
        )
        .into());
    }

    println!("\n✓ topup phase complete: {fuel_count} fresh fuel UTXOs in basket {fuel_basket:?}");
    Ok(())
}

async fn list_basket(
    wallet: &dyn WalletInterface,
    basket: &str,
    originator: &str,
) -> Result<Vec<bsv::wallet::interfaces::Output>, Box<dyn std::error::Error>> {
    let result = wallet
        .list_outputs(
            ListOutputsArgs {
                basket: basket.to_string(),
                tags: vec![],
                tag_query_mode: None,
                include: Some(OutputInclude::LockingScripts),
                include_custom_instructions: BooleanDefaultFalse(Some(true)),
                include_tags: BooleanDefaultFalse(Some(false)),
                include_labels: BooleanDefaultFalse(Some(false)),
                limit: Some(100),
                offset: None,
                seek_permission: BooleanDefaultTrue(Some(true)),
            },
            Some(originator),
        )
        .await?;
    Ok(result.outputs)
}
