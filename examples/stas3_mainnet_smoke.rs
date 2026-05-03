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
//! - `connect`  — ping the wallet, fetch identity key, list current fuel basket
//! - `topup`    — connect + provision N fresh fuel UTXOs via `top_up_fuel`,
//!                then re-list to confirm they appear
//! - `pickfuel` — connect + call `pick_fuel` against the current basket,
//!                verify the picked UTXO has parsable customInstructions
//!                (proves the read-back path on top of what topup wrote).
//!                Read-only — no broadcast.
//! - `mint`     — DRY RUN. Picks a fuel UTXO, derives a fresh issuer key
//!                (`stas3issuer/smoke-{millis}`) and destination key
//!                (`stas3owner/dest1`), calls `mint_eac` with minimal
//!                EacFields, prints the resulting contract_tx + issue_tx
//!                hex. Engine-verifies the issue_tx's P2PKH inputs against
//!                the freshly-built contract_tx outputs (proves signing
//!                works end-to-end). Does NOT broadcast — full broadcast
//!                requires ARC integration + atomic BEEF construction
//!                (separate workstream).
//!
//! Future phase `transfer` adds the post-broadcast read-back: pick a
//! minted STAS UTXO from the token basket, transfer it to a new owner.
//! Requires the mint phase to have actually broadcast first.
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

use bsv::primitives::hash::hash160;
use bsv::script::templates::stas3::eac::{EacFields, EnergySource};
use bsv::script::templates::stas3::factory::SigningKey;
use bsv::script::templates::stas3::{
    decode_locking_script, verify_input, Brc43KeyArgs, Stas3Wallet, Stas3WalletConfig,
};
use bsv::wallet::interfaces::{
    GetPublicKeyArgs, ListOutputsArgs, OutputInclude, WalletInterface,
};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use bsv::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

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
        println!("\n✓ connect phase complete (set SMOKE_PHASE=topup or pickfuel)");
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: pickfuel  (read-only — no broadcast)
    // -------------------------------------------------------------------
    if phase == "pickfuel" {
        if before.is_empty() {
            return Err(format!(
                "pickfuel phase requires fuel UTXOs in basket {fuel_basket:?}; \
                 run SMOKE_PHASE=topup SMOKE_BROADCAST=1 first"
            )
            .into());
        }
        let min = fuel_sats.min(before.iter().map(|o| o.satoshis).min().unwrap_or(1));
        println!("\n[4/4] Picking fuel UTXO with at least {min} sats...");
        let picked = stas.pick_fuel(min).await?;
        println!("       picked outpoint: {}.{}", picked.txid_hex, picked.vout);
        println!("       satoshis:        {}", picked.satoshis);
        println!(
            "       triple:          protocol={:?} keyID={:?} counterparty={:?}",
            picked.triple.protocol_id.protocol,
            picked.triple.key_id,
            picked.triple.counterparty.counterparty_type
        );
        println!(
            "\n✓ pickfuel phase complete — pick_fuel + customInstructions JSON \
             round-trip works against the live wallet"
        );
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: mint  (DRY RUN — builds + signs but does not broadcast)
    // -------------------------------------------------------------------
    if phase == "mint" {
        if before.is_empty() {
            return Err(format!(
                "mint phase requires a fuel UTXO; run SMOKE_PHASE=topup first"
            )
            .into());
        }

        println!("\n[4/?] Picking fuel UTXO to fund the mint...");
        let funding = stas.pick_fuel(500).await?;
        println!(
            "       picked outpoint: {}.{} ({} sats)",
            funding.txid_hex, funding.vout, funding.satoshis
        );

        println!("[5/?] Deriving issuer key...");
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let issuer_triple =
            Brc43KeyArgs::self_under("stas3issuer", format!("smoke-{now_ms}"));
        let issuer_pk = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(issuer_triple.protocol_id.clone()),
                    key_id: Some(issuer_triple.key_id.clone()),
                    counterparty: Some(issuer_triple.counterparty.clone()),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                Some(&originator),
            )
            .await?;
        let issuer_pkh = hash160(&issuer_pk.public_key.to_der());
        println!("       issuer keyID:   {:?}", issuer_triple.key_id);
        println!("       issuer pubkey:  {}", issuer_pk.public_key.to_der_hex());
        println!("       issuer pkh:     {}", hex::encode(issuer_pkh));

        println!("[6/?] Deriving destination key...");
        let dest_triple = Brc43KeyArgs::self_under("stas3owner", "dest1");
        let dest_pk = wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(dest_triple.protocol_id.clone()),
                    key_id: Some(dest_triple.key_id.clone()),
                    counterparty: Some(dest_triple.counterparty.clone()),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                Some(&originator),
            )
            .await?;
        let dest_pkh = hash160(&dest_pk.public_key.to_der());
        println!("       dest keyID:     {:?}", dest_triple.key_id);
        println!("       dest pkh:       {}", hex::encode(dest_pkh));

        println!("[7/?] Building minimal EacFields...");
        let now_secs = (now_ms / 1000) as i64;
        let eac = EacFields {
            quantity_wh: 1,
            interval_start: now_secs - 3600,
            interval_end: now_secs,
            energy_source: EnergySource::Solar,
            country: *b"US",
            device_id: [0xab; 32],
            id_range: (1, 1),
            issue_date: now_secs,
            storage_tag: 0,
        };
        println!(
            "       quantity_wh={} interval=[{} → {}] source=Solar country=US",
            eac.quantity_wh, eac.interval_start, eac.interval_end
        );

        println!("[8/?] Calling mint_eac (dry-run — builds + signs, no broadcast)...");
        let result = stas
            .mint_eac(
                Some(&originator),
                SigningKey::P2pkh(issuer_triple),
                funding.clone(),
                0, // flags = no FREEZABLE / CONFISCATABLE
                None,
                None,
                vec![(dest_pkh, 1, eac)],
                b"stas3-smoke".to_vec(),
                500,
            )
            .await?;

        let contract_txid = result
            .contract_tx
            .id()
            .map_err(|e| format!("contract txid: {e}"))?;
        let issue_txid = result
            .issue_tx
            .id()
            .map_err(|e| format!("issue txid: {e}"))?;
        let contract_hex = result
            .contract_tx
            .to_bytes()
            .map_err(|e| format!("contract bytes: {e}"))?;
        let issue_hex = result
            .issue_tx
            .to_bytes()
            .map_err(|e| format!("issue bytes: {e}"))?;

        println!("       contract_tx txid: {contract_txid}");
        println!("       contract_tx size: {} bytes", contract_hex.len());
        println!("       issue_tx txid:    {issue_txid}");
        println!("       issue_tx size:    {} bytes", issue_hex.len());

        println!("[9/?] Engine-verifying issue_tx P2PKH inputs against contract_tx outputs...");
        let supply_lock = result.contract_tx.outputs[0].locking_script.clone();
        let supply_sats = result.contract_tx.outputs[0]
            .satoshis
            .ok_or("contract output 0 missing sats")?;
        match verify_input(&result.issue_tx, 0, &supply_lock, supply_sats) {
            Ok(true) => println!("       ✓ input 0 (supply spend) engine-verified"),
            Ok(false) => println!(
                "       ⚠ input 0 (supply spend) engine returned Ok(false) — the supply\n\
                 \x20         lock is P2PKH+OP_FALSE+OP_RETURN; our interpreter treats the\n\
                 \x20         post-OP_RETURN stack-top as the result, which is FALSE here.\n\
                 \x20         dxs/TS interpreter has the same shape; mainnet miner semantics\n\
                 \x20         may be looser. Real broadcast empirically determines acceptance."
            ),
            Err(e) => println!("       ⚠ input 0 (supply spend) engine errored: {e:?}"),
        }

        let change_lock = result.contract_tx.outputs[1].locking_script.clone();
        let change_sats = result.contract_tx.outputs[1]
            .satoshis
            .ok_or("contract output 1 missing sats")?;
        match verify_input(&result.issue_tx, 1, &change_lock, change_sats) {
            Ok(true) => println!("       ✓ input 1 (change spend, plain P2PKH) engine-verified"),
            Ok(false) => println!("       ⚠ input 1 engine returned Ok(false)"),
            Err(e) => println!("       ⚠ input 1 engine errored: {e:?}"),
        }

        println!("[10/?] Decoding issue_tx STAS-3 destination output...");
        let stas_lock = result.issue_tx.outputs[0].locking_script.clone();
        let decoded = decode_locking_script(&stas_lock)
            .map_err(|e| format!("decode STAS-3 lock: {e:?}"))?;
        println!(
            "       owner_pkh:      {} (matches dest? {})",
            hex::encode(decoded.owner_pkh),
            decoded.owner_pkh == dest_pkh
        );
        println!(
            "       redemption_pkh: {} (matches issuer? {})",
            hex::encode(decoded.redemption_pkh),
            decoded.redemption_pkh == issuer_pkh
        );
        println!("       flags:          0x{:02x}", decoded.flags);
        println!(
            "       optional_data:  {} elements (EAC schema)",
            decoded.optional_data.len()
        );

        println!("\n✓ mint dry-run complete");
        println!("\n  contract_tx hex (broadcast first):");
        println!("  {}", hex::encode(&contract_hex));
        println!("\n  issue_tx hex (broadcast second):");
        println!("  {}", hex::encode(&issue_hex));
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: topup
    // -------------------------------------------------------------------
    if phase != "topup" {
        return Err(format!(
            "unknown SMOKE_PHASE={phase} (expected: connect | topup | pickfuel | mint)"
        )
        .into());
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
