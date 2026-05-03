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
//! - `connect`       — ping the wallet, fetch identity key, list current fuel basket
//! - `topup`         — connect + provision N fresh fuel UTXOs via `top_up_fuel`,
//!                     then re-list to confirm they appear
//! - `pickfuel`      — connect + call `pick_fuel` against the current basket,
//!                     verify the picked UTXO has parsable customInstructions
//!                     (proves the read-back path on top of what topup wrote).
//!                     Read-only — no broadcast.
//! - `mint`          — DRY RUN. Picks a fuel UTXO, derives a fresh issuer key
//!                     (`stas3issuer/smoke-{millis}`) and destination key
//!                     (`stas3owner/dest1`), calls `mint_eac` with minimal
//!                     EacFields, prints the resulting contract_tx + issue_tx
//!                     hex. Engine-verifies the issue_tx's P2PKH inputs against
//!                     the freshly-built contract_tx outputs (proves signing
//!                     works end-to-end). Does NOT broadcast.
//! - `mint-broadcast` — Full on-chain mint. Performs the same build + sign
//!                     steps as `mint`, then broadcasts contract_tx and
//!                     issue_tx via ARC, and registers the new STAS-3 token
//!                     output in the wallet's token basket via
//!                     `internalize_action`. Requires `SMOKE_BROADCAST=1`
//!                     (without it the phase prints "broadcast skipped" and
//!                     exits cleanly). Additional env vars:
//!                     `SMOKE_ARC_URL` (default: gorillapool free tier) and
//!                     `SMOKE_ARC_API_KEY` (optional).
//!
//! Future phase `transfer` adds the post-broadcast read-back: pick a
//! minted STAS UTXO from the token basket, transfer it to a new owner.
//! Requires the mint phase to have actually broadcast first.
//!
//! # Configuration (env vars)
//!
//! - `WALLET_URL`         — BRC-100 wallet JSON endpoint (default `http://localhost:3321`)
//! - `ORIGINATOR`         — originator string passed to the wallet (default `stas3-smoke`)
//! - `SMOKE_PHASE`        — `connect` (default) | `topup` | `pickfuel` | `mint` | `mint-broadcast`
//! - `SMOKE_BROADCAST`    — `1` to actually broadcast; anything else (default) is dry-run
//! - `SMOKE_FUEL_SATS`    — satoshis per fuel UTXO (default `2000`)
//! - `SMOKE_FUEL_COUNT`   — how many fuel UTXOs to provision (default `2`)
//! - `SMOKE_FUEL_BASKET`  — basket name override (default uses Stas3Wallet's default)
//! - `SMOKE_ARC_URL`      — ARC endpoint used by `mint-broadcast`
//!                          (default `https://api.gorillapool.io/v1/tx`)
//! - `SMOKE_ARC_API_KEY`  — optional API key for the ARC endpoint (default: none)
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
//!
//! # dry-run mint-broadcast (builds + signs + verifies, no actual broadcast):
//! SMOKE_PHASE=mint-broadcast \
//!   WALLET_URL=http://localhost:3321 \
//!   cargo run --example stas3_mainnet_smoke --features network
//!
//! # full on-chain mint (real money — ensure fuel UTXOs exist first):
//! SMOKE_PHASE=mint-broadcast SMOKE_BROADCAST=1 \
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
use bsv::transaction::beef::{Beef, BEEF_V1};
use bsv::transaction::broadcasters::arc::ARC;
use bsv::transaction::Broadcaster;
use bsv::wallet::interfaces::{
    GetPublicKeyArgs, ListOutputsArgs, OutputInclude, WalletInterface,
};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use bsv::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

const DEFAULT_WALLET_URL: &str = "http://localhost:3321";
const DEFAULT_ORIGINATOR: &str = "stas3-smoke";
const DEFAULT_FUEL_SATS: u64 = 2_000;
const DEFAULT_FUEL_COUNT: usize = 2;
const DEFAULT_ARC_URL: &str = "https://api.gorillapool.io/v1/tx";

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
    let arc_url = env::var("SMOKE_ARC_URL").unwrap_or_else(|_| DEFAULT_ARC_URL.into());
    let arc_api_key = env::var("SMOKE_ARC_API_KEY").ok();

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
        let valid_in0 = verify_input(&result.issue_tx, 0, &supply_lock, supply_sats)
            .map_err(|e| format!("issue_tx input 0 verify: {e:?}"))?;
        if !valid_in0 {
            return Err(
                "issue_tx input 0 (P2PKH+OP_RETURN supply spend) failed engine verification".into(),
            );
        }
        println!("       ✓ input 0 (P2PKH+OP_RETURN supply spend) engine-verified");

        let change_lock = result.contract_tx.outputs[1].locking_script.clone();
        let change_sats = result.contract_tx.outputs[1]
            .satoshis
            .ok_or("contract output 1 missing sats")?;
        let valid_in1 = verify_input(&result.issue_tx, 1, &change_lock, change_sats)
            .map_err(|e| format!("issue_tx input 1 verify: {e:?}"))?;
        if !valid_in1 {
            return Err("issue_tx input 1 (plain P2PKH change spend) failed engine verification".into());
        }
        println!("       ✓ input 1 (plain P2PKH change spend) engine-verified");

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
    // Phase: mint-broadcast  (builds + signs + broadcasts + internalizes)
    // -------------------------------------------------------------------
    if phase == "mint-broadcast" {
        if before.is_empty() {
            return Err(format!(
                "mint-broadcast phase requires a fuel UTXO; \
                 run SMOKE_PHASE=topup SMOKE_BROADCAST=1 first"
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

        println!("[8/?] Calling mint_eac (builds + signs txs)...");
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

        println!("       contract_tx txid: {contract_txid}");
        println!(
            "       contract_tx size: {} bytes",
            result
                .contract_tx
                .to_bytes()
                .map(|b| b.len())
                .unwrap_or(0)
        );
        println!("       issue_tx txid:    {issue_txid}");
        println!(
            "       issue_tx size:    {} bytes",
            result.issue_tx.to_bytes().map(|b| b.len()).unwrap_or(0)
        );

        println!("[9/?] Engine-verifying issue_tx inputs...");
        let supply_lock = result.contract_tx.outputs[0].locking_script.clone();
        let supply_sats = result.contract_tx.outputs[0]
            .satoshis
            .ok_or("contract output 0 missing sats")?;
        let valid_in0 = verify_input(&result.issue_tx, 0, &supply_lock, supply_sats)
            .map_err(|e| format!("issue_tx input 0 verify: {e:?}"))?;
        if !valid_in0 {
            return Err(
                "issue_tx input 0 (P2PKH+OP_RETURN supply spend) failed engine verification".into(),
            );
        }
        println!("       ✓ input 0 (supply spend) engine-verified");

        let change_lock = result.contract_tx.outputs[1].locking_script.clone();
        let change_sats = result.contract_tx.outputs[1]
            .satoshis
            .ok_or("contract output 1 missing sats")?;
        let valid_in1 = verify_input(&result.issue_tx, 1, &change_lock, change_sats)
            .map_err(|e| format!("issue_tx input 1 verify: {e:?}"))?;
        if !valid_in1 {
            return Err(
                "issue_tx input 1 (plain P2PKH change spend) failed engine verification".into(),
            );
        }
        println!("       ✓ input 1 (change spend) engine-verified");

        // --- Dry-run gate ---
        if !broadcast {
            println!(
                "\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to actually broadcast)"
            );
            println!("  ARC URL would be: {arc_url}");
            println!("\n✓ mint-broadcast dry-run complete (build + sign + verify OK)");
            return Ok(());
        }

        // --- Live broadcast path ---
        println!("[10/?] Broadcasting via ARC ({arc_url})...");
        let arc = ARC::new(&arc_url, arc_api_key.clone());

        println!("       Broadcasting contract_tx ({contract_txid})...");
        let contract_resp = arc.broadcast(&result.contract_tx).await.map_err(|e| {
            format!(
                "FAILED to broadcast contract_tx: code={} status={} desc={}",
                e.code, e.status, e.description
            )
        })?;
        println!(
            "       contract_tx broadcast OK: txid={} status={} msg={}",
            contract_resp.txid, contract_resp.status, contract_resp.message
        );

        println!("       Broadcasting issue_tx ({issue_txid})...");
        let issue_resp = arc.broadcast(&result.issue_tx).await.map_err(|e| {
            format!(
                "FAILED to broadcast issue_tx: code={} status={} desc={}",
                e.code, e.status, e.description
            )
        })?;
        println!(
            "       issue_tx broadcast OK: txid={} status={} msg={}",
            issue_resp.txid, issue_resp.status, issue_resp.message
        );

        // --- Build atomic BEEF for internalize_action ---
        // The wallet needs an AtomicBEEF containing:
        //   fuel source tx (mined, from wallet) + contract_tx + issue_tx
        println!("[11/?] Fetching fuel source tx for BEEF construction...");
        let fuel_with_tx = wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: fuel_basket.clone(),
                    tags: vec![],
                    tag_query_mode: None,
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: BooleanDefaultFalse(Some(false)),
                    include_tags: BooleanDefaultFalse(Some(false)),
                    include_labels: BooleanDefaultFalse(Some(false)),
                    limit: Some(100),
                    offset: None,
                    seek_permission: BooleanDefaultTrue(Some(true)),
                },
                Some(&originator),
            )
            .await
            .map_err(|e| format!("list_outputs(EntireTransactions) failed: {e}"))?;

        // The wallet returns source txs in the top-level BEEF field.
        let fuel_beef_bytes = fuel_with_tx
            .beef
            .ok_or("list_outputs(EntireTransactions) returned no BEEF field")?;

        println!("       fuel basket BEEF: {} bytes", fuel_beef_bytes.len());

        // Build a BEEF starting from the wallet's BEEF (preserves bumps + fuel source tx),
        // then add contract_tx and issue_tx on top.
        println!("[12/?] Constructing atomic BEEF for issue_tx internalization...");
        let mut beef = Beef::new(BEEF_V1);
        beef.merge_beef_from_binary(&fuel_beef_bytes)
            .map_err(|e| format!("merge wallet BEEF: {e}"))?;

        // Confirm the fuel source tx made it into our BEEF.
        if beef.find_txid(&funding.txid_hex).is_none() {
            return Err(format!(
                "fuel source txid {} not found in BEEF from wallet \
                 (BEEF has {} txs: {:?})",
                funding.txid_hex,
                beef.txs.len(),
                beef.txs.iter().map(|t| &t.txid).collect::<Vec<_>>()
            )
            .into());
        }
        println!(
            "       wallet BEEF merged: {} tx(s), {} bump(s); \
             fuel source tx {} confirmed",
            beef.txs.len(),
            beef.bumps.len(),
            funding.txid_hex
        );

        // Add contract_tx (no bump — just broadcast, not yet mined).
        let contract_tx_bytes = result
            .contract_tx
            .to_bytes()
            .map_err(|e| format!("serialize contract_tx: {e}"))?;
        beef.merge_raw_tx(&contract_tx_bytes, None)
            .map_err(|e| format!("merge contract_tx into BEEF: {e}"))?;

        // Add issue_tx (no bump — just broadcast, not yet mined).
        let issue_tx_bytes = result
            .issue_tx
            .to_bytes()
            .map_err(|e| format!("serialize issue_tx: {e}"))?;
        beef.merge_raw_tx(&issue_tx_bytes, None)
            .map_err(|e| format!("merge issue_tx into BEEF: {e}"))?;

        // Produce atomic BEEF with issue_tx as the proven subject.
        let atomic_beef_bytes = beef
            .to_binary_atomic(&issue_txid)
            .map_err(|e| format!("to_binary_atomic(issue_txid): {e}"))?;

        println!(
            "       atomic BEEF built: {} bytes ({} txs, {} bumps)",
            atomic_beef_bytes.len(),
            beef.txs.len(),
            beef.bumps.len()
        );

        // --- Internalize the STAS-3 output ---
        println!("[13/?] Internalizing STAS-3 output into token basket...");
        stas.internalize_stas_outputs(
            atomic_beef_bytes,
            vec![(0, dest_triple.clone(), Some("EAC1".to_string()))],
            "stas3 smoke mint",
        )
        .await
        .map_err(|e| format!("internalize_stas_outputs failed: {e}"))?;
        println!("       internalize_action accepted");

        // --- Verify the token now appears in the basket ---
        println!("[14/?] Verifying STAS-3 token now appears in token basket...");
        let token_basket = stas.config().token_basket.clone();
        let tokens = list_basket(&*wallet, &token_basket, &originator).await?;
        println!("       basket {token_basket:?}: {} UTXO(s)", tokens.len());
        if tokens.is_empty() {
            println!(
                "  WARNING: token basket is empty — the wallet may not yet \
                 have indexed the new UTXO (try listing again shortly)"
            );
        } else {
            println!("       ✓ {} token UTXO(s) found in basket", tokens.len());
        }

        println!("\n✓ mint-broadcast phase complete");
        println!("  contract_tx txid: {contract_txid}");
        println!("  issue_tx txid:    {issue_txid}");
        println!("  STAS-3 token registered in basket {token_basket:?}");
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: topup
    // -------------------------------------------------------------------
    if phase != "topup" {
        return Err(format!(
            "unknown SMOKE_PHASE={phase} \
             (expected: connect | topup | pickfuel | mint | mint-broadcast)"
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
