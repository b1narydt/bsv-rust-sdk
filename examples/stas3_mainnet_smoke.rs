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
//! - `transfer`     — Full on-chain transfer flow. Requires a STAS-3 token
//!                     to already exist in `stas3tokens` (run mint-broadcast
//!                     first). Picks the first token UTXO, derives a new
//!                     owner key (`stas3owner/dest2` by default; override
//!                     via `SMOKE_TRANSFER_DEST_KEYID`), builds + signs a
//!                     transfer tx via `transfer_with_fuel_pick`,
//!                     engine-verifies the STAS input, then — when
//!                     `SMOKE_BROADCAST=1` — broadcasts via ARC, builds
//!                     atomic BEEF, and internalizes the new token UTXO.
//! - `redeem`        — Full on-chain redeem flow. Requires a STAS-3 token
//!                     in `stas3tokens` whose `owner_pkh == redemption_pkh`
//!                     (i.e. the token has been transferred back to the
//!                     issuer). Builds + signs a redeem tx via
//!                     `Stas3Wallet::redeem`, engine-verifies the STAS
//!                     input, then — when `SMOKE_BROADCAST=1` — broadcasts
//!                     via ARC. The output is a 70-byte P2MPKH (NOT a
//!                     STAS-3 lock) so no `internalize_stas_outputs` step
//!                     is needed.
//! - `split`         — Full on-chain split flow. Requires a STAS-3 token
//!                     with `satoshis >= 2`. Splits into two halves
//!                     (`stas3owner/split-a` and `stas3owner/split-b`),
//!                     broadcasts, and internalizes BOTH new STAS outputs.
//! - `freeze`        — Full on-chain freeze flow. Requires a STAS-3 token
//!                     whose flags has FREEZABLE set. Derives the freeze
//!                     authority triple (`stas3freezeauth/main`) used at
//!                     mint, signs the freeze tx, broadcasts, and
//!                     internalizes the new (Frozen) STAS output.
//! - `unfreeze`      — Full on-chain unfreeze flow. Requires a STAS-3
//!                     token whose `current_action_data` is
//!                     `ActionData::Frozen(...)`. Same flow as freeze but
//!                     the resulting output is back in the Passive state.
//! - `confiscate`    — Full on-chain confiscate flow. Requires a STAS-3
//!                     token whose flags has CONFISCATABLE set AND whose
//!                     `current_action_data == Frozen` (per spec §5.3
//!                     confiscation seizes a frozen UTXO). Derives the
//!                     confiscation authority triple
//!                     (`stas3confiscauth/main`) used at mint, signs the
//!                     confiscate tx, broadcasts, and internalizes the
//!                     new STAS output owned by `stas3owner/confisc-dest`.
//!                     Set up via:
//!                     `SMOKE_MINT_FLAGS=3 SMOKE_PHASE=mint-broadcast`
//!                     then `SMOKE_PHASE=freeze` first.
//! - `merge`         — Full on-chain 2-input merge flow. Requires 2+
//!                     STAS-3 tokens of the SAME TYPE (same
//!                     redemption_pkh + flags + service_fields +
//!                     optional_data) in the token basket. Picks the
//!                     first two of matching type, hydrates each input's
//!                     `source_tx_bytes` from the token-basket BEEF
//!                     (required by the merge factory per spec §9.5),
//!                     calls `Stas3Wallet::merge` with destination
//!                     `stas3owner/merge-dest`, broadcasts, and
//!                     internalizes the merged STAS output. To set up:
//!                     mint twice with the same `SMOKE_MINT_ISSUER_KEYID`
//!                     so both tokens share a redemption_pkh.
//!
//! # Configuration (env vars)
//!
//! - `WALLET_URL`         — BRC-100 wallet JSON endpoint (default `http://localhost:3321`)
//! - `ORIGINATOR`         — originator string passed to the wallet (default `stas3-smoke`)
//! - `SMOKE_PHASE`        — `connect` (default) | `topup` | `pickfuel` | `mint` | `mint-broadcast` | `transfer` | `redeem` | `split` | `freeze` | `unfreeze` | `confiscate` | `merge`
//! - `SMOKE_BROADCAST`    — `1` to actually broadcast; anything else (default) is dry-run
//! - `SMOKE_FUEL_SATS`    — satoshis per fuel UTXO (default `2000`)
//! - `SMOKE_FUEL_COUNT`   — how many fuel UTXOs to provision (default `2`)
//! - `SMOKE_FUEL_BASKET`  — basket name override (default uses Stas3Wallet's default)
//! - `SMOKE_ARC_URL`      — ARC endpoint used by `mint-broadcast`
//!                          (default `https://api.gorillapool.io/v1/tx`)
//! - `SMOKE_ARC_API_KEY`  — optional API key for the ARC endpoint (default: none)
//! - `SMOKE_TRANSFER_DEST_KEYID` — keyID of the transfer destination owner (default `dest2`)
//! - `SMOKE_MINT_SATS`    — satoshis per minted STAS token output (default `1`).
//!                          Set higher (e.g. `5`) when you intend to follow
//!                          mint-broadcast with the `split` phase.
//! - `SMOKE_MINT_FLAGS`   — STAS-3 flags byte for the mint (default `0`).
//!                          `1` = FREEZABLE, `2` = CONFISCATABLE, `3` = both.
//!                          When FREEZABLE is set the freeze authority pkh
//!                          is derived from `stas3freezeauth/main`; when
//!                          CONFISCATABLE is set the confiscation authority
//!                          pkh is derived from `stas3confiscauth/main`.
//! - `SMOKE_MINT_TO_ISSUER` — `1` to set the mint destination
//!                          `owner_pkh = issuer_pkh` (instead of the
//!                          default `stas3owner/dest1` derivation). The
//!                          resulting token has
//!                          `owner_pkh == redemption_pkh`, which is the
//!                          precondition for the `redeem` phase. Default
//!                          `0`.
//! - `SMOKE_MINT_ISSUER_KEYID` — overrides the issuer Type-42 keyID used
//!                          at mint (default: a fresh `smoke-{millis}`
//!                          per run). Set this to a stable string and run
//!                          `mint-broadcast` twice to produce two tokens
//!                          that share a redemption_pkh — required for
//!                          the `merge` phase (which needs two tokens of
//!                          the SAME TYPE).
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
use bsv::script::templates::stas3::action_data::ActionData;
use bsv::script::templates::stas3::eac::{EacFields, EnergySource};
use bsv::script::templates::stas3::factory::{SigningKey, SplitDestination};
use bsv::script::templates::stas3::{
    decode_locking_script, flags as stas3_flags, verify_input, Brc43KeyArgs, Stas3Wallet,
    Stas3WalletConfig,
};
use bsv::transaction::beef::{Beef, BEEF_V1, BEEF_V2};
use bsv::transaction::beef_tx::BeefTx;
use bsv::transaction::transaction::Transaction;
use bsv::wallet::interfaces::{
    GetPublicKeyArgs, ListOutputsArgs, Output, OutputInclude, WalletInterface,
};
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use bsv::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

const DEFAULT_WALLET_URL: &str = "http://localhost:3321";
const DEFAULT_ORIGINATOR: &str = "stas3-smoke";
const DEFAULT_FUEL_SATS: u64 = 2_000;
const DEFAULT_FUEL_COUNT: usize = 2;
// NOTE: the ARC broadcaster auto-appends "/v1/tx" to this URL — pass the
// base host only.
const DEFAULT_ARC_URL: &str = "https://arc.gorillapool.io";
const DEFAULT_TRANSFER_DEST_KEYID: &str = "dest2";
const DEFAULT_MINT_SATS: u64 = 1;
const DEFAULT_MINT_FLAGS: u8 = 0;
/// Type-42 keyID used by every freeze-authority derivation in this smoke
/// — both at mint time (when FREEZABLE is set) and at freeze/unfreeze
/// time (when looking up the authority that signs the freeze).
const FREEZE_AUTH_KEY_ID: &str = "main";
/// Same idea as [`FREEZE_AUTH_KEY_ID`] but for the confiscation authority
/// (only used when CONFISCATABLE is set on the mint).
const CONFISC_AUTH_KEY_ID: &str = "main";

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
    let transfer_dest_keyid = env::var("SMOKE_TRANSFER_DEST_KEYID")
        .unwrap_or_else(|_| DEFAULT_TRANSFER_DEST_KEYID.into());
    let mint_sats = env::var("SMOKE_MINT_SATS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MINT_SATS);
    let mint_flags = env::var("SMOKE_MINT_FLAGS")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(DEFAULT_MINT_FLAGS);
    let mint_to_issuer = env::var("SMOKE_MINT_TO_ISSUER")
        .map(|v| v == "1")
        .unwrap_or(false);
    // When set, this string overrides the issuer Type-42 keyID. Required
    // for `merge` (two tokens must share a redemption_pkh, which means
    // sharing an issuer key, which means sharing the keyID). When unset,
    // the existing per-call `smoke-{millis}` derivation is used.
    let mint_issuer_keyid_override = env::var("SMOKE_MINT_ISSUER_KEYID").ok();

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
        let issuer_keyid = mint_issuer_keyid_override
            .clone()
            .unwrap_or_else(|| format!("smoke-{now_ms}"));
        let issuer_triple = Brc43KeyArgs::self_under("stas3issuer", issuer_keyid.as_str());
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

        // SMOKE_MINT_TO_ISSUER=1 → produce a token where
        // `owner_pkh == redemption_pkh` (precondition for the redeem
        // phase). Otherwise derive the standard `stas3owner/dest1`.
        println!("[6/?] Deriving destination key (mint_to_issuer={mint_to_issuer})...");
        let (dest_triple, dest_pkh) = if mint_to_issuer {
            // Use the issuer triple itself for ownership; pkh already computed.
            (issuer_triple.clone(), issuer_pkh)
        } else {
            let dt = Brc43KeyArgs::self_under("stas3owner", "dest1");
            let dpk = wallet
                .get_public_key(
                    GetPublicKeyArgs {
                        identity_key: false,
                        protocol_id: Some(dt.protocol_id.clone()),
                        key_id: Some(dt.key_id.clone()),
                        counterparty: Some(dt.counterparty.clone()),
                        privileged: false,
                        privileged_reason: None,
                        for_self: Some(true),
                        seek_permission: None,
                    },
                    Some(&originator),
                )
                .await?;
            (dt, hash160(&dpk.public_key.to_der()))
        };
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

        println!(
            "[7b/?] Resolving mint authorities (flags=0x{:02x}, sats={mint_sats})...",
            mint_flags
        );
        let (freeze_auth_pkh, confisc_auth_pkh) =
            resolve_mint_authorities(&*wallet, &originator, mint_flags).await?;
        if let Some(pkh) = freeze_auth_pkh {
            println!("       freeze_auth pkh:     {}", hex::encode(pkh));
        }
        if let Some(pkh) = confisc_auth_pkh {
            println!("       confiscate_auth pkh: {}", hex::encode(pkh));
        }

        println!("[8/?] Calling mint_eac (dry-run — builds + signs, no broadcast)...");
        let result = stas
            .mint_eac(
                Some(&originator),
                SigningKey::P2pkh(issuer_triple),
                funding.clone(),
                mint_flags,
                freeze_auth_pkh,
                confisc_auth_pkh,
                vec![(dest_pkh, mint_sats, eac)],
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
        let issuer_keyid = mint_issuer_keyid_override
            .clone()
            .unwrap_or_else(|| format!("smoke-{now_ms}"));
        let issuer_triple = Brc43KeyArgs::self_under("stas3issuer", issuer_keyid.as_str());
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

        // SMOKE_MINT_TO_ISSUER=1 → produce a token where
        // `owner_pkh == redemption_pkh` (precondition for the redeem
        // phase). Otherwise derive the standard `stas3owner/dest1`.
        println!("[6/?] Deriving destination key (mint_to_issuer={mint_to_issuer})...");
        let (dest_triple, dest_pkh) = if mint_to_issuer {
            (issuer_triple.clone(), issuer_pkh)
        } else {
            let dt = Brc43KeyArgs::self_under("stas3owner", "dest1");
            let dpk = wallet
                .get_public_key(
                    GetPublicKeyArgs {
                        identity_key: false,
                        protocol_id: Some(dt.protocol_id.clone()),
                        key_id: Some(dt.key_id.clone()),
                        counterparty: Some(dt.counterparty.clone()),
                        privileged: false,
                        privileged_reason: None,
                        for_self: Some(true),
                        seek_permission: None,
                    },
                    Some(&originator),
                )
                .await?;
            (dt, hash160(&dpk.public_key.to_der()))
        };
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

        println!(
            "[7b/?] Resolving mint authorities (flags=0x{:02x}, sats={mint_sats})...",
            mint_flags
        );
        let (freeze_auth_pkh, confisc_auth_pkh) =
            resolve_mint_authorities(&*wallet, &originator, mint_flags).await?;
        if let Some(pkh) = freeze_auth_pkh {
            println!("       freeze_auth pkh:     {}", hex::encode(pkh));
        }
        if let Some(pkh) = confisc_auth_pkh {
            println!("       confiscate_auth pkh: {}", hex::encode(pkh));
        }

        println!("[8/?] Calling mint_eac (builds + signs txs)...");
        let result = stas
            .mint_eac(
                Some(&originator),
                SigningKey::P2pkh(issuer_triple),
                funding.clone(),
                mint_flags,
                freeze_auth_pkh,
                confisc_auth_pkh,
                vec![(dest_pkh, mint_sats, eac)],
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

        // --- Fetch fuel source tx FIRST (needed for both EF broadcast + BEEF) ---
        // ARC requires Extended Format (EF) hex — that requires every input to
        // carry its source-output data. The factory leaves source_transaction
        // unpopulated, so we hydrate it here from the wallet's BEEF.
        println!("[10/?] Fetching fuel source tx (needed for EF broadcast + BEEF)...");
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

        // Parse the wallet's BEEF and extract the fuel source tx so we can
        // attach it to the contract_tx's funding input. Without this the
        // factory leaves source_transaction = None, and to_hex_ef() (used by
        // ARC.broadcast under the hood) fails with "missing source transaction".
        let mut fuel_beef_cursor = std::io::Cursor::new(&fuel_beef_bytes);
        let parsed_fuel_beef = Beef::from_binary(&mut fuel_beef_cursor)
            .map_err(|e| format!("parse wallet fuel BEEF: {e}"))?;
        let fuel_source_tx = parsed_fuel_beef
            .find_txid(&funding.txid_hex)
            .and_then(|btx| btx.tx.clone())
            .ok_or_else(|| {
                format!(
                    "fuel source txid {} not found in wallet BEEF \
                     (BEEF has {} txs: {:?})",
                    funding.txid_hex,
                    parsed_fuel_beef.txs.len(),
                    parsed_fuel_beef.txs.iter().map(|t| &t.txid).collect::<Vec<_>>()
                )
            })?;
        println!("       fuel source tx parsed (txid={})", funding.txid_hex);

        // Hydrate contract_tx input 0 with the fuel source tx so EF serialization works.
        let mut contract_tx = result.contract_tx.clone();
        contract_tx.inputs[0].source_transaction = Some(Box::new(fuel_source_tx));

        // --- Live broadcast path ---
        // NOTE: bypassing the SDK's ARC broadcaster here. It sends EF hex with
        // Content-Type: application/octet-stream which ARC rejects (octet-stream
        // expects raw binary, not hex). We POST hex with Content-Type: text/plain
        // which ARC accepts. SDK fix is a separate PR.
        println!("[11/?] Broadcasting via ARC ({arc_url})...");

        println!("       Broadcasting contract_tx ({contract_txid})...");
        let contract_resp_txid =
            arc_broadcast(&arc_url, arc_api_key.as_deref(), &contract_tx).await?;
        println!("       contract_tx broadcast OK: txid={contract_resp_txid}");

        // Hydrate issue_tx's two inputs with the just-broadcast contract_tx so
        // EF serialization works. Inputs 0 and 1 both spend contract_tx outputs.
        let mut issue_tx = result.issue_tx.clone();
        issue_tx.inputs[0].source_transaction = Some(Box::new(contract_tx.clone()));
        issue_tx.inputs[1].source_transaction = Some(Box::new(contract_tx.clone()));

        println!("       Broadcasting issue_tx ({issue_txid})...");
        let issue_resp_txid =
            arc_broadcast(&arc_url, arc_api_key.as_deref(), &issue_tx).await?;
        println!("       issue_tx broadcast OK: txid={issue_resp_txid}");

        // --- Build atomic BEEF for internalize_action ---
        println!("[12/?] Constructing atomic BEEF for issue_tx internalization...");
        let mut beef = Beef::new(BEEF_V1);
        beef.merge_beef_from_binary(&fuel_beef_bytes)
            .map_err(|e| format!("merge wallet BEEF: {e}"))?;

        // Add contract_tx (no bump — just broadcast, not yet mined).
        let contract_tx_bytes = contract_tx
            .to_bytes()
            .map_err(|e| format!("serialize contract_tx: {e}"))?;
        beef.merge_raw_tx(&contract_tx_bytes, None)
            .map_err(|e| format!("merge contract_tx into BEEF: {e}"))?;

        // Add issue_tx (no bump — just broadcast, not yet mined).
        let issue_tx_bytes = issue_tx
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
    // Phase: transfer
    // -------------------------------------------------------------------
    if phase == "transfer" {
        let token_basket = stas.config().token_basket.clone();

        println!("\n[4/?] Listing token basket {token_basket:?}...");
        let token_outputs = list_basket(&*wallet, &token_basket, &originator).await?;
        if token_outputs.is_empty() {
            return Err(format!(
                "transfer phase requires a STAS-3 token in basket {token_basket:?}; \
                 run SMOKE_PHASE=mint-broadcast first"
            )
            .into());
        }
        println!(
            "       basket {token_basket:?}: {} token UTXO(s)",
            token_outputs.len()
        );

        // Pick the first token UTXO.
        let token_output: &Output = &token_outputs[0];
        let token_outpoint = &token_output.outpoint;
        println!("       using outpoint: {token_outpoint}");
        println!("       satoshis:       {}", token_output.satoshis);

        // Decode the locking script so we can show the fields.
        let locking_bytes = token_output
            .locking_script
            .as_ref()
            .ok_or("token UTXO missing locking_script")?;
        let locking_script =
            bsv::script::locking_script::LockingScript::from_binary(locking_bytes);
        let decoded_token = decode_locking_script(&locking_script)
            .map_err(|e| format!("decode token locking_script: {e:?}"))?;
        println!(
            "       owner_pkh:      {}",
            hex::encode(decoded_token.owner_pkh)
        );
        println!(
            "       redemption_pkh: {}",
            hex::encode(decoded_token.redemption_pkh)
        );
        println!("       flags:          0x{:02x}", decoded_token.flags);
        println!(
            "       optional_data:  {} elements",
            decoded_token.optional_data.len()
        );

        // Resolve the full TokenInput (derives signing_key from customInstructions).
        println!("[5/?] Resolving TokenInput via find_token({token_outpoint:?})...");
        let token_input = stas.find_token(token_outpoint).await?;
        println!(
            "       TokenInput: txid={}.{} sats={} lock_len={}",
            token_input.txid_hex,
            token_input.vout,
            token_input.satoshis,
            token_input.locking_script.to_binary().len()
        );
        println!(
            "       Output:     {} sats={} lock_len={}",
            token_outpoint,
            token_output.satoshis,
            locking_script.to_binary().len()
        );
        if let bsv::script::templates::stas3::factory::SigningKey::P2pkh(ref tr) =
            token_input.signing_key
        {
            println!(
                "       resolved signing key: protocol={:?} keyID={:?} counterparty={:?}",
                tr.protocol_id.protocol, tr.key_id, tr.counterparty.counterparty_type
            );
        }

        // Derive the destination owner key for the transfer.
        println!("[6/?] Deriving transfer destination key (keyID={transfer_dest_keyid:?})...");
        let dest_triple = Brc43KeyArgs::self_under("stas3owner", transfer_dest_keyid.as_str());
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
        println!(
            "       dest triple:    protocol={:?} keyID={:?}",
            dest_triple.protocol_id.protocol, dest_triple.key_id
        );
        println!("       dest pkh:       {}", hex::encode(dest_pkh));

        // Derive a change PKH using the wallet identity key. This PKH receives
        // the fuel change (satoshis from the fuel UTXO minus tx fee); it has
        // nothing to do with the STAS token satoshis.
        println!("[7/?] Deriving change PKH from identity key...");
        let change_pkh = hash160(&id.public_key.to_der());
        println!("       change pkh:     {}", hex::encode(change_pkh));

        // The change_satoshis parameter controls how many satoshis go back to
        // change_pkh from the fuel UTXO. fee = funding - token_sats - change.
        // Transfer tx with 11 EAC optional_data elements is ~3.4kB; at
        // 0.2 sat/byte ARC expects ~700 sat fee. With a 2000-sat fuel UTXO,
        // change=1200 leaves ~800 sats fee budget (the STAS output keeps its 1
        // sat regardless).
        let change_satoshis: u64 = 1_200;

        // Pick fuel manually (instead of transfer_with_fuel_pick) so we keep
        // the funding triple — needed below to sign the fuel input before
        // broadcast (the factory leaves funding inputs unsigned by convention).
        println!("[8/?] Picking fuel UTXO for transfer...");
        let funding = stas.pick_fuel(change_satoshis.saturating_add(200)).await?;
        println!(
            "       picked fuel: {}.{} ({} sats)",
            funding.txid_hex, funding.vout, funding.satoshis
        );

        println!(
            "[8b/?] Calling transfer (dest_pkh={}, change_sats={change_satoshis})...",
            hex::encode(dest_pkh)
        );
        let transfer_tx = stas
            .transfer(
                token_input,
                funding.clone(),
                dest_pkh,
                change_pkh,
                change_satoshis,
                Some(b"stas3 smoke transfer".to_vec()),
            )
            .await?;

        let transfer_txid = transfer_tx
            .id()
            .map_err(|e| format!("transfer tx id: {e}"))?;
        let transfer_hex = transfer_tx
            .to_bytes()
            .map_err(|e| format!("transfer tx bytes: {e}"))?;

        println!("       transfer_tx txid: {transfer_txid}");
        println!("       transfer_tx size: {} bytes", transfer_hex.len());

        // Engine-verify the STAS input (input 0) before broadcast.
        println!("[9/?] Engine-verifying transfer_tx STAS input (index 0)...");
        let valid = verify_input(&transfer_tx, 0, &locking_script, token_output.satoshis)
            .map_err(|e| format!("transfer tx STAS input verify: {e:?}"))?;
        if !valid {
            return Err("transfer tx STAS input (index 0) failed engine verify".into());
        }
        println!("       ✓ STAS input engine-verified OK");

        // Dry-run exit — print hex and quit without broadcasting.
        if !broadcast {
            println!(
                "\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)"
            );
            println!("  txid: {transfer_txid}");
            println!("  hex:  {}", hex::encode(&transfer_hex));
            println!("\n✓ transfer dry-run complete");
            return Ok(());
        }

        // Hydrate transfer_tx inputs with their source transactions BEFORE
        // broadcast — ARC requires Extended Format (EF) hex which embeds each
        // input's source-output data. Both baskets contribute: token basket
        // for the STAS input, fuel basket for the funding input.
        println!("[10/?] Fetching source txs from token + fuel baskets...");
        let token_list_with_txs = wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: token_basket.clone(),
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
            .await?;
        let fuel_list_with_txs = wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: stas.config().fuel_basket.clone(),
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
            .await?;

        // Merge both BEEFs into a lookup so we can resolve each input's source tx.
        let mut lookup_beef = Beef::new(BEEF_V2);
        if let Some(ref b) = token_list_with_txs.beef {
            lookup_beef
                .merge_beef_from_binary(b)
                .map_err(|e| format!("merge token BEEF: {e}"))?;
        }
        if let Some(ref b) = fuel_list_with_txs.beef {
            lookup_beef
                .merge_beef_from_binary(b)
                .map_err(|e| format!("merge fuel BEEF: {e}"))?;
        }

        // Hydrate every input on transfer_tx.
        let mut transfer_tx = transfer_tx;
        for (i, input) in transfer_tx.inputs.iter_mut().enumerate() {
            let src_txid = input
                .source_txid
                .as_ref()
                .ok_or_else(|| format!("transfer_tx input {i} missing source_txid"))?
                .clone();
            let src_tx = lookup_beef
                .find_txid(&src_txid)
                .and_then(|btx| btx.tx.clone())
                .ok_or_else(|| {
                    format!(
                        "source tx {src_txid} for transfer_tx input {i} not found in \
                         wallet BEEFs (token+fuel)"
                    )
                })?;
            input.source_transaction = Some(Box::new(src_tx));
        }

        // Sign the fuel input (input 1) — the transfer factory only signs the
        // STAS input. Without this, ARC rejects with "inputs must have an
        // unlocking script."
        println!("[10b/?] Signing fuel input (P2PKH) before broadcast...");
        sign_p2pkh_input_in_smoke(
            &*wallet,
            &originator,
            &mut transfer_tx,
            1,
            funding.satoshis,
            &funding.locking_script,
            &funding.triple,
        )
        .await?;
        println!("       fuel input signed");

        println!("[11/?] Broadcasting transfer_tx via ARC ({arc_url})...");
        let bcast_txid =
            arc_broadcast(&arc_url, arc_api_key.as_deref(), &transfer_tx).await?;
        println!("       transfer_tx broadcast OK: txid={bcast_txid}");

        // Build atomic BEEF for internalize_action.
        println!("[12/?] Building atomic BEEF for internalize_action...");

        // Recompute the txid AFTER signing the fuel input — signing changes
        // the unlocking script, which changes the tx bytes, which changes
        // the txid. The pre-broadcast `transfer_txid` (cached before signing)
        // is stale; the ARC response txid (`bcast_txid`) is the real one.
        let final_txid = transfer_tx
            .id()
            .map_err(|e| format!("recompute transfer txid post-sign: {e}"))?;
        debug_assert_eq!(
            final_txid, bcast_txid,
            "computed txid != ARC-returned txid"
        );

        // Reuse lookup_beef (already has both baskets' source txs) and add
        // the transfer tx itself, then produce atomic BEEF.
        let mut beef = lookup_beef;
        let beef_tx = BeefTx::from_tx(transfer_tx.clone(), None)
            .map_err(|e| format!("BeefTx::from_tx: {e}"))?;
        beef.txs.push(beef_tx);
        beef.sort_txs();

        let atomic_beef_bytes = beef
            .to_binary_atomic(&final_txid)
            .map_err(|e| format!("to_binary_atomic: {e}"))?;
        println!(
            "       atomic BEEF size: {} bytes",
            atomic_beef_bytes.len()
        );

        // Internalize the new STAS-3 output (index 0 of the transfer tx).
        println!("[12/?] Internalizing new STAS-3 output (index 0) into {token_basket:?}...");
        stas.internalize_stas_outputs(
            atomic_beef_bytes,
            vec![(0u32, dest_triple.clone(), None)],
            "stas3 smoke transfer",
        )
        .await
        .map_err(|e| format!("internalize_stas_outputs: {e:?}"))?;
        println!("       internalize_action OK");

        // Verification: re-list and confirm the new outpoint appears with the
        // correct owner_pkh.
        println!("[13/?] Re-listing token basket to verify new UTXO...");
        let after = list_basket(&*wallet, &token_basket, &originator).await?;
        println!(
            "       before: {} UTXO(s)  after: {} UTXO(s)",
            token_outputs.len(),
            after.len()
        );

        // Find the new outpoint (txid matches transfer_txid, vout 0).
        let expected_outpoint = format!("{final_txid}.0");
        let new_output = after.iter().find(|o| o.outpoint == expected_outpoint);
        match new_output {
            Some(out) => {
                let new_lock_bytes = out
                    .locking_script
                    .as_ref()
                    .ok_or("new token UTXO missing locking_script")?;
                let new_lock =
                    bsv::script::locking_script::LockingScript::from_binary(new_lock_bytes);
                let new_decoded = decode_locking_script(&new_lock)
                    .map_err(|e| format!("decode new token lock: {e:?}"))?;
                if new_decoded.owner_pkh != dest_pkh {
                    return Err(format!(
                        "new token owner_pkh mismatch: got {} expected {}",
                        hex::encode(new_decoded.owner_pkh),
                        hex::encode(dest_pkh)
                    )
                    .into());
                }
                println!(
                    "       ✓ new outpoint {expected_outpoint} owner_pkh={} (matches dest)",
                    hex::encode(new_decoded.owner_pkh)
                );
            }
            None => {
                // The wallet may not reflect the new UTXO immediately (eventual
                // consistency). Print a warning rather than hard-failing so the
                // smoke test doesn't give a false negative.
                println!(
                    "       WARNING: outpoint {expected_outpoint} not yet visible in basket \
                     (wallet may be indexing) — check again in a few seconds"
                );
            }
        }

        println!(
            "\n✓ transfer phase complete — STAS-3 token transferred to new owner on-chain"
        );
        println!("  txid: {transfer_txid}");
        return Ok(());
    }
    // -------------------------------------------------------------------
    // Phase: redeem
    // -------------------------------------------------------------------
    if phase == "redeem" {
        run_redeem_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: split
    // -------------------------------------------------------------------
    if phase == "split" {
        run_split_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: freeze
    // -------------------------------------------------------------------
    if phase == "freeze" {
        run_freeze_or_unfreeze_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
            FreezeOp::Freeze,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: unfreeze
    // -------------------------------------------------------------------
    if phase == "unfreeze" {
        run_freeze_or_unfreeze_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
            FreezeOp::Unfreeze,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: confiscate
    // -------------------------------------------------------------------
    if phase == "confiscate" {
        run_confiscate_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: merge
    // -------------------------------------------------------------------
    if phase == "merge" {
        run_merge_phase(
            &*wallet,
            &stas,
            &originator,
            &id.public_key.to_der(),
            &arc_url,
            arc_api_key.as_deref(),
            broadcast,
        )
        .await?;
        return Ok(());
    }

    // -------------------------------------------------------------------
    // Phase: topup
    // -------------------------------------------------------------------
    if phase != "topup" {
        return Err(format!(
            "unknown SMOKE_PHASE={phase} \
             (expected: connect | topup | pickfuel | mint | mint-broadcast | transfer | redeem | split | freeze | unfreeze | confiscate | merge)"
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

/// Sign a P2PKH input on `tx` using the wallet's `create_signature` against
/// the BIP-143 preimage hash, then install the resulting `<sig+sighash>
/// <pubkey>` unlocking script. Mirrors `factory::issue::sign_p2pkh_input`
/// (which is module-private). Used by the smoke test to sign the fuel
/// input on a transfer tx before broadcast — the transfer factory leaves
/// funding inputs unsigned by convention.
async fn sign_p2pkh_input_in_smoke(
    wallet: &dyn WalletInterface,
    originator: &str,
    tx: &mut Transaction,
    input_index: usize,
    source_satoshis: u64,
    prev_locking_script: &bsv::script::locking_script::LockingScript,
    triple: &Brc43KeyArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    use bsv::primitives::hash::hash256;
    use bsv::script::templates::stas3::build_preimage;
    use bsv::script::unlocking_script::UnlockingScript;
    use bsv::wallet::interfaces::CreateSignatureArgs;

    let preimage = build_preimage(tx, input_index, source_satoshis, prev_locking_script)
        .map_err(|e| format!("build_preimage input {input_index}: {e:?}"))?;
    let preimage_hash = hash256(&preimage).to_vec();

    let sig_result = wallet
        .create_signature(
            CreateSignatureArgs {
                protocol_id: triple.protocol_id.clone(),
                key_id: triple.key_id.clone(),
                counterparty: triple.counterparty.clone(),
                data: None,
                hash_to_directly_sign: Some(preimage_hash),
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            Some(originator),
        )
        .await
        .map_err(|e| format!("create_signature for input {input_index}: {e}"))?;
    let mut sig = sig_result.signature;
    sig.push(0x41); // SIGHASH_ALL | SIGHASH_FORKID

    let pk = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(triple.protocol_id.clone()),
                key_id: Some(triple.key_id.clone()),
                counterparty: Some(triple.counterparty.clone()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
            Some(originator),
        )
        .await
        .map_err(|e| format!("get_public_key for input {input_index}: {e}"))?;
    let pubkey_der = pk.public_key.to_der();

    // P2PKH unlock = <sig+sighash> <pubkey>
    let mut unlock = Vec::with_capacity(1 + sig.len() + 1 + pubkey_der.len());
    push_data_minimal_smoke(&mut unlock, &sig);
    push_data_minimal_smoke(&mut unlock, &pubkey_der);

    tx.inputs[input_index].unlocking_script = Some(UnlockingScript::from_binary(&unlock));
    Ok(())
}

/// Minimal Bitcoin push encoder for `data` (length up to 65535). Used by
/// `sign_p2pkh_input_in_smoke` since the SDK's `push_data_minimal` is
/// crate-private to `templates::stas3::lock`.
fn push_data_minimal_smoke(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n == 0 {
        out.push(0x00); // OP_0
    } else if n <= 75 {
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 255 {
        out.push(0x4c); // OP_PUSHDATA1
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 65535 {
        out.push(0x4d); // OP_PUSHDATA2
        out.push((n & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.extend_from_slice(data);
    } else {
        panic!("push too large for smoke helper: {n} bytes");
    }
}

/// POST a transaction to ARC `/v1/tx` as Extended Format hex with
/// `Content-Type: text/plain` (which ARC accepts; `application/octet-stream`
/// is reserved for raw binary and rejects hex input). Returns the broadcast
/// txid on success.
async fn arc_broadcast(
    arc_url: &str,
    arc_api_key: Option<&str>,
    tx: &Transaction,
) -> Result<String, Box<dyn std::error::Error>> {
    let ef_hex = tx
        .to_hex_ef()
        .map_err(|e| format!("to_hex_ef: {e}"))?;
    let url = format!("{}/v1/tx", arc_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let mut req = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(ef_hex);
    if let Some(key) = arc_api_key {
        req = req.header("X-Api-Key", key);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("ARC POST {url}: network error {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "ARC rejected tx: status={} body={}",
            status.as_u16(),
            body
        )
        .into());
    }
    // ARC returns JSON like {"txid":"...","status":200,...}
    let parsed: serde_json::Value =
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let txid = parsed
        .get("txid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if txid.is_empty() {
        return Err(format!("ARC accepted but no txid in response: body={body}").into());
    }
    Ok(txid)
}

// ---------------------------------------------------------------------------
// Mint authority resolution + new STAS-input phases (redeem / split /
// freeze / unfreeze) — all share a common pattern: pick a token from the
// token basket, pick a fuel UTXO, build the operation tx via the wallet
// wrapper, engine-verify the STAS input, hydrate every input's
// source_transaction from the merged token+fuel BEEF, sign the fuel
// input, ARC-broadcast, build atomic BEEF, internalize any new STAS
// outputs.
// ---------------------------------------------------------------------------

/// Derive the (HASH160 of) public key for a given Type-42 triple via the
/// wallet's `get_public_key`.
async fn derive_pkh_for_triple(
    wallet: &dyn WalletInterface,
    originator: &str,
    triple: &Brc43KeyArgs,
) -> Result<[u8; 20], Box<dyn std::error::Error>> {
    let pk = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(triple.protocol_id.clone()),
                key_id: Some(triple.key_id.clone()),
                counterparty: Some(triple.counterparty.clone()),
                privileged: false,
                privileged_reason: None,
                for_self: Some(true),
                seek_permission: None,
            },
            Some(originator),
        )
        .await
        .map_err(|e| format!("get_public_key({:?}): {e}", triple.key_id))?;
    Ok(hash160(&pk.public_key.to_der()))
}

/// Given the configured `mint_flags`, resolve the freeze-authority and
/// confiscation-authority pubkey hashes to feed into `mint_eac`. Returns
/// `(None, None)` when both bits are clear. The freeze authority triple
/// is `stas3freezeauth/main`; the confiscation authority triple is
/// `stas3confiscauth/main`. Both are stable across smoke runs so the
/// later `freeze` / `unfreeze` phases can re-derive the same authority.
async fn resolve_mint_authorities(
    wallet: &dyn WalletInterface,
    originator: &str,
    flags: u8,
) -> Result<(Option<[u8; 20]>, Option<[u8; 20]>), Box<dyn std::error::Error>> {
    let freeze_pkh = if stas3_flags::is_freezable(flags) {
        let triple = Brc43KeyArgs::self_under("stas3freezeauth", FREEZE_AUTH_KEY_ID);
        Some(derive_pkh_for_triple(wallet, originator, &triple).await?)
    } else {
        None
    };
    let confisc_pkh = if stas3_flags::is_confiscatable(flags) {
        let triple = Brc43KeyArgs::self_under("stas3confiscauth", CONFISC_AUTH_KEY_ID);
        Some(derive_pkh_for_triple(wallet, originator, &triple).await?)
    } else {
        None
    };
    Ok((freeze_pkh, confisc_pkh))
}

/// Decode the STAS-3 lock on a basket `Output`. Wraps the boilerplate of
/// "pull `locking_script` bytes, build a `LockingScript`, decode it."
fn decode_token_output(
    output: &Output,
) -> Result<
    (
        bsv::script::locking_script::LockingScript,
        bsv::script::templates::stas3::DecodedLock,
    ),
    Box<dyn std::error::Error>,
> {
    let locking_bytes = output
        .locking_script
        .as_ref()
        .ok_or("token UTXO missing locking_script")?;
    let locking_script = bsv::script::locking_script::LockingScript::from_binary(locking_bytes);
    let decoded = decode_locking_script(&locking_script)
        .map_err(|e| format!("decode token locking_script: {e:?}"))?;
    Ok((locking_script, decoded))
}

/// Fetch the token basket + fuel basket with `EntireTransactions` and
/// merge their BEEFs into one lookup `Beef` we can resolve every input's
/// `source_transaction` from. Mirrors what the `transfer` phase does
/// inline.
async fn build_token_and_fuel_lookup_beef(
    wallet: &dyn WalletInterface,
    originator: &str,
    token_basket: &str,
    fuel_basket: &str,
) -> Result<Beef, Box<dyn std::error::Error>> {
    let token_list = wallet
        .list_outputs(
            ListOutputsArgs {
                basket: token_basket.to_string(),
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
            Some(originator),
        )
        .await?;
    let fuel_list = wallet
        .list_outputs(
            ListOutputsArgs {
                basket: fuel_basket.to_string(),
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
            Some(originator),
        )
        .await?;

    let mut lookup = Beef::new(BEEF_V2);
    if let Some(ref b) = token_list.beef {
        lookup
            .merge_beef_from_binary(b)
            .map_err(|e| format!("merge token BEEF: {e}"))?;
    }
    if let Some(ref b) = fuel_list.beef {
        lookup
            .merge_beef_from_binary(b)
            .map_err(|e| format!("merge fuel BEEF: {e}"))?;
    }
    Ok(lookup)
}

/// Walk every input on `tx` and hydrate `source_transaction` from the
/// merged lookup BEEF. Errors if any input's source txid is absent from
/// the lookup.
fn hydrate_inputs_from_lookup(
    tx: &mut Transaction,
    lookup: &Beef,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, input) in tx.inputs.iter_mut().enumerate() {
        let src_txid = input
            .source_txid
            .as_ref()
            .ok_or_else(|| format!("tx input {i} missing source_txid"))?
            .clone();
        let src_tx = lookup
            .find_txid(&src_txid)
            .and_then(|btx| btx.tx.clone())
            .ok_or_else(|| {
                format!(
                    "source tx {src_txid} for tx input {i} not found in merged \
                     wallet BEEFs (token+fuel)"
                )
            })?;
        input.source_transaction = Some(Box::new(src_tx));
    }
    Ok(())
}

/// Build atomic BEEF for `tx`: re-uses the `lookup` BEEF (which already
/// has every input's source-tx) plus the spending tx itself, sorted, then
/// serialized atomically against `final_txid`.
fn build_atomic_beef_for(
    mut lookup: Beef,
    tx: &Transaction,
    final_txid: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let beef_tx = BeefTx::from_tx(tx.clone(), None).map_err(|e| format!("BeefTx::from_tx: {e}"))?;
    lookup.txs.push(beef_tx);
    lookup.sort_txs();
    let bytes = lookup
        .to_binary_atomic(final_txid)
        .map_err(|e| format!("to_binary_atomic({final_txid}): {e}"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Phase: redeem
// ---------------------------------------------------------------------------

async fn run_redeem_phase<W: WalletInterface>(
    wallet: &dyn WalletInterface,
    stas: &Stas3Wallet<W>,
    originator: &str,
    identity_pubkey_der: &[u8],
    arc_url: &str,
    arc_api_key: Option<&str>,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_basket = stas.config().token_basket.clone();
    let fuel_basket = stas.config().fuel_basket.clone();

    println!("\n[4/?] Listing token basket {token_basket:?}...");
    let tokens = list_basket(wallet, &token_basket, originator).await?;
    if tokens.is_empty() {
        return Err(format!(
            "redeem phase requires a STAS-3 token in basket {token_basket:?}; \
             run SMOKE_PHASE=mint-broadcast first (and likely a transfer back to \
             the issuer to make owner_pkh == redemption_pkh)"
        )
        .into());
    }

    // Find a token whose owner_pkh == redemption_pkh and sats > 0.
    let mut chosen: Option<(&Output, bsv::script::locking_script::LockingScript)> = None;
    for o in &tokens {
        if o.satoshis == 0 {
            continue;
        }
        let (lock, decoded) = decode_token_output(o)?;
        if decoded.owner_pkh == decoded.redemption_pkh {
            chosen = Some((o, lock));
            break;
        }
    }
    let (token_output, locking_script) = chosen.ok_or_else(|| {
        "redeem phase requires a STAS-3 token with owner_pkh == redemption_pkh \
         (i.e. transferred back to the issuer's protoID address); none found"
    })?;
    let token_outpoint = &token_output.outpoint;
    println!("       using outpoint: {token_outpoint} ({} sats)", token_output.satoshis);

    println!("[5/?] Resolving TokenInput via find_token({token_outpoint:?})...");
    let token_input = stas.find_token(token_outpoint).await?;

    // Derive a redemption-destination key (where the burned satoshis land).
    println!("[6/?] Deriving redemption destination PKH (stas3owner/redeem)...");
    let dest_triple = Brc43KeyArgs::self_under("stas3owner", "redeem");
    let dest_pkh = derive_pkh_for_triple(wallet, originator, &dest_triple).await?;
    println!("       redemption dest pkh: {}", hex::encode(dest_pkh));

    let change_pkh = hash160(identity_pubkey_der);
    let change_satoshis: u64 = 1_200;

    println!("[7/?] Picking fuel UTXO for redeem...");
    let funding = stas.pick_fuel(change_satoshis.saturating_add(200)).await?;
    println!(
        "       picked fuel: {}.{} ({} sats)",
        funding.txid_hex, funding.vout, funding.satoshis
    );

    println!("[8/?] Calling Stas3Wallet::redeem...");
    let mut redeem_tx = stas
        .redeem(token_input, funding.clone(), dest_pkh, change_pkh, change_satoshis)
        .await?;
    let redeem_txid = redeem_tx.id().map_err(|e| format!("redeem tx id: {e}"))?;
    let redeem_hex = redeem_tx
        .to_bytes()
        .map_err(|e| format!("redeem tx bytes: {e}"))?;
    println!("       redeem_tx txid: {redeem_txid}");
    println!("       redeem_tx size: {} bytes", redeem_hex.len());

    println!("[9/?] Engine-verifying redeem_tx STAS input (index 0)...");
    let valid = verify_input(&redeem_tx, 0, &locking_script, token_output.satoshis)
        .map_err(|e| format!("redeem tx STAS input verify: {e:?}"))?;
    if !valid {
        return Err("redeem tx STAS input (index 0) failed engine verify".into());
    }
    println!("       ✓ STAS input engine-verified OK");

    if !broadcast {
        println!("\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)");
        println!("  txid: {redeem_txid}");
        println!("  hex:  {}", hex::encode(&redeem_hex));
        println!("\n✓ redeem dry-run complete");
        return Ok(());
    }

    println!("[10/?] Fetching source txs from token + fuel baskets...");
    let lookup = build_token_and_fuel_lookup_beef(
        wallet,
        originator,
        &token_basket,
        &fuel_basket,
    )
    .await?;
    hydrate_inputs_from_lookup(&mut redeem_tx, &lookup)?;

    println!("[10b/?] Signing fuel input (P2PKH) before broadcast...");
    sign_p2pkh_input_in_smoke(
        wallet,
        originator,
        &mut redeem_tx,
        1,
        funding.satoshis,
        &funding.locking_script,
        &funding.triple,
    )
    .await?;

    println!("[11/?] Broadcasting redeem_tx via ARC ({arc_url})...");
    let bcast_txid = arc_broadcast(arc_url, arc_api_key, &redeem_tx).await?;
    println!("       redeem_tx broadcast OK: txid={bcast_txid}");

    let final_txid = redeem_tx
        .id()
        .map_err(|e| format!("recompute redeem txid post-sign: {e}"))?;
    debug_assert_eq!(final_txid, bcast_txid, "computed txid != ARC-returned txid");

    // Build atomic BEEF (records the burn for our own audit trail) but we
    // don't `internalize_stas_outputs` — the redeem output is a 70-byte
    // P2MPKH, not a STAS-3 lock.
    let _atomic_beef = build_atomic_beef_for(lookup, &redeem_tx, &final_txid)?;
    println!("       atomic BEEF constructed (no STAS-3 outputs to internalize)");

    println!("\n✓ redeem phase complete — STAS-3 token burned to P2MPKH on-chain");
    println!("  txid: {final_txid}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase: split
// ---------------------------------------------------------------------------

async fn run_split_phase<W: WalletInterface>(
    wallet: &dyn WalletInterface,
    stas: &Stas3Wallet<W>,
    originator: &str,
    identity_pubkey_der: &[u8],
    arc_url: &str,
    arc_api_key: Option<&str>,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_basket = stas.config().token_basket.clone();
    let fuel_basket = stas.config().fuel_basket.clone();

    println!("\n[4/?] Listing token basket {token_basket:?}...");
    let tokens = list_basket(wallet, &token_basket, originator).await?;
    if tokens.is_empty() {
        return Err(format!(
            "split phase requires a STAS-3 token in basket {token_basket:?}; \
             run SMOKE_PHASE=mint-broadcast first"
        )
        .into());
    }

    // Pick the first token with sats >= 2 (we need at least two units to split).
    let token_output = tokens
        .iter()
        .find(|o| o.satoshis >= 2)
        .ok_or_else(|| {
            "split phase requires a STAS-3 token with sats >= 2; mint one with \
             SMOKE_MINT_SATS=5 SMOKE_PHASE=mint-broadcast first"
                .to_string()
        })?;
    let (locking_script, _decoded) = decode_token_output(token_output)?;
    let token_outpoint = &token_output.outpoint;
    let token_sats = token_output.satoshis;
    println!("       using outpoint: {token_outpoint} ({token_sats} sats)");

    println!("[5/?] Resolving TokenInput via find_token({token_outpoint:?})...");
    let token_input = stas.find_token(token_outpoint).await?;

    // Derive two destination keys.
    println!("[6/?] Deriving split destinations (stas3owner/split-a, stas3owner/split-b)...");
    let dest_a_triple = Brc43KeyArgs::self_under("stas3owner", "split-a");
    let dest_b_triple = Brc43KeyArgs::self_under("stas3owner", "split-b");
    let dest_a_pkh = derive_pkh_for_triple(wallet, originator, &dest_a_triple).await?;
    let dest_b_pkh = derive_pkh_for_triple(wallet, originator, &dest_b_triple).await?;
    let half_a = token_sats / 2;
    let half_b = token_sats - half_a;
    println!(
        "       dest A pkh: {} ({} sats)",
        hex::encode(dest_a_pkh),
        half_a
    );
    println!(
        "       dest B pkh: {} ({} sats)",
        hex::encode(dest_b_pkh),
        half_b
    );

    let change_pkh = hash160(identity_pubkey_der);
    // Split tx ~9.7kB (2 STAS-3 outputs); needs ~1000 sat fee at mainnet rate.
    let change_satoshis: u64 = 1_000;

    println!("[7/?] Picking fuel UTXO for split...");
    let funding = stas.pick_fuel(change_satoshis.saturating_add(200)).await?;
    println!(
        "       picked fuel: {}.{} ({} sats)",
        funding.txid_hex, funding.vout, funding.satoshis
    );

    println!("[8/?] Calling Stas3Wallet::split...");
    let destinations = vec![
        SplitDestination {
            owner_pkh: dest_a_pkh,
            satoshis: half_a,
        },
        SplitDestination {
            owner_pkh: dest_b_pkh,
            satoshis: half_b,
        },
    ];
    let mut split_tx = stas
        .split(
            token_input,
            funding.clone(),
            destinations,
            change_pkh,
            change_satoshis,
            Some(b"stas3 smoke split".to_vec()),
        )
        .await?;
    let split_txid = split_tx.id().map_err(|e| format!("split tx id: {e}"))?;
    let split_hex = split_tx
        .to_bytes()
        .map_err(|e| format!("split tx bytes: {e}"))?;
    println!("       split_tx txid: {split_txid}");
    println!("       split_tx size: {} bytes", split_hex.len());

    println!("[9/?] Engine-verifying split_tx STAS input (index 0)...");
    let valid = verify_input(&split_tx, 0, &locking_script, token_sats)
        .map_err(|e| format!("split tx STAS input verify: {e:?}"))?;
    if !valid {
        return Err("split tx STAS input (index 0) failed engine verify".into());
    }
    println!("       ✓ STAS input engine-verified OK");

    if !broadcast {
        println!("\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)");
        println!("  txid: {split_txid}");
        println!("  hex:  {}", hex::encode(&split_hex));
        println!("\n✓ split dry-run complete");
        return Ok(());
    }

    println!("[10/?] Fetching source txs from token + fuel baskets...");
    let lookup = build_token_and_fuel_lookup_beef(
        wallet,
        originator,
        &token_basket,
        &fuel_basket,
    )
    .await?;
    hydrate_inputs_from_lookup(&mut split_tx, &lookup)?;

    println!("[10b/?] Signing fuel input (P2PKH) before broadcast...");
    sign_p2pkh_input_in_smoke(
        wallet,
        originator,
        &mut split_tx,
        1,
        funding.satoshis,
        &funding.locking_script,
        &funding.triple,
    )
    .await?;

    println!("[11/?] Broadcasting split_tx via ARC ({arc_url})...");
    let bcast_txid = arc_broadcast(arc_url, arc_api_key, &split_tx).await?;
    println!("       split_tx broadcast OK: txid={bcast_txid}");

    let final_txid = split_tx
        .id()
        .map_err(|e| format!("recompute split txid post-sign: {e}"))?;
    debug_assert_eq!(final_txid, bcast_txid, "computed txid != ARC-returned txid");

    println!("[12/?] Building atomic BEEF for split_tx...");
    let atomic_beef = build_atomic_beef_for(lookup, &split_tx, &final_txid)?;
    println!("       atomic BEEF size: {} bytes", atomic_beef.len());

    println!(
        "[13/?] Internalizing both new STAS-3 outputs (indices 0 and 1) into {token_basket:?}..."
    );
    stas.internalize_stas_outputs(
        atomic_beef,
        vec![
            (0u32, dest_a_triple, None),
            (1u32, dest_b_triple, None),
        ],
        "stas3 smoke split",
    )
    .await
    .map_err(|e| format!("internalize_stas_outputs: {e:?}"))?;

    println!("[14/?] Re-listing token basket to verify new UTXOs...");
    let after = list_basket(wallet, &token_basket, originator).await?;
    println!(
        "       before: {} UTXO(s)  after: {} UTXO(s)",
        tokens.len(),
        after.len()
    );

    println!("\n✓ split phase complete — STAS-3 token split into two halves on-chain");
    println!("  txid: {final_txid}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase: freeze / unfreeze (shared implementation — same shape)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreezeOp {
    Freeze,
    Unfreeze,
}

impl FreezeOp {
    fn name(self) -> &'static str {
        match self {
            FreezeOp::Freeze => "freeze",
            FreezeOp::Unfreeze => "unfreeze",
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_freeze_or_unfreeze_phase<W: WalletInterface>(
    wallet: &dyn WalletInterface,
    stas: &Stas3Wallet<W>,
    originator: &str,
    identity_pubkey_der: &[u8],
    arc_url: &str,
    arc_api_key: Option<&str>,
    broadcast: bool,
    op: FreezeOp,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_basket = stas.config().token_basket.clone();
    let fuel_basket = stas.config().fuel_basket.clone();
    let op_name = op.name();

    println!("\n[4/?] Listing token basket {token_basket:?}...");
    let tokens = list_basket(wallet, &token_basket, originator).await?;
    if tokens.is_empty() {
        return Err(format!(
            "{op_name} phase requires a STAS-3 token in basket {token_basket:?}; \
             run SMOKE_PHASE=mint-broadcast first"
        )
        .into());
    }

    // Find an eligible token. For freeze: FREEZABLE flag set AND not already
    // frozen. For unfreeze: action_data == Frozen.
    let mut chosen: Option<(
        &Output,
        bsv::script::locking_script::LockingScript,
        bsv::script::templates::stas3::DecodedLock,
    )> = None;
    for o in &tokens {
        let (lock, decoded) = decode_token_output(o)?;
        let is_frozen = matches!(decoded.action_data, ActionData::Frozen(_));
        let is_eligible = match op {
            FreezeOp::Freeze => stas3_flags::is_freezable(decoded.flags) && !is_frozen,
            FreezeOp::Unfreeze => is_frozen,
        };
        if is_eligible {
            chosen = Some((o, lock, decoded));
            break;
        }
    }
    let (token_output, locking_script, decoded) = chosen.ok_or_else(|| {
        match op {
            FreezeOp::Freeze => {
                "freeze phase requires a FREEZABLE token; mint one with \
                 SMOKE_MINT_FLAGS=1 SMOKE_PHASE=mint-broadcast first"
                    .to_string()
            }
            FreezeOp::Unfreeze => {
                "unfreeze phase requires a Frozen token; run SMOKE_PHASE=freeze first"
                    .to_string()
            }
        }
    })?;
    let token_outpoint = &token_output.outpoint;
    println!(
        "       using outpoint: {token_outpoint} ({} sats, flags=0x{:02x}, frozen={})",
        token_output.satoshis,
        decoded.flags,
        matches!(decoded.action_data, ActionData::Frozen(_)),
    );

    println!("[5/?] Resolving TokenInput via find_token({token_outpoint:?})...");
    let token_input = stas.find_token(token_outpoint).await?;
    // Cache the owning triple from the resolved TokenInput so we can
    // re-internalize the new STAS-3 output under the same wallet identity
    // (freeze and unfreeze keep `owner_pkh` byte-identical to the input).
    let owner_triple = match &token_input.signing_key {
        SigningKey::P2pkh(t) => t.clone(),
        SigningKey::Multi { .. } => {
            return Err(format!(
                "{op_name} phase: multisig-owned tokens not supported in this smoke"
            )
            .into());
        }
    };

    // Derive the freeze authority triple — same one used at mint time when
    // FREEZABLE was set. Both freeze and unfreeze use this authority.
    println!("[6/?] Deriving freeze authority triple (stas3freezeauth/{FREEZE_AUTH_KEY_ID})...");
    let auth_triple = Brc43KeyArgs::self_under("stas3freezeauth", FREEZE_AUTH_KEY_ID);
    let auth_pkh = derive_pkh_for_triple(wallet, originator, &auth_triple).await?;
    println!("       freeze auth pkh: {}", hex::encode(auth_pkh));
    // Sanity check: this MUST match service_fields[0] on the input lock,
    // otherwise the factory will accept the build but the engine will
    // reject the spend.
    if let Some(expected) = decoded.service_fields.first() {
        if expected.as_slice() != auth_pkh {
            println!(
                "       WARNING: derived freeze auth pkh ({}) != \
                 service_fields[0] on token ({}); the {op_name} tx will fail engine verify",
                hex::encode(auth_pkh),
                hex::encode(expected),
            );
        } else {
            println!("       ✓ matches token's service_fields[0]");
        }
    }

    let change_pkh = hash160(identity_pubkey_der);
    let change_satoshis: u64 = 1_200;

    println!("[7/?] Picking fuel UTXO for {op_name}...");
    let funding = stas.pick_fuel(change_satoshis.saturating_add(200)).await?;
    println!(
        "       picked fuel: {}.{} ({} sats)",
        funding.txid_hex, funding.vout, funding.satoshis
    );

    println!("[8/?] Calling Stas3Wallet::{op_name}...");
    let mut op_tx = match op {
        FreezeOp::Freeze => stas
            .freeze(
                token_input,
                funding.clone(),
                SigningKey::P2pkh(auth_triple.clone()),
                change_pkh,
                change_satoshis,
            )
            .await?,
        FreezeOp::Unfreeze => stas
            .unfreeze(
                token_input,
                funding.clone(),
                SigningKey::P2pkh(auth_triple.clone()),
                change_pkh,
                change_satoshis,
            )
            .await?,
    };
    let op_txid = op_tx.id().map_err(|e| format!("{op_name} tx id: {e}"))?;
    let op_hex = op_tx
        .to_bytes()
        .map_err(|e| format!("{op_name} tx bytes: {e}"))?;
    println!("       {op_name}_tx txid: {op_txid}");
    println!("       {op_name}_tx size: {} bytes", op_hex.len());

    println!("[9/?] Engine-verifying {op_name}_tx STAS input (index 0)...");
    let valid = verify_input(&op_tx, 0, &locking_script, token_output.satoshis)
        .map_err(|e| format!("{op_name} tx STAS input verify: {e:?}"))?;
    if !valid {
        return Err(format!("{op_name} tx STAS input (index 0) failed engine verify").into());
    }
    println!("       ✓ STAS input engine-verified OK");

    if !broadcast {
        println!("\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)");
        println!("  txid: {op_txid}");
        println!("  hex:  {}", hex::encode(&op_hex));
        println!("\n✓ {op_name} dry-run complete");
        return Ok(());
    }

    println!("[10/?] Fetching source txs from token + fuel baskets...");
    let lookup = build_token_and_fuel_lookup_beef(
        wallet,
        originator,
        &token_basket,
        &fuel_basket,
    )
    .await?;
    hydrate_inputs_from_lookup(&mut op_tx, &lookup)?;

    println!("[10b/?] Signing fuel input (P2PKH) before broadcast...");
    sign_p2pkh_input_in_smoke(
        wallet,
        originator,
        &mut op_tx,
        1,
        funding.satoshis,
        &funding.locking_script,
        &funding.triple,
    )
    .await?;

    println!("[11/?] Broadcasting {op_name}_tx via ARC ({arc_url})...");
    let bcast_txid = arc_broadcast(arc_url, arc_api_key, &op_tx).await?;
    println!("       {op_name}_tx broadcast OK: txid={bcast_txid}");

    let final_txid = op_tx
        .id()
        .map_err(|e| format!("recompute {op_name} txid post-sign: {e}"))?;
    debug_assert_eq!(final_txid, bcast_txid, "computed txid != ARC-returned txid");

    println!("[12/?] Building atomic BEEF for {op_name}_tx...");
    let atomic_beef = build_atomic_beef_for(lookup, &op_tx, &final_txid)?;
    println!("       atomic BEEF size: {} bytes", atomic_beef.len());

    println!(
        "[13/?] Internalizing new STAS-3 output (index 0) into {token_basket:?}..."
    );
    stas.internalize_stas_outputs(
        atomic_beef,
        vec![(0u32, owner_triple, None)],
        match op {
            FreezeOp::Freeze => "stas3 smoke freeze",
            FreezeOp::Unfreeze => "stas3 smoke unfreeze",
        },
    )
    .await
    .map_err(|e| format!("internalize_stas_outputs: {e:?}"))?;

    println!("[14/?] Re-listing token basket to verify state transition...");
    let after = list_basket(wallet, &token_basket, originator).await?;
    println!(
        "       before: {} UTXO(s)  after: {} UTXO(s)",
        tokens.len(),
        after.len()
    );

    println!("\n✓ {op_name} phase complete — STAS-3 state transition broadcast on-chain");
    println!("  txid: {final_txid}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase: confiscate
// ---------------------------------------------------------------------------
//
// Picks a STAS-3 token from `stas3tokens` that:
//   - has CONFISCATABLE flag set, AND
//   - is currently `Frozen` (per spec §5.3, confiscation seizes a frozen UTXO).
//
// Derives the confiscation authority via `stas3confiscauth/main` (the same
// triple that was used at mint when CONFISCATABLE was set), verifies it
// matches the relevant service field on the input lock (`service_fields[0]`
// when CONFISCATABLE-only, `service_fields[1]` when both FREEZABLE and
// CONFISCATABLE are set — left-to-right by lowest flag bit per spec §5.2.2),
// builds + signs + broadcasts the confiscate tx, and internalizes the new
// STAS output (now owned by `stas3owner/confisc-dest`).

#[allow(clippy::too_many_arguments)]
async fn run_confiscate_phase<W: WalletInterface>(
    wallet: &dyn WalletInterface,
    stas: &Stas3Wallet<W>,
    originator: &str,
    identity_pubkey_der: &[u8],
    arc_url: &str,
    arc_api_key: Option<&str>,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_basket = stas.config().token_basket.clone();
    let fuel_basket = stas.config().fuel_basket.clone();

    println!("\n[4/?] Listing token basket {token_basket:?}...");
    let tokens = list_basket(wallet, &token_basket, originator).await?;
    if tokens.is_empty() {
        return Err(format!(
            "confiscate phase requires a STAS-3 token in basket {token_basket:?}; \
             run SMOKE_PHASE=mint-broadcast first"
        )
        .into());
    }

    // Find a token that is both CONFISCATABLE-flagged and Frozen.
    let mut chosen: Option<(
        &Output,
        bsv::script::locking_script::LockingScript,
        bsv::script::templates::stas3::DecodedLock,
    )> = None;
    for o in &tokens {
        let (lock, decoded) = decode_token_output(o)?;
        let is_confisc = stas3_flags::is_confiscatable(decoded.flags);
        let is_frozen = matches!(decoded.action_data, ActionData::Frozen(_));
        if is_confisc && is_frozen {
            chosen = Some((o, lock, decoded));
            break;
        }
    }
    let (token_output, locking_script, decoded) = chosen.ok_or_else(|| {
        "confiscate phase requires a STAS-3 token with CONFISCATABLE flag set \
         AND current_action_data == Frozen; mint one with \
         SMOKE_MINT_FLAGS=3 SMOKE_PHASE=mint-broadcast then SMOKE_PHASE=freeze first"
            .to_string()
    })?;
    let token_outpoint = &token_output.outpoint;
    println!(
        "       using outpoint: {token_outpoint} ({} sats, flags=0x{:02x}, frozen=true)",
        token_output.satoshis, decoded.flags
    );

    println!("[5/?] Resolving TokenInput via find_token({token_outpoint:?})...");
    let token_input = stas.find_token(token_outpoint).await?;

    // Derive the confiscation authority triple (`stas3confiscauth/main`).
    println!(
        "[6/?] Deriving confiscation authority triple (stas3confiscauth/{CONFISC_AUTH_KEY_ID})..."
    );
    let auth_triple = Brc43KeyArgs::self_under("stas3confiscauth", CONFISC_AUTH_KEY_ID);
    let auth_pkh = derive_pkh_for_triple(wallet, originator, &auth_triple).await?;
    println!("       confiscation auth pkh: {}", hex::encode(auth_pkh));

    // Verify auth_pkh matches the right service field on the input lock.
    // Position depends on flags: CONFISCATABLE-only → service_fields[0];
    // FREEZABLE+CONFISCATABLE → service_fields[1] (lowest bit first).
    let confisc_field_idx = if stas3_flags::is_freezable(decoded.flags) {
        1
    } else {
        0
    };
    if let Some(expected) = decoded.service_fields.get(confisc_field_idx) {
        if expected.as_slice() != auth_pkh {
            println!(
                "       WARNING: derived confisc auth pkh ({}) != \
                 service_fields[{confisc_field_idx}] on token ({}); \
                 confiscate tx will fail engine verify",
                hex::encode(auth_pkh),
                hex::encode(expected),
            );
        } else {
            println!(
                "       ✓ matches token's service_fields[{confisc_field_idx}]"
            );
        }
    } else {
        println!(
            "       WARNING: token has no service_fields[{confisc_field_idx}] \
             — flags=0x{:02x} disagrees with decoded layout",
            decoded.flags
        );
    }

    // Derive the destination owner (where the confiscated token goes).
    println!("[7/?] Deriving confiscation destination (stas3owner/confisc-dest)...");
    let dest_triple = Brc43KeyArgs::self_under("stas3owner", "confisc-dest");
    let dest_pkh = derive_pkh_for_triple(wallet, originator, &dest_triple).await?;
    println!("       confisc dest pkh: {}", hex::encode(dest_pkh));

    let change_pkh = hash160(identity_pubkey_der);
    let change_satoshis: u64 = 1_200;

    println!("[8/?] Picking fuel UTXO for confiscate...");
    let funding = stas.pick_fuel(change_satoshis.saturating_add(200)).await?;
    println!(
        "       picked fuel: {}.{} ({} sats)",
        funding.txid_hex, funding.vout, funding.satoshis
    );

    println!("[9/?] Calling Stas3Wallet::confiscate...");
    let mut confisc_tx = stas
        .confiscate(
            token_input,
            funding.clone(),
            SigningKey::P2pkh(auth_triple.clone()),
            dest_pkh,
            change_pkh,
            change_satoshis,
        )
        .await?;
    let confisc_txid = confisc_tx
        .id()
        .map_err(|e| format!("confiscate tx id: {e}"))?;
    let confisc_hex = confisc_tx
        .to_bytes()
        .map_err(|e| format!("confiscate tx bytes: {e}"))?;
    println!("       confiscate_tx txid: {confisc_txid}");
    println!("       confiscate_tx size: {} bytes", confisc_hex.len());

    println!("[10/?] Engine-verifying confiscate_tx STAS input (index 0)...");
    let valid = verify_input(&confisc_tx, 0, &locking_script, token_output.satoshis)
        .map_err(|e| format!("confiscate tx STAS input verify: {e:?}"))?;
    if !valid {
        return Err("confiscate tx STAS input (index 0) failed engine verify".into());
    }
    println!("       ✓ STAS input engine-verified OK");

    if !broadcast {
        println!("\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)");
        println!("  txid: {confisc_txid}");
        println!("  hex:  {}", hex::encode(&confisc_hex));
        println!("\n✓ confiscate dry-run complete");
        return Ok(());
    }

    println!("[11/?] Fetching source txs from token + fuel baskets...");
    let lookup = build_token_and_fuel_lookup_beef(
        wallet,
        originator,
        &token_basket,
        &fuel_basket,
    )
    .await?;
    hydrate_inputs_from_lookup(&mut confisc_tx, &lookup)?;

    println!("[11b/?] Signing fuel input (P2PKH) before broadcast...");
    sign_p2pkh_input_in_smoke(
        wallet,
        originator,
        &mut confisc_tx,
        1,
        funding.satoshis,
        &funding.locking_script,
        &funding.triple,
    )
    .await?;

    println!("[12/?] Broadcasting confiscate_tx via ARC ({arc_url})...");
    let bcast_txid = arc_broadcast(arc_url, arc_api_key, &confisc_tx).await?;
    println!("       confiscate_tx broadcast OK: txid={bcast_txid}");

    let final_txid = confisc_tx
        .id()
        .map_err(|e| format!("recompute confiscate txid post-sign: {e}"))?;
    debug_assert_eq!(final_txid, bcast_txid, "computed txid != ARC-returned txid");

    println!("[13/?] Building atomic BEEF for confiscate_tx...");
    let atomic_beef = build_atomic_beef_for(lookup, &confisc_tx, &final_txid)?;
    println!("       atomic BEEF size: {} bytes", atomic_beef.len());

    println!("[14/?] Internalizing confiscated STAS-3 output (index 0) into {token_basket:?}...");
    stas.internalize_stas_outputs(
        atomic_beef,
        vec![(0u32, dest_triple, None)],
        "stas3 smoke confiscate",
    )
    .await
    .map_err(|e| format!("internalize_stas_outputs: {e:?}"))?;

    println!("[15/?] Re-listing token basket to verify new owner...");
    let after = list_basket(wallet, &token_basket, originator).await?;
    println!(
        "       before: {} UTXO(s)  after: {} UTXO(s)",
        tokens.len(),
        after.len()
    );

    println!("\n✓ confiscate phase complete — STAS-3 token seized to confisc-dest on-chain");
    println!("  txid: {final_txid}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase: merge
// ---------------------------------------------------------------------------
//
// Picks 2 STAS-3 tokens of the SAME TYPE from `stas3tokens` (same
// redemption_pkh + flags + service_fields + optional_data), hydrates each
// `TokenInput.source_tx_bytes` from the token-basket BEEF (required by the
// merge factory per spec §9.5 — the raw preceding tx is needed to excise
// the asset locking script for the trailing piece array), and atomically
// merges them into one STAS output owned by `stas3owner/merge-dest`.

/// Returns `true` when two tokens are mergeable (same type per spec §8.1):
/// same redemption_pkh, flags, service_fields, AND optional_data.
fn is_same_token_type(
    a: &bsv::script::templates::stas3::DecodedLock,
    b: &bsv::script::templates::stas3::DecodedLock,
) -> bool {
    a.redemption_pkh == b.redemption_pkh
        && a.flags == b.flags
        && a.service_fields == b.service_fields
        && a.optional_data == b.optional_data
}

#[allow(clippy::too_many_arguments)]
async fn run_merge_phase<W: WalletInterface>(
    wallet: &dyn WalletInterface,
    stas: &Stas3Wallet<W>,
    originator: &str,
    identity_pubkey_der: &[u8],
    arc_url: &str,
    arc_api_key: Option<&str>,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_basket = stas.config().token_basket.clone();
    let fuel_basket = stas.config().fuel_basket.clone();

    println!("\n[4/?] Listing token basket {token_basket:?}...");
    let tokens = list_basket(wallet, &token_basket, originator).await?;
    if tokens.len() < 2 {
        return Err(format!(
            "merge phase requires 2+ STAS-3 tokens of the same type in basket \
             {token_basket:?}; got {}. Mint twice with the same SMOKE_MINT_ISSUER_KEYID \
             (e.g. SMOKE_MINT_ISSUER_KEYID=merge1 SMOKE_PHASE=mint-broadcast \
             — repeat) so both tokens share a redemption_pkh.",
            tokens.len()
        )
        .into());
    }

    // Decode all tokens, then find any pair of the same type.
    let mut decoded_all: Vec<(usize, bsv::script::locking_script::LockingScript,
        bsv::script::templates::stas3::DecodedLock)> = Vec::new();
    for (i, o) in tokens.iter().enumerate() {
        let (lock, dec) = decode_token_output(o)?;
        decoded_all.push((i, lock, dec));
    }

    let mut pair: Option<(usize, usize)> = None;
    'outer: for i in 0..decoded_all.len() {
        for j in (i + 1)..decoded_all.len() {
            if is_same_token_type(&decoded_all[i].2, &decoded_all[j].2) {
                pair = Some((i, j));
                break 'outer;
            }
        }
    }
    let (idx_a, idx_b) = pair.ok_or_else(|| {
        "merge phase requires 2+ STAS-3 tokens of the same type \
         (same redemption_pkh + flags + service_fields + optional_data); \
         no such pair found. Mint twice with the same SMOKE_MINT_ISSUER_KEYID."
            .to_string()
    })?;

    let token_a = &tokens[idx_a];
    let token_b = &tokens[idx_b];
    let lock_a = decoded_all[idx_a].1.clone();
    let lock_b = decoded_all[idx_b].1.clone();
    println!(
        "       picked pair: {} ({} sats) + {} ({} sats)",
        token_a.outpoint, token_a.satoshis, token_b.outpoint, token_b.satoshis
    );

    // Resolve TokenInputs (find_token leaves source_tx_bytes = None — we
    // hydrate it ourselves below from the token-basket BEEF).
    println!("[5/?] Resolving TokenInputs via find_token...");
    let mut token_input_a = stas.find_token(&token_a.outpoint).await?;
    let mut token_input_b = stas.find_token(&token_b.outpoint).await?;

    // Pre-fetch the token + fuel BEEFs (we need them anyway for hydrating
    // source_transaction on every input pre-broadcast, and we ALSO need to
    // populate source_tx_bytes for merge per spec §9.5).
    println!("[6/?] Fetching source txs from token + fuel baskets...");
    let lookup = build_token_and_fuel_lookup_beef(
        wallet,
        originator,
        &token_basket,
        &fuel_basket,
    )
    .await?;
    let src_a = lookup
        .find_txid(&token_input_a.txid_hex)
        .and_then(|btx| btx.tx.clone())
        .ok_or_else(|| {
            format!(
                "source tx {} for merge input A not found in token-basket BEEF",
                token_input_a.txid_hex
            )
        })?;
    let src_b = lookup
        .find_txid(&token_input_b.txid_hex)
        .and_then(|btx| btx.tx.clone())
        .ok_or_else(|| {
            format!(
                "source tx {} for merge input B not found in token-basket BEEF",
                token_input_b.txid_hex
            )
        })?;
    let src_a_bytes = src_a
        .to_bytes()
        .map_err(|e| format!("serialize merge input A source tx: {e}"))?;
    let src_b_bytes = src_b
        .to_bytes()
        .map_err(|e| format!("serialize merge input B source tx: {e}"))?;
    token_input_a.source_tx_bytes = Some(src_a_bytes);
    token_input_b.source_tx_bytes = Some(src_b_bytes);
    println!("       hydrated source_tx_bytes for both merge inputs");

    // Derive merge destination (recipient of the merged token).
    println!("[7/?] Deriving merge destination (stas3owner/merge-dest)...");
    let dest_triple = Brc43KeyArgs::self_under("stas3owner", "merge-dest");
    let dest_pkh = derive_pkh_for_triple(wallet, originator, &dest_triple).await?;
    println!("       merge dest pkh: {}", hex::encode(dest_pkh));

    let change_pkh = hash160(identity_pubkey_der);
    // Merge tx is bigger than transfer (~4.5kB-ish with EAC optional_data
    // on both inputs). Leave a healthy fee budget.
    let change_satoshis: u64 = 800;

    println!("[8/?] Picking fuel UTXO for merge...");
    let funding = stas.pick_fuel(change_satoshis.saturating_add(500)).await?;
    println!(
        "       picked fuel: {}.{} ({} sats)",
        funding.txid_hex, funding.vout, funding.satoshis
    );

    println!("[9/?] Calling Stas3Wallet::merge (2 STAS inputs + 1 fuel)...");
    let mut merge_tx = stas
        .merge(
            vec![token_input_a, token_input_b],
            funding.clone(),
            dest_pkh,
            change_pkh,
            change_satoshis,
            Some(b"stas3 smoke merge".to_vec()),
        )
        .await?;
    let merge_txid = merge_tx.id().map_err(|e| format!("merge tx id: {e}"))?;
    let merge_hex = merge_tx
        .to_bytes()
        .map_err(|e| format!("merge tx bytes: {e}"))?;
    println!("       merge_tx txid: {merge_txid}");
    println!("       merge_tx size: {} bytes", merge_hex.len());

    // Engine-verify both STAS inputs (index 0 and 1).
    println!("[10/?] Engine-verifying merge_tx STAS inputs (index 0 and 1)...");
    let valid_0 = verify_input(&merge_tx, 0, &lock_a, token_a.satoshis)
        .map_err(|e| format!("merge tx STAS input 0 verify: {e:?}"))?;
    if !valid_0 {
        return Err("merge tx STAS input 0 failed engine verify".into());
    }
    let valid_1 = verify_input(&merge_tx, 1, &lock_b, token_b.satoshis)
        .map_err(|e| format!("merge tx STAS input 1 verify: {e:?}"))?;
    if !valid_1 {
        return Err("merge tx STAS input 1 failed engine verify".into());
    }
    println!("       ✓ both STAS inputs engine-verified OK");

    if !broadcast {
        println!("\n  broadcast skipped (dry-run — set SMOKE_BROADCAST=1 to broadcast)");
        println!("  txid: {merge_txid}");
        println!("  hex:  {}", hex::encode(&merge_hex));
        println!("\n✓ merge dry-run complete");
        return Ok(());
    }

    // Hydrate source_transaction on every input (3 inputs: 2 STAS + 1 fuel)
    // so EF serialization works.
    hydrate_inputs_from_lookup(&mut merge_tx, &lookup)?;

    // Sign the fuel input (input 2 — STAS inputs are at 0 and 1).
    println!("[10b/?] Signing fuel input (P2PKH, index 2) before broadcast...");
    sign_p2pkh_input_in_smoke(
        wallet,
        originator,
        &mut merge_tx,
        2,
        funding.satoshis,
        &funding.locking_script,
        &funding.triple,
    )
    .await?;

    println!("[11/?] Broadcasting merge_tx via ARC ({arc_url})...");
    let bcast_txid = arc_broadcast(arc_url, arc_api_key, &merge_tx).await?;
    println!("       merge_tx broadcast OK: txid={bcast_txid}");

    let final_txid = merge_tx
        .id()
        .map_err(|e| format!("recompute merge txid post-sign: {e}"))?;
    debug_assert_eq!(final_txid, bcast_txid, "computed txid != ARC-returned txid");

    println!("[12/?] Building atomic BEEF for merge_tx...");
    let atomic_beef = build_atomic_beef_for(lookup, &merge_tx, &final_txid)?;
    println!("       atomic BEEF size: {} bytes", atomic_beef.len());

    println!("[13/?] Internalizing merged STAS-3 output (index 0) into {token_basket:?}...");
    stas.internalize_stas_outputs(
        atomic_beef,
        vec![(0u32, dest_triple, None)],
        "stas3 smoke merge",
    )
    .await
    .map_err(|e| format!("internalize_stas_outputs: {e:?}"))?;

    println!("[14/?] Re-listing token basket to verify merged UTXO...");
    let after = list_basket(wallet, &token_basket, originator).await?;
    println!(
        "       before: {} UTXO(s)  after: {} UTXO(s)",
        tokens.len(),
        after.len()
    );

    println!(
        "\n✓ merge phase complete — 2 STAS-3 tokens merged into 1 ({} + {} = {} sats)",
        token_a.satoshis,
        token_b.satoshis,
        token_a.satoshis + token_b.satoshis
    );
    println!("  txid: {final_txid}");
    Ok(())
}
