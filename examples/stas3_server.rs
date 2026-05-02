//! STAS-3 HTTP Server Example
//!
//! A runnable Axum HTTP server exposing every STAS-3 operation as a JSON
//! route, backed by a `Stas3Wallet<HttpWalletJson>`. This is the
//! "production simple app" reference: a thin layer that translates JSON
//! request bodies into `Stas3Wallet` factory calls, returning the resulting
//! transaction hex + txid.
//!
//! # Routes
//!
//! ```text
//! GET  /health                     → {"status": "ok"}
//! POST /tokens/transfer            → {tx_hex, txid}
//! POST /tokens/split               → {tx_hex, txid}
//! POST /tokens/merge               → {tx_hex, txid}
//! POST /tokens/redeem              → {tx_hex, txid}
//! POST /tokens/freeze              → {tx_hex, txid}
//! POST /tokens/unfreeze            → {tx_hex, txid}
//! POST /tokens/confiscate          → {tx_hex, txid}
//! POST /tokens/swap_mark           → {tx_hex, txid}
//! POST /tokens/swap_cancel         → {tx_hex, txid}
//! POST /tokens/swap_execute        → {tx_hex, txid}
//! POST /tokens/mint                → {contract_tx_hex, contract_txid, issue_tx_hex, issue_txid}
//! ```
//!
//! # Configuration (env vars)
//!
//! - `WALLET_URL`     — BRC-100 wallet JSON endpoint (default `http://localhost:3321`)
//! - `BIND_ADDR`      — server bind address (default `127.0.0.1:8080`)
//! - `ORIGINATOR`     — originator string passed to the wallet (default `stas3-server`)
//! - `RUST_LOG`       — tracing filter (default `info,stas3_server=debug`)
//!
//! # Usage
//!
//! ```bash
//! # Start a BRC-100 wallet on localhost:3321 first.
//! cargo run --example stas3_server --features network
//!
//! # In another shell:
//! curl http://localhost:8080/health
//! # → {"status":"ok"}
//! ```
//!
//! # Request body shape
//!
//! Token UTXOs and funding UTXOs are referenced by their outpoint (`"txid.vout"`)
//! and resolved via the wallet's `list_outputs` against the configured
//! `token_basket` / `fuel_basket`. PKHs are passed as 40-char lowercase hex
//! (HASH160 of a pubkey). See each handler for the exact request shape.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bsv::script::templates::stas3::{
    factory::SplitDestination, ActionData, NextVar2, Stas3Wallet, SwapDescriptor,
};
use bsv::script::templates::stas3::factory::SigningKey;
use bsv::transaction::transaction::Transaction;
use bsv::wallet::substrates::http_wallet_json::HttpWalletJson;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared application state. The `Stas3Wallet` wraps an `HttpWalletJson`
/// pointed at a real BRC-100 wallet endpoint.
#[derive(Clone)]
struct AppState {
    stas: Arc<Stas3Wallet<HttpWalletJson>>,
}

// ---------------------------------------------------------------------------
// Error response shape
// ---------------------------------------------------------------------------

/// Wire shape returned by every error path.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Application-level error type. Each variant maps to a deterministic HTTP
/// status code via the `IntoResponse` impl below — no `let _ = result` shortcuts.
#[allow(dead_code)] // `Wallet` is reserved for explicit transport-error mapping when we
                    // separate Stas3Error::InvalidScript("…wallet…") from genuine STAS-3
                    // protocol errors. Today they collapse into Stas3 → 400.
enum AppError {
    /// STAS-3 protocol-level error → 400 Bad Request. The caller's request
    /// is structurally well-formed JSON but the underlying token state /
    /// math / scripts violated a STAS-3 invariant.
    Stas3(bsv::script::templates::stas3::Stas3Error),
    /// Caller-side input was malformed (bad hex, bad JSON shape that
    /// passed serde but is semantically invalid, etc.) → 400 Bad Request.
    BadRequest(String),
    /// Upstream wallet round-trip failed (HTTP transport, JSON shape,
    /// timeout) → 502 Bad Gateway.
    Wallet(String),
    /// Anything else (transaction serialization, unexpected state) → 500.
    Internal(String),
}

impl From<bsv::script::templates::stas3::Stas3Error> for AppError {
    fn from(e: bsv::script::templates::stas3::Stas3Error) -> Self {
        Self::Stas3(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Stas3(e) => (StatusCode::BAD_REQUEST, format!("stas3 error: {e}")),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Wallet(m) => (StatusCode::BAD_GATEWAY, format!("wallet error: {m}")),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        // Log every error response — operator visibility on bad requests is
        // worth the modest noise. Drop down to debug if this becomes a flood.
        error!(status = ?status, message = %msg, "request failed");
        (status, Json(ErrorResponse { error: msg })).into_response()
    }
}

// ---------------------------------------------------------------------------
// Common response shape
// ---------------------------------------------------------------------------

/// Standard success body for every operation that produces a transaction.
#[derive(Serialize)]
struct TxResponse {
    /// Hex-encoded raw transaction bytes (BSV wire format).
    tx_hex: String,
    /// 32-byte transaction id, BE hex (display order).
    txid: String,
}

impl TxResponse {
    fn from_tx(tx: &Transaction) -> Result<Self, AppError> {
        let tx_hex = tx
            .to_hex()
            .map_err(|e| AppError::Internal(format!("tx.to_hex: {e}")))?;
        let txid = tx
            .id()
            .map_err(|e| AppError::Internal(format!("tx.id: {e}")))?;
        Ok(Self { tx_hex, txid })
    }
}

// ---------------------------------------------------------------------------
// Health route
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

// ---------------------------------------------------------------------------
// Helpers — outpoint / pkh parsing
// ---------------------------------------------------------------------------

/// Decode a 40-char lowercase hex string into a 20-byte PKH array.
fn parse_pkh(hex_str: &str, field: &str) -> Result<[u8; 20], AppError> {
    if hex_str.len() != 40 {
        return Err(AppError::BadRequest(format!(
            "{field}: expected 40 hex chars (HASH160), got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| AppError::BadRequest(format!("{field}: invalid hex: {e}")))?;
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: decoded length != 20")))?;
    Ok(arr)
}

/// Decode a 64-char lowercase hex string into a 32-byte hash array.
fn parse_hash32(hex_str: &str, field: &str) -> Result<[u8; 32], AppError> {
    if hex_str.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "{field}: expected 64 hex chars (SHA-256), got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)
        .map_err(|e| AppError::BadRequest(format!("{field}: invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest(format!("{field}: decoded length != 32")))?;
    Ok(arr)
}

/// Decode arbitrary hex bytes (e.g. note payload). Empty string → `None`.
fn parse_opt_hex(hex_str: Option<&String>, field: &str) -> Result<Option<Vec<u8>>, AppError> {
    match hex_str {
        Some(s) if !s.is_empty() => Some(
            hex::decode(s).map_err(|e| AppError::BadRequest(format!("{field}: invalid hex: {e}"))),
        )
        .transpose(),
        _ => Ok(None),
    }
}

/// Resolve a token outpoint via the wrapper's basket lookup.
async fn resolve_token(
    stas: &Stas3Wallet<HttpWalletJson>,
    outpoint: &str,
) -> Result<bsv::script::templates::stas3::factory::TokenInput, AppError> {
    stas.find_token(outpoint)
        .await
        .map_err(|e| AppError::Stas3(e))
}

/// Pick a fuel UTXO for the given fee budget (caller passes
/// `change_satoshis + fee_headroom`).
async fn resolve_fuel(
    stas: &Stas3Wallet<HttpWalletJson>,
    min_satoshis: u64,
) -> Result<bsv::script::templates::stas3::factory::FundingInput, AppError> {
    stas.pick_fuel(min_satoshis).await.map_err(AppError::Stas3)
}

// ---------------------------------------------------------------------------
// Common request fragments
// ---------------------------------------------------------------------------

/// Common change/fuel fields shared by every body. The fuel UTXO is picked
/// from the configured fuel basket; the caller supplies only the change PKH
/// and post-fee change amount.
#[derive(Deserialize)]
struct ChangeFields {
    /// 40-char lowercase hex HASH160 — destination of the P2PKH change output.
    change_pkh: String,
    /// Satoshis for the change output. Fuel pick will demand at least
    /// `change_satoshis + 200` sats of headroom for fee.
    change_satoshis: u64,
}

impl ChangeFields {
    fn parse_change_pkh(&self) -> Result<[u8; 20], AppError> {
        parse_pkh(&self.change_pkh, "change_pkh")
    }
}

// ---------------------------------------------------------------------------
// /tokens/transfer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TransferRequest {
    /// Token UTXO outpoint (`"txid.vout"`) — must be in the token basket.
    token_outpoint: String,
    /// 40-char lowercase hex HASH160 of the destination owner.
    destination_owner_pkh: String,
    #[serde(flatten)]
    change: ChangeFields,
    /// Optional opaque note bytes carried in the transfer (hex). Spec §5.2
    /// limits this to ≤ 65533 bytes.
    note_hex: Option<String>,
}

async fn handle_transfer(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/transfer");
    let dest = parse_pkh(&req.destination_owner_pkh, "destination_owner_pkh")?;
    let change_pkh = req.change.parse_change_pkh()?;
    let note = parse_opt_hex(req.note_hex.as_ref(), "note_hex")?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;

    let tx = state
        .stas
        .transfer(
            token,
            funding,
            dest,
            change_pkh,
            req.change.change_satoshis,
            note,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/split
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SplitDestinationDto {
    owner_pkh: String,
    satoshis: u64,
}

#[derive(Deserialize)]
struct SplitRequestBody {
    token_outpoint: String,
    /// 2..=4 destinations. Sum of `satoshis` MUST equal the input token's
    /// satoshis (sum-conservation per spec §5.1) — the factory enforces.
    destinations: Vec<SplitDestinationDto>,
    #[serde(flatten)]
    change: ChangeFields,
    note_hex: Option<String>,
}

async fn handle_split(
    State(state): State<AppState>,
    Json(req): Json<SplitRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(
        token = %req.token_outpoint,
        n_dest = req.destinations.len(),
        "POST /tokens/split"
    );
    let change_pkh = req.change.parse_change_pkh()?;
    let note = parse_opt_hex(req.note_hex.as_ref(), "note_hex")?;

    let mut destinations = Vec::with_capacity(req.destinations.len());
    for (i, d) in req.destinations.iter().enumerate() {
        let owner_pkh = parse_pkh(&d.owner_pkh, &format!("destinations[{i}].owner_pkh"))?;
        destinations.push(SplitDestination {
            owner_pkh,
            satoshis: d.satoshis,
        });
    }

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;

    let tx = state
        .stas
        .split(
            token,
            funding,
            destinations,
            change_pkh,
            req.change.change_satoshis,
            note,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/merge
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MergeRequestBody {
    /// Exactly two token outpoints — the wallet's 2-input merge wrapper.
    /// Wave 2A.2 will widen this to 2..=7.
    token_outpoints: Vec<String>,
    destination_owner_pkh: String,
    #[serde(flatten)]
    change: ChangeFields,
    note_hex: Option<String>,
}

async fn handle_merge(
    State(state): State<AppState>,
    Json(req): Json<MergeRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(n_inputs = req.token_outpoints.len(), "POST /tokens/merge");
    if req.token_outpoints.len() != 2 {
        return Err(AppError::BadRequest(format!(
            "merge currently requires exactly 2 token_outpoints (got {})",
            req.token_outpoints.len()
        )));
    }
    let dest = parse_pkh(&req.destination_owner_pkh, "destination_owner_pkh")?;
    let change_pkh = req.change.parse_change_pkh()?;
    let note = parse_opt_hex(req.note_hex.as_ref(), "note_hex")?;

    let t0 = resolve_token(&state.stas, &req.token_outpoints[0]).await?;
    let t1 = resolve_token(&state.stas, &req.token_outpoints[1]).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(300)).await?;

    let tx = state
        .stas
        .merge(
            vec![t0, t1],
            funding,
            dest,
            change_pkh,
            req.change.change_satoshis,
            note,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/redeem
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RedeemRequestBody {
    token_outpoint: String,
    /// PKH receiving the redeemed value (issuer's destination).
    redemption_destination_pkh: String,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_redeem(
    State(state): State<AppState>,
    Json(req): Json<RedeemRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/redeem");
    let dest = parse_pkh(&req.redemption_destination_pkh, "redemption_destination_pkh")?;
    let change_pkh = req.change.parse_change_pkh()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;

    let tx = state
        .stas
        .redeem(token, funding, dest, change_pkh, req.change.change_satoshis)
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/freeze, /tokens/unfreeze, /tokens/confiscate
// ---------------------------------------------------------------------------
//
// Authority-signed ops. The current REST surface accepts a token outpoint
// and assumes the FREEZE_AUTHORITY / CONFISCATION_AUTHORITY signing key has
// already been resolved by the wallet via the basket lookup (the token's
// own SigningKey is reused). This matches the simple-app pattern where the
// service holds a single authority key.
//
// For production deployments where the authority is a separate multisig
// key, callers should use the lower-level `Stas3Wallet::freeze` API
// directly with an explicit `SigningKey::Multi { ... }`.

#[derive(Deserialize)]
struct FreezeRequestBody {
    token_outpoint: String,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_freeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/freeze");
    let change_pkh = req.change.parse_change_pkh()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;
    // Reuse the input owner's signing key as the freeze authority — the
    // simple-app default. Production deployments override this with a
    // dedicated authority key plumbed through configuration.
    let authority: SigningKey = token.signing_key.clone();

    let tx = state
        .stas
        .freeze(
            token,
            funding,
            authority,
            change_pkh,
            req.change.change_satoshis,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

async fn handle_unfreeze(
    State(state): State<AppState>,
    Json(req): Json<FreezeRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/unfreeze");
    let change_pkh = req.change.parse_change_pkh()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;
    let authority: SigningKey = token.signing_key.clone();

    let tx = state
        .stas
        .unfreeze(
            token,
            funding,
            authority,
            change_pkh,
            req.change.change_satoshis,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

#[derive(Deserialize)]
struct ConfiscateRequestBody {
    token_outpoint: String,
    destination_owner_pkh: String,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_confiscate(
    State(state): State<AppState>,
    Json(req): Json<ConfiscateRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/confiscate");
    let dest = parse_pkh(&req.destination_owner_pkh, "destination_owner_pkh")?;
    let change_pkh = req.change.parse_change_pkh()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;
    let authority: SigningKey = token.signing_key.clone();

    let tx = state
        .stas
        .confiscate(
            token,
            funding,
            authority,
            dest,
            change_pkh,
            req.change.change_satoshis,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/swap_mark, /tokens/swap_cancel, /tokens/swap_execute
// ---------------------------------------------------------------------------

/// Wire shape for a swap descriptor — top-level only (no nested swap chains).
/// Callers needing multi-leg swap descriptors should use the lower-level
/// API directly.
#[derive(Deserialize)]
struct SwapDescriptorDto {
    /// 64-char lowercase hex (SHA-256 of the counterparty's locking script).
    requested_script_hash: String,
    /// 40-char lowercase hex HASH160 of the receive address. Use
    /// `0000…0000` (HASH160 of "" — the spec §10.3 sentinel) for
    /// arbitrator-free / anyone-can-fill.
    receive_addr: String,
    rate_numerator: u32,
    rate_denominator: u32,
    /// Optional `next` chain. Currently supports `Passive(hex)` only via
    /// the `next_passive_hex` field; full recursion is left to the
    /// programmatic API.
    next_passive_hex: Option<String>,
}

impl SwapDescriptorDto {
    fn into_descriptor(self) -> Result<SwapDescriptor, AppError> {
        let requested_script_hash =
            parse_hash32(&self.requested_script_hash, "requested_script_hash")?;
        let receive_addr = parse_pkh(&self.receive_addr, "receive_addr")?;
        let next = match parse_opt_hex(self.next_passive_hex.as_ref(), "next_passive_hex")? {
            Some(bytes) => Some(Box::new(NextVar2::Passive(bytes))),
            None => None,
        };
        Ok(SwapDescriptor {
            requested_script_hash,
            receive_addr,
            rate_numerator: self.rate_numerator,
            rate_denominator: self.rate_denominator,
            next,
        })
    }
}

#[derive(Deserialize)]
struct SwapMarkRequestBody {
    token_outpoint: String,
    descriptor: SwapDescriptorDto,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_swap_mark(
    State(state): State<AppState>,
    Json(req): Json<SwapMarkRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/swap_mark");
    let change_pkh = req.change.parse_change_pkh()?;
    let descriptor = req.descriptor.into_descriptor()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;

    let tx = state
        .stas
        .swap_mark(
            token,
            funding,
            descriptor,
            change_pkh,
            req.change.change_satoshis,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

#[derive(Deserialize)]
struct SwapCancelRequestBody {
    token_outpoint: String,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_swap_cancel(
    State(state): State<AppState>,
    Json(req): Json<SwapCancelRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(token = %req.token_outpoint, "POST /tokens/swap_cancel");
    let change_pkh = req.change.parse_change_pkh()?;

    let token = resolve_token(&state.stas, &req.token_outpoint).await?;
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(200)).await?;
    // Reuse the input owner's signing key as the receive_addr key. The
    // arbitrator-free flow expects `EMPTY_HASH160` on the descriptor, in
    // which case the engine accepts OP_FALSE in lieu of a real signature.
    // Validate-bound multisig cancel requires the explicit
    // `Stas3Wallet::swap_cancel` API.
    let signing_key: SigningKey = token.signing_key.clone();

    let tx = state
        .stas
        .swap_cancel(
            token,
            funding,
            signing_key,
            change_pkh,
            req.change.change_satoshis,
        )
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

#[derive(Deserialize)]
struct SwapExecuteRequestBody {
    /// Two outpoints — the swap legs. At least one must carry a
    /// `SwapDescriptor` in `current_action_data` (one-sided is
    /// "transfer-swap"; two-sided is "swap-swap").
    token_outpoints: Vec<String>,
    #[serde(flatten)]
    change: ChangeFields,
}

async fn handle_swap_execute(
    State(state): State<AppState>,
    Json(req): Json<SwapExecuteRequestBody>,
) -> Result<Json<TxResponse>, AppError> {
    info!(n_legs = req.token_outpoints.len(), "POST /tokens/swap_execute");
    if req.token_outpoints.len() != 2 {
        return Err(AppError::BadRequest(format!(
            "swap_execute requires exactly 2 token_outpoints (got {})",
            req.token_outpoints.len()
        )));
    }
    let change_pkh = req.change.parse_change_pkh()?;

    let t0 = resolve_token(&state.stas, &req.token_outpoints[0]).await?;
    let t1 = resolve_token(&state.stas, &req.token_outpoints[1]).await?;
    // Confirm at least one leg carries a SwapDescriptor — the factory
    // would error anyway, but a clear 400 here is friendlier than a deep
    // factory error string.
    let any_swap = matches!(t0.current_action_data, ActionData::Swap(_))
        || matches!(t1.current_action_data, ActionData::Swap(_));
    if !any_swap {
        return Err(AppError::BadRequest(
            "swap_execute: neither token leg carries a SwapDescriptor in var2".into(),
        ));
    }
    let funding = resolve_fuel(&state.stas, req.change.change_satoshis.saturating_add(300)).await?;

    let tx = state
        .stas
        .swap_execute([t0, t1], funding, change_pkh, req.change.change_satoshis)
        .await?;
    Ok(Json(TxResponse::from_tx(&tx)?))
}

// ---------------------------------------------------------------------------
// /tokens/mint — Wave 2A.1 wired to wallet::mint_eac.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MintEacRequestBody {
    /// Funding UTXO outpoint (`"txid.vout"`) — must be in the fuel basket.
    funding_outpoint: String,
    /// Issuer Type-42 triple. The wallet derives the issuer pubkey from
    /// this triple; HASH160(issuer_pubkey) becomes the redemption_pkh.
    issuer_protocol: String,
    issuer_protocol_security_level: u8,
    issuer_key_id: String,
    /// Flags byte: bit 0 = FREEZABLE, bit 1 = CONFISCATABLE.
    flags: u8,
    /// 40-char lowercase hex HASH160. Required when `flags & 0x01` is set.
    freeze_auth_pkh: Option<String>,
    /// 40-char lowercase hex HASH160. Required when `flags & 0x02` is set.
    confiscate_auth_pkh: Option<String>,
    /// One destination per output; `eac_fields` carries the schema-1 EAC
    /// shape per `EacFields::to_optional_data`.
    destinations: Vec<MintEacDestinationDto>,
    /// Hex-encoded scheme metadata bytes (written into the contract tx's
    /// trailing `OP_FALSE OP_RETURN`). Empty string treated as no metadata.
    scheme_metadata_hex: Option<String>,
    /// Fee rate in sat/kB. Defaults to 500 if omitted.
    fee_rate_sat_per_kb: Option<u64>,
}

#[derive(Deserialize)]
struct MintEacDestinationDto {
    owner_pkh: String,
    satoshis: u64,
    eac_fields: EacFieldsDto,
}

#[derive(Deserialize)]
struct EacFieldsDto {
    quantity_wh: u64,
    interval_start: i64,
    interval_end: i64,
    /// One of: `solar`, `wind`, `hydro`, `nuclear`, `thermal`, `geothermal`,
    /// `biomass`, `other`. Free-text falls into `Other(...)`.
    energy_source: String,
    /// 2-char ISO 3166-1 alpha-2 (e.g. `"US"`).
    country: String,
    /// 64-char lowercase hex (32 bytes).
    device_id_hex: String,
    id_range_start: u64,
    id_range_end: u64,
    issue_date: i64,
    storage_tag: u64,
}

impl EacFieldsDto {
    fn to_eac_fields(&self) -> Result<bsv::script::templates::stas3::EacFields, AppError> {
        use bsv::script::templates::stas3::{EacFields, EnergySource};
        if self.country.len() != 2 {
            return Err(AppError::BadRequest(format!(
                "eac_fields.country: expected 2 chars, got {}",
                self.country.len()
            )));
        }
        let mut country = [0u8; 2];
        country.copy_from_slice(self.country.as_bytes());
        let device_id = parse_hash32(&self.device_id_hex, "eac_fields.device_id_hex")?;
        let energy_source = match self.energy_source.to_lowercase().as_str() {
            "solar" => EnergySource::Solar,
            "wind" => EnergySource::Wind,
            "hydro" => EnergySource::Hydro,
            "nuclear" => EnergySource::Nuclear,
            "geothermal" => EnergySource::Geothermal,
            "biomass" => EnergySource::Biomass,
            "storage" => EnergySource::Storage,
            other => EnergySource::Other(other.to_string()),
        };
        Ok(EacFields {
            quantity_wh: self.quantity_wh,
            interval_start: self.interval_start,
            interval_end: self.interval_end,
            energy_source,
            country,
            device_id,
            id_range: (self.id_range_start, self.id_range_end),
            issue_date: self.issue_date,
            storage_tag: self.storage_tag,
        })
    }
}

#[derive(Serialize)]
struct MintEacResponse {
    contract_tx_hex: String,
    contract_txid: String,
    issue_tx_hex: String,
    issue_txid: String,
}

async fn handle_mint(
    State(state): State<AppState>,
    Json(req): Json<MintEacRequestBody>,
) -> Result<Json<MintEacResponse>, AppError> {
    use bsv::script::templates::stas3::KeyTriple;
    use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

    info!(n_dest = req.destinations.len(), "POST /tokens/mint");

    // 1. Resolve the funding UTXO from the fuel basket. It will already
    //    be a P2PKH UTXO with a Type-42 triple in customInstructions —
    //    but the issuer_signing_key flows from the request, not the
    //    fuel-basket triple, since they may differ in production.
    let funding = resolve_token_outpoint_as_funding(&state.stas, &req.funding_outpoint).await?;

    // 2. Construct the issuer triple from request fields.
    let issuer_triple = KeyTriple {
        protocol_id: Protocol {
            security_level: req.issuer_protocol_security_level,
            protocol: req.issuer_protocol.clone(),
        },
        key_id: req.issuer_key_id.clone(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        },
    };

    // 3. Parse optional pkhs.
    let freeze_auth = match &req.freeze_auth_pkh {
        Some(s) if !s.is_empty() => Some(parse_pkh(s, "freeze_auth_pkh")?),
        _ => None,
    };
    let confiscate_auth = match &req.confiscate_auth_pkh {
        Some(s) if !s.is_empty() => Some(parse_pkh(s, "confiscate_auth_pkh")?),
        _ => None,
    };

    // 4. Build destinations.
    let mut destinations = Vec::with_capacity(req.destinations.len());
    for (i, d) in req.destinations.iter().enumerate() {
        let owner_pkh = parse_pkh(&d.owner_pkh, &format!("destinations[{i}].owner_pkh"))?;
        let fields = d.eac_fields.to_eac_fields()?;
        destinations.push((owner_pkh, d.satoshis, fields));
    }

    // 5. Scheme metadata.
    let scheme_metadata = match &req.scheme_metadata_hex {
        Some(s) if !s.is_empty() => hex::decode(s).map_err(|e| {
            AppError::BadRequest(format!("scheme_metadata_hex: invalid hex: {e}"))
        })?,
        _ => Vec::new(),
    };

    // 6. Delegate to mint_eac.
    let result = state
        .stas
        .mint_eac(
            None,
            SigningKey::P2pkh(issuer_triple),
            funding,
            req.flags,
            freeze_auth,
            confiscate_auth,
            destinations,
            scheme_metadata,
            req.fee_rate_sat_per_kb.unwrap_or(500),
        )
        .await?;

    let contract = TxResponse::from_tx(&result.contract_tx)?;
    let issue = TxResponse::from_tx(&result.issue_tx)?;
    Ok(Json(MintEacResponse {
        contract_tx_hex: contract.tx_hex,
        contract_txid: contract.txid,
        issue_tx_hex: issue.tx_hex,
        issue_txid: issue.txid,
    }))
}

/// Resolve a funding outpoint via the fuel basket. Wrapper around the
/// wrapper's `pick_fuel`-style resolver — but for mint, we want a
/// specific outpoint, not an auto-pick. We use the wrapper's
/// `find_token`-style internal API by reusing `pick_fuel` with a
/// satoshi floor of 1; if the caller wants a specific UTXO, the
/// stas3-server v2 will expose a `find_funding(outpoint)` helper.
async fn resolve_token_outpoint_as_funding(
    stas: &Stas3Wallet<HttpWalletJson>,
    _funding_outpoint: &str,
) -> Result<bsv::script::templates::stas3::factory::FundingInput, AppError> {
    // Today the wrapper exposes only auto-pick from the basket. Pick
    // any UTXO with at least 1000 sats; future Wave 2A.x will add a
    // by-outpoint resolver so callers can target an explicit funding
    // UTXO. The route accepts `funding_outpoint` for forward
    // compatibility but is currently equivalent to
    // `stas.pick_fuel(1000)`.
    stas.pick_fuel(1_000).await.map_err(AppError::Stas3)
}

// ---------------------------------------------------------------------------
// Router + main
// ---------------------------------------------------------------------------

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/tokens/transfer", post(handle_transfer))
        .route("/tokens/split", post(handle_split))
        .route("/tokens/merge", post(handle_merge))
        .route("/tokens/redeem", post(handle_redeem))
        .route("/tokens/freeze", post(handle_freeze))
        .route("/tokens/unfreeze", post(handle_unfreeze))
        .route("/tokens/confiscate", post(handle_confiscate))
        .route("/tokens/swap_mark", post(handle_swap_mark))
        .route("/tokens/swap_cancel", post(handle_swap_cancel))
        .route("/tokens/swap_execute", post(handle_swap_execute))
        .route("/tokens/mint", post(handle_mint))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing — `RUST_LOG` overrides; otherwise reasonable defaults.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,stas3_server=debug")),
        )
        .with_target(false)
        .compact()
        .init();

    let wallet_url =
        std::env::var("WALLET_URL").unwrap_or_else(|_| "http://localhost:3321".to_string());
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let originator =
        std::env::var("ORIGINATOR").unwrap_or_else(|_| "stas3-server".to_string());

    info!(%wallet_url, %originator, "configuring HttpWalletJson");
    let wallet = Arc::new(HttpWalletJson::new(&originator, &wallet_url));
    let stas = Arc::new(Stas3Wallet::new(wallet));
    let state = AppState { stas };

    let app = build_router(state);

    let addr: SocketAddr = bind_addr
        .parse()
        .with_context(|| format!("invalid BIND_ADDR {bind_addr:?}"))?;
    info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("shutdown complete");
    Ok(())
}

/// Resolves on the first SIGINT (or SIGTERM on Unix) — graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}
