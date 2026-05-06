//! Broadcaster trait and response types for submitting transactions to the BSV network.

use crate::transaction::Transaction;
use async_trait::async_trait;

/// Response from a successful broadcast.
///
/// Mirrors canonical TS `Broadcaster.ts:11-22` shape. Fields beyond the
/// core triple (`status`, `txid`, `message`) are optional and only
/// populated when the upstream service surfaces them — typed so callers
/// can recover them programmatically rather than parsing description text.
#[derive(Debug, Clone, Default)]
pub struct BroadcastResponse {
    /// The status of the broadcast (e.g., "success").
    pub status: String,
    /// The txid of the broadcast transaction.
    pub txid: String,
    /// Optional human-readable message.
    pub message: String,
    /// Competing tx IDs surfaced by ARC's `competingTxs` array. Populated
    /// on `DOUBLE_SPEND_ATTEMPTED` and similar conditions where the
    /// broadcast still succeeded but the network is aware of conflicts.
    /// Mirrors TS `BroadcastResponse.competingTxs?` (`Broadcaster.ts:21`).
    pub competing_txs: Option<Vec<String>>,
}

/// Failure from a broadcast attempt.
///
/// Mirrors canonical TS `Broadcaster.ts:24-34`. Optional fields (`txid`,
/// `competing_txs`, `more`) carry structured upstream metadata so that
/// programmatic callers don't need to regex-parse `description`.
#[derive(Debug, Clone, Default)]
pub struct BroadcastFailure {
    /// HTTP status code (if applicable).
    pub status: u32,
    /// Error code from the service.
    pub code: String,
    /// Human-readable description.
    pub description: String,
    /// Txid echoed by the upstream service on failure (e.g. ARC populates
    /// this on 200-with-error-status to identify which tx the failure
    /// concerns). Mirrors TS `BroadcastFailure.txid?`
    /// (`Broadcaster.ts:30`).
    pub txid: Option<String>,
    /// Competing tx IDs (ARC `DOUBLE_SPEND_ATTEMPTED`). Mirrors TS
    /// `BroadcastFailure.competingTxs?` (`Broadcaster.ts:31`).
    pub competing_txs: Option<Vec<String>>,
    /// Raw upstream JSON body for inspection. Mirrors TS
    /// `BroadcastFailure.more?: object` (`Broadcaster.ts:33`). Useful
    /// when the upstream service surfaces fields that the typed envelope
    /// doesn't accommodate (e.g. ARC's RFC-7807 `instance`, `type`).
    pub more: Option<serde_json::Value>,
}

/// Trait for broadcasting transactions to the BSV network.
///
/// Implementations send a serialized transaction to a network service and return
/// either a success response (containing the txid) or a failure description.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Broadcast the given transaction to the network.
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure>;
}
