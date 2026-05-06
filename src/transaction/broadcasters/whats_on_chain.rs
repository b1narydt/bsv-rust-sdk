//! WhatsOnChain broadcaster implementation.
//!
//! Broadcasts transactions to the WhatsOnChain API by POSTing the raw
//! transaction hex to `/v1/bsv/{network}/tx/raw`.

use async_trait::async_trait;
use reqwest::Client;

use super::util::classify_reqwest_err;
use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::Transaction;

/// WhatsOnChain broadcaster that sends transactions via the WoC API.
pub struct WhatsOnChainBroadcaster {
    network: String,
    client: Client,
}

impl WhatsOnChainBroadcaster {
    /// Create a new WhatsOnChain broadcaster for the given network ("main" or "test").
    pub fn new(network: &str) -> Self {
        Self {
            network: network.to_string(),
            client: Client::new(),
        }
    }

    fn base_url(&self) -> String {
        format!("https://api.whatsonchain.com/v1/bsv/{}", self.network)
    }
}

/// Internal struct allowing URL override for testing.
pub struct WhatsOnChainBroadcasterWithUrl {
    network: String,
    base_url: String,
    client: Client,
}

impl WhatsOnChainBroadcasterWithUrl {
    /// Create with a custom base URL (for testing with mock servers).
    pub fn new(network: &str, base_url: &str) -> Self {
        Self {
            network: network.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }
}

/// Shared broadcast implementation for both `WhatsOnChainBroadcaster` and
/// `WhatsOnChainBroadcasterWithUrl` — guarantees both wrappers stay in sync
/// (e.g. error-code parity, header set, response parsing).
///
/// Failure codes mirror canonical TS `WhatsOnChainBroadcaster.ts:67-69`:
/// non-2xx responses surface the upstream HTTP status as `code` (rather
/// than a generic `BROADCAST_FAILED`) so callers can branch on retryable
/// vs permanent classes (429 vs 4xx) without re-parsing description text.
async fn broadcast_to_woc_url(
    client: &Client,
    url: &str,
    network: &str,
    tx: &Transaction,
) -> Result<BroadcastResponse, BroadcastFailure> {
    let raw_hex = tx.to_hex().map_err(|e| BroadcastFailure {
        status: 0,
        code: "SERIALIZE_ERROR".to_string(),
        description: format!("failed to serialize transaction: {}", e),
        ..Default::default()
    })?;

    let response = client
        .post(url)
        .header("Accept", "text/plain")
        .json(&serde_json::json!({ "txhex": raw_hex }))
        .send()
        .await
        .map_err(|e| {
            let (code, description) = classify_reqwest_err(&e);
            BroadcastFailure {
                status: 0,
                code: code.to_string(),
                description,
                ..Default::default()
            }
        })?;

    let status = response.status().as_u16() as u32;
    let body_text = response.text().await.map_err(|e| {
        let (code, description) = classify_reqwest_err(&e);
        BroadcastFailure {
            status,
            // Body-read failures are mid-stream — usually mid-body timeout or
            // peer reset. Carry the upstream HTTP status (we got a header) and
            // the classified error code.
            code: code.to_string(),
            description: format!("failed to read WoC response body: {description}"),
            ..Default::default()
        }
    })?;

    if status == 200 || status == 201 {
        // WoC returns the txid as plain text (quoted string)
        let txid = body_text.trim().trim_matches('"').to_string();

        // F32-18 (Quaakee): tighten validation. `trim_matches('"')` strips
        // any number of quotes, so a 200 body of `"error: invalid"` would
        // previously slip through as a "success" txid. Real WoC mainnet
        // success bodies are always 64-char hex. STAS3's `wait_for_visibility`
        // path consumes this txid, so a malformed value is poisonous.
        let is_valid_txid = txid.len() == 64 && txid.chars().all(|c| c.is_ascii_hexdigit());
        if !is_valid_txid {
            return Err(BroadcastFailure {
                status,
                code: "MALFORMED_SUCCESS_BODY".to_string(),
                description: format!(
                    "WhatsOnChain ({network} {status}) 2xx body not a 64-char hex txid: {}",
                    truncate_for_preview(&body_text)
                ),
                ..Default::default()
            });
        }

        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid,
            message: String::new(),
            ..Default::default()
        })
    } else {
        Err(BroadcastFailure {
            status,
            code: status.to_string(),
            description: truncate_for_preview(&body_text),
            ..Default::default()
        })
    }
}

#[async_trait]
impl Broadcaster for WhatsOnChainBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let url = format!("{}/tx/raw", self.base_url());
        broadcast_to_woc_url(&self.client, &url, &self.network, tx).await
    }
}

#[async_trait]
impl Broadcaster for WhatsOnChainBroadcasterWithUrl {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let url = format!("{}/v1/bsv/{}/tx/raw", self.base_url, self.network);
        broadcast_to_woc_url(&self.client, &url, &self.network, tx).await
    }
}

/// Truncate a body to ~4 KiB worth of characters for inclusion in error
/// descriptions. Operates on chars (not bytes) so we don't bisect a UTF-8
/// codepoint.
fn truncate_for_preview(s: &str) -> String {
    const MAX_CHARS: usize = 4096;
    if s.chars().count() <= MAX_CHARS {
        return s.to_string();
    }
    s.chars().take(MAX_CHARS).collect()
}

/// Wait for a tx to become visible on WhatsOnChain via GET, with bounded
/// exponential backoff.
///
/// First attempt fires at `t=0`; subsequent attempts back off by an initial
/// gap of 2s that doubles each iteration, clamped by the remaining budget.
/// With `max_wait_secs = 60` the schedule is roughly `t = 0, 2s, 6s, 14s,
/// 30s, 60s` (~5–6 attempts).
///
/// Behaviour per response:
/// - **200**: return `Ok(())` immediately.
/// - **404 / 429 / 5xx / network error**: retryable; sleep + try again.
/// - **400 / 401 / 403**: bail fast with an error carrying the actual
///   status — these are caller-side / auth errors that no amount of waiting
///   will fix, so burning the whole budget is pointless.
///
/// On budget exhaustion, returns a `BroadcastFailure` whose `status` and
/// `description` reflect the **last** observed outcome (HTTP status or
/// network error message) — not a fabricated 404.
///
/// Production callers pass `max_wait_secs` (typically 60); tests use
/// [`wait_for_visibility_against`] for an explicit base URL.
pub async fn wait_for_visibility(txid: &str, max_wait_secs: u64) -> Result<(), BroadcastFailure> {
    wait_for_visibility_against("https://api.whatsonchain.com", "main", txid, max_wait_secs).await
}

/// Test-friendly variant of [`wait_for_visibility`] taking an explicit base
/// URL + network. Production callers should use `wait_for_visibility`.
///
/// See [`wait_for_visibility`] for the retry schedule and bail-fast vs
/// retry behaviour per status code.
pub async fn wait_for_visibility_against(
    base_url: &str,
    network: &str,
    txid: &str,
    max_wait_secs: u64,
) -> Result<(), BroadcastFailure> {
    let url = format!(
        "{}/v1/bsv/{}/tx/{}",
        base_url.trim_end_matches('/'),
        network,
        txid
    );
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs);
    let mut sleep_ms: u64 = 2_000;
    let mut attempts: u32 = 0;
    // Track the outcome of the most recent attempt: either an HTTP status
    // code or a network error message. None until the first attempt finishes.
    enum LastAttempt {
        Status(u16),
        NetworkError(String),
    }
    // The initial `None` is overwritten on the first iteration of the loop
    // below (we always either receive a response or a network error before
    // breaking). Clippy flags this as a dead store; allow it because using
    // a non-`mut` `Option<LastAttempt>` declared after the loop would
    // require unsafe-style "maybe-init" tracking.
    #[allow(unused_assignments)]
    let mut last: Option<LastAttempt> = None;

    loop {
        attempts += 1;
        match client.get(&url).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                last = Some(LastAttempt::Status(s));
                if s == 200 {
                    return Ok(());
                }
                // Bail-fast on caller-side errors — waiting won't fix
                // 400 (bad txid), 401/403 (auth). These exhaust the
                // budget for no benefit.
                if matches!(s, 400 | 401 | 403) {
                    return Err(BroadcastFailure {
                        status: s as u32,
                        code: format!("VISIBILITY_HTTP_{}", s),
                        description: format!(
                            "wait_for_visibility {}: HTTP {} after {} attempt(s); not retrying — caller-side errors aren't recoverable by waiting",
                            url, s, attempts
                        ),
                        ..Default::default()
                    });
                }
                // 404 / 429 / 5xx fall through to retry.
            }
            Err(e) => {
                last = Some(LastAttempt::NetworkError(e.to_string()));
                // Network errors fall through to retry.
            }
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
        let to_sleep = sleep_ms.min(remaining);
        tokio::time::sleep(std::time::Duration::from_millis(to_sleep)).await;
        sleep_ms = sleep_ms.saturating_mul(2);
    }

    let (last_status_for_failure, last_desc) = match &last {
        Some(LastAttempt::Status(s)) => (*s as u32, format!("last status: {}", s)),
        Some(LastAttempt::NetworkError(e)) => (0u32, format!("last network error: {}", e)),
        None => (0u32, "no responses observed".to_string()),
    };
    Err(BroadcastFailure {
        status: last_status_for_failure,
        code: "NOT_VISIBLE".to_string(),
        description: format!(
            "tx {} not visible on WoC after {} attempts within {}s; {}",
            txid, attempts, max_wait_secs, last_desc
        ),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_test_tx() -> Transaction {
        Transaction::new()
    }

    #[tokio::test]
    async fn test_woc_broadcast_success() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/bsv/main/tx/raw"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "\"a3f7d2e1b8c4506f9d2e3a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9\"",
            ))
            .mount(&mock_server)
            .await;

        let broadcaster = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let tx = make_test_tx();
        let result = broadcaster.broadcast(&tx).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(
            resp.txid,
            "a3f7d2e1b8c4506f9d2e3a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9"
        );
        assert_eq!(resp.status, "success");
    }

    #[tokio::test]
    async fn test_woc_sends_accept_text_plain_header() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/bsv/main/tx/raw"))
            .and(matchers::header("Accept", "text/plain"))
            .and(matchers::header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "\"a3f7d2e1b8c4506f9d2e3a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9\"",
            ))
            .mount(&mock_server)
            .await;

        let woc = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let tx = make_test_tx();
        let resp = woc.broadcast(&tx).await.expect("broadcast ok");
        assert_eq!(
            resp.txid,
            "a3f7d2e1b8c4506f9d2e3a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9"
        );
    }

    /// F32-18 (Quaakee): WoC `trim_matches('"')` strips multiple quote
    /// layers; previously a 200 body of `"error: invalid"` would be
    /// accepted as a "success" txid. Tighten validation: only 64-char
    /// lowercase-hex passes.
    #[tokio::test]
    async fn test_woc_2xx_with_non_hex_body_returns_malformed() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/bsv/main/tx/raw"))
            .respond_with(ResponseTemplate::new(200).set_body_string("\"error: invalid\""))
            .mount(&mock_server)
            .await;
        let woc = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let err = woc.broadcast(&make_test_tx()).await.unwrap_err();
        assert_eq!(err.code, "MALFORMED_SUCCESS_BODY");
        assert!(
            err.description.contains("not a 64-char hex txid"),
            "unexpected description: {}",
            err.description
        );
    }

    #[tokio::test]
    async fn test_woc_broadcast_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/bsv/main/tx/raw"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid transaction format"))
            .mount(&mock_server)
            .await;

        let broadcaster = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let tx = make_test_tx();
        let result = broadcaster.broadcast(&tx).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 400);
        // Failure `code` carries the upstream HTTP status (matches canonical
        // ts-sdk WhatsOnChainBroadcaster.ts:67-69), not a generic literal.
        assert_eq!(err.code, "400");
        assert_eq!(err.description, "Invalid transaction format");
    }

    #[tokio::test]
    async fn test_wait_for_visibility_returns_ok_on_first_200() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/bsv/main/tx/abc123"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = wait_for_visibility_against(&mock_server.uri(), "main", "abc123", 60).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_visibility_errors_after_404_exhaustion() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/bsv/main/tx/notfound"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let result = wait_for_visibility_against(&mock_server.uri(), "main", "notfound", 3).await;
        let err = result.unwrap_err();
        assert_eq!(err.code, "NOT_VISIBLE");
        assert_eq!(err.status, 404);
        assert!(
            err.description.contains("last status: 404"),
            "expected description to mention 'last status: 404', got: {}",
            err.description
        );
    }

    #[tokio::test]
    async fn test_wait_for_visibility_succeeds_mid_budget_after_404() {
        let mock_server = MockServer::start().await;
        // First request: 404 (only once).
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/bsv/main/tx/midbudget"))
            .respond_with(ResponseTemplate::new(404))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        // Subsequent requests: 200.
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/bsv/main/tx/midbudget"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = wait_for_visibility_against(&mock_server.uri(), "main", "midbudget", 60).await;
        assert!(
            result.is_ok(),
            "expected Ok after 404 → 200, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_wait_for_visibility_bails_fast_on_401() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/v1/bsv/main/tx/unauth"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let start = std::time::Instant::now();
        // Pass a long budget; if the implementation respects bail-fast,
        // the call should return well under that budget.
        let result = wait_for_visibility_against(&mock_server.uri(), "main", "unauth", 60).await;
        let elapsed = start.elapsed();

        let err = result.unwrap_err();
        assert_eq!(err.status, 401);
        assert_eq!(err.code, "VISIBILITY_HTTP_401");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "expected bail-fast under 5s, took {:?}",
            elapsed
        );
    }

    /// Drives wait_for_visibility's all-network-errors branch by pointing
    /// at a closed local port (TcpListener is bound, then immediately
    /// dropped — the OS may keep the port reserved briefly but inbound
    /// connect() either gets ECONNREFUSED or a request error). On budget
    /// exhaustion the failure should carry status: 0 and the description
    /// must include the "last network error" prefix from the
    /// LastAttempt::NetworkError branch.
    #[tokio::test]
    async fn test_wait_for_visibility_all_network_errors_returns_zero_status() {
        // Bind to ephemeral port, capture the address, then drop the
        // listener so the port is closed. This is the standard "find a
        // dead port" trick that avoids hard-coding a port number which
        // might collide with an actual service.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        let dead_url = format!("http://{}", addr);

        // Short budget so the test doesn't burn 60s. The retry loop will
        // attempt at least once; on failure it sleeps then retries until
        // the deadline.
        let result = wait_for_visibility_against(&dead_url, "main", "abc123", 1).await;

        let err = result.unwrap_err();
        assert_eq!(
            err.status, 0,
            "all-network-error branch must report status 0 (no HTTP \
             response was ever received)"
        );
        assert_eq!(err.code, "NOT_VISIBLE");
        assert!(
            err.description.contains("last network error"),
            "expected description to include 'last network error', got: {}",
            err.description
        );
    }
}
