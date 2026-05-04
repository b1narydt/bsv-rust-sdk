//! WhatsOnChain broadcaster implementation.
//!
//! Broadcasts transactions to the WhatsOnChain API by POSTing the raw
//! transaction hex to `/v1/bsv/{network}/tx/raw`.

use async_trait::async_trait;
use reqwest::Client;

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

#[async_trait]
impl Broadcaster for WhatsOnChainBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let raw_hex = tx.to_hex().map_err(|e| BroadcastFailure {
            status: 0,
            code: "SERIALIZE_ERROR".to_string(),
            description: format!("failed to serialize transaction: {}", e),
        })?;

        let url = format!("{}/tx/raw", self.base_url());

        let response = self
            .client
            .post(&url)
            .header("Accept", "text/plain")
            .json(&serde_json::json!({ "txhex": raw_hex }))
            .send()
            .await
            .map_err(|e| BroadcastFailure {
                status: 0,
                code: "NETWORK_ERROR".to_string(),
                description: format!("network error: {}", e),
            })?;

        let status = response.status().as_u16() as u32;
        let body_text = response.text().await.unwrap_or_default();

        if status == 200 || status == 201 {
            // WoC returns the txid as plain text (quoted string)
            let txid = body_text.trim().trim_matches('"').to_string();

            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message: String::new(),
            })
        } else {
            Err(BroadcastFailure {
                status,
                code: "BROADCAST_FAILED".to_string(),
                description: body_text,
            })
        }
    }
}

#[async_trait]
impl Broadcaster for WhatsOnChainBroadcasterWithUrl {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let raw_hex = tx.to_hex().map_err(|e| BroadcastFailure {
            status: 0,
            code: "SERIALIZE_ERROR".to_string(),
            description: format!("failed to serialize transaction: {}", e),
        })?;

        let url = format!("{}/v1/bsv/{}/tx/raw", self.base_url, self.network);

        let response = self
            .client
            .post(&url)
            .header("Accept", "text/plain")
            .json(&serde_json::json!({ "txhex": raw_hex }))
            .send()
            .await
            .map_err(|e| BroadcastFailure {
                status: 0,
                code: "NETWORK_ERROR".to_string(),
                description: format!("network error: {}", e),
            })?;

        let status = response.status().as_u16() as u32;
        let body_text = response.text().await.unwrap_or_default();

        if status == 200 || status == 201 {
            let txid = body_text.trim().trim_matches('"').to_string();
            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message: String::new(),
            })
        } else {
            Err(BroadcastFailure {
                status,
                code: "BROADCAST_FAILED".to_string(),
                description: body_text,
            })
        }
    }
}

/// Wait for a tx to become visible on WhatsOnChain via GET, with bounded
/// exponential backoff. Tries at t=0; on 404, sleeps `gap`ms then retries,
/// where `gap` doubles each attempt up to `max_wait_secs`. Returns Ok on
/// first 200 within budget; Err after exhausting attempts.
///
/// Production callers pass `max_wait_secs` (typically 60); tests use
/// [`wait_for_visibility_against`] for an explicit base URL.
pub async fn wait_for_visibility(txid: &str, max_wait_secs: u64) -> Result<(), BroadcastFailure> {
    wait_for_visibility_against("https://api.whatsonchain.com", "main", txid, max_wait_secs).await
}

/// Test-friendly variant of [`wait_for_visibility`] taking an explicit base
/// URL + network. Production callers should use `wait_for_visibility`.
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
    loop {
        attempts += 1;
        let resp = client.get(&url).send().await;
        if let Ok(r) = resp {
            if r.status().as_u16() == 200 {
                return Ok(());
            }
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(BroadcastFailure {
                status: 404,
                code: "NOT_VISIBLE".to_string(),
                description: format!(
                    "tx {} not visible on WoC after {} attempts within {}s",
                    txid, attempts, max_wait_secs
                ),
            });
        }
        let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
        let to_sleep = sleep_ms.min(remaining);
        tokio::time::sleep(std::time::Duration::from_millis(to_sleep)).await;
        sleep_ms = sleep_ms.saturating_mul(2);
    }
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
            .respond_with(ResponseTemplate::new(200).set_body_string("\"abc123def456\""))
            .mount(&mock_server)
            .await;

        let broadcaster = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let tx = make_test_tx();
        let result = broadcaster.broadcast(&tx).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.txid, "abc123def456");
        assert_eq!(resp.status, "success");
    }

    #[tokio::test]
    async fn test_woc_sends_accept_text_plain_header() {
        let mock_server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/bsv/main/tx/raw"))
            .and(matchers::header("Accept", "text/plain"))
            .and(matchers::header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("\"deadbeef\""))
            .mount(&mock_server)
            .await;

        let woc = WhatsOnChainBroadcasterWithUrl::new("main", &mock_server.uri());
        let tx = make_test_tx();
        let resp = woc.broadcast(&tx).await.expect("broadcast ok");
        assert_eq!(resp.txid, "deadbeef");
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
        assert!(result.is_err());
    }
}
