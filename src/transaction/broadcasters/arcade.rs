//! Arcade broadcaster implementation.
//!
//! Broadcasts transactions to a `bsv-blockchain/arcade` endpoint by POSTing
//! the standard binary tx to `/tx` (no `/v1/` prefix) with
//! `Content-Type: application/octet-stream`. No auth on submit per the
//! Arcade handler source (`services/api_server/handlers.go`).

use async_trait::async_trait;
use reqwest::Client;

use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::Transaction;

/// Configuration for the Arcade broadcaster.
#[derive(Default, Clone)]
pub struct ArcadeConfig {
    /// Optional notification URL for tx status callbacks.
    pub callback_url: Option<String>,
    /// Token sent as `X-CallbackToken` along with the callback URL.
    pub callback_token: Option<String>,
    /// Set to true to request comprehensive status updates on the callback.
    pub full_status_updates: bool,
}

/// Arcade broadcaster.
pub struct Arcade {
    url: String,
    config: ArcadeConfig,
    client: Client,
}

impl Arcade {
    /// Create a new Arcade broadcaster.
    pub fn new(url: &str, config: ArcadeConfig) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            config,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Broadcaster for Arcade {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let bytes = tx.to_bytes().map_err(|e| BroadcastFailure {
            status: 0,
            code: "SERIALIZE_ERROR".to_string(),
            description: format!("failed to serialize transaction: {}", e),
        })?;

        let mut request = self
            .client
            .post(format!("{}/tx", self.url))
            .header("Content-Type", "application/octet-stream")
            .body(bytes);

        if let Some(ref u) = self.config.callback_url {
            request = request.header("X-CallbackUrl", u);
        }
        if let Some(ref t) = self.config.callback_token {
            request = request.header("X-CallbackToken", t);
        }
        if self.config.full_status_updates {
            request = request.header("X-FullStatusUpdates", "true");
        }

        let response = request.send().await.map_err(|e| BroadcastFailure {
            status: 0,
            code: "NETWORK_ERROR".to_string(),
            description: format!("network error: {}", e),
        })?;

        let status = response.status().as_u16() as u32;
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::json!({}));

        if status == 200 || status == 201 || status == 202 {
            let txid = body["txid"].as_str().unwrap_or("").to_string();
            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message: body["txStatus"].as_str().unwrap_or("").to_string(),
            })
        } else {
            Err(BroadcastFailure {
                status,
                code: body["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                description: body["description"]
                    .as_str()
                    .or_else(|| body["message"].as_str())
                    .unwrap_or("unknown error")
                    .to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_test_tx() -> Transaction {
        Transaction::new()
    }

    #[tokio::test]
    async fn test_arcade_posts_to_slash_tx_no_v1() {
        let mock_server = MockServer::start().await;
        let tx = make_test_tx();
        let expected = tx.to_bytes().expect("to_bytes");

        Mock::given(method("POST"))
            .and(path("/tx"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(body_bytes(expected))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "RECEIVED"
            })))
            .mount(&mock_server)
            .await;

        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let resp = arcade.broadcast(&tx).await.expect("broadcast ok");
        assert_eq!(resp.txid, "deadbeef");
    }

    #[tokio::test]
    async fn test_arcade_no_authorization_header() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"txid": "x"})),
            )
            .mount(&mock_server)
            .await;
        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let _ = arcade.broadcast(&make_test_tx()).await;

        let received = mock_server.received_requests().await.expect("requests");
        assert_eq!(received.len(), 1);
        let auth_present = received[0]
            .headers
            .iter()
            .any(|(name, _)| name.as_str().eq_ignore_ascii_case("authorization"));
        assert!(
            !auth_present,
            "Authorization header should be absent on Arcade submit"
        );
    }

    #[tokio::test]
    async fn test_arcade_callback_headers_when_configured() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .and(header("X-CallbackUrl", "https://example/cb"))
            .and(header("X-CallbackToken", "secret"))
            .and(header("X-FullStatusUpdates", "true"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"txid": "x"})),
            )
            .mount(&mock_server)
            .await;
        let cfg = ArcadeConfig {
            callback_url: Some("https://example/cb".into()),
            callback_token: Some("secret".into()),
            full_status_updates: true,
        };
        let arcade = Arcade::new(&mock_server.uri(), cfg);
        let _ = arcade.broadcast(&make_test_tx()).await;
    }
}
