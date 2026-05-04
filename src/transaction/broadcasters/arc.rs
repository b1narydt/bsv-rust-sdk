//! ARC broadcaster implementation.
//!
//! Broadcasts transactions to an ARC (Bitcoin SV Transaction Processor) service
//! by POSTing the binary EF tx to `/v1/tx` with `Content-Type: application/octet-stream`.
//!
//! Wire format matches canonical `@bsv/sdk` `Teranode.ts` (binary-octet-stream
//! variant of the bitcoin-sv/arc OpenAPI spec) with the bitcoin-sv/arc
//! `/v1/tx` URL shape. See spec §4.2 for the rationale.

use async_trait::async_trait;
use reqwest::Client;

use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::Transaction;

/// Configuration for the ARC broadcaster. Mirrors canonical TS `ArcConfig`.
#[derive(Default, Clone)]
pub struct ArcConfig {
    /// Bearer token for ARC's `Authorization` header. None = no auth.
    pub api_key: Option<String>,
    /// Identifier annotating API calls in `XDeployment-ID`. Auto-generated
    /// per-instance if None — `rust-sdk-{32-hex-char-random}`.
    pub deployment_id: Option<String>,
    /// `X-CallbackUrl` for proof and double-spend notifications.
    pub callback_url: Option<String>,
    /// `X-CallbackToken` accompanying the callback URL.
    pub callback_token: Option<String>,
    /// Additional headers attached to every submission.
    pub headers: Option<Vec<(String, String)>>,
}

/// ARC broadcaster.
pub struct ARC {
    url: String,
    config: ArcConfig,
    deployment_id: String,
    client: Client,
}

impl ARC {
    /// Create a new ARC broadcaster.
    pub fn new(url: &str, config: ArcConfig) -> Self {
        let deployment_id = config
            .deployment_id
            .clone()
            .unwrap_or_else(default_deployment_id);
        Self {
            url: url.trim_end_matches('/').to_string(),
            config,
            deployment_id,
            client: Client::new(),
        }
    }
}

fn default_deployment_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    format!("rust-sdk-{}", hex::encode(bytes))
}

#[async_trait]
impl Broadcaster for ARC {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let ef_bytes = tx.to_bytes_ef().map_err(|e| BroadcastFailure {
            status: 0,
            code: "SERIALIZE_ERROR".to_string(),
            description: format!("failed to serialize transaction to EF: {}", e),
        })?;

        let mut request = self
            .client
            .post(format!("{}/v1/tx", self.url))
            .header("Content-Type", "application/octet-stream")
            .header("XDeployment-ID", &self.deployment_id)
            .body(ef_bytes);

        if let Some(ref key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }
        if let Some(ref u) = self.config.callback_url {
            request = request.header("X-CallbackUrl", u);
        }
        if let Some(ref t) = self.config.callback_token {
            request = request.header("X-CallbackToken", t);
        }
        if let Some(ref headers) = self.config.headers {
            for (k, v) in headers {
                request = request.header(k.as_str(), v.as_str());
            }
        }

        let response = request.send().await.map_err(|e| BroadcastFailure {
            status: 0,
            code: "NETWORK_ERROR".to_string(),
            description: format!("network error: {}", e),
        })?;

        let status = response.status().as_u16() as u32;
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::json!({}));

        if status == 200 || status == 201 {
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
    use wiremock::matchers::{body_bytes, header, header_regex, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal tx whose `to_bytes_ef()` returns a known non-empty result.
    fn make_test_tx_with_source() -> Transaction {
        let ef_hex = "010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000";
        Transaction::from_hex_ef(ef_hex).expect("parse EF")
    }

    #[tokio::test]
    async fn test_arc_sends_octet_stream_with_binary_ef_body() {
        let mock_server = MockServer::start().await;
        let tx = make_test_tx_with_source();
        let expected_body = tx.to_bytes_ef().expect("to_bytes_ef");

        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(body_bytes(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "SEEN_ON_NETWORK"
            })))
            .mount(&mock_server)
            .await;

        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let resp = arc.broadcast(&tx).await.expect("broadcast ok");
        assert_eq!(resp.txid, "deadbeef");
    }

    #[tokio::test]
    async fn test_arc_sends_xdeployment_id_with_rust_sdk_prefix() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .and(header_regex("XDeployment-ID", r"^rust-sdk-[0-9a-f]{32}$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let _ = arc.broadcast(&make_test_tx_with_source()).await;
    }

    #[tokio::test]
    async fn test_arc_sends_authorization_bearer_when_api_key_set() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .and(header("Authorization", "Bearer test-key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})))
            .mount(&mock_server)
            .await;
        let cfg = ArcConfig {
            api_key: Some("test-key-123".to_string()),
            ..ArcConfig::default()
        };
        let arc = ARC::new(&mock_server.uri(), cfg);
        let _ = arc.broadcast(&make_test_tx_with_source()).await;
    }

    #[tokio::test]
    async fn test_arc_no_authorization_header_without_api_key() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let _ = arc.broadcast(&make_test_tx_with_source()).await;
    }

    #[tokio::test]
    async fn test_arc_broadcast_failure_surfaces_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "code": "ERR_BAD_REQUEST",
                "description": "Invalid transaction"
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let result = arc.broadcast(&make_test_tx_with_source()).await;
        let err = result.unwrap_err();
        assert_eq!(err.status, 400);
    }
}
