//! ARC broadcaster implementation.
//!
//! Broadcasts transactions to an ARC (Bitcoin SV Transaction Processor) service
//! by POSTing the binary EF tx to `/v1/tx` with
//! `Content-Type: application/octet-stream`.
//!
//! ## Canonicality — what this broadcaster matches and what it doesn't
//!
//! `@bsv/sdk` ships **two** distinct ARC-family broadcasters and this Rust
//! port is a hybrid of the two:
//!
//! - **`ARC.ts`** — canonical for the public ARC service. POSTs to
//!   `{URL}/v1/tx` with `Content-Type: application/json` and body
//!   `{rawTx: <hex EF, fallback to plain hex>}`. Auth: `Authorization:
//!   Bearer <key>` when an api-key is set, plus optional callback headers.
//!   Surfaces a fixed list of `txStatus` values (DOUBLE_SPEND_ATTEMPTED,
//!   REJECTED, INVALID, MALFORMED, MINED_IN_STALE_BLOCK) and ORPHAN
//!   substrings as failures even on HTTP 200.
//! - **`Teranode.ts`** — canonical for self-hosted Teranode nodes. POSTs to
//!   `{URL}` (no `/v1/tx` suffix) with `Content-Type: application/octet-
//!   stream` and a binary EF body. No auth.
//!
//! This Rust broadcaster targets ARC's **`/v1/tx` URL** (canonical to
//! `ARC.ts`) but uses **`Teranode.ts`'s binary octet-stream wire format**
//! for the body. ARC's OpenAPI accepts both JSON and octet-stream so this
//! works server-side, but it is **not strict `ARC.ts` parity** — it is a
//! deliberate hybrid. Future maintainers porting parity changes should
//! check the right canonical TS file:
//!   - URL/headers/auth/2xx-failure detection → `ARC.ts`
//!   - Body format (binary EF + octet-stream) → `Teranode.ts`
//!
//! See the bitcoin-sv/arc OpenAPI spec on GitHub
//! (`https://github.com/bitcoin-sv/arc`) for endpoint details.

use async_trait::async_trait;
use reqwest::Client;

use super::util::parse_broadcast_body;
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
    // Use `getrandom` directly (already a direct dep) to avoid pulling in
    // `rand` or `uuid` for what is just a 16-byte non-cryptographic telemetry
    // ID. The `rand` dep was removed in commit 41ff58c — please don't bring
    // it back without checking the dep graph first.
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    let hex = bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{:02x}", b);
        acc
    });
    format!("rust-sdk-{}", hex)
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

        let (status, body) = parse_broadcast_body(response).await?;

        if status == 200 || status == 201 {
            // Canonical TS @bsv/sdk ARC.ts (master, blob bb5b2f181) detects a
            // fixed list of txStatus values that ARC returns with HTTP 200
            // but indicate a broadcast failure. Also matches ORPHAN as a
            // substring in either txStatus or extraInfo (case-insensitive).
            // The Rust port previously reported these as success with txid
            // set, which is dangerous in mint-and-merge flows where a
            // DOUBLE_SPEND_ATTEMPTED would be persisted as confirmed.
            const ERROR_TX_STATUSES: &[&str] = &[
                "DOUBLE_SPEND_ATTEMPTED",
                "REJECTED",
                "INVALID",
                "MALFORMED",
                "MINED_IN_STALE_BLOCK",
            ];

            let tx_status_raw = body["txStatus"].as_str().unwrap_or("");
            let extra_info_raw = body["extraInfo"].as_str().unwrap_or("");
            let tx_status_upper = tx_status_raw.to_ascii_uppercase();
            let extra_info_upper = extra_info_raw.to_ascii_uppercase();
            let is_error_status = ERROR_TX_STATUSES.contains(&tx_status_upper.as_str());
            let is_orphan =
                tx_status_upper.contains("ORPHAN") || extra_info_upper.contains("ORPHAN");

            if is_error_status || is_orphan {
                let body_txid = body["txid"].as_str().unwrap_or("").to_string();
                let code = if tx_status_upper.is_empty() {
                    "UNKNOWN".to_string()
                } else {
                    tx_status_upper.clone()
                };
                let mut description = format!("{} {}", tx_status_raw, extra_info_raw);
                let trimmed_desc = description.trim().to_string();
                description = trimmed_desc;
                // BroadcastFailure has no `more`/`competingTxs` field today
                // (see broadcaster.rs); surface competingTxs in the
                // description so downstream callers can still observe them.
                if let Some(competing) = body.get("competingTxs") {
                    if !competing.is_null() {
                        let competing_str = competing.to_string();
                        if !competing_str.is_empty() && competing_str != "null" {
                            description = if description.is_empty() {
                                format!("competingTxs={}", competing_str)
                            } else {
                                format!("{} competingTxs={}", description, competing_str)
                            };
                        }
                    }
                }
                if !body_txid.is_empty() {
                    description = if description.is_empty() {
                        format!("txid={}", body_txid)
                    } else {
                        format!("{} txid={}", description, body_txid)
                    };
                }
                return Err(BroadcastFailure {
                    status,
                    code,
                    description,
                });
            }

            let txid = body["txid"].as_str().unwrap_or("").to_string();
            if txid.is_empty() {
                return Err(BroadcastFailure {
                    status,
                    code: "MALFORMED_SUCCESS_BODY".to_string(),
                    description: format!(
                        "ARC ({}) returned 2xx but no txid in body: {}",
                        status, body
                    ),
                });
            }
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
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})),
            )
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        arc.broadcast(&make_test_tx_with_source())
            .await
            .expect("broadcast ok");
    }

    #[tokio::test]
    async fn test_arc_sends_authorization_bearer_when_api_key_set() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .and(header("Authorization", "Bearer test-key-123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})),
            )
            .mount(&mock_server)
            .await;
        let cfg = ArcConfig {
            api_key: Some("test-key-123".to_string()),
            ..ArcConfig::default()
        };
        let arc = ARC::new(&mock_server.uri(), cfg);
        arc.broadcast(&make_test_tx_with_source())
            .await
            .expect("broadcast ok");
    }

    #[tokio::test]
    async fn test_arc_no_authorization_header_without_api_key() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"txid": "x"})),
            )
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        arc.broadcast(&make_test_tx_with_source())
            .await
            .expect("broadcast ok");

        let received = mock_server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(received.len(), 1, "expected exactly one request");
        let auth_present = received[0]
            .headers
            .keys()
            .any(|name| name.as_str().eq_ignore_ascii_case("authorization"));
        assert!(
            !auth_present,
            "Authorization header should be absent without api_key"
        );
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
        assert_eq!(err.code, "ERR_BAD_REQUEST");
        assert!(
            err.description.contains("Invalid transaction"),
            "expected description to contain 'Invalid transaction', got: {}",
            err.description
        );
    }

    #[tokio::test]
    async fn test_arc_non_json_body_surfaces_raw_preview() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(
                ResponseTemplate::new(502).set_body_string("<html>502 Bad Gateway</html>"),
            )
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 502);
        // Canonical TS ARC.ts uses response.status.toString() as the code
        // for non-2xx failures; the previous "NON_JSON_BODY" code masked
        // the upstream HTTP status from caller-side retry logic.
        assert_eq!(err.code, "502");
        assert!(
            err.description.starts_with("non-JSON body:"),
            "expected description to start with 'non-JSON body:', got: {}",
            err.description
        );
        assert!(
            err.description.contains("502 Bad Gateway"),
            "expected raw body in description, got: {}",
            err.description
        );
    }

    #[tokio::test]
    async fn test_arc_2xx_with_empty_txid_returns_malformed_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 200);
        assert_eq!(err.code, "MALFORMED_SUCCESS_BODY");
    }

    /// Canonical TS @bsv/sdk ARC.ts treats DOUBLE_SPEND_ATTEMPTED on a
    /// 200 OK as a broadcast failure. Rust must not silently surface it
    /// as success — see fix(sdk): ARC — return BroadcastFailure on 2xx
    /// with error txStatus.
    #[tokio::test]
    async fn test_arc_2xx_with_double_spend_attempted_returns_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "DOUBLE_SPEND_ATTEMPTED",
                "extraInfo": "competing tx already in mempool",
                "competingTxs": ["abc123"]
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 200);
        assert_eq!(err.code, "DOUBLE_SPEND_ATTEMPTED");
        assert!(
            err.description.contains("DOUBLE_SPEND_ATTEMPTED"),
            "expected txStatus in description, got: {}",
            err.description
        );
        assert!(
            err.description.contains("competing tx already in mempool"),
            "expected extraInfo in description, got: {}",
            err.description
        );
        assert!(
            err.description.contains("abc123"),
            "expected competingTxs surfaced in description, got: {}",
            err.description
        );
    }

    /// ARC.ts matches ORPHAN as a substring (case-insensitive) in either
    /// txStatus or extraInfo. Test the extraInfo branch.
    #[tokio::test]
    async fn test_arc_2xx_with_orphan_in_extra_info_returns_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "SEEN_ON_NETWORK",
                "extraInfo": "tx is an orphan: missing parent abc"
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 200);
        // txStatus is non-empty, so the code is the uppercased status
        // (SEEN_ON_NETWORK). The fact that it's a failure comes from
        // ORPHAN substring detection in extraInfo.
        assert_eq!(err.code, "SEEN_ON_NETWORK");
        assert!(
            err.description.contains("orphan")
                || err.description.contains("ORPHAN")
                || err.description.contains("missing parent"),
            "expected orphan/extraInfo in description, got: {}",
            err.description
        );
    }

    /// REJECTED on 200 must be surfaced as a failure with
    /// `code = "REJECTED"`.
    #[tokio::test]
    async fn test_arc_2xx_with_rejected_status_returns_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "REJECTED",
                "extraInfo": "policy violation"
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 200);
        assert_eq!(err.code, "REJECTED");
        assert!(
            err.description.contains("REJECTED"),
            "expected txStatus in description, got: {}",
            err.description
        );
        assert!(
            err.description.contains("policy violation"),
            "expected extraInfo in description, got: {}",
            err.description
        );
    }
}
