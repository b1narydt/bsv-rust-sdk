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

use super::util::{classify_reqwest_err, parse_broadcast_body, MAX_BODY_PREVIEW_CHARS};
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
    //
    // Do NOT panic on entropy failure: `XDeployment-ID` is a telemetry
    // header. ARC servers ignore non-conforming values, so degrading to a
    // non-unique literal is strictly preferable to crashing the constructor
    // in sandboxed / no-entropy environments (seccomp, embedded targets).
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "rust-sdk-no-entropy".to_string();
    }
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
            ..Default::default()
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

        let response = request.send().await.map_err(|e| {
            let (code, description) = classify_reqwest_err(&e);
            BroadcastFailure {
                status: 0,
                code: code.to_string(),
                description,
                ..Default::default()
            }
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

            // Distinguish "field absent" (Null — acceptable) from "field
            // present but not a string" (Number, Object, …) — the latter is
            // a malformed ARC response that must surface as
            // MALFORMED_SUCCESS_BODY. Real ARC servers always return string
            // txStatus per the bitcoin-sv/arc OpenAPI spec.
            for key in ["txStatus", "extraInfo"] {
                let v = &body[key];
                if !v.is_null() && !v.is_string() {
                    return Err(BroadcastFailure {
                        status,
                        code: "MALFORMED_SUCCESS_BODY".to_string(),
                        description: format!(
                            "ARC ({status}) returned 2xx with non-string `{key}`: {body}"
                        ),
                        ..Default::default()
                    });
                }
            }
            // `competingTxs` must be an array of strings per OpenAPI;
            // anything else (number / object / non-string element) is a
            // malformed body. Validate before extracting.
            let competing = &body["competingTxs"];
            if !competing.is_null() && !competing.is_array() {
                return Err(BroadcastFailure {
                    status,
                    code: "MALFORMED_SUCCESS_BODY".to_string(),
                    description: format!(
                        "ARC ({status}) returned 2xx with non-array `competingTxs`: {body}"
                    ),
                    ..Default::default()
                });
            }
            if let Some(arr) = competing.as_array() {
                if arr.iter().any(|v| !v.is_string()) {
                    return Err(BroadcastFailure {
                        status,
                        code: "MALFORMED_SUCCESS_BODY".to_string(),
                        description: format!(
                            "ARC ({status}) `competingTxs` array element is not a string: {body}"
                        ),
                        ..Default::default()
                    });
                }
            }
            let competing_txs: Option<Vec<String>> = competing.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

            let tx_status_raw = body["txStatus"].as_str().unwrap_or("");
            let extra_info_raw = body["extraInfo"].as_str().unwrap_or("");
            let tx_status_upper = tx_status_raw.to_ascii_uppercase();
            let extra_info_upper = extra_info_raw.to_ascii_uppercase();
            let is_error_status = ERROR_TX_STATUSES.contains(&tx_status_upper.as_str());
            let is_orphan =
                tx_status_upper.contains("ORPHAN") || extra_info_upper.contains("ORPHAN");

            if is_error_status || is_orphan {
                let body_txid = body["txid"]
                    .as_str()
                    .map(String::from)
                    .filter(|s| !s.is_empty());
                let code = if tx_status_upper.is_empty() {
                    "UNKNOWN".to_string()
                } else {
                    tx_status_upper.clone()
                };
                let description = format!("{tx_status_raw} {extra_info_raw}")
                    .trim()
                    .to_string();
                return Err(BroadcastFailure {
                    status,
                    code,
                    description,
                    txid: body_txid,
                    competing_txs,
                    more: Some(body.clone()),
                });
            }

            let txid = body["txid"].as_str().unwrap_or("").to_string();
            if txid.is_empty() {
                return Err(BroadcastFailure {
                    status,
                    code: "MALFORMED_SUCCESS_BODY".to_string(),
                    description: format!("ARC ({status}) returned 2xx but no txid in body: {body}"),
                    ..Default::default()
                });
            }
            // Surface txStatus + extraInfo together (matches canonical TS
            // ARC.ts:182 `message: \`${txStatus} ${extraInfo}\``). With only
            // txStatus, callers lose ARC's human-readable detail (e.g. the
            // mempool reason for a SEEN_ON_NETWORK retry).
            let message = if extra_info_raw.is_empty() {
                tx_status_raw.to_string()
            } else if tx_status_raw.is_empty() {
                extra_info_raw.to_string()
            } else {
                format!("{tx_status_raw} {extra_info_raw}")
            };
            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message,
                competing_txs,
            })
        } else {
            // Non-2xx with valid JSON body.
            //
            // F32-4 (Quaakee): canonical TS ARC.ts:189-195 uses
            // `response.status.toString()` for `code` — Rust now matches.
            // Any structured `body.code` is preserved on `more` so
            // callers can recover it.
            //
            // F32-3 (Quaakee): canonical TS ARC.ts:213-215 reads
            // `body.detail` (RFC-7807 problem-details — what real ARC
            // servers actually emit). Fallback chain `detail → description
            // → title → message` keeps strict canonical-ARC behavior while
            // tolerating self-hosted variants.
            let code = status.to_string();
            let mut description = body["detail"]
                .as_str()
                .or_else(|| body["description"].as_str())
                .or_else(|| body["title"].as_str())
                .or_else(|| body["message"].as_str())
                .map(|s| s.to_string())
                .unwrap_or_default();
            if description.is_empty() {
                let raw = body.to_string();
                let preview: String = raw.chars().take(MAX_BODY_PREVIEW_CHARS).collect();
                description = format!(
                    "ARC ({status}) returned no `detail`/`description`/`title`/`message`; body: {preview}"
                );
            }
            let body_txid = body["txid"]
                .as_str()
                .map(String::from)
                .filter(|s| !s.is_empty());
            Err(BroadcastFailure {
                status,
                code,
                description,
                txid: body_txid,
                more: Some(body.clone()),
                ..Default::default()
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
        // Canonical TS ARC.ts:189-195 uses `response.status.toString()` as
        // the code; structured `body.code` (when present) is preserved on
        // `more`. Cross-SDK retry policies keying on `code` now match.
        assert_eq!(err.code, "400");
        // Body's structured `code` is recoverable via `more`.
        let more = err.more.as_ref().expect("more should carry raw body");
        assert_eq!(more["code"].as_str(), Some("ERR_BAD_REQUEST"));
        assert!(
            err.description.contains("Invalid transaction"),
            "expected description to contain 'Invalid transaction', got: {}",
            err.description
        );
    }

    /// Canonical TS ARC.ts:213-215 reads `body.detail` (RFC-7807 problem-
    /// details — what real ARC servers actually emit). PR previously fell
    /// through to a body preview when `detail` was the only error field.
    #[tokio::test]
    async fn test_arc_failure_uses_rfc7807_detail_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "type": "https://example.com/probs/bad-request",
                "title": "Bad Request",
                "status": 400,
                "detail": "transaction has invalid script"
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.code, "400");
        assert_eq!(err.description, "transaction has invalid script");
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
        // competingTxs is now exposed as a typed Option<Vec<String>> on
        // BroadcastFailure rather than being mangled into the description.
        assert_eq!(
            err.competing_txs.as_deref(),
            Some(&["abc123".to_string()][..])
        );
        // Failure-path txid is also exposed structurally.
        assert_eq!(err.txid.as_deref(), Some("deadbeef"));
    }

    /// `competingTxs` must be a JSON array per the OpenAPI spec; a non-
    /// array (e.g. a stringified array, an integer) must surface as
    /// MALFORMED_SUCCESS_BODY rather than be silently coerced.
    #[tokio::test]
    async fn test_arc_2xx_with_non_array_competing_txs_returns_malformed() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "DOUBLE_SPEND_ATTEMPTED",
                "competingTxs": 42
            })))
            .mount(&mock_server)
            .await;
        let arc = ARC::new(&mock_server.uri(), ArcConfig::default());
        let err = arc
            .broadcast(&make_test_tx_with_source())
            .await
            .unwrap_err();
        assert_eq!(err.code, "MALFORMED_SUCCESS_BODY");
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

    /// `default_deployment_id` is the source of the `XDeployment-ID`
    /// header per ArcConfig. It must (a) match the canonical format
    /// `^rust-sdk-[0-9a-f]{32}$` (16 random bytes hex-encoded), and
    /// (b) yield distinct values on consecutive calls so multiple
    /// concurrent ARC instances don't collide on telemetry.
    #[test]
    fn test_default_deployment_id_is_unique_per_call() {
        let a = default_deployment_id();
        let b = default_deployment_id();

        // Format: literal prefix + exactly 32 lowercase hex chars.
        let re_format = |s: &str| -> bool {
            if let Some(rest) = s.strip_prefix("rust-sdk-") {
                rest.len() == 32
                    && rest
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            } else {
                false
            }
        };
        assert!(
            re_format(&a),
            "deployment_id {:?} did not match ^rust-sdk-[0-9a-f]{{32}}$",
            a
        );
        assert!(
            re_format(&b),
            "deployment_id {:?} did not match ^rust-sdk-[0-9a-f]{{32}}$",
            b
        );

        // Two consecutive calls must differ. With 16 bytes (128 bits) of
        // randomness the collision probability is negligible — a flake
        // here would indicate getrandom is returning constant data.
        assert_ne!(
            a, b,
            "default_deployment_id returned the same value twice — \
             getrandom may be broken"
        );
    }

    /// F32-33 (Quaakee): custom headers configured via `ArcConfig.headers`
    /// must be emitted on the wire. Previously the merge loop was
    /// untested.
    #[tokio::test]
    async fn test_arc_custom_headers_passthrough() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tx"))
            .and(header("X-Custom-A", "alpha"))
            .and(header("X-Custom-B", "beta"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "deadbeef",
                "txStatus": "SEEN_ON_NETWORK"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let cfg = ArcConfig {
            headers: Some(vec![
                ("X-Custom-A".to_string(), "alpha".to_string()),
                ("X-Custom-B".to_string(), "beta".to_string()),
            ]),
            ..ArcConfig::default()
        };
        let arc = ARC::new(&mock_server.uri(), cfg);
        arc.broadcast(&make_test_tx_with_source())
            .await
            .expect("broadcast ok");
        mock_server.verify().await;
    }
}
