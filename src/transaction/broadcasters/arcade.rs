//! Arcade broadcaster implementation.
//!
//! Broadcasts transactions to a `bsv-blockchain/arcade` endpoint by POSTing
//! the standard binary tx to `/tx` (no `/v1/` prefix) with
//! `Content-Type: application/octet-stream`. No auth on submit per the
//! Arcade handler source (`services/api_server/handlers.go`).
//!
//! ## Response contract
//!
//! Arcade's `POST /tx` handler (main, commit 0a2671c — see
//! `services/api_server/handlers.go:552` and the routes.go `ResponseFormat`
//! doc) returns:
//!
//! - **`202 Accepted`** with body `{"status": "submitted"}`. **No `txid`
//!   field.** The server computes the txid the same way the client does,
//!   so it has nothing to add by echoing it back.
//! - **`4xx` / `5xx`** with body `{"error": "<message>"}`.
//!
//! This broadcaster therefore asserts `status == "submitted"` on a 202 and
//! returns the **locally-computed** canonical txid (`Transaction::id()`).
//! The stale openspec at `services/api_server/openspec/specs/api-server/
//! spec.md` suggests the txid is returned, but the route doc + handler are
//! the source of truth and contradict that.

use async_trait::async_trait;
use reqwest::Client;

use super::util::parse_broadcast_body;
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

        let (status, body) = parse_broadcast_body(response).await?;

        if (200..300).contains(&status) {
            // Arcade returns 202 {"status":"submitted"} with NO txid field
            // (services/api_server/handlers.go:552, main commit 0a2671c).
            // Assert the status, then return the locally-computed txid.
            let body_status = body["status"].as_str().unwrap_or("");
            if body_status != "submitted" {
                return Err(BroadcastFailure {
                    status,
                    code: "MALFORMED_SUCCESS_BODY".to_string(),
                    description: format!(
                        "Arcade ({}) returned 2xx but body status was {:?}, expected \"submitted\": {}",
                        status, body_status, body
                    ),
                });
            }
            let txid = tx.id().map_err(|e| BroadcastFailure {
                status,
                code: "TXID_COMPUTE_ERROR".to_string(),
                description: format!("failed to compute canonical txid: {}", e),
            })?;
            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message: "submitted".to_string(),
            })
        } else {
            // Non-2xx: Arcade returns {"error": "<msg>"} per handlers.go.
            // Use the upstream HTTP status as the failure code (canonical
            // TS @bsv/sdk ARC.ts parity — see parse_broadcast_body docs).
            let description = body["error"]
                .as_str()
                .or_else(|| body["description"].as_str())
                .or_else(|| body["message"].as_str())
                .unwrap_or("unknown error")
                .to_string();
            Err(BroadcastFailure {
                status,
                code: status.to_string(),
                description,
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
        let local_txid = tx.id().expect("id");

        // Canonical Arcade response: 202 {"status":"submitted"}, NO txid
        // field. Client returns the locally-computed canonical txid.
        Mock::given(method("POST"))
            .and(path("/tx"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(body_bytes(expected))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "status": "submitted"
            })))
            .mount(&mock_server)
            .await;

        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let resp = arcade.broadcast(&tx).await.expect("broadcast ok");
        assert_eq!(
            resp.txid, local_txid,
            "Arcade does not echo the txid in its response — the broadcaster \
             must return the locally-computed canonical txid"
        );
        assert_eq!(resp.status, "success");
        assert_eq!(resp.message, "submitted");
    }

    #[tokio::test]
    async fn test_arcade_no_authorization_header() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({"status": "submitted"})),
            )
            .mount(&mock_server)
            .await;
        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        // Asserting on the broadcast result (not `let _ = ...`) so any
        // wiremock matcher / response-shape regression surfaces here
        // instead of silently passing the auth-header assertion below.
        arcade
            .broadcast(&make_test_tx())
            .await
            .expect("broadcast ok");

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
                ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({"status": "submitted"})),
            )
            .mount(&mock_server)
            .await;
        let cfg = ArcadeConfig {
            callback_url: Some("https://example/cb".into()),
            callback_token: Some("secret".into()),
            full_status_updates: true,
        };
        let arcade = Arcade::new(&mock_server.uri(), cfg);
        // Same rationale as test_arcade_no_authorization_header: assert
        // on the result so a header-matcher regression surfaces.
        arcade
            .broadcast(&make_test_tx())
            .await
            .expect("broadcast ok");
    }

    /// A 2xx response that doesn't contain `{"status":"submitted"}` is a
    /// protocol violation (the Arcade handler only ever writes that
    /// payload on accept). Surface it as a malformed-success error so
    /// nobody persists the broadcast as confirmed.
    #[tokio::test]
    async fn test_arcade_2xx_with_status_not_submitted_returns_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"status": "queued"})),
            )
            .mount(&mock_server)
            .await;
        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let err = arcade.broadcast(&make_test_tx()).await.unwrap_err();
        assert_eq!(err.status, 202);
        assert_eq!(err.code, "MALFORMED_SUCCESS_BODY");
        assert!(
            err.description.contains("queued"),
            "expected actual body status surfaced in description, got: {}",
            err.description
        );
    }

    /// 4xx with the canonical `{"error": "..."}` JSON shape per Arcade's
    /// handler must surface the message in the description and the HTTP
    /// status as the code (canonical TS ARC.ts non-2xx parity).
    #[tokio::test]
    async fn test_arcade_4xx_json_error_surfaces_description() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid hex"
            })))
            .mount(&mock_server)
            .await;
        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let err = arcade.broadcast(&make_test_tx()).await.unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.code, "400");
        assert!(
            err.description.contains("invalid hex"),
            "expected upstream error message, got: {}",
            err.description
        );
    }

    /// 5xx with a non-JSON body (e.g. an HTML gateway error page) must
    /// surface the upstream HTTP status as the code and include the body
    /// preview in the description (canonical TS ARC.ts non-2xx parity).
    #[tokio::test]
    async fn test_arcade_5xx_non_json_body_surfaces_status_and_preview() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/tx"))
            .respond_with(
                ResponseTemplate::new(502).set_body_string("<html>502 Bad Gateway</html>"),
            )
            .mount(&mock_server)
            .await;
        let arcade = Arcade::new(&mock_server.uri(), ArcadeConfig::default());
        let err = arcade.broadcast(&make_test_tx()).await.unwrap_err();
        assert_eq!(err.status, 502);
        assert_eq!(err.code, "502");
        assert!(
            err.description.contains("502 Bad Gateway"),
            "expected raw body preview in description, got: {}",
            err.description
        );
    }
}
