//! Internal helpers shared across broadcaster implementations.
//!
//! Centralises body-parse logic so that parse failures are surfaced (instead
//! of swallowed) and that empty-txid responses on a 2xx never silently look
//! like a successful broadcast.

use crate::transaction::broadcaster::BroadcastFailure;

/// Maximum number of body characters echoed back inside a `BroadcastFailure`
/// description on parse failure. The bound is enforced via `chars().take(N)`
/// (UTF-8-codepoint-safe), so the unit is chars, not bytes — a body of
/// 4-byte codepoints could legally exceed 4 KiB after the truncation.
/// Larger bodies are truncated to keep error messages bounded.
pub(super) const MAX_BODY_PREVIEW_CHARS: usize = 4096;

/// Parse a JSON broadcaster response body, returning the HTTP status and the
/// parsed JSON. On read failure or non-JSON body, returns a
/// [`BroadcastFailure`] carrying the actual HTTP status, an error `code`, and
/// the raw body (truncated to 4 KiB) so operators can debug upstream
/// gateway / HTML-error pages.
///
/// Error code semantics (matches canonical TS `@bsv/sdk` `ARC.ts` non-2xx
/// path which uses `response.status.toString()` as the code):
/// - **Non-2xx with non-JSON body**: `code = response.status.toString()`
///   (e.g. `"502"`). The "non-JSON body" context lives in the `description`
///   prefix so callers matching on `code` for retry policy can still
///   distinguish a 502 gateway error from a 4xx client error.
/// - **2xx with non-JSON body**: `code = "NON_JSON_BODY"`. The HTTP status
///   (success) carries no useful diagnostic; the malformed body IS the
///   signal, so a synthetic code is the most informative thing to surface.
///
/// Callers are responsible for branching on the returned status (2xx vs
/// otherwise) and for validating the parsed payload (e.g. non-empty txid).
pub(super) async fn parse_broadcast_body(
    response: reqwest::Response,
) -> Result<(u32, serde_json::Value), BroadcastFailure> {
    let status = response.status().as_u16() as u32;
    let bytes = response.bytes().await.map_err(|e| BroadcastFailure {
        status,
        code: "READ_ERROR".to_string(),
        description: format!("failed to read response body: {e}"),
    })?;

    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(v) => Ok((status, v)),
        Err(e) => {
            let preview: String = String::from_utf8_lossy(&bytes)
                .chars()
                .take(MAX_BODY_PREVIEW_CHARS)
                .collect();
            // 2xx success-but-malformed-body is distinct from an HTTP-level
            // failure: surface the synthetic code only when the HTTP status
            // itself isn't a useful error signal. For non-2xx, preserve the
            // upstream status as the code (canonical TS ARC.ts parity).
            let is_success = (200..300).contains(&status);
            let code = if is_success {
                "NON_JSON_BODY".to_string()
            } else {
                status.to_string()
            };
            Err(BroadcastFailure {
                status,
                code,
                description: format!("non-JSON body: ({e}): {preview}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A non-JSON body of >4 KiB must be truncated to MAX_BODY_PREVIEW_CHARS
    /// characters in the failure description, so error messages stay
    /// bounded even when an upstream returns a multi-megabyte HTML
    /// gateway page.
    #[tokio::test]
    async fn test_parse_broadcast_body_truncates_oversized_body() {
        let mock_server = MockServer::start().await;
        // 8192 ASCII bytes (and chars) — twice the cap.
        let oversized: String = "A".repeat(8192);
        Mock::given(method("POST"))
            .and(path("/echo"))
            .respond_with(ResponseTemplate::new(502).set_body_string(oversized.clone()))
            .mount(&mock_server)
            .await;

        let resp = reqwest::Client::new()
            .post(format!("{}/echo", mock_server.uri()))
            .send()
            .await
            .expect("send");
        let err = parse_broadcast_body(resp).await.unwrap_err();

        assert_eq!(err.status, 502);
        // Description format: "non-JSON body: ({serde_err}): {preview}".
        // The preview substring is the `oversized` body truncated to
        // MAX_BODY_PREVIEW_CHARS chars. Total description length must be
        // bounded by MAX_BODY_PREVIEW_CHARS plus a small overhead for the
        // prefix and the serde error message — pick a generous bound
        // (256 chars) since serde error wording can vary across versions.
        const PREFIX_OVERHEAD_BUDGET: usize = 256;
        let upper_bound = MAX_BODY_PREVIEW_CHARS + PREFIX_OVERHEAD_BUDGET;
        let actual_chars = err.description.chars().count();
        assert!(
            actual_chars <= upper_bound,
            "description exceeded MAX_BODY_PREVIEW_CHARS+overhead: \
             {} chars (cap was {} + {} overhead = {})",
            actual_chars,
            MAX_BODY_PREVIEW_CHARS,
            PREFIX_OVERHEAD_BUDGET,
            upper_bound
        );
        // Lower bound: the preview should still contain MAX_BODY_PREVIEW_CHARS
        // 'A's even with the prefix, so the description is at least that
        // long.
        assert!(
            actual_chars >= MAX_BODY_PREVIEW_CHARS,
            "description shorter than MAX_BODY_PREVIEW_CHARS: {} chars",
            actual_chars
        );
        // And the preview must NOT contain all 8192 'A's — exactly
        // MAX_BODY_PREVIEW_CHARS would round-trip if no truncation
        // happened.
        let a_count = err.description.chars().filter(|c| *c == 'A').count();
        assert_eq!(
            a_count, MAX_BODY_PREVIEW_CHARS,
            "expected exactly MAX_BODY_PREVIEW_CHARS 'A's in preview \
             after truncation, got {}",
            a_count
        );
    }
}
