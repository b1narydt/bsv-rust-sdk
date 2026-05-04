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
