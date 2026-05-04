//! Internal helpers shared across broadcaster implementations.
//!
//! Centralises body-parse logic so that parse failures are surfaced (instead
//! of swallowed) and that empty-txid responses on a 2xx never silently look
//! like a successful broadcast.

use crate::transaction::broadcaster::BroadcastFailure;

/// Maximum number of body bytes echoed back inside a `BroadcastFailure`
/// description on parse failure. Larger bodies are truncated to keep error
/// messages bounded.
pub(super) const MAX_BODY_PREVIEW_BYTES: usize = 4096;

/// Parse a JSON broadcaster response body, returning the HTTP status and the
/// parsed JSON. On read failure or non-JSON body, returns a
/// [`BroadcastFailure`] carrying the actual HTTP status, a distinct error
/// `code`, and the raw body (truncated to 4 KiB) so operators can debug
/// upstream gateway/HTML-error pages.
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
                .take(MAX_BODY_PREVIEW_BYTES)
                .collect();
            Err(BroadcastFailure {
                status,
                code: "NON_JSON_BODY".to_string(),
                description: format!("response body was not JSON ({e}): {preview}"),
            })
        }
    }
}
