//! HTTPWalletWire: sends binary wallet wire frames over HTTP POST.
//!
//! Implements WalletWire by parsing the request frame to extract the
//! call code, mapping it to a URL endpoint, and POSTing the binary
//! payload. The response bytes are returned directly.
//!
//! Translated from Go SDK wallet/substrates/http_wallet_wire.go.
//! Only available with the "network" feature.

use crate::wallet::error::WalletError;
use crate::wallet::serializer::frame::read_request_frame;
use crate::wallet::substrates::wallet_wire_calls::WalletWireCall;
use crate::wallet::substrates::WalletWire;

/// HTTP binary transport for wallet wire protocol.
///
/// Sends the full wire frame payload (without the frame header) to
/// per-method endpoints like `{base_url}/encrypt`, receiving raw
/// binary response bytes.
pub struct HttpWalletWire {
    base_url: String,
    client: reqwest::Client,
}

impl HttpWalletWire {
    /// Create a new HTTP wallet wire transport.
    ///
    /// `base_url` should be the wallet server root, e.g. "http://localhost:3301".
    /// If empty, defaults to "http://localhost:3301".
    pub fn new(base_url: &str) -> Self {
        let url = if base_url.is_empty() {
            "http://localhost:3301".to_string()
        } else {
            base_url.to_string()
        };
        Self {
            base_url: url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl WalletWire for HttpWalletWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, WalletError> {
        // Parse the request frame to get call code and originator
        let frame = read_request_frame(message)?;
        let call = WalletWireCall::try_from(frame.call)?;
        let url = format!("{}/{}", self.base_url, call.to_call_path());

        // POST the raw params payload (not the full frame)
        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(frame.params.clone());

        if !frame.originator.is_empty() {
            request = request.header("Origin", frame.originator.clone());
        }

        let response = request
            .send()
            .await
            .map_err(|e| WalletError::Internal(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(WalletError::Internal(format!(
                "HTTP request failed with status: {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| WalletError::Internal(format!("failed to read response: {}", e)))?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_wallet_wire_construction() {
        let wire = HttpWalletWire::new("http://example.com:3301");
        assert_eq!(wire.base_url, "http://example.com:3301");
    }

    #[test]
    fn test_http_wallet_wire_default_url() {
        let wire = HttpWalletWire::new("");
        assert_eq!(wire.base_url, "http://localhost:3301");
    }
}
