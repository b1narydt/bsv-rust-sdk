//! HTTPWalletJSON: sends JSON-encoded wallet args over HTTP POST.
//!
//! Implements WalletInterface directly (not WalletWire) by serializing
//! each method's args to JSON, POSTing to per-method endpoints, and
//! deserializing JSON responses.
//!
//! Translated from Go SDK wallet/substrates/http_wallet_json.go.
//! Only available with the "network" feature.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

/// HTTP JSON transport for wallet interface.
///
/// Each wallet method is mapped to a POST endpoint like
/// `{base_url}/encrypt` with JSON request/response bodies.
pub struct HttpWalletJson {
    base_url: String,
    client: reqwest::Client,
    originator: String,
}

impl HttpWalletJson {
    /// Create a new HTTP JSON wallet transport.
    ///
    /// `base_url` should be the wallet server root, e.g. "http://localhost:3321".
    /// If empty, defaults to "http://localhost:3321".
    pub fn new(originator: &str, base_url: &str) -> Self {
        let url = if base_url.is_empty() {
            "http://localhost:3321".to_string()
        } else {
            base_url.to_string()
        };
        Self {
            base_url: url,
            client: reqwest::Client::new(),
            originator: originator.to_string(),
        }
    }

    /// Make an HTTP POST request to the given call endpoint with JSON body.
    /// If `originator_override` is Some, use it instead of the default originator.
    async fn api(
        &self,
        call: &str,
        body: &[u8],
        originator_override: Option<&str>,
    ) -> Result<Vec<u8>, WalletError> {
        let url = format!("{}/{}", self.base_url, call);

        let originator = originator_override.unwrap_or(&self.originator);

        let mut request = self
            .client
            .post(&url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(body.to_vec());

        if !originator.is_empty() {
            request = request.header("Originator", originator.to_string());
        }

        let response = request
            .send()
            .await
            .map_err(|e| WalletError::Internal(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown".to_string());
            return Err(WalletError::Internal(format!(
                "HTTP request failed with status {}: {}",
                status, body
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| WalletError::Internal(format!("failed to read response: {}", e)))?;
        Ok(bytes.to_vec())
    }
}

/// Helper macro that implements a WalletInterface method for HttpWalletJson.
/// Each method serializes args to JSON, POSTs to the endpoint, and deserializes the result.
/// Uses desugared async-trait form so it works inside #[async_trait] impl blocks.
macro_rules! impl_json_method {
    // Method with args parameter
    ($method:ident, $args_type:ty, $result_type:ty, $endpoint:expr) => {
        fn $method<'life0, 'life1, 'async_trait>(
            &'life0 self,
            args: $args_type,
            originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$result_type, WalletError>> + ::core::marker::Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let json_bytes = serde_json::to_vec(&args)
                    .map_err(|e| WalletError::Internal(format!("JSON serialize failed: {}", e)))?;
                let response = self.api($endpoint, &json_bytes, originator).await?;
                let result: $result_type = serde_json::from_slice(&response)
                    .map_err(|e| WalletError::Internal(format!("JSON deserialize failed: {}", e)))?;
                Ok(result)
            })
        }
    };
    // Method without args parameter (auth/info methods)
    (no_args $method:ident, $result_type:ty, $endpoint:expr) => {
        fn $method<'life0, 'life1, 'async_trait>(
            &'life0 self,
            originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<$result_type, WalletError>> + ::core::marker::Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let json_bytes = b"{}";
                let response = self.api($endpoint, json_bytes, originator).await?;
                let result: $result_type = serde_json::from_slice(&response)
                    .map_err(|e| WalletError::Internal(format!("JSON deserialize failed: {}", e)))?;
                Ok(result)
            })
        }
    };
}

#[async_trait::async_trait]
impl WalletInterface for HttpWalletJson {
    // -- Action methods --
    impl_json_method!(
        create_action,
        CreateActionArgs,
        CreateActionResult,
        "createAction"
    );
    impl_json_method!(sign_action, SignActionArgs, SignActionResult, "signAction");
    impl_json_method!(
        abort_action,
        AbortActionArgs,
        AbortActionResult,
        "abortAction"
    );
    impl_json_method!(
        list_actions,
        ListActionsArgs,
        ListActionsResult,
        "listActions"
    );
    impl_json_method!(
        internalize_action,
        InternalizeActionArgs,
        InternalizeActionResult,
        "internalizeAction"
    );

    // -- Output methods --
    impl_json_method!(
        list_outputs,
        ListOutputsArgs,
        ListOutputsResult,
        "listOutputs"
    );
    impl_json_method!(
        relinquish_output,
        RelinquishOutputArgs,
        RelinquishOutputResult,
        "relinquishOutput"
    );

    // -- Key/Crypto methods --
    impl_json_method!(
        get_public_key,
        GetPublicKeyArgs,
        GetPublicKeyResult,
        "getPublicKey"
    );
    impl_json_method!(
        reveal_counterparty_key_linkage,
        RevealCounterpartyKeyLinkageArgs,
        RevealCounterpartyKeyLinkageResult,
        "revealCounterpartyKeyLinkage"
    );
    impl_json_method!(
        reveal_specific_key_linkage,
        RevealSpecificKeyLinkageArgs,
        RevealSpecificKeyLinkageResult,
        "revealSpecificKeyLinkage"
    );
    impl_json_method!(encrypt, EncryptArgs, EncryptResult, "encrypt");
    impl_json_method!(decrypt, DecryptArgs, DecryptResult, "decrypt");
    impl_json_method!(create_hmac, CreateHmacArgs, CreateHmacResult, "createHmac");
    impl_json_method!(verify_hmac, VerifyHmacArgs, VerifyHmacResult, "verifyHmac");
    impl_json_method!(
        create_signature,
        CreateSignatureArgs,
        CreateSignatureResult,
        "createSignature"
    );
    impl_json_method!(
        verify_signature,
        VerifySignatureArgs,
        VerifySignatureResult,
        "verifySignature"
    );

    // -- Certificate methods --
    impl_json_method!(
        acquire_certificate,
        AcquireCertificateArgs,
        Certificate,
        "acquireCertificate"
    );
    impl_json_method!(
        list_certificates,
        ListCertificatesArgs,
        ListCertificatesResult,
        "listCertificates"
    );
    impl_json_method!(
        prove_certificate,
        ProveCertificateArgs,
        ProveCertificateResult,
        "proveCertificate"
    );
    impl_json_method!(
        relinquish_certificate,
        RelinquishCertificateArgs,
        RelinquishCertificateResult,
        "relinquishCertificate"
    );

    // -- Discovery methods --
    impl_json_method!(
        discover_by_identity_key,
        DiscoverByIdentityKeyArgs,
        DiscoverCertificatesResult,
        "discoverByIdentityKey"
    );
    impl_json_method!(
        discover_by_attributes,
        DiscoverByAttributesArgs,
        DiscoverCertificatesResult,
        "discoverByAttributes"
    );

    // -- Auth/Info methods (no args) --
    impl_json_method!(no_args is_authenticated, AuthenticatedResult, "isAuthenticated");
    impl_json_method!(no_args wait_for_authentication, AuthenticatedResult, "waitForAuthentication");
    impl_json_method!(no_args get_height, GetHeightResult, "getHeight");
    impl_json_method!(
        get_header_for_height,
        GetHeaderArgs,
        GetHeaderResult,
        "getHeaderForHeight"
    );
    impl_json_method!(no_args get_network, GetNetworkResult, "getNetwork");
    impl_json_method!(no_args get_version, GetVersionResult, "getVersion");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_wallet_json_construction() {
        let json = HttpWalletJson::new("test-app", "http://example.com:3321");
        assert_eq!(json.base_url, "http://example.com:3321");
        assert_eq!(json.originator, "test-app");
    }

    #[test]
    fn test_http_wallet_json_default_url() {
        let json = HttpWalletJson::new("app", "");
        assert_eq!(json.base_url, "http://localhost:3321");
    }
}
