//! StorageUploader for uploading files via UHRP protocol.
//!
//! Translates the TS SDK StorageUploader.ts. Uploads files using an
//! AuthFetch-based presigned URL flow: POST to negotiate upload, PUT to
//! upload the file, then compute the UHRP URL from the SHA-256 hash.

use std::collections::HashMap;

use crate::auth::clients::auth_fetch::AuthFetch;
use crate::auth::error::AuthError;
use crate::primitives::hash::sha256;
use crate::services::ServicesError;
use crate::wallet::interfaces::WalletInterface;

use super::storage_utils::get_url_for_hash;

/// Configuration for the StorageUploader.
#[derive(Debug, Clone)]
pub struct StorageUploaderConfig {
    /// Base URL for the storage server.
    pub base_url: String,
    /// Default retention period in minutes.
    pub default_retention_period: Option<u64>,
}

impl Default for StorageUploaderConfig {
    fn default() -> Self {
        StorageUploaderConfig {
            base_url: "https://storage.bsvb.tech".into(),
            default_retention_period: None,
        }
    }
}

/// Result from a successful file upload.
#[derive(Debug, Clone)]
pub struct UploadFileResult {
    /// Whether the file was published.
    pub published: bool,
    /// The UHRP URL for the uploaded file.
    pub uhrp_url: String,
}

/// Response from the upload info endpoint.
#[cfg(feature = "serde")]
#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct UploadInfoResponse {
    status: Option<String>,
    #[serde(rename = "uploadURL")]
    upload_url: Option<String>,
    #[serde(rename = "requiredHeaders")]
    required_headers: Option<HashMap<String, String>>,
    #[allow(dead_code)]
    amount: Option<u64>,
}

/// StorageUploader provides authenticated file uploads via the UHRP protocol.
///
/// Uses AuthFetch for the initial upload negotiation (POST) and plain HTTP
/// PUT for the actual upload to a presigned URL.
pub struct StorageUploader<W: WalletInterface + Clone + 'static> {
    auth_fetch: AuthFetch<W>,
    config: StorageUploaderConfig,
}

impl<W: WalletInterface + Clone + 'static> StorageUploader<W> {
    /// Create a new StorageUploader with the given wallet and config.
    pub fn new(wallet: W, config: StorageUploaderConfig) -> Self {
        StorageUploader {
            auth_fetch: AuthFetch::new(wallet),
            config,
        }
    }

    /// Upload file data and return the UHRP URL.
    ///
    /// Flow:
    /// 1. POST to `{base_url}/upload` via AuthFetch to get presigned URL and headers.
    /// 2. PUT data to the presigned URL (plain HTTP, not AuthFetch).
    /// 3. Compute SHA-256 of data, convert to UHRP URL.
    #[cfg(feature = "network")]
    pub async fn upload(
        &mut self,
        data: &[u8],
        content_type: &str,
        retention_period: Option<u64>,
    ) -> Result<UploadFileResult, ServicesError> {
        let retention = retention_period
            .or(self.config.default_retention_period)
            .unwrap_or(525600); // default 1 year in minutes

        // Step 1: negotiate upload via AuthFetch
        let body = serde_json::json!({
            "fileSize": data.len(),
            "retentionPeriod": retention,
        });
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| ServicesError::Serialization(e.to_string()))?;

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let url = format!("{}/upload", self.config.base_url);
        let response = self
            .auth_fetch
            .fetch(&url, "POST", Some(body_bytes), Some(headers))
            .await
            .map_err(|e: AuthError| ServicesError::Auth(e))?;

        if response.status >= 400 {
            return Err(ServicesError::Storage(format!(
                "upload info request failed: HTTP {}",
                response.status
            )));
        }

        let info: UploadInfoResponse = serde_json::from_slice(&response.body)
            .map_err(|e| ServicesError::Serialization(e.to_string()))?;

        if info.status.as_deref() == Some("error") {
            return Err(ServicesError::Storage(
                "upload route returned an error".into(),
            ));
        }

        let upload_url = info
            .upload_url
            .ok_or_else(|| ServicesError::Storage("upload response missing uploadURL".into()))?;
        let required_headers = info.required_headers.unwrap_or_default();

        // Step 2: PUT data to presigned URL (plain HTTP)
        let client = reqwest::Client::new();
        let mut req = client
            .put(&upload_url)
            .header("Content-Type", content_type)
            .body(data.to_vec());

        for (k, v) in &required_headers {
            req = req.header(k, v);
        }

        let put_response = req
            .send()
            .await
            .map_err(|e| ServicesError::Http(e.to_string()))?;

        if !put_response.status().is_success() {
            return Err(ServicesError::Storage(format!(
                "file upload failed: HTTP {}",
                put_response.status()
            )));
        }

        // Step 3: compute UHRP URL from SHA-256 of the data
        let hash = sha256(data);
        let uhrp_url = get_url_for_hash(&hash);

        Ok(UploadFileResult {
            published: true,
            uhrp_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uhrp_url_from_upload_data() {
        // Verify that the UHRP URL computation is correct for known data.
        let data = b"test file content";
        let hash = sha256(data);
        let url = get_url_for_hash(&hash);

        // Should be a valid UHRP URL.
        assert!(super::super::storage_utils::is_valid_url(&url));

        // Roundtrip the hash.
        let recovered = super::super::storage_utils::get_hash_from_url(&url).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_default_config() {
        let config = StorageUploaderConfig::default();
        assert!(config.base_url.contains("storage"));
        assert!(config.default_retention_period.is_none());
    }
}
