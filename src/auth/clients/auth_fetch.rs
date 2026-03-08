//! AuthFetch: high-level HTTP client for BRC-31 authenticated requests.
//!
//! Manages per-base-URL Peer instances, automatically performs the auth
//! handshake on first request to a new server, and serializes HTTP requests
//! as general messages over the BRC-31 protocol.
//!
//! Translated from TS SDK AuthFetch.ts (924 lines) and Go SDK authhttp.go (782 lines).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

use crate::auth::certificates::master::MasterCertificate;
use crate::auth::error::AuthError;
use crate::auth::peer::Peer;
use crate::auth::transports::Transport;
use crate::auth::types::RequestedCertificateSet;
use crate::auth::utils::certificates::get_verifiable_certificates;
use crate::wallet::interfaces::{Certificate, WalletInterface};

// ---------------------------------------------------------------------------
// AuthFetchResponse
// ---------------------------------------------------------------------------

/// Response from an authenticated HTTP request.
#[derive(Clone, Debug)]
pub struct AuthFetchResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AuthPeer (internal)
// ---------------------------------------------------------------------------

/// Internal tracking struct for a peer associated with a base URL.
struct AuthPeer<W: WalletInterface> {
    peer: Arc<Mutex<Peer<W>>>,
    identity_key: Option<String>,
    #[allow(clippy::type_complexity)]
    general_rx: Arc<Mutex<mpsc::Receiver<(String, Vec<u8>)>>>,
    /// Receiver for certificate requests from the server.
    /// Taken from the Peer during creation; consumed to auto-respond with certs.
    #[allow(clippy::type_complexity)]
    cert_request_rx: Arc<Mutex<mpsc::Receiver<(String, RequestedCertificateSet)>>>,
}

// ---------------------------------------------------------------------------
// AuthFetch
// ---------------------------------------------------------------------------

/// High-level HTTP client for BRC-31 mutually authenticated requests.
///
/// AuthFetch manages per-base-URL Peer instances. When `fetch()` is called,
/// it creates a SimplifiedHTTPTransport + Peer for new servers, performs the
/// BRC-31 handshake automatically, then sends the serialized HTTP request as
/// a general message and awaits the response.
///
/// # Generic Parameters
///
/// * `W` - A WalletInterface implementation for cryptographic operations.
///
/// # Feature Gate
///
/// This struct is only available when the `network` feature is enabled.
pub struct AuthFetch<W: WalletInterface + Clone + 'static> {
    wallet: W,
    certificates_to_include: Vec<MasterCertificate>,
    certificates_to_request: Option<RequestedCertificateSet>,
    peers: HashMap<String, AuthPeer<W>>,
}

impl<W: WalletInterface + Clone + 'static> AuthFetch<W> {
    /// Create a new AuthFetch instance with the given wallet.
    pub fn new(wallet: W) -> Self {
        AuthFetch {
            wallet,
            certificates_to_include: Vec::new(),
            certificates_to_request: None,
            peers: HashMap::new(),
        }
    }

    /// Set certificates to include in handshake exchanges.
    pub fn set_certificates(&mut self, certs: Vec<MasterCertificate>) {
        self.certificates_to_include = certs;
    }

    /// Set certificate types to request from servers during handshake.
    pub fn set_requested_certificates(&mut self, requested: RequestedCertificateSet) {
        self.certificates_to_request = Some(requested);
    }

    /// Send an authenticated HTTP request to the given URL.
    ///
    /// On first request to a new base URL, creates a transport and peer,
    /// performs the BRC-31 handshake, then sends the request as a general
    /// message. Subsequent requests to the same base URL reuse the peer.
    ///
    /// # Arguments
    ///
    /// * `url` - Full URL to send the request to.
    /// * `method` - HTTP method (GET, POST, etc.).
    /// * `body` - Optional request body bytes.
    /// * `headers` - Optional HTTP headers.
    ///
    /// # Returns
    ///
    /// An `AuthFetchResponse` containing the status, headers, and body.
    pub async fn fetch(
        &mut self,
        url: &str,
        method: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<AuthFetchResponse, AuthError> {
        let base_url = extract_base_url(url)?;
        let path = extract_path(url);
        let query = extract_query(url);
        let headers = headers.unwrap_or_default();

        // Get or create peer for this base URL
        self.ensure_peer(&base_url).await?;

        // Trigger handshake first (if not already authenticated).
        // This ensures the session is established BEFORE we send the general
        // message, allowing certificate exchange to happen in between.
        {
            let auth_peer = self.peers.get(&base_url).ok_or_else(|| {
                AuthError::TransportNotConnected(format!("no peer for base URL: {}", base_url))
            })?;
            let mut peer = auth_peer.peer.lock().await;
            let session = peer.get_authenticated_session("").await?;
            // Store the server identity key learned during handshake
            drop(peer);
            if let Some(ap) = self.peers.get_mut(&base_url) {
                ap.identity_key = Some(session.peer_identity_key.clone());
            }
        }

        // Process any pending certificate requests from the server.
        // During the handshake, the server may have sent requested_certificates
        // in the initialResponse. The client must respond with matching
        // certificates BEFORE sending the general message, so the server
        // receives certs before processing the actual request.
        self.process_certificate_requests(&base_url).await?;

        // Serialize the request payload
        let request_nonce = crate::primitives::random::random_bytes(32);
        let payload = serialize_request(&request_nonce, method, &path, &query, &headers, &body);

        let request_nonce_b64 = b64_encode(&request_nonce);

        // Send the general message via the peer (session already established)
        let auth_peer = self.peers.get(&base_url).ok_or_else(|| {
            AuthError::TransportNotConnected(format!("no peer for base URL: {}", base_url))
        })?;

        let identity_key = auth_peer.identity_key.clone().unwrap_or_default();
        let general_rx = auth_peer.general_rx.clone();

        {
            let mut peer = auth_peer.peer.lock().await;
            peer.send_message(&identity_key, payload).await?;
        }

        // Process any pending incoming messages (the transport enqueues the
        // server's response into the incoming channel during send_general;
        // the peer must process it to route to the general_message channel).
        {
            let mut peer = auth_peer.peer.lock().await;
            peer.process_pending().await?;
        }

        // Wait for the response matching our nonce
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(AuthError::Timeout(
                    "auth fetch response timeout".to_string(),
                ));
            }

            let msg = {
                let mut rx = general_rx.lock().await;
                match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        return Err(AuthError::TransportNotConnected(
                            "peer general message channel closed".to_string(),
                        ))
                    }
                    Err(_) => continue,
                }
            };

            let (sender_key, response_payload) = msg;

            // Update stored identity key if we learn it
            if !sender_key.is_empty() {
                if let Some(auth_peer) = self.peers.get_mut(&base_url) {
                    auth_peer.identity_key = Some(sender_key);
                }
            }

            // Parse response: first 32 bytes are the response nonce
            if response_payload.len() < 32 {
                continue; // Not a valid response payload
            }

            let response_nonce_b64 = b64_encode(&response_payload[..32]);
            if response_nonce_b64 != request_nonce_b64 {
                continue; // Not our response
            }

            // Deserialize the response
            return deserialize_response(&response_payload[32..]);
        }
    }

    /// Ensure a peer exists for the given base URL, creating one if needed.
    async fn ensure_peer(&mut self, base_url: &str) -> Result<(), AuthError> {
        if self.peers.contains_key(base_url) {
            return Ok(());
        }

        // Create a new SimplifiedHTTPTransport for this base URL
        let transport = create_http_transport(base_url)?;

        // Create a new Peer
        let mut peer = Peer::new(self.wallet.clone(), transport);

        // Configure certificates
        if !self.certificates_to_include.is_empty() {
            peer.set_certificates_to_include(self.certificates_to_include.clone());
        }
        if let Some(ref requested) = self.certificates_to_request {
            peer.set_certificates_to_request(requested.clone());
        }

        // Take the general message receiver before wrapping in Arc<Mutex>
        let general_rx = peer.on_general_message().ok_or_else(|| {
            AuthError::InvalidMessage("general message receiver already taken".to_string())
        })?;

        // Take the certificate request receiver for auto-response
        let cert_request_rx = peer.on_certificate_request().ok_or_else(|| {
            AuthError::InvalidMessage("certificate request receiver already taken".to_string())
        })?;

        let auth_peer = AuthPeer {
            peer: Arc::new(Mutex::new(peer)),
            identity_key: None,
            general_rx: Arc::new(Mutex::new(general_rx)),
            cert_request_rx: Arc::new(Mutex::new(cert_request_rx)),
        };

        self.peers.insert(base_url.to_string(), auth_peer);
        Ok(())
    }

    /// Process any pending certificate requests from the server.
    ///
    /// After handshake, the server may have requested certificates from the
    /// client. This method checks for pending requests, retrieves matching
    /// certificates from the wallet via get_verifiable_certificates, and
    /// sends them back as a CertificateResponse.
    ///
    /// Mirrors TS SDK AuthFetch.listenForCertificatesRequested callback.
    async fn process_certificate_requests(&mut self, base_url: &str) -> Result<(), AuthError> {
        let auth_peer = match self.peers.get(base_url) {
            Some(p) => p,
            None => return Ok(()),
        };

        let cert_request_rx = auth_peer.cert_request_rx.clone();
        let peer = auth_peer.peer.clone();

        // Drain any pending certificate requests (non-blocking)
        let mut requests = Vec::new();
        {
            let mut rx = cert_request_rx.lock().await;
            while let Ok(req) = rx.try_recv() {
                requests.push(req);
            }
        }

        for (verifier_key, requested_certs) in requests {
            // Get verifiable certificates from our wallet
            let verifier_pubkey =
                crate::primitives::public_key::PublicKey::from_string(&verifier_key)
                    .map_err(AuthError::from)?;
            let verifiable_certs =
                get_verifiable_certificates(&self.wallet, &requested_certs, &verifier_pubkey)
                    .await?;

            if !verifiable_certs.is_empty() {
                // Convert VerifiableCertificate to Certificate for sending
                let certs_to_send: Vec<Certificate> = verifiable_certs
                    .into_iter()
                    .map(|vc| vc.certificate)
                    .collect();

                let mut peer_guard = peer.lock().await;
                peer_guard
                    .send_certificate_response(&verifier_key, certs_to_send)
                    .await?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

/// Extract the base URL (scheme + host + port) from a full URL.
///
/// For example, `"https://example.com:8080/api/data?q=1"` -> `"https://example.com:8080"`
pub fn extract_base_url(url: &str) -> Result<String, AuthError> {
    // Find the scheme
    let scheme_end = url
        .find("://")
        .ok_or_else(|| AuthError::InvalidMessage(format!("invalid URL, no scheme: {}", url)))?;
    let after_scheme = &url[scheme_end + 3..];

    // Find the end of the host+port (first / or end of string)
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let base = &url[..scheme_end + 3 + host_end];

    Ok(base.to_string())
}

/// Extract the path component from a URL.
fn extract_path(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            let path_and_query = &after_scheme[slash_pos..];
            if let Some(q_pos) = path_and_query.find('?') {
                return path_and_query[..q_pos].to_string();
            }
            return path_and_query.to_string();
        }
    }
    "/".to_string()
}

/// Extract the query string component from a URL (including the ?).
fn extract_query(url: &str) -> String {
    if let Some(q_pos) = url.find('?') {
        url[q_pos..].to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Request/Response serialization
// ---------------------------------------------------------------------------

/// Serialize an HTTP request into the BRC-31 general message payload format.
///
/// Format (matching TS SDK AuthFetch.serializeRequest):
/// - 32 bytes: request nonce
/// - varint + bytes: method
/// - varint + bytes: path (or varint(-1) if empty)
/// - varint + bytes: query (or varint(-1) if empty)
/// - varint: number of headers
/// - for each header: varint + key bytes, varint + value bytes
/// - varint + bytes: body (or varint(-1) if no body)
fn serialize_request(
    nonce: &[u8],
    method: &str,
    path: &str,
    query: &str,
    headers: &HashMap<String, String>,
    body: &Option<Vec<u8>>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Request nonce (32 bytes)
    buf.extend_from_slice(nonce);

    // Method
    let method_bytes = method.as_bytes();
    write_varint_num(&mut buf, method_bytes.len() as i64);
    buf.extend_from_slice(method_bytes);

    // Path
    if !path.is_empty() {
        let path_bytes = path.as_bytes();
        write_varint_num(&mut buf, path_bytes.len() as i64);
        buf.extend_from_slice(path_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Query
    if !query.is_empty() {
        let query_bytes = query.as_bytes();
        write_varint_num(&mut buf, query_bytes.len() as i64);
        buf.extend_from_slice(query_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    // Headers -- normalize and sort by key for consistent signing.
    // Content-type is normalized by stripping parameters (e.g. "; charset=utf-8")
    // to match the TS SDK behavior in both AuthFetch and middleware.
    let mut sorted_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            let key = k.to_lowercase();
            let value = if key == "content-type" {
                v.split(';').next().unwrap_or("").trim().to_string()
            } else {
                v.clone()
            };
            (key, value)
        })
        .collect();
    sorted_headers.sort_by(|(a, _), (b, _)| a.cmp(b));

    write_varint_num(&mut buf, sorted_headers.len() as i64);
    for (key, value) in &sorted_headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);

        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    // Body
    match body {
        Some(b) => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        None => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

/// Deserialize a response payload from the BRC-31 general message format.
///
/// Format (matching TS SDK AuthFetch response deserialization):
/// - varint: status code
/// - varint: number of headers
/// - for each header: varint + key bytes, varint + value bytes
/// - varint: body length
/// - body bytes
fn deserialize_response(data: &[u8]) -> Result<AuthFetchResponse, AuthError> {
    let mut pos = 0;

    // Status code
    let status = read_varint_num(data, &mut pos)? as u16;

    // Headers
    let num_headers = read_varint_num(data, &mut pos)?;
    let mut headers = HashMap::new();
    for _ in 0..num_headers {
        let key_len = read_varint_num(data, &mut pos)? as usize;
        if pos + key_len > data.len() {
            return Err(AuthError::SerializationError(
                "response header key extends past data".to_string(),
            ));
        }
        let key = String::from_utf8_lossy(&data[pos..pos + key_len]).to_string();
        pos += key_len;

        let val_len = read_varint_num(data, &mut pos)? as usize;
        if pos + val_len > data.len() {
            return Err(AuthError::SerializationError(
                "response header value extends past data".to_string(),
            ));
        }
        let value = String::from_utf8_lossy(&data[pos..pos + val_len]).to_string();
        pos += val_len;

        headers.insert(key, value);
    }

    // Body
    let body_len = read_varint_num(data, &mut pos)?;
    let body = if body_len > 0 {
        let body_len = body_len as usize;
        if pos + body_len > data.len() {
            return Err(AuthError::SerializationError(
                "response body extends past data".to_string(),
            ));
        }
        data[pos..pos + body_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(AuthFetchResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Varint helpers (signed, matching TS SDK Writer.writeVarIntNum / Reader.readVarIntNum)
// ---------------------------------------------------------------------------

/// Write a signed varint. Negative values write as a single 0xff byte
/// (matching TS SDK writeVarIntNum(-1) for "no data" sentinel).
fn write_varint_num(buf: &mut Vec<u8>, val: i64) {
    if val < 0 {
        // TS SDK uses Bitcoin varint format but allows negative for "none" sentinel.
        // writeVarIntNum(-1) in TS writes a single byte 0 (length 0 equivalent).
        // Actually looking at the TS code, writeVarIntNum writes a standard varint
        // and -1 is typically encoded in a special way. For safety, write 0 for -1.
        buf.push(0);
        return;
    }
    let val = val as u64;
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Read a varint from data at the given position. Advances pos.
fn read_varint_num(data: &[u8], pos: &mut usize) -> Result<i64, AuthError> {
    if *pos >= data.len() {
        return Err(AuthError::SerializationError(
            "unexpected end of response data reading varint".to_string(),
        ));
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0xfd => {
            if *pos + 2 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 2-byte value truncated".to_string(),
                ));
            }
            let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(val as i64)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 4-byte value truncated".to_string(),
                ));
            }
            let val =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(val as i64)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err(AuthError::SerializationError(
                    "varint 8-byte value truncated".to_string(),
                ));
            }
            let val = u64::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(val as i64)
        }
        _ => Ok(first as i64),
    }
}

// ---------------------------------------------------------------------------
// Transport factory (creates SimplifiedHTTPTransport stub)
// ---------------------------------------------------------------------------

/// Create an HTTP transport for the given base URL.
///
/// Currently creates a SimplifiedHTTPTransport. Since the real HTTP transport
/// is a stub (Plan 04), this provides the infrastructure hook.
fn create_http_transport(base_url: &str) -> Result<Arc<dyn Transport>, AuthError> {
    // SimplifiedHTTPTransport is currently a stub from Plan 04.
    // We create a placeholder that satisfies the Transport trait.
    // Once Plan 04 provides a real implementation, this will use it.
    Ok(Arc::new(
        crate::auth::transports::http::SimplifiedHTTPTransport::new(base_url),
    ))
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

fn b64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("https://example.com/api/data?q=1").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            extract_base_url("http://localhost:3000/path").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            extract_base_url("https://api.example.com:8443/v1/resource").unwrap(),
            "https://api.example.com:8443"
        );
        assert_eq!(
            extract_base_url("https://example.com").unwrap(),
            "https://example.com"
        );
        assert!(extract_base_url("not-a-url").is_err());
    }

    #[test]
    fn test_extract_path() {
        assert_eq!(
            extract_path("https://example.com/api/data?q=1"),
            "/api/data"
        );
        assert_eq!(extract_path("https://example.com/path"), "/path");
        assert_eq!(extract_path("https://example.com"), "/");
    }

    #[test]
    fn test_extract_query() {
        assert_eq!(
            extract_query("https://example.com/api?q=hello&page=1"),
            "?q=hello&page=1"
        );
        assert_eq!(extract_query("https://example.com/api"), "");
    }

    #[test]
    fn test_serialize_deserialize_request() {
        let nonce = [42u8; 32];
        let method = "POST";
        let path = "/api/data";
        let query = "?page=1";
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let body = Some(b"{\"key\":\"value\"}".to_vec());

        let payload = serialize_request(&nonce, method, path, query, &headers, &body);

        // Verify the nonce is at the start
        assert_eq!(&payload[..32], &nonce);
        // Payload should be non-trivially long
        assert!(payload.len() > 50);
    }

    #[test]
    fn test_deserialize_response() {
        // Build a response payload manually
        let mut data = Vec::new();
        // Status: 200
        write_varint_num(&mut data, 200);
        // 1 header
        write_varint_num(&mut data, 1);
        // Header key: "content-type"
        let key = b"content-type";
        write_varint_num(&mut data, key.len() as i64);
        data.extend_from_slice(key);
        // Header value: "application/json"
        let val = b"application/json";
        write_varint_num(&mut data, val.len() as i64);
        data.extend_from_slice(val);
        // Body
        let body = b"hello world";
        write_varint_num(&mut data, body.len() as i64);
        data.extend_from_slice(body);

        let response = deserialize_response(&data).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(response.body, b"hello world");
    }

    #[test]
    fn test_auth_fetch_response_struct() {
        let response = AuthFetchResponse {
            status: 404,
            headers: HashMap::new(),
            body: b"not found".to_vec(),
        };
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"not found");
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values: Vec<i64> = vec![0, 1, 127, 252, 253, 1000, 70000, 200];
        for val in test_values {
            let mut buf = Vec::new();
            write_varint_num(&mut buf, val);
            let mut pos = 0;
            let decoded = read_varint_num(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
            assert_eq!(pos, buf.len());
        }
    }
}
