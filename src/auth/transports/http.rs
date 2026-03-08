//! HTTP transport for BRC-31 authentication.
//!
//! Implements SimplifiedHTTPTransport which sends auth messages via HTTP POST
//! and receives responses. Translates from TS SimplifiedFetchTransport.ts
//! and Go simplified_http_transport.go.

use std::collections::HashMap;

use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::mpsc;

use super::Transport;
use crate::auth::error::AuthError;
use crate::auth::types::{AuthMessage, MessageType};

// ---------------------------------------------------------------------------
// Auth header constants
// ---------------------------------------------------------------------------

/// BSV Auth protocol version header.
pub const HEADER_AUTH_VERSION: &str = "x-bsv-auth-version";

/// Identity key header (compressed hex public key).
pub const HEADER_IDENTITY_KEY: &str = "x-bsv-auth-identity-key";

/// Sender nonce header.
pub const HEADER_NONCE: &str = "x-bsv-auth-nonce";

/// Echoed peer nonce header.
pub const HEADER_YOUR_NONCE: &str = "x-bsv-auth-your-nonce";

/// ECDSA signature header (hex-encoded).
pub const HEADER_SIGNATURE: &str = "x-bsv-auth-signature";

/// Certificates header (JSON).
pub const HEADER_CERTIFICATES: &str = "x-bsv-auth-certificates";

/// Requested certificates header (JSON).
pub const HEADER_REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";

/// Message type header.
pub const HEADER_MESSAGE_TYPE: &str = "x-bsv-auth-message-type";

/// Request ID header.
pub const HEADER_REQUEST_ID: &str = "x-bsv-auth-request-id";

// ---------------------------------------------------------------------------
// SimplifiedHTTPTransport
// ---------------------------------------------------------------------------

/// HTTP transport for BRC-31 authentication.
///
/// For non-general messages (InitialRequest, InitialResponse, etc.), sends
/// JSON POSTs to `{base_url}/.well-known/auth` and parses the JSON response
/// as an AuthMessage.
///
/// For general messages, adds auth headers to the HTTP request and constructs
/// an AuthMessage from the response headers and body.
///
/// Incoming messages are delivered through an mpsc channel obtained via
/// `subscribe()`.
pub struct SimplifiedHTTPTransport {
    base_url: String,
    client: Client,
    /// Sender half for incoming messages.
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Receiver half, wrapped for interior mutability (take-once pattern).
    /// Uses std::sync::Mutex because subscribe() is a sync fn that may be
    /// called from within an async runtime (Peer::new calls it synchronously).
    incoming_rx: std::sync::Mutex<Option<mpsc::Receiver<AuthMessage>>>,
}

impl SimplifiedHTTPTransport {
    /// Create a new SimplifiedHTTPTransport targeting the given base URL.
    ///
    /// Creates an mpsc channel with buffer size 32 for incoming messages.
    pub fn new(base_url: &str) -> Self {
        let (tx, rx) = mpsc::channel(32);
        SimplifiedHTTPTransport {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            incoming_tx: tx,
            incoming_rx: std::sync::Mutex::new(Some(rx)),
        }
    }

    /// Send a non-general auth message (InitialRequest, InitialResponse, etc.)
    /// by POSTing JSON to the `/.well-known/auth` endpoint.
    async fn send_non_general(&self, message: &AuthMessage) -> Result<(), AuthError> {
        let url = format!("{}/.well-known/auth", self.base_url);

        let body = serde_json::to_string(message).map_err(|e| {
            AuthError::SerializationError(format!("failed to serialize auth message: {}", e))
        })?;

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                AuthError::TransportError(format!("HTTP request to {} failed: {}", url, e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            return Err(AuthError::TransportError(format!(
                "HTTP {} from {}: {}",
                status, url, body_text
            )));
        }

        let response_text = response.text().await.map_err(|e| {
            AuthError::TransportError(format!("failed to read response body: {}", e))
        })?;

        if response_text.is_empty() {
            // For messages that don't expect a response body (e.g., CertificateResponse),
            // an empty or non-parseable response is acceptable.
            if message.message_type == MessageType::CertificateResponse
                || message.message_type == MessageType::CertificateRequest
            {
                return Ok(());
            }
            return Err(AuthError::TransportError("empty response body".to_string()));
        }

        // Try to parse as AuthMessage. For certificate messages, the server
        // may return a simple JSON ack that isn't a valid AuthMessage.
        match serde_json::from_str::<AuthMessage>(&response_text) {
            Ok(response_msg) => {
                self.incoming_tx.send(response_msg).await.map_err(|e| {
                    AuthError::TransportError(format!("failed to enqueue incoming message: {}", e))
                })?;
            }
            Err(_) => {
                // Non-AuthMessage response is acceptable for certificate messages
                if message.message_type != MessageType::CertificateResponse
                    && message.message_type != MessageType::CertificateRequest
                {
                    return Err(AuthError::SerializationError(format!(
                        "failed to deserialize auth response: {}",
                        response_text
                    )));
                }
            }
        }

        Ok(())
    }

    /// Send a general authenticated message by adding auth headers to the
    /// HTTP request and constructing a response AuthMessage from the response.
    async fn send_general(&self, message: &AuthMessage) -> Result<(), AuthError> {
        // For general messages, the payload encodes the actual HTTP request.
        // We extract the relevant request data and forward it with auth headers.
        let payload = message.payload.as_ref().ok_or_else(|| {
            AuthError::InvalidMessage("general message missing payload".to_string())
        })?;

        let request = deserialize_request_payload(payload)?;

        let url = format!("{}{}", self.base_url, request.url_postfix);

        let mut req_builder = match request.method.as_str() {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            "PATCH" => self.client.patch(&url),
            "HEAD" => self.client.head(&url),
            other => {
                return Err(AuthError::InvalidMessage(format!(
                    "unsupported HTTP method: {}",
                    other
                )));
            }
        };

        // Add user headers from the deserialized payload
        for (key, value) in &request.headers {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }

        // Add auth headers
        req_builder = req_builder.header(HEADER_AUTH_VERSION, &message.version);
        req_builder = req_builder.header(HEADER_IDENTITY_KEY, &message.identity_key);
        if let Some(ref nonce) = message.nonce {
            req_builder = req_builder.header(HEADER_NONCE, nonce);
        }
        if let Some(ref your_nonce) = message.your_nonce {
            req_builder = req_builder.header(HEADER_YOUR_NONCE, your_nonce);
        }
        if let Some(ref sig) = message.signature {
            req_builder = req_builder.header(HEADER_SIGNATURE, hex_encode(sig));
        }
        req_builder = req_builder.header(HEADER_REQUEST_ID, &request.request_id);

        // Add body if present
        if !request.body.is_empty() {
            req_builder = req_builder.body(request.body.clone());
        }

        let response = req_builder.send().await.map_err(|e| {
            AuthError::TransportError(format!("HTTP request to {} failed: {}", url, e))
        })?;

        // Check for required auth headers in the response
        let version = response
            .headers()
            .get(HEADER_AUTH_VERSION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if version.is_none() {
            let status = response.status();
            let _body_bytes = response.bytes().await.unwrap_or_default();
            return Err(AuthError::TransportError(format!(
                "HTTP {} from {} without valid BSV authentication",
                status, url
            )));
        }

        let identity_key = response
            .headers()
            .get(HEADER_IDENTITY_KEY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let resp_nonce = response
            .headers()
            .get(HEADER_NONCE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let resp_your_nonce = response
            .headers()
            .get(HEADER_YOUR_NONCE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let resp_signature = response
            .headers()
            .get(HEADER_SIGNATURE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| hex_decode(s).ok());

        let message_type_header = response
            .headers()
            .get(HEADER_MESSAGE_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("general");

        let msg_type = if message_type_header == "certificateRequest" {
            MessageType::CertificateRequest
        } else {
            MessageType::General
        };

        let requested_certificates = response
            .headers()
            .get(HEADER_REQUESTED_CERTIFICATES)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        let resp_request_id = response
            .headers()
            .get(HEADER_REQUEST_ID)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let status_code = response.status().as_u16();

        // Collect signed headers: x-bsv-* (excluding x-bsv-auth-*) and authorization
        let mut included_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in response.headers().iter() {
            let lower_name = name.as_str().to_lowercase();
            if let Ok(val_str) = value.to_str() {
                if (lower_name.starts_with("x-bsv-") && !lower_name.starts_with("x-bsv-auth"))
                    || lower_name == "authorization"
                {
                    included_headers.push((lower_name, val_str.to_string()));
                }
            }
        }
        included_headers.sort_by(|a, b| a.0.cmp(&b.0));

        let body_bytes = response.bytes().await.map_err(|e| {
            AuthError::TransportError(format!("failed to read response body: {}", e))
        })?;

        // Build payload matching TS SDK format:
        // requestId (raw bytes from base64) + varint status + headers + body
        let mut payload_out: Vec<u8> = Vec::new();

        // Request ID bytes (base64-decoded)
        if let Some(ref rid) = resp_request_id {
            if let Ok(decoded) = base64_decode(rid) {
                payload_out.extend_from_slice(&decoded);
            }
        }

        // Status code as varint
        write_varint(&mut payload_out, status_code as u64);

        // Number of included headers
        write_varint(&mut payload_out, included_headers.len() as u64);
        for (key, value) in &included_headers {
            let key_bytes = key.as_bytes();
            write_varint(&mut payload_out, key_bytes.len() as u64);
            payload_out.extend_from_slice(key_bytes);
            let value_bytes = value.as_bytes();
            write_varint(&mut payload_out, value_bytes.len() as u64);
            payload_out.extend_from_slice(value_bytes);
        }

        // Body
        write_varint(&mut payload_out, body_bytes.len() as u64);
        if !body_bytes.is_empty() {
            payload_out.extend_from_slice(&body_bytes);
        }

        // SAFETY: version is guaranteed Some -- the is_none() check above returns Err early.
        let response_msg = AuthMessage {
            version: version.unwrap_or_else(|| "0.1".to_string()),
            message_type: msg_type,
            identity_key,
            nonce: resp_nonce,
            your_nonce: resp_your_nonce,
            initial_nonce: None,
            certificates: None,
            requested_certificates,
            payload: Some(payload_out),
            signature: resp_signature,
        };

        self.incoming_tx.send(response_msg).await.map_err(|e| {
            AuthError::TransportError(format!("failed to enqueue incoming message: {}", e))
        })?;

        Ok(())
    }
}

#[async_trait]
impl Transport for SimplifiedHTTPTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        match message.message_type {
            MessageType::General => self.send_general(&message).await,
            _ => self.send_non_general(&message).await,
        }
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .lock()
            .expect("incoming_rx mutex poisoned")
            .take()
            .expect("subscribe() can only be called once per transport")
    }
}

// ---------------------------------------------------------------------------
// Request payload deserialization (matches TS SDK format)
// ---------------------------------------------------------------------------

/// Deserialized HTTP request from an AuthMessage general payload.
struct DeserializedRequest {
    request_id: String,
    method: String,
    url_postfix: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Deserialize a general message payload into an HTTP request structure.
///
/// Wire format (matching TS SDK):
/// - 32 bytes: request ID
/// - varint + bytes: method
/// - varint + bytes: path
/// - varint + bytes: search/query string
/// - varint: number of headers, then for each: varint+key, varint+value
/// - varint + bytes: body
fn deserialize_request_payload(payload: &[u8]) -> Result<DeserializedRequest, AuthError> {
    let mut pos = 0;

    if payload.len() < 32 {
        return Err(AuthError::InvalidMessage(
            "payload too short for request ID".to_string(),
        ));
    }

    // Request ID: first 32 bytes, base64-encoded
    let request_id = base64_encode(&payload[..32]);
    pos += 32;

    // Method
    let (method_len, consumed) = read_varint(&payload[pos..])?;
    pos += consumed;
    let method = if method_len > 0 {
        let end = pos + method_len as usize;
        if end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at method".to_string(),
            ));
        }
        let m = String::from_utf8_lossy(&payload[pos..end]).to_string();
        pos = end;
        m
    } else {
        "GET".to_string()
    };

    // Path
    let (path_len, consumed) = read_varint(&payload[pos..])?;
    pos += consumed;
    let path = if path_len > 0 {
        let end = pos + path_len as usize;
        if end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at path".to_string(),
            ));
        }
        let p = String::from_utf8_lossy(&payload[pos..end]).to_string();
        pos = end;
        p
    } else {
        String::new()
    };

    // Search/query string
    let (search_len, consumed) = read_varint(&payload[pos..])?;
    pos += consumed;
    let search = if search_len > 0 {
        let end = pos + search_len as usize;
        if end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at search".to_string(),
            ));
        }
        let s = String::from_utf8_lossy(&payload[pos..end]).to_string();
        pos = end;
        s
    } else {
        String::new()
    };

    // Headers
    let (n_headers, consumed) = read_varint(&payload[pos..])?;
    pos += consumed;
    let mut headers = HashMap::new();
    for _ in 0..n_headers {
        let (key_len, consumed) = read_varint(&payload[pos..])?;
        pos += consumed;
        let key_end = pos + key_len as usize;
        if key_end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at header key".to_string(),
            ));
        }
        let key = String::from_utf8_lossy(&payload[pos..key_end]).to_string();
        pos = key_end;

        let (val_len, consumed) = read_varint(&payload[pos..])?;
        pos += consumed;
        let val_end = pos + val_len as usize;
        if val_end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at header value".to_string(),
            ));
        }
        let val = String::from_utf8_lossy(&payload[pos..val_end]).to_string();
        pos = val_end;

        headers.insert(key, val);
    }

    // Body
    let (body_len, consumed) = read_varint(&payload[pos..])?;
    pos += consumed;
    let body = if body_len > 0 {
        let end = pos + body_len as usize;
        if end > payload.len() {
            return Err(AuthError::InvalidMessage(
                "payload truncated at body".to_string(),
            ));
        }
        payload[pos..end].to_vec()
    } else {
        Vec::new()
    };

    Ok(DeserializedRequest {
        request_id,
        method,
        url_postfix: format!("{}{}", path, search),
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Varint helpers (Bitcoin-style varint matching TS SDK Reader/Writer)
// ---------------------------------------------------------------------------

/// Read a Bitcoin-style varint from a byte slice.
/// Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Result<(u64, usize), AuthError> {
    if data.is_empty() {
        return Err(AuthError::InvalidMessage(
            "unexpected end of data reading varint".to_string(),
        ));
    }
    match data[0] {
        0..=252 => Ok((data[0] as u64, 1)),
        253 => {
            if data.len() < 3 {
                return Err(AuthError::InvalidMessage(
                    "truncated varint (fd)".to_string(),
                ));
            }
            Ok((u16::from_le_bytes([data[1], data[2]]) as u64, 3))
        }
        254 => {
            if data.len() < 5 {
                return Err(AuthError::InvalidMessage(
                    "truncated varint (fe)".to_string(),
                ));
            }
            Ok((
                u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64,
                5,
            ))
        }
        255 => {
            if data.len() < 9 {
                return Err(AuthError::InvalidMessage(
                    "truncated varint (ff)".to_string(),
                ));
            }
            Ok((
                u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]),
                9,
            ))
        }
    }
}

/// Write a Bitcoin-style varint to a byte vector.
fn write_varint(buf: &mut Vec<u8>, value: u64) {
    if value < 253 {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(253);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        buf.push(254);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(255);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Minimal hex helpers (self-contained, no external crate)
// ---------------------------------------------------------------------------

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for byte in data {
        s.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        s.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, AuthError> {
    if !s.len().is_multiple_of(2) {
        return Err(AuthError::SerializationError(
            "odd-length hex string".to_string(),
        ));
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn hex_nibble(b: u8) -> Result<u8, AuthError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(AuthError::SerializationError(format!(
            "invalid hex char: {}",
            b as char
        ))),
    }
}

// ---------------------------------------------------------------------------
// Minimal base64 helpers (self-contained, no external crate)
// ---------------------------------------------------------------------------

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => {
                return Err(AuthError::SerializationError(format!(
                    "invalid base64 character: {}",
                    ch as char
                )));
            }
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for val in [0u64, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let (decoded, consumed) = read_varint(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello, BRC-31 auth!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_deserialize_request_payload() {
        // Build a minimal payload: 32 bytes request ID + method + path + search + 0 headers + 0 body
        let mut payload = vec![0u8; 32]; // request ID (all zeros)

        // Method: "POST" (4 bytes)
        write_varint(&mut payload, 4);
        payload.extend_from_slice(b"POST");

        // Path: "/api/test" (9 bytes)
        write_varint(&mut payload, 9);
        payload.extend_from_slice(b"/api/test");

        // Search: "?q=1" (4 bytes)
        write_varint(&mut payload, 4);
        payload.extend_from_slice(b"?q=1");

        // 0 headers
        write_varint(&mut payload, 0);

        // Body: "hello" (5 bytes)
        write_varint(&mut payload, 5);
        payload.extend_from_slice(b"hello");

        let req = deserialize_request_payload(&payload).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.url_postfix, "/api/test?q=1");
        assert!(req.headers.is_empty());
        assert_eq!(req.body, b"hello");
    }

    #[tokio::test]
    async fn test_http_transport_send_non_general() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Build a valid AuthMessage JSON response
        let response_body = serde_json::json!({
            "version": "0.1",
            "messageType": "initialResponse",
            "identityKey": "02abc123",
            "nonce": "resp-nonce"
        });

        Mock::given(method("POST"))
            .and(path("/.well-known/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let transport = SimplifiedHTTPTransport::new(&mock_server.uri());

        // Take the receiver before sending
        let mut rx = {
            let mut guard = transport.incoming_rx.lock().await;
            guard.take().unwrap()
        };

        let message = AuthMessage {
            version: "0.1".to_string(),
            message_type: MessageType::InitialRequest,
            identity_key: "02def456".to_string(),
            nonce: Some("test-nonce".to_string()),
            your_nonce: None,
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        };

        transport.send_non_general(&message).await.unwrap();

        // Verify we received the response on the channel
        let received = rx.recv().await.unwrap();
        assert_eq!(received.version, "0.1");
        assert_eq!(received.message_type, MessageType::InitialResponse);
        assert_eq!(received.identity_key, "02abc123");
    }

    #[test]
    fn test_header_constants() {
        assert_eq!(HEADER_AUTH_VERSION, "x-bsv-auth-version");
        assert_eq!(HEADER_IDENTITY_KEY, "x-bsv-auth-identity-key");
        assert_eq!(HEADER_NONCE, "x-bsv-auth-nonce");
        assert_eq!(HEADER_YOUR_NONCE, "x-bsv-auth-your-nonce");
        assert_eq!(HEADER_SIGNATURE, "x-bsv-auth-signature");
        assert_eq!(HEADER_CERTIFICATES, "x-bsv-auth-certificates");
        assert_eq!(
            HEADER_REQUESTED_CERTIFICATES,
            "x-bsv-auth-requested-certificates"
        );
    }
}
