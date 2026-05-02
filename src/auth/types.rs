//! Core types for the auth module.
//!
//! Defines AuthMessage, MessageType, PeerSession, protocol constants,
//! and the RequestedCertificateSet type alias.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

/// Auth protocol version.
pub const AUTH_VERSION: &str = "0.1";

/// Protocol ID used for signing auth messages.
pub const AUTH_PROTOCOL_ID: &str = "auth message signature";

/// Protocol ID used for signing certificates.
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";

/// Protocol ID used for encrypting certificate fields.
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";

/// Protocol ID used for HMAC-based nonce operations.
pub const SERVER_HMAC_PROTOCOL: &str = "server hmac";

/// Security level used for nonce HMAC operations.
pub const NONCE_SECURITY_LEVEL: u8 = 2;

// ---------------------------------------------------------------------------
// MessageType
// ---------------------------------------------------------------------------

/// The type of an authentication protocol message.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MessageType {
    /// Initial authentication request from client to server.
    #[cfg_attr(feature = "serde", serde(rename = "initialRequest"))]
    InitialRequest,
    /// Response to an initial authentication request.
    #[cfg_attr(feature = "serde", serde(rename = "initialResponse"))]
    InitialResponse,
    /// Request for certificates from the peer.
    #[cfg_attr(feature = "serde", serde(rename = "certificateRequest"))]
    CertificateRequest,
    /// Response containing requested certificates.
    #[cfg_attr(feature = "serde", serde(rename = "certificateResponse"))]
    CertificateResponse,
    /// General authenticated message after handshake is complete.
    #[cfg_attr(feature = "serde", serde(rename = "general"))]
    General,
}

// ---------------------------------------------------------------------------
// RequestedCertificateSet
// ---------------------------------------------------------------------------

/// A set of certificates being requested from a peer.
///
/// Matches the TS SDK's RequestedCertificateSet wire format:
/// `{ certifiers: string[], types: { [certTypeBase64]: string[] } }`
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestedCertificateSet {
    /// Certifier public keys whose certificates are accepted.
    #[cfg_attr(feature = "serde", serde(default))]
    pub certifiers: Vec<String>,
    /// Maps certificate type (base64) to the list of field names to request.
    #[cfg_attr(feature = "serde", serde(default))]
    pub types: HashMap<String, Vec<String>>,
}

impl RequestedCertificateSet {
    /// Returns true if no certificate types are requested.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Iterate over the requested certificate type keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.types.keys()
    }

    /// Check if a certificate type is in the requested set.
    pub fn contains_key(&self, key: &str) -> bool {
        self.types.contains_key(key)
    }

    /// Get the requested fields for a certificate type.
    pub fn get(&self, key: &str) -> Option<&Vec<String>> {
        self.types.get(key)
    }

    /// Insert a certificate type and its requested fields.
    pub fn insert(&mut self, key: String, fields: Vec<String>) {
        self.types.insert(key, fields);
    }
}

// ---------------------------------------------------------------------------
// AuthMessage
// ---------------------------------------------------------------------------

/// A message in the BRC-31 Authrite authentication protocol.
///
/// All fields match the TS SDK AuthMessage format for wire compatibility.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AuthMessage {
    /// Protocol version string.
    pub version: String,

    /// The type of this message.
    pub message_type: MessageType,

    /// Compressed hex public key of the sender.
    pub identity_key: String,

    /// Base64-encoded nonce created by the sender.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nonce: Option<String>,

    /// The other party's nonce (echoed back in responses).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub your_nonce: Option<String>,

    /// For general messages, references the session's initial nonce.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub initial_nonce: Option<String>,

    /// Certificates to share with the peer.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub certificates: Option<Vec<crate::wallet::interfaces::Certificate>>,

    /// Certificate types and fields being requested from the peer.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub requested_certificates: Option<RequestedCertificateSet>,

    /// General message payload bytes.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub payload: Option<Vec<u8>>,

    /// ECDSA signature over the message.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub signature: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// PeerSession
// ---------------------------------------------------------------------------

/// Tracks the state of an authenticated session with a peer.
#[derive(Clone, Debug)]
pub struct PeerSession {
    /// The nonce that identifies this session.
    pub session_nonce: String,
    /// The peer's compressed hex identity key.
    pub peer_identity_key: String,
    /// The peer's nonce for this session.
    pub peer_nonce: String,
    /// Whether the handshake has completed successfully.
    pub is_authenticated: bool,
}
