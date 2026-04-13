//! Error types for the auth module.

use thiserror::Error;

/// Unified error type for all authentication operations.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Session not found for the given identity key.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Peer is not authenticated.
    #[error("not authenticated: {0}")]
    NotAuthenticated(String),

    /// Authentication handshake failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Received an invalid or malformed message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Transport is not connected.
    #[error("transport not connected: {0}")]
    TransportNotConnected(String),

    /// Nonce verification failed.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Required certificate is missing.
    #[error("missing certificate: {0}")]
    MissingCertificate(String),

    /// Certificate validation failed.
    #[error("certificate validation error: {0}")]
    CertificateValidation(String),

    /// Transport-level error.
    #[error("transport error: {0}")]
    TransportError(String),

    /// Serialization or deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Error from the wallet layer.
    #[error("wallet error: {0}")]
    Wallet(#[from] crate::wallet::WalletError),

    /// Error from the primitives layer.
    #[error("primitives error: {0}")]
    Primitives(#[from] crate::primitives::PrimitivesError),

    /// Generic payment flow error (bad header, missing tx, etc.).
    #[error("payment flow error: {0}")]
    Payment(String),

    /// Paid request exhausted all retry attempts.
    #[error("paid request failed after {attempts}/{max_attempts} attempts: {message}")]
    PaymentFailed {
        attempts: u32,
        max_attempts: u32,
        message: String,
    },
}
