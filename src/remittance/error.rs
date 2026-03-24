//! Error types for the remittance subsystem.

/// Errors that can occur during remittance protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum RemittanceError {
    /// Generic protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Attempted an invalid state transition.
    #[error("invalid state transition from '{from}' to '{to}'")]
    InvalidStateTransition {
        /// The state being transitioned from.
        from: String,
        /// The state being transitioned to.
        to: String,
    },

    /// JSON serialization or deserialization failure.
    #[cfg(feature = "network")]
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A wallet operation failed.
    #[error("wallet error: {0}")]
    Wallet(String),

    /// An operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// A requested module was not found in the registry.
    #[error("module not found: {0}")]
    ModuleNotFound(String),

    /// A duplicate message was received.
    #[error("duplicate message: {0}")]
    DuplicateMessage(String),
}
