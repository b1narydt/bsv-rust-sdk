//! Error types for the wallet module.

use thiserror::Error;

/// Unified error type for all wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Protocol-level error with a numeric code and message.
    #[error("protocol error (code {code}): {message}")]
    Protocol { code: u8, message: String },

    /// Invalid parameter supplied to a wallet operation.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Requested functionality is not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// Internal error wrapping lower-level failures.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<crate::primitives::PrimitivesError> for WalletError {
    fn from(e: crate::primitives::PrimitivesError) -> Self {
        WalletError::Internal(e.to_string())
    }
}

impl From<crate::script::ScriptError> for WalletError {
    fn from(e: crate::script::ScriptError) -> Self {
        WalletError::Internal(e.to_string())
    }
}

impl From<crate::transaction::TransactionError> for WalletError {
    fn from(e: crate::transaction::TransactionError) -> Self {
        WalletError::Internal(e.to_string())
    }
}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Internal(e.to_string())
    }
}
