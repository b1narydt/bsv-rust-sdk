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

    /// Insufficient funds for the requested action.
    /// Matches TS SDK `WERR_INSUFFICIENT_FUNDS`.
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),

    /// User must review and approve pending actions.
    /// Matches TS SDK `WERR_REVIEW_ACTIONS`.
    #[error("review actions: {0}")]
    ReviewActions(String),

    /// HMAC verification failed.
    /// Matches TS SDK behavior which throws on invalid HMAC rather than returning false.
    #[error("HMAC is not valid")]
    InvalidHmac,

    /// Signature verification failed.
    /// Matches TS SDK behavior which throws on invalid signature rather than returning false.
    #[error("signature is not valid")]
    InvalidSignature,
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
