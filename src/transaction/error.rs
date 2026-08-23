//! Error types for the transaction module.

use thiserror::Error;

/// Unified error type for all transaction operations.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("missing source transaction")]
    MissingSourceTransaction,

    #[error("A reference to an an input transaction is required. If the input transaction itself cannot be referenced, its TXID must still be provided.")]
    MissingInputSourceReference,

    #[error("either satoshis must be defined or change must be set to true")]
    MissingOutputValue,

    #[error("Source transactions or sourceSatoshis are required for all inputs to calculate fee")]
    MissingInputSourceValue,

    #[error("input {input_index} references missing source output {output_index}")]
    MissingSourceOutput {
        input_index: usize,
        output_index: u32,
    },

    #[error("missing unlocking script")]
    MissingUnlockingScript,

    #[error("missing locking script")]
    MissingLockingScript,

    #[error("invalid sighash: {0}")]
    InvalidSighash(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("fee calculation failed: {0}")]
    FeeCalculationFailed(String),

    #[error("merkle path verification failed: {0}")]
    MerklePathVerificationFailed(String),

    #[error("BEEF error: {0}")]
    BeefError(String),

    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("script error: {0}")]
    Script(#[from] crate::script::error::ScriptError),

    #[error("primitives error: {0}")]
    Primitives(#[from] crate::primitives::error::PrimitivesError),
}
