//! Script template system: traits and implementations for standard Bitcoin scripts.
//!
//! Provides ScriptTemplateLock and ScriptTemplateUnlock traits, plus implementations
//! for P2PKH, PushDrop, and RPuzzle templates. Translates the TS SDK ScriptTemplate.ts
//! and related template classes.

pub mod p2pkh;
pub mod push_drop;
pub mod r_puzzle;
pub mod stas3;

pub use p2pkh::P2PKH;
pub use push_drop::PushDrop;
pub use r_puzzle::RPuzzle;

use crate::script::error::ScriptError;
use crate::script::{LockingScript, UnlockingScript};

/// Trait for creating locking scripts (analogous to TS SDK ScriptTemplate).
///
/// Implementors produce a LockingScript from configuration stored in the struct.
pub trait ScriptTemplateLock {
    /// Create a locking script from the template's parameters.
    fn lock(&self) -> Result<LockingScript, ScriptError>;
}

/// Trait for creating unlocking scripts (analogous to TS SDK ScriptTemplateUnlock).
///
/// Implementors produce an UnlockingScript and can estimate its byte length
/// for fee calculation purposes.
pub trait ScriptTemplateUnlock {
    /// Sign a transaction input and produce an unlocking script.
    ///
    /// The `preimage` is the sighash preimage bytes that the caller computes
    /// from the transaction context. The template signs this directly.
    fn sign(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError>;

    /// Estimate the byte length of the unlocking script (for fee calculation).
    fn estimate_length(&self) -> Result<usize, ScriptError>;
}
