//! Script template system: traits and implementations for standard Bitcoin scripts.
//!
//! Provides ScriptTemplateLock and ScriptTemplateUnlock traits, plus implementations
//! for P2PKH, PushDrop, and RPuzzle templates. Translates the TS SDK ScriptTemplate.ts
//! and related template classes.

pub mod p2pkh;
pub mod push_drop;
pub mod r_puzzle;

pub use p2pkh::P2PKH;
pub use push_drop::{
    decode as decode_push_drop, push_drop_unlocking_script, LockPosition, PushDrop,
    PushDropData, PushDropSigner, PushDropUnlock,
};
pub use r_puzzle::RPuzzle;

use async_trait::async_trait;

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
/// Both methods are `async`, matching TS, whose `sign` and `estimateLength` both
/// return a `Promise`. Signing is not always a local computation: a wallet-backed
/// template — MPC vault, HSM, remote signer — reaches the key over the network.
/// A synchronous `sign` forces such a template to refuse at RUNTIME, which is a
/// compile-time error wearing a runtime costume. `#[async_trait]` is used rather
/// than a native `async fn` in trait because [`crate::transaction::Transaction`]
/// drives templates as `&dyn ScriptTemplateUnlock`, and native async fns are not
/// dyn-compatible.
///
/// `Send + Sync` are supertraits — as on [`crate::wallet::interfaces::WalletInterface`]
/// — because [`crate::transaction::Transaction::sign`] takes `&dyn
/// ScriptTemplateUnlock` and holds it across an `.await`. Without `Sync` on the
/// trait object that reference is not `Send`, so the whole `Transaction::sign`
/// future is not `Send`, and it cannot be awaited from any `#[async_trait]`
/// method — which is where wallets actually sign. Every template in this crate
/// is plain data or a borrow of a `WalletInterface`, so all of them already
/// qualify.
#[async_trait]
pub trait ScriptTemplateUnlock: Send + Sync {
    /// Sign a transaction input and produce an unlocking script.
    ///
    /// The `preimage` is the sighash preimage bytes that the caller computes
    /// from the transaction context. The template signs this directly.
    async fn sign(&self, preimage: &[u8]) -> Result<UnlockingScript, ScriptError>;

    /// Estimate the byte length of the unlocking script (for fee calculation).
    async fn estimate_length(&self) -> Result<usize, ScriptError>;
}
