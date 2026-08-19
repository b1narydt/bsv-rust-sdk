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
    decode as decode_push_drop, push_drop_unlocking_script, LockPosition, PushDrop, PushDropData,
    PushDropUnlock,
};
pub use r_puzzle::RPuzzle;

use async_trait::async_trait;

use crate::script::error::ScriptError;
use crate::script::{LockingScript, UnlockingScript};
use crate::transaction::sighash_preimage::SighashPreimage;

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
///
/// `sign` is `async`, matching TS, whose `sign` returns a `Promise`. Signing is
/// not always a local computation: a wallet-backed template — MPC vault, HSM,
/// remote signer — reaches the key over the network. A synchronous `sign` forces
/// such a template to refuse at RUNTIME, which is a compile-time error wearing a
/// runtime costume. `#[async_trait]` is used rather than a native `async fn` in
/// trait because [`crate::transaction::Transaction`] drives templates as
/// `&dyn ScriptTemplateUnlock`, and native async fns are not dyn-compatible.
///
/// The trait carries NO supertraits, as in TS (`ScriptTemplateUnlock.sign`) and
/// Go (`UnlockingScriptTemplate.Sign`), which require nothing of implementors.
/// [`crate::transaction::Transaction::sign`] holds its template across an
/// `.await`, and `&T` is `Send` only when `T: Sync`, so it asks for
/// `&(dyn ScriptTemplateUnlock + Sync)` at that ONE call site — the constraint is
/// written where it is needed rather than levied on everyone, and it no longer
/// leaks into `Box<dyn ScriptTemplateUnlock>` or into generic code over
/// `T: ScriptTemplateUnlock`.
///
/// Be aware of what this does NOT buy, though: `#[async_trait]` boxes `sign`'s
/// future as `+ Send`, and that future captures `&self`, so EVERY implementor
/// still has to be `Sync` — a template holding an `Rc` or a `RefCell` cannot
/// implement `sign` no matter what the supertrait list says. Admitting one would
/// mean `#[async_trait(?Send)]`, which makes `Transaction::sign`'s own future
/// non-`Send` and breaks the wallets that await it from inside their own
/// `#[async_trait]` methods. The requirement is real; it just comes from the
/// desugaring, not from here.
#[async_trait]
pub trait ScriptTemplateUnlock {
    /// Sign a transaction input and produce an unlocking script.
    ///
    /// `preimage` carries both the sighash preimage bytes and the scope they were
    /// computed under. Implementors that append a sighash byte to a DER signature
    /// MUST take it from [`SighashPreimage::scope`] — storing a scope of their own
    /// is how a signature ends up committing to one scope and advertising another.
    async fn sign(&self, preimage: &SighashPreimage) -> Result<UnlockingScript, ScriptError>;

    /// Estimate the byte length of the unlocking script (for fee calculation).
    ///
    /// Synchronous: an estimate is arithmetic over the template's own fields, and
    /// no port awaits anything to produce it — Go's is `EstimateLength() uint32`.
    /// TS's returns a Promise only because `Transaction.fee()` awaits it while
    /// passing `(tx, inputIndex)`, parameters this port does not take.
    fn estimate_length(&self) -> Result<usize, ScriptError>;
}
