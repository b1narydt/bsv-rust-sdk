//! The sighash preimage — bytes and scope, as one indivisible value.

use std::ops::Deref;

/// A sighash preimage together with the sighash scope it was computed under.
///
/// # Why these two travel as one value
///
/// A Bitcoin signature commits to the scope twice: the scope is serialized into
/// the last four bytes of the preimage that gets hashed and signed, and the same
/// scope is appended as a single byte to the DER signature in the unlocking
/// script. A verifier recomputes the preimage from the byte in the script. If the
/// two disagree the signature is over a message nobody will recompute, and the
/// network rejects it — after the transaction was assembled, broadcast and paid
/// for.
///
/// An earlier revision of this SDK let them disagree by construction:
/// `Transaction::sign` took a `scope` argument and computed the preimage under it,
/// while the script template carried its OWN `sighash_type` field, captured
/// separately, which it stamped into the script. Two values, no binding, and a
/// mismatch that compiled, signed and produced a dead transaction.
///
/// This type is the binding. Its only constructor is
/// [`Transaction::sighash_preimage`](crate::transaction::Transaction::sighash_preimage),
/// which sets [`scope`](Self::scope) to the very `u32` it serialized into
/// [`bytes`](Self::bytes) — so `scope()` is not a second opinion about the
/// preimage, it is a readback of it. Templates hold no scope of their own; they
/// stamp `preimage.scope()`. There is one value, and it is reachable only through
/// the object built from it.
///
/// TS and Go reach the same property differently: their `sign` takes the whole
/// transaction and computes the preimage itself, from a scope the template holds.
/// One value there too — but this port's `sign` receives a preimage rather than a
/// transaction, so the scope must ride along with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SighashPreimage {
    bytes: Vec<u8>,
    scope: u32,
}

impl SighashPreimage {
    /// Bind a preimage to the scope it was computed under.
    ///
    /// Deliberately visible only inside `crate::transaction`: the preimage
    /// serialization is what makes `scope` true, so only the code that performed
    /// that serialization may claim it.
    pub(in crate::transaction) fn new(bytes: Vec<u8>, scope: u32) -> Self {
        Self { bytes, scope }
    }

    /// The preimage bytes — what gets `hash256`'d and signed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The effective sighash scope, exactly as serialized into the preimage's
    /// trailing four bytes. Script templates append `scope() as u8` to the DER.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// Consume the binding, yielding the raw preimage bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Deref for SighashPreimage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for SighashPreimage {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::SighashPreimage;
    use crate::script::locking_script::LockingScript;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};

    /// A REAL preimage for script-template tests, under `scope`.
    ///
    /// Built by [`Transaction::sighash_preimage`] rather than fabricated, so
    /// `scope()` is a readback of the bytes — a test fixture that could set the
    /// two independently would be testing a property this type exists to deny.
    pub(crate) fn preimage_under(scope: u32) -> SighashPreimage {
        let lock = LockingScript::from_binary(&[0x76, 0xa9, 0x14]);
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_transaction: None,
            source_txid: Some("ab".repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffff_ffff,
        });
        tx.add_output(TransactionOutput {
            satoshis: Some(9_000),
            locking_script: lock.clone(),
            change: false,
        });
        tx.sighash_preimage(0, scope, 10_000, &lock)
            .expect("fixture preimage")
    }
}
