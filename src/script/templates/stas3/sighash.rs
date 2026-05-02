//! BIP-143 sighash preimage construction for STAS-3 spends.
//!
//! Wraps `Transaction::sighash_preimage` with the STAS-3 default scope
//! (SIGHASH_ALL | SIGHASH_FORKID). The resulting preimage is what slot 19
//! of the unlocking script holds, and is what `wallet.create_signature`
//! signs (after `hash256()` of the preimage).

use super::error::Stas3Error;
use crate::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use crate::script::locking_script::LockingScript;
use crate::transaction::transaction::Transaction;

/// STAS-3 default sighash scope (SIGHASH_ALL | SIGHASH_FORKID = 0x41).
pub const STAS3_SIGHASH_SCOPE: u32 = SIGHASH_ALL | SIGHASH_FORKID;

/// Build the BIP-143 sighash preimage for a STAS-3 input spending `prev_locking_script`.
///
/// Uses the canonical scope (SIGHASH_ALL | SIGHASH_FORKID). Caller hashes
/// the resulting bytes with `hash256` and passes that to `wallet.create_signature`.
pub fn build_preimage(
    tx: &Transaction,
    input_index: usize,
    source_satoshis: u64,
    prev_locking_script: &LockingScript,
) -> Result<Vec<u8>, Stas3Error> {
    tx.sighash_preimage(
        input_index,
        STAS3_SIGHASH_SCOPE,
        source_satoshis,
        prev_locking_script,
    )
    .map_err(|e| Stas3Error::InvalidScript(format!("sighash preimage: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::transaction_input::TransactionInput;
    use crate::transaction::transaction_output::TransactionOutput;

    fn dummy_tx() -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 2;
        tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some("00".repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        tx.outputs.push(TransactionOutput {
            satoshis: Some(1_000),
            locking_script: LockingScript::from_binary(&[0x51]), // OP_1
            change: false,
        });
        tx
    }

    #[test]
    fn test_preimage_uses_canonical_scope() {
        let tx = dummy_tx();
        let lock = LockingScript::from_binary(&[0x51]); // OP_1
        let preimage = build_preimage(&tx, 0, 1_000, &lock).unwrap();
        // Trailing 4 bytes are the sighash type field, little-endian = 0x00000041.
        let n = preimage.len();
        assert!(n >= 4, "preimage too short");
        assert_eq!(
            &preimage[n - 4..],
            &[0x41, 0x00, 0x00, 0x00],
            "trailing sighash type must be 0x41 LE for SIGHASH_ALL|SIGHASH_FORKID"
        );
    }

    #[test]
    fn test_preimage_round_trip_basic() {
        let tx = dummy_tx();
        let lock = LockingScript::from_binary(&[0x51]); // OP_1
        // Should not panic; minimum BIP-143 preimage is 4 (version) + 32 (hashPrevouts)
        // + 32 (hashSequence) + 36 (outpoint) + varint + script + 8 + 4 + 32 + 4 = ~150B+.
        let preimage = build_preimage(&tx, 0, 1_000, &lock).unwrap();
        assert!(preimage.len() > 100, "preimage suspiciously short: {}", preimage.len());
    }

    #[test]
    fn test_scope_constant_is_0x41() {
        assert_eq!(STAS3_SIGHASH_SCOPE, 0x41);
    }
}
