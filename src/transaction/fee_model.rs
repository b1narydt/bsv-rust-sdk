//! Fee model trait and implementations for Bitcoin transaction fee calculation.
//!
//! Provides the FeeModel trait and the standard SatoshisPerKilobyte implementation
//! that computes transaction fees based on estimated transaction size.

use crate::transaction::error::TransactionError;
use crate::transaction::transaction::Transaction;

/// Trait for computing transaction fees.
///
/// Implementations estimate the fee required for a transaction based on its size
/// or other properties. The standard implementation is SatoshisPerKilobyte.
pub trait FeeModel {
    /// Compute the fee in satoshis for the given transaction.
    fn compute_fee(&self, tx: &Transaction) -> Result<u64, TransactionError>;
}

/// Fee model that charges a fixed rate per kilobyte of transaction size.
///
/// This is the standard BSV fee model. The `value` field represents the
/// number of satoshis per 1000 bytes of transaction data.
#[derive(Debug, Clone, Copy)]
pub struct SatoshisPerKilobyte {
    /// Satoshis per 1000 bytes.
    pub value: u64,
}

impl SatoshisPerKilobyte {
    /// Create a new SatoshisPerKilobyte fee model.
    pub fn new(value: u64) -> Self {
        SatoshisPerKilobyte { value }
    }
}

impl FeeModel for SatoshisPerKilobyte {
    /// Compute the fee based on estimated transaction size.
    ///
    /// For each input: 32 (txid) + 4 (output_index) + 4 (sequence) = 40 bytes fixed,
    /// plus the unlocking script length (or estimated 107 bytes for unsigned P2PKH inputs)
    /// plus the varint overhead for the script length.
    ///
    /// For each output: 8 (satoshis) + script length + varint overhead.
    ///
    /// Transaction overhead: 4 (version) + 4 (locktime) + varint(input_count) + varint(output_count).
    ///
    /// Uses ceiling division: `(size * value + 999) / 1000`.
    fn compute_fee(&self, tx: &Transaction) -> Result<u64, TransactionError> {
        let mut size: u64 = 4; // version

        // Input count varint
        size += varint_size(tx.inputs.len() as u64);

        for input in &tx.inputs {
            size += 40; // txid(32) + output_index(4) + sequence(4)

            let script_length = if let Some(ref script) = input.unlocking_script {
                let bin = script.to_binary();
                bin.len() as u64
            } else {
                // Default estimate for unsigned P2PKH input: ~107 bytes
                107
            };

            size += varint_size(script_length);
            size += script_length;
        }

        // Output count varint
        size += varint_size(tx.outputs.len() as u64);

        for output in &tx.outputs {
            size += 8; // satoshis
            let script_bytes = output.locking_script.to_binary();
            size += varint_size(script_bytes.len() as u64);
            size += script_bytes.len() as u64;
        }

        size += 4; // locktime

        // Ceiling division: (size * value + 999) / 1000
        Ok((size * self.value).div_ceil(1000))
    }
}

/// Compute the byte size of a Bitcoin varint encoding for a given value.
fn varint_size(val: u64) -> u64 {
    if val < 0xfd {
        1
    } else if val <= 0xffff {
        3
    } else if val <= 0xffff_ffff {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::script::templates::p2pkh::P2PKH;
    use crate::script::templates::ScriptTemplateLock;
    use crate::transaction::transaction_input::TransactionInput;
    use crate::transaction::transaction_output::TransactionOutput;

    #[test]
    fn test_fee_model_empty_tx() {
        let model = SatoshisPerKilobyte::new(1000);
        let tx = Transaction::new();
        let fee = model.compute_fee(&tx).unwrap();
        // Empty tx: version(4) + varint_inputs(1) + varint_outputs(1) + locktime(4) = 10 bytes
        // fee = (10 * 1000 + 999) / 1000 = 10
        assert_eq!(fee, 10);
    }

    #[test]
    fn test_fee_model_one_input_one_output() {
        let model = SatoshisPerKilobyte::new(1000);
        let mut tx = Transaction::new();

        // Add unsigned input (will use default 107 estimate)
        tx.add_input(TransactionInput::default());

        // Add P2PKH output (25 bytes script)
        let p2pkh = P2PKH::from_public_key_hash([0xab; 20]);
        let lock_script = p2pkh.lock().unwrap();
        tx.add_output(TransactionOutput {
            satoshis: Some(50000),
            locking_script: lock_script,
            change: false,
        });

        let fee = model.compute_fee(&tx).unwrap();
        // version(4) + varint_inputs(1) + input(40 + varint(107)=1 + 107) + varint_outputs(1) + output(8 + varint(25)=1 + 25) + locktime(4)
        // = 4 + 1 + 148 + 1 + 34 + 4 = 192 bytes
        // fee = (192 * 1000 + 999) / 1000 = 192
        assert_eq!(fee, 192);
    }

    #[test]
    fn test_fee_model_standard_rate() {
        let model = SatoshisPerKilobyte::new(500);
        let tx = Transaction::new();
        let fee = model.compute_fee(&tx).unwrap();
        // 10 bytes * 500 sat/KB = 5000/1000 = 5
        assert_eq!(fee, 5);
    }

    #[test]
    fn test_fee_model_ceiling_division() {
        // Verify ceiling division works: 1 byte * 1 sat/KB = ceil(1/1000) = 1
        let model = SatoshisPerKilobyte::new(1);
        let tx = Transaction::new();
        let fee = model.compute_fee(&tx).unwrap();
        // 10 bytes * 1 sat/KB = ceil(10/1000) = 1
        assert_eq!(fee, 1);
    }

    #[test]
    fn test_fee_model_with_signed_input() {
        let model = SatoshisPerKilobyte::new(1000);
        let mut tx = Transaction::new();

        // Create a signed input with a known unlocking script
        let key = crate::primitives::private_key::PrivateKey::from_hex("1").unwrap();
        let p2pkh = P2PKH::from_private_key(key.clone());
        let unlock = p2pkh.unlock(b"test preimage").unwrap();
        let unlock_len = unlock.to_binary().len() as u64;

        let mut input = TransactionInput::default();
        input.unlocking_script = Some(unlock);
        input.source_txid = Some("00".repeat(32));
        tx.add_input(input);

        let p2pkh_lock = P2PKH::from_public_key_hash([0xab; 20]);
        tx.add_output(TransactionOutput {
            satoshis: Some(50000),
            locking_script: p2pkh_lock.lock().unwrap(),
            change: false,
        });

        let fee = model.compute_fee(&tx).unwrap();

        // Calculate expected: version(4) + varint(1) + input(40 + varint(unlock_len) + unlock_len) + varint(1) + output(8 + varint(25) + 25) + locktime(4)
        let expected_size =
            4 + 1 + (40 + varint_size(unlock_len) + unlock_len) + 1 + (8 + 1 + 25) + 4;
        let expected_fee = (expected_size * 1000).div_ceil(1000);
        assert_eq!(fee, expected_fee);
    }
}
