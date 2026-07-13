//! Bitcoin transaction input type.

use std::io::{Read, Write};

use crate::script::unlocking_script::UnlockingScript;
use crate::transaction::error::TransactionError;
use crate::transaction::transaction::Transaction;
use crate::transaction::{read_u32_le, read_varint, write_u32_le, write_varint};

/// A single input in a Bitcoin transaction.
#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// The full source transaction (if available, e.g. from BEEF).
    pub source_transaction: Option<Box<Transaction>>,
    /// The source transaction ID as hex string (display/BE format).
    pub source_txid: Option<String>,
    /// The index of the output being spent.
    pub source_output_index: u32,
    /// The unlocking script (scriptSig).
    pub unlocking_script: Option<UnlockingScript>,
    /// Sequence number (default 0xFFFFFFFF).
    pub sequence: u32,
}

impl Default for TransactionInput {
    fn default() -> Self {
        Self {
            source_transaction: None,
            source_txid: None,
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xFFFFFFFF,
        }
    }
}

impl TransactionInput {
    /// Deserialize a transaction input from binary wire format.
    ///
    /// Wire format: txid(32, reversed) + output_index(4 LE) +
    ///   varint(script_len) + script + sequence(4 LE)
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        // Read 32-byte txid (stored in internal/LE byte order on wire)
        let mut txid_bytes = [0u8; 32];
        reader.read_exact(&mut txid_bytes)?;

        // Reverse to get display/BE format, then hex-encode
        txid_bytes.reverse();
        let source_txid = bytes_to_hex(&txid_bytes);

        // Read output index (4 bytes LE)
        let source_output_index = read_u32_le(reader)?;

        // Read script (varint length + bytes)
        let script_len = read_varint(reader)? as usize;
        let unlocking_script = if script_len > 0 {
            let mut script_bytes = vec![0u8; script_len];
            reader.read_exact(&mut script_bytes)?;
            Some(UnlockingScript::from_binary(&script_bytes))
        } else {
            // Read zero-length script as an empty unlocking script
            Some(UnlockingScript::from_binary(&[]))
        };

        // Read sequence (4 bytes LE)
        let sequence = read_u32_le(reader)?;

        Ok(TransactionInput {
            source_transaction: None,
            source_txid: Some(source_txid),
            source_output_index,
            unlocking_script,
            sequence,
        })
    }

    /// Serialize a transaction input to binary wire format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        // Write TXID in reversed (internal/LE) byte order
        if let Some(ref txid) = self.source_txid {
            let mut txid_bytes = hex_to_bytes(txid)
                .map_err(|e| TransactionError::InvalidFormat(format!("invalid txid hex: {e}")))?;
            txid_bytes.reverse();
            writer.write_all(&txid_bytes)?;
        } else if let Some(ref source_tx) = self.source_transaction {
            // hash() returns LE byte order already
            let hash = source_tx.hash()?;
            writer.write_all(&hash)?;
        } else {
            // Write 32 zero bytes (coinbase or empty)
            writer.write_all(&[0u8; 32])?;
        }

        // Write output index
        write_u32_le(writer, self.source_output_index)?;

        // Write script
        if let Some(ref script) = self.unlocking_script {
            let script_bin = script.to_binary();
            write_varint(writer, script_bin.len() as u64)?;
            writer.write_all(&script_bin)?;
        } else {
            write_varint(writer, 0)?;
        }

        // Write sequence
        write_u32_le(writer, self.sequence)?;

        Ok(())
    }
}

/// Convert a byte slice to a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Convert a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex string".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at position {i}: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}
