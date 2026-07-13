//! BeefTx: a single transaction within a BEEF validity proof set.
//!
//! Wraps a Transaction with BEEF metadata (bump index, txid-only support).
//! Supports V1 and V2 binary serialization formats.

use std::io::{Read, Write};

use crate::primitives::utils::{from_hex, to_hex};
use crate::transaction::error::TransactionError;
use crate::transaction::transaction::Transaction;
use crate::transaction::{read_varint, write_varint};

/// Format marker for transactions in BEEF V2 format (BRC-96).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDataFormat {
    /// Raw transaction without BUMP proof.
    RawTx = 0,
    /// Raw transaction with a BUMP index.
    RawTxAndBumpIndex = 1,
    /// Transaction represented by txid only (no raw data).
    TxidOnly = 2,
}

impl TxDataFormat {
    /// Convert a u8 byte to a TxDataFormat variant.
    pub fn from_byte(b: u8) -> Result<Self, TransactionError> {
        match b {
            0 => Ok(TxDataFormat::RawTx),
            1 => Ok(TxDataFormat::RawTxAndBumpIndex),
            2 => Ok(TxDataFormat::TxidOnly),
            _ => Err(TransactionError::InvalidFormat(format!(
                "unknown TxDataFormat byte: {b}"
            ))),
        }
    }
}

/// A single bitcoin transaction associated with a BEEF validity proof set.
///
/// Simple case: transaction data included directly as a full Transaction.
/// Supports "known" transactions represented by just their txid.
#[derive(Debug, Clone)]
pub struct BeefTx {
    /// The transaction (None if txid-only format).
    pub tx: Option<Transaction>,
    /// TXID hex (big-endian display format).
    pub txid: String,
    /// BUMP index into the Beef.bumps array (None if no proof).
    pub bump_index: Option<usize>,
    /// List of input txids this transaction depends on.
    pub input_txids: Vec<String>,
}

impl BeefTx {
    /// Create a BeefTx from a full Transaction.
    pub fn from_tx(tx: Transaction, bump_index: Option<usize>) -> Result<Self, TransactionError> {
        let txid = tx.id()?;
        let input_txids = if bump_index.is_some() {
            Vec::new()
        } else {
            Self::collect_input_txids(&tx)
        };
        Ok(BeefTx {
            tx: Some(tx),
            txid,
            bump_index,
            input_txids,
        })
    }

    /// Create a BeefTx from a txid only (no raw transaction data).
    pub fn from_txid(txid: String) -> Self {
        BeefTx {
            tx: None,
            txid,
            bump_index: None,
            input_txids: Vec::new(),
        }
    }

    /// Whether this transaction is represented by txid only (no raw data).
    pub fn is_txid_only(&self) -> bool {
        self.tx.is_none()
    }

    /// Whether this transaction has a BUMP proof.
    pub fn has_proof(&self) -> bool {
        self.bump_index.is_some()
    }

    /// Collect unique input txids from a transaction.
    fn collect_input_txids(tx: &Transaction) -> Vec<String> {
        let mut txids = Vec::new();
        for input in &tx.inputs {
            if let Some(ref stxid) = input.source_txid {
                if !txids.contains(stxid) {
                    txids.push(stxid.clone());
                }
            }
        }
        txids
    }

    /// Deserialize a BeefTx from BEEF V1 binary format.
    ///
    /// V1 format: raw_transaction + has_bump(u8) + [bump_index(varint)]
    pub fn from_binary_v1(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let tx = Transaction::from_binary(reader)?;
        let mut has_bump_buf = [0u8; 1];
        reader.read_exact(&mut has_bump_buf)?;
        let bump_index = if has_bump_buf[0] != 0 {
            Some(
                read_varint(reader).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
                    as usize,
            )
        } else {
            None
        };
        Self::from_tx(tx, bump_index)
    }

    /// Deserialize a BeefTx from BEEF V2 binary format (BRC-96).
    ///
    /// V2 format: tx_data_format(u8) + format-specific data
    pub fn from_binary_v2(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let mut format_buf = [0u8; 1];
        reader.read_exact(&mut format_buf)?;
        let format = TxDataFormat::from_byte(format_buf[0])?;

        match format {
            TxDataFormat::TxidOnly => {
                // Read 32-byte txid (stored reversed/LE on wire)
                let mut txid_bytes = [0u8; 32];
                reader.read_exact(&mut txid_bytes)?;
                txid_bytes.reverse();
                let txid = to_hex(&txid_bytes);
                Ok(BeefTx::from_txid(txid))
            }
            TxDataFormat::RawTxAndBumpIndex => {
                let bump_index = read_varint(reader)
                    .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
                    as usize;
                let tx = Transaction::from_binary(reader)?;
                Self::from_tx(tx, Some(bump_index))
            }
            TxDataFormat::RawTx => {
                let tx = Transaction::from_binary(reader)?;
                Self::from_tx(tx, None)
            }
        }
    }

    /// Serialize a BeefTx to BEEF V1 binary format.
    pub fn to_binary_v1(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        if let Some(ref tx) = self.tx {
            tx.to_binary(writer)?;
        } else {
            return Err(TransactionError::BeefError(
                "cannot serialize txid-only BeefTx in V1 format".to_string(),
            ));
        }

        if let Some(bump_index) = self.bump_index {
            writer.write_all(&[1u8])?; // has_bump = true
            write_varint(writer, bump_index as u64)?;
        } else {
            writer.write_all(&[0u8])?; // has_bump = false
        }
        Ok(())
    }

    /// Serialize a BeefTx to BEEF V2 binary format (BRC-96).
    pub fn to_binary_v2(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        if self.is_txid_only() {
            writer.write_all(&[TxDataFormat::TxidOnly as u8])?;
            let mut txid_bytes =
                from_hex(&self.txid).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
            txid_bytes.reverse(); // Display BE -> wire LE
            writer.write_all(&txid_bytes)?;
        } else if let Some(bump_index) = self.bump_index {
            writer.write_all(&[TxDataFormat::RawTxAndBumpIndex as u8])?;
            write_varint(writer, bump_index as u64)?;
            self.tx
                .as_ref()
                .ok_or_else(|| {
                    TransactionError::InvalidFormat("BeefTx has bump_index but no tx".to_string())
                })?
                .to_binary(writer)?;
        } else {
            writer.write_all(&[TxDataFormat::RawTx as u8])?;
            self.tx
                .as_ref()
                .ok_or_else(|| {
                    TransactionError::InvalidFormat("BeefTx has no tx data".to_string())
                })?
                .to_binary(writer)?;
        }
        Ok(())
    }
}
