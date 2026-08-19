//! Bitcoin transaction types and serialization.
//!
//! This module provides the core transaction types: Transaction, TransactionInput,
//! TransactionOutput, plus binary wire format and EF format (BRC-30) serialization.

pub mod beef;
pub mod beef_party;
pub mod beef_tx;
pub mod broadcaster;
pub mod broadcasters;
pub mod chain_tracker;
pub mod chaintrackers;
pub mod error;
pub mod fee_model;
pub mod merkle_path;
pub mod sighash_preimage;
#[allow(clippy::module_inception)]
pub mod transaction;
pub mod transaction_input;
pub mod transaction_output;

pub use beef::Beef;
pub use beef_party::BeefParty;
pub use beef_tx::BeefTx;
pub use broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
pub use chain_tracker::ChainTracker;
pub use error::TransactionError;
pub use fee_model::{FeeModel, SatoshisPerKilobyte};
pub use merkle_path::{MerklePath, MerklePathLeaf};
pub use sighash_preimage::SighashPreimage;
pub use transaction::Transaction;
pub use transaction_input::TransactionInput;
pub use transaction_output::TransactionOutput;

use std::io::{self, Read, Write};

/// Read a Bitcoin varint from a reader.
///
/// Bitcoin varint encoding:
/// - 0x00..0xfc: 1 byte (value as-is)
/// - 0xfd: 3 bytes (0xfd + u16 LE)
/// - 0xfe: 5 bytes (0xfe + u32 LE)
/// - 0xff: 9 bytes (0xff + u64 LE)
pub(crate) fn read_varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    match first[0] {
        0..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

/// Write a Bitcoin varint to a writer.
pub(crate) fn write_varint(writer: &mut impl Write, val: u64) -> io::Result<()> {
    if val < 0xfd {
        writer.write_all(&[val as u8])
    } else if val <= 0xffff {
        writer.write_all(&[0xfd])?;
        writer.write_all(&(val as u16).to_le_bytes())
    } else if val <= 0xffff_ffff {
        writer.write_all(&[0xfe])?;
        writer.write_all(&(val as u32).to_le_bytes())
    } else {
        writer.write_all(&[0xff])?;
        writer.write_all(&val.to_le_bytes())
    }
}

/// Read a u32 in little-endian from a reader.
pub(crate) fn read_u32_le(reader: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Write a u32 in little-endian to a writer.
pub(crate) fn write_u32_le(writer: &mut impl Write, val: u32) -> io::Result<()> {
    writer.write_all(&val.to_le_bytes())
}

/// Read a u64 in little-endian from a reader.
pub(crate) fn read_u64_le(reader: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Write a u64 in little-endian to a writer.
pub(crate) fn write_u64_le(writer: &mut impl Write, val: u64) -> io::Result<()> {
    writer.write_all(&val.to_le_bytes())
}

/// Compute the byte size of a varint for a given value.
#[allow(dead_code)]
pub(crate) fn varint_size(val: u64) -> u64 {
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
