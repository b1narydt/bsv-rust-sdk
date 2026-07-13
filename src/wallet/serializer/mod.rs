//! Wire protocol serialization for all 28 wallet methods.
//!
//! Provides binary serialization/deserialization matching the Go SDK
//! wallet/serializer package, using Bitcoin-style varints and specific
//! sentinel values for optional fields.

use std::collections::HashMap;
use std::io::{Read, Write};

use crate::primitives::public_key::PublicKey;
use crate::wallet::error::WalletError;
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

pub mod frame;

pub mod abort_action;
pub mod acquire_certificate;
pub mod authenticated;
pub mod certificate_ser;
pub mod create_action;
pub mod create_hmac;
pub mod create_signature;
pub mod decrypt;
pub mod discover_by_attributes;
pub mod discover_by_identity_key;
pub mod discover_certificates_result;
pub mod encrypt;
pub mod get_header;
pub mod get_height;
pub mod get_network;
pub mod get_public_key;
pub mod get_version;
pub mod internalize_action;
pub mod list_actions;
pub mod list_certificates;
pub mod list_outputs;
pub mod prove_certificate;
pub mod relinquish_certificate;
pub mod relinquish_output;
pub mod reveal_counterparty_key_linkage;
pub mod reveal_specific_key_linkage;
pub mod sign_action;
pub mod verify_hmac;
pub mod verify_signature;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel value for "negative one" / "none" in varint encoding.
const NEGATIVE_ONE: u64 = u64::MAX;

/// Sentinel byte for "none" in single-byte optional fields.
const NEGATIVE_ONE_BYTE: u8 = 0xFF;

/// Counterparty type codes matching Go SDK.
const COUNTERPARTY_UNINITIALIZED: u8 = 0x00;
const COUNTERPARTY_SELF: u8 = 0x0B;
const COUNTERPARTY_ANYONE: u8 = 0x0C;

/// Size of a compressed public key.
const SIZE_PUB_KEY: usize = 33;

/// Size of certificate type and serial number fields.
const SIZE_TYPE: usize = 32;
const SIZE_SERIAL: usize = 32;

/// Call byte constants for each wallet method (request frame).
pub const CALL_CREATE_ACTION: u8 = 1;
pub const CALL_SIGN_ACTION: u8 = 2;
pub const CALL_ABORT_ACTION: u8 = 3;
pub const CALL_LIST_ACTIONS: u8 = 4;
pub const CALL_INTERNALIZE_ACTION: u8 = 5;
pub const CALL_LIST_OUTPUTS: u8 = 6;
pub const CALL_RELINQUISH_OUTPUT: u8 = 7;
pub const CALL_GET_PUBLIC_KEY: u8 = 8;
pub const CALL_REVEAL_COUNTERPARTY_KEY_LINKAGE: u8 = 9;
pub const CALL_REVEAL_SPECIFIC_KEY_LINKAGE: u8 = 10;
pub const CALL_ENCRYPT: u8 = 11;
pub const CALL_DECRYPT: u8 = 12;
pub const CALL_CREATE_HMAC: u8 = 13;
pub const CALL_VERIFY_HMAC: u8 = 14;
pub const CALL_CREATE_SIGNATURE: u8 = 15;
pub const CALL_VERIFY_SIGNATURE: u8 = 16;
pub const CALL_ACQUIRE_CERTIFICATE: u8 = 17;
pub const CALL_LIST_CERTIFICATES: u8 = 18;
pub const CALL_PROVE_CERTIFICATE: u8 = 19;
pub const CALL_RELINQUISH_CERTIFICATE: u8 = 20;
pub const CALL_DISCOVER_BY_IDENTITY_KEY: u8 = 21;
pub const CALL_DISCOVER_BY_ATTRIBUTES: u8 = 22;
pub const CALL_IS_AUTHENTICATED: u8 = 23;
pub const CALL_WAIT_FOR_AUTHENTICATION: u8 = 24;
pub const CALL_GET_HEIGHT: u8 = 25;
pub const CALL_GET_HEADER_FOR_HEIGHT: u8 = 26;
pub const CALL_GET_NETWORK: u8 = 27;
pub const CALL_GET_VERSION: u8 = 28;

// ---------------------------------------------------------------------------
// VarInt helpers (Bitcoin-style)
// ---------------------------------------------------------------------------

/// Write a Bitcoin-style variable-length integer.
pub fn write_varint(writer: &mut impl Write, value: u64) -> Result<(), WalletError> {
    let bytes = varint_bytes(value);
    writer
        .write_all(&bytes)
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read a Bitcoin-style variable-length integer.
pub fn read_varint(reader: &mut impl Read) -> Result<u64, WalletError> {
    let mut first = [0u8; 1];
    reader
        .read_exact(&mut first)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    match first[0] {
        0xff => {
            let mut buf = [0u8; 8];
            reader
                .read_exact(&mut buf)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            Ok(u64::from_le_bytes(buf))
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xfd => {
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        b => Ok(b as u64),
    }
}

/// Encode a u64 as Bitcoin-style varint bytes.
fn varint_bytes(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value < 0x10000 {
        let mut buf = vec![0xfd, 0, 0];
        buf[1..3].copy_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value < 0x100000000 {
        let mut buf = vec![0xfe, 0, 0, 0, 0];
        buf[1..5].copy_from_slice(&(value as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        buf[1..9].copy_from_slice(&value.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/// Write a single byte.
pub fn write_byte(writer: &mut impl Write, b: u8) -> Result<(), WalletError> {
    writer
        .write_all(&[b])
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read a single byte.
pub fn read_byte(reader: &mut impl Read) -> Result<u8, WalletError> {
    let mut buf = [0u8; 1];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(buf[0])
}

/// Write varint-length-prefixed bytes.
pub fn write_bytes(writer: &mut impl Write, data: &[u8]) -> Result<(), WalletError> {
    write_varint(writer, data.len() as u64)?;
    writer
        .write_all(data)
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read varint-length-prefixed bytes.
pub fn read_bytes(reader: &mut impl Read) -> Result<Vec<u8>, WalletError> {
    let len = read_varint(reader)?;
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(buf)
}

/// Write raw bytes without length prefix.
pub fn write_raw_bytes(writer: &mut impl Write, data: &[u8]) -> Result<(), WalletError> {
    writer
        .write_all(data)
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read exactly n raw bytes.
pub fn read_raw_bytes(reader: &mut impl Read, n: usize) -> Result<Vec<u8>, WalletError> {
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(buf)
}

/// Read n raw bytes and reverse them (for txid display order).
pub fn read_raw_bytes_reverse(reader: &mut impl Read, n: usize) -> Result<Vec<u8>, WalletError> {
    let mut buf = read_raw_bytes(reader, n)?;
    buf.reverse();
    Ok(buf)
}

/// Write bytes in reversed order (for txid display order).
pub fn write_raw_bytes_reverse(writer: &mut impl Write, data: &[u8]) -> Result<(), WalletError> {
    let mut reversed = data.to_vec();
    reversed.reverse();
    write_raw_bytes(writer, &reversed)
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed UTF-8 string.
pub fn write_string(writer: &mut impl Write, s: &str) -> Result<(), WalletError> {
    let bytes = s.as_bytes();
    write_varint(writer, bytes.len() as u64)?;
    writer
        .write_all(bytes)
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read a length-prefixed UTF-8 string.
pub fn read_string(reader: &mut impl Read) -> Result<String, WalletError> {
    let len = read_varint(reader)?;
    if len == NEGATIVE_ONE || len == 0 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| WalletError::Internal(e.to_string()))
}

/// Write an optional string. None writes the full varint NegativeOne sentinel.
pub fn write_optional_string(
    writer: &mut impl Write,
    s: &Option<String>,
) -> Result<(), WalletError> {
    match s {
        Some(ref val) if !val.is_empty() => write_string(writer, val),
        _ => write_varint(writer, NEGATIVE_ONE),
    }
}

/// Read an optional string. Varint NegativeOne = None.
pub fn read_optional_string(reader: &mut impl Read) -> Result<Option<String>, WalletError> {
    let len = read_varint(reader)?;
    if len == NEGATIVE_ONE {
        return Ok(None);
    }
    if len == 0 {
        return Ok(Some(String::new()));
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    let s = String::from_utf8(buf).map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(Some(s))
}

/// Write a string that uses the full varint negative-one sentinel for empty.
/// This matches Go SDK's WriteOptionalString behavior (empty string -> NegativeOne).
pub fn write_string_optional(writer: &mut impl Write, s: &str) -> Result<(), WalletError> {
    if s.is_empty() {
        write_varint(writer, NEGATIVE_ONE)
    } else {
        write_string(writer, s)
    }
}

/// Read a string that uses NegativeOne sentinel for None (returns empty string for None).
pub fn read_string_optional(reader: &mut impl Read) -> Result<String, WalletError> {
    let len = read_varint(reader)?;
    if len == NEGATIVE_ONE || len == 0 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| WalletError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Bool helpers
// ---------------------------------------------------------------------------

/// Write an optional bool: 0x00=false, 0x01=true, 0xFF=none.
pub fn write_optional_bool(writer: &mut impl Write, v: Option<bool>) -> Result<(), WalletError> {
    match v {
        None => write_byte(writer, NEGATIVE_ONE_BYTE),
        Some(true) => write_byte(writer, 1),
        Some(false) => write_byte(writer, 0),
    }
}

/// Read an optional bool: 0x00=false, 0x01=true, 0xFF=none.
pub fn read_optional_bool(reader: &mut impl Read) -> Result<Option<bool>, WalletError> {
    let b = read_byte(reader)?;
    match b {
        0xFF => Ok(None),
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        _ => Err(WalletError::Internal(format!(
            "invalid optional bool byte: {b}"
        ))),
    }
}

/// Write a bool: 0x00=false, 0x01=true.
pub fn write_bool(writer: &mut impl Write, v: bool) -> Result<(), WalletError> {
    write_byte(writer, if v { 1 } else { 0 })
}

/// Read a bool: 0x00=false, 0x01=true.
pub fn read_bool(reader: &mut impl Read) -> Result<bool, WalletError> {
    Ok(read_byte(reader)? == 1)
}

// ---------------------------------------------------------------------------
// Integer helpers
// ---------------------------------------------------------------------------

/// Write a u32 as little-endian 4 bytes.
pub fn write_uint32(writer: &mut impl Write, v: u32) -> Result<(), WalletError> {
    writer
        .write_all(&v.to_le_bytes())
        .map_err(|e| WalletError::Internal(e.to_string()))
}

/// Read a u32 from little-endian 4 bytes.
pub fn read_uint32(reader: &mut impl Read) -> Result<u32, WalletError> {
    let mut buf = [0u8; 4];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(u32::from_le_bytes(buf))
}

/// Write an optional u32 using varint. None writes NegativeOne sentinel.
pub fn write_optional_uint32(writer: &mut impl Write, v: Option<u32>) -> Result<(), WalletError> {
    match v {
        Some(val) => write_varint(writer, val as u64),
        None => write_varint(writer, NEGATIVE_ONE),
    }
}

/// Read an optional u32 from varint. NegativeOne = None.
pub fn read_optional_uint32(reader: &mut impl Read) -> Result<Option<u32>, WalletError> {
    let val = read_varint(reader)?;
    if val == NEGATIVE_ONE {
        Ok(None)
    } else {
        Ok(Some(val as u32))
    }
}

// ---------------------------------------------------------------------------
// Counterparty encoding
// ---------------------------------------------------------------------------

/// Write a counterparty: Uninitialized=0x00, Self_=0x0B, Anyone=0x0C,
/// Other=0x02/0x03 prefix + 32 bytes x-coordinate.
pub fn write_counterparty(writer: &mut impl Write, c: &Counterparty) -> Result<(), WalletError> {
    match c.counterparty_type {
        CounterpartyType::Uninitialized => write_byte(writer, COUNTERPARTY_UNINITIALIZED),
        CounterpartyType::Self_ => write_byte(writer, COUNTERPARTY_SELF),
        CounterpartyType::Anyone => write_byte(writer, COUNTERPARTY_ANYONE),
        CounterpartyType::Other => {
            let pk = c.public_key.as_ref().ok_or_else(|| {
                WalletError::Internal("counterparty is Other but no public key".to_string())
            })?;
            let compressed = pk.to_der();
            write_raw_bytes(writer, &compressed)
        }
    }
}

/// Read a counterparty from wire format.
pub fn read_counterparty(reader: &mut impl Read) -> Result<Counterparty, WalletError> {
    let flag = read_byte(reader)?;
    match flag {
        COUNTERPARTY_UNINITIALIZED => Ok(Counterparty {
            counterparty_type: CounterpartyType::Uninitialized,
            public_key: None,
        }),
        COUNTERPARTY_SELF => Ok(Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        }),
        COUNTERPARTY_ANYONE => Ok(Counterparty {
            counterparty_type: CounterpartyType::Anyone,
            public_key: None,
        }),
        0x02 | 0x03 => {
            let mut buf = vec![flag];
            let rest = read_raw_bytes(reader, 32)?;
            buf.extend_from_slice(&rest);
            let pk = PublicKey::from_der_bytes(&buf)?;
            Ok(Counterparty {
                counterparty_type: CounterpartyType::Other,
                public_key: Some(pk),
            })
        }
        _ => Err(WalletError::Internal(format!(
            "invalid counterparty flag byte: 0x{flag:02x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Protocol encoding
// ---------------------------------------------------------------------------

/// Write a protocol: security_level byte + protocol name string.
pub fn write_protocol(writer: &mut impl Write, p: &Protocol) -> Result<(), WalletError> {
    write_byte(writer, p.security_level)?;
    write_string(writer, &p.protocol)
}

/// Read a protocol from wire.
pub fn read_protocol(reader: &mut impl Read) -> Result<Protocol, WalletError> {
    let security_level = read_byte(reader)?;
    let protocol = read_string(reader)?;
    Ok(Protocol {
        security_level,
        protocol,
    })
}

// ---------------------------------------------------------------------------
// Key-related params (common prefix for crypto methods)
// ---------------------------------------------------------------------------

/// Common parameters for key-related wallet operations.
pub struct KeyRelatedParams {
    pub protocol: Protocol,
    pub key_id: String,
    pub counterparty: Counterparty,
    pub privileged: Option<bool>,
    pub privileged_reason: String,
}

/// Write the common key-related params prefix.
pub fn write_key_related_params(
    writer: &mut impl Write,
    params: &KeyRelatedParams,
) -> Result<(), WalletError> {
    write_protocol(writer, &params.protocol)?;
    write_string(writer, &params.key_id)?;
    write_counterparty(writer, &params.counterparty)?;
    write_privileged_params(writer, params.privileged, &params.privileged_reason)
}

/// Read the common key-related params prefix.
pub fn read_key_related_params(reader: &mut impl Read) -> Result<KeyRelatedParams, WalletError> {
    let protocol = read_protocol(reader)?;
    let key_id = read_string(reader)?;
    let counterparty = read_counterparty(reader)?;
    let (privileged, privileged_reason) = read_privileged_params(reader)?;
    Ok(KeyRelatedParams {
        protocol,
        key_id,
        counterparty,
        privileged,
        privileged_reason,
    })
}

// ---------------------------------------------------------------------------
// Privileged params encoding
// ---------------------------------------------------------------------------

/// Write privileged flag + optional reason.
pub fn write_privileged_params(
    writer: &mut impl Write,
    privileged: Option<bool>,
    privileged_reason: &str,
) -> Result<(), WalletError> {
    write_optional_bool(writer, privileged)?;
    if !privileged_reason.is_empty() {
        write_string(writer, privileged_reason)
    } else {
        write_byte(writer, NEGATIVE_ONE_BYTE)
    }
}

/// Read privileged flag + optional reason.
pub fn read_privileged_params(
    reader: &mut impl Read,
) -> Result<(Option<bool>, String), WalletError> {
    let privileged = read_optional_bool(reader)?;
    let b = read_byte(reader)?;
    if b == NEGATIVE_ONE_BYTE {
        return Ok((privileged, String::new()));
    }
    // The byte we just read is the first byte of the varint length.
    // We need to reconstruct the string by "unreading" this byte.
    // Since we already consumed it, we need to decode it as part of the varint.
    let len = match b {
        0xff => {
            // This case shouldn't happen since we already handled 0xFF above
            return Ok((privileged, String::new()));
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            u32::from_le_bytes(buf) as u64
        }
        0xfd => {
            let mut buf = [0u8; 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| WalletError::Internal(e.to_string()))?;
            u16::from_le_bytes(buf) as u64
        }
        _ => b as u64,
    };
    if len == 0 {
        return Ok((privileged, String::new()));
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    let reason = String::from_utf8(buf).map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok((privileged, reason))
}

// ---------------------------------------------------------------------------
// String slice helpers
// ---------------------------------------------------------------------------

/// Write a string slice (nil-able). Go uses NegativeOne for nil slices.
pub fn write_string_slice(
    writer: &mut impl Write,
    slice: &Option<Vec<String>>,
) -> Result<(), WalletError> {
    match slice {
        None => write_varint(writer, NEGATIVE_ONE),
        Some(s) => {
            write_varint(writer, s.len() as u64)?;
            for item in s {
                write_string_optional(writer, item)?;
            }
            Ok(())
        }
    }
}

/// Read a string slice (nil-able).
pub fn read_string_slice(reader: &mut impl Read) -> Result<Option<Vec<String>>, WalletError> {
    let count = read_varint(reader)?;
    if count == NEGATIVE_ONE {
        return Ok(None);
    }
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        result.push(read_string_optional(reader)?);
    }
    Ok(Some(result))
}

// ---------------------------------------------------------------------------
// String map helpers
// ---------------------------------------------------------------------------

/// Write a sorted string map (key-value pairs).
pub fn write_string_map(
    writer: &mut impl Write,
    map: &HashMap<String, String>,
) -> Result<(), WalletError> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    write_varint(writer, keys.len() as u64)?;
    for key in keys {
        write_string(writer, key)?;
        write_string(writer, &map[key])?;
    }
    Ok(())
}

/// Read a string map.
pub fn read_string_map(reader: &mut impl Read) -> Result<HashMap<String, String>, WalletError> {
    let count = read_varint(reader)?;
    let mut map = HashMap::with_capacity(count as usize);
    for _ in 0..count {
        let key = read_string(reader)?;
        let value = read_string(reader)?;
        map.insert(key, value);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Optional bytes helpers (with flag/options matching Go SDK)
// ---------------------------------------------------------------------------

/// Write optional bytes with a presence flag byte.
/// If data is Some and non-empty: write 1 then len-prefixed bytes.
/// If data is None or empty: write 0.
pub fn write_optional_bytes_with_flag(
    writer: &mut impl Write,
    data: Option<&[u8]>,
) -> Result<(), WalletError> {
    match data {
        Some(b) if !b.is_empty() => {
            write_byte(writer, 1)?;
            write_bytes(writer, b)
        }
        _ => write_byte(writer, 0),
    }
}

/// Read optional bytes with a presence flag byte.
pub fn read_optional_bytes_with_flag(
    reader: &mut impl Read,
) -> Result<Option<Vec<u8>>, WalletError> {
    let flag = read_byte(reader)?;
    if flag != 1 {
        return Ok(None);
    }
    let data = read_bytes(reader)?;
    Ok(Some(data))
}

/// Write optional bytes with flag but without length prefix (fixed-size like txid).
pub fn write_optional_bytes_with_flag_fixed(
    writer: &mut impl Write,
    data: Option<&[u8]>,
) -> Result<(), WalletError> {
    match data {
        Some(b) if !b.is_empty() => {
            write_byte(writer, 1)?;
            write_raw_bytes(writer, b)
        }
        _ => write_byte(writer, 0),
    }
}

/// Read optional bytes with flag but fixed size (txid = 32 bytes).
pub fn read_optional_bytes_with_flag_fixed(
    reader: &mut impl Read,
    size: usize,
) -> Result<Option<Vec<u8>>, WalletError> {
    let flag = read_byte(reader)?;
    if flag != 1 {
        return Ok(None);
    }
    read_raw_bytes(reader, size).map(Some)
}

/// Write optional bytes using varint sentinel (NegativeOne = None).
pub fn write_optional_bytes_varint(
    writer: &mut impl Write,
    data: Option<&[u8]>,
) -> Result<(), WalletError> {
    match data {
        Some(b) if !b.is_empty() => write_bytes(writer, b),
        _ => write_varint(writer, NEGATIVE_ONE),
    }
}

/// Read optional bytes using varint sentinel (NegativeOne = None).
pub fn read_optional_bytes_varint(reader: &mut impl Read) -> Result<Option<Vec<u8>>, WalletError> {
    let len = read_varint(reader)?;
    if len == NEGATIVE_ONE || len == 0 {
        return Ok(None);
    }
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(Some(buf))
}

// ---------------------------------------------------------------------------
// Outpoint encoding
// ---------------------------------------------------------------------------

/// Write an outpoint (txid bytes in display hex order + index as varint).
/// Expects outpoint in "txid.index" format where txid is display-order hex.
/// The Go SDK writes outpoint txids in display order on wire
/// (chainhash stores internal order, WriteBytesReverse converts to display).
pub fn write_outpoint(writer: &mut impl Write, outpoint: &str) -> Result<(), WalletError> {
    let parts: Vec<&str> = outpoint.split('.').collect();
    if parts.len() != 2 {
        return Err(WalletError::Internal(format!(
            "invalid outpoint format: {outpoint}"
        )));
    }
    let txid_bytes = hex_decode(parts[0])?;
    if txid_bytes.len() != 32 {
        return Err(WalletError::Internal(format!(
            "invalid txid length: {}",
            txid_bytes.len()
        )));
    }
    // Write txid in display hex order (same as Go SDK's WriteBytesReverse of internal-order hash)
    write_raw_bytes(writer, &txid_bytes)?;
    let index: u32 = parts[1].parse().map_err(|e: std::num::ParseIntError| {
        WalletError::Internal(format!("invalid outpoint index: {e}"))
    })?;
    write_varint(writer, index as u64)
}

/// Read an outpoint (txid in display hex order + varint index) and return as "txid.index".
pub fn read_outpoint(reader: &mut impl Read) -> Result<String, WalletError> {
    let txid_bytes = read_raw_bytes(reader, 32)?;
    let index = read_varint(reader)? as u32;
    Ok(format!("{}.{}", hex_encode(&txid_bytes), index))
}

// ---------------------------------------------------------------------------
// PublicKey helpers
// ---------------------------------------------------------------------------

/// Write a compressed public key (33 bytes).
pub fn write_public_key(writer: &mut impl Write, pk: &PublicKey) -> Result<(), WalletError> {
    write_raw_bytes(writer, &pk.to_der())
}

/// Read a compressed public key (33 bytes).
pub fn read_public_key(reader: &mut impl Read) -> Result<PublicKey, WalletError> {
    let buf = read_raw_bytes(reader, SIZE_PUB_KEY)?;
    PublicKey::from_der_bytes(&buf).map_err(|e| WalletError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Decode a hex string to bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, WalletError> {
    let mut result = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    if !chars.len().is_multiple_of(2) {
        return Err(WalletError::Internal(
            "hex string has odd length".to_string(),
        ));
    }
    for i in (0..chars.len()).step_by(2) {
        let hi = hex_nibble(chars[i])?;
        let lo = hex_nibble(chars[i + 1])?;
        result.push((hi << 4) | lo);
    }
    Ok(result)
}

fn hex_nibble(c: char) -> Result<u8, WalletError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(WalletError::Internal(format!("invalid hex char: {c}"))),
    }
}

/// Encode bytes to lowercase hex string.
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Convenience: serialize to Vec<u8>
// ---------------------------------------------------------------------------

/// Helper to serialize using a closure that writes to a `Vec<u8>`.
pub fn serialize_to_vec<F>(f: F) -> Result<Vec<u8>, WalletError>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), WalletError>,
{
    let mut buf = Vec::new();
    f(&mut buf)?;
    Ok(buf)
}
