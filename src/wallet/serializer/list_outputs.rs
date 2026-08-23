//! ListOutputs args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

const TAG_QUERY_MODE_ALL: u8 = 1;
const TAG_QUERY_MODE_ANY: u8 = 2;
const OUTPUT_INCLUDE_LOCKING_SCRIPTS: u8 = 1;
const OUTPUT_INCLUDE_ENTIRE_TRANSACTIONS: u8 = 2;

pub fn serialize_list_outputs_args(args: &ListOutputsArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_string(w, &args.basket)?;
        // The TypeScript transceiver collapses omitted and empty tags to a
        // zero count on this call, unlike the nil-able arrays on createAction.
        write_string_slice(w, &Some(args.tags.clone()))?;
        match args.tag_query_mode {
            Some(QueryMode::All) => write_byte(w, TAG_QUERY_MODE_ALL)?,
            Some(QueryMode::Any) => write_byte(w, TAG_QUERY_MODE_ANY)?,
            None => write_byte(w, NEGATIVE_ONE_BYTE)?,
        }
        match args.include {
            Some(OutputInclude::LockingScripts) => write_byte(w, OUTPUT_INCLUDE_LOCKING_SCRIPTS)?,
            Some(OutputInclude::EntireTransactions) => {
                write_byte(w, OUTPUT_INCLUDE_ENTIRE_TRANSACTIONS)?
            }
            None => write_byte(w, NEGATIVE_ONE_BYTE)?,
        }
        write_optional_bool(w, args.include_custom_instructions.0)?;
        write_optional_bool(w, args.include_tags.0)?;
        write_optional_bool(w, args.include_labels.0)?;
        write_optional_uint32(w, args.limit)?;
        match args.offset {
            Some(offset) => write_varint(w, offset as u64)?,
            None => write_varint(w, NEGATIVE_ONE)?,
        }
        write_optional_bool(w, args.seek_permission.0)
    })
}

pub fn deserialize_list_outputs_args(data: &[u8]) -> Result<ListOutputsArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let basket = read_string(&mut r)?;
    let tags = read_string_slice(&mut r)?.unwrap_or_default();
    let tq_byte = read_byte(&mut r)?;
    let tag_query_mode = match tq_byte {
        TAG_QUERY_MODE_ALL => Some(QueryMode::All),
        TAG_QUERY_MODE_ANY => Some(QueryMode::Any),
        _ => None,
    };
    let inc_byte = read_byte(&mut r)?;
    let include = match inc_byte {
        OUTPUT_INCLUDE_LOCKING_SCRIPTS => Some(OutputInclude::LockingScripts),
        OUTPUT_INCLUDE_ENTIRE_TRANSACTIONS => Some(OutputInclude::EntireTransactions),
        _ => None,
    };
    let include_custom_instructions = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_tags = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_labels = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let limit = read_optional_uint32(&mut r)?;
    // Match WalletWireProcessor: negative offsets are carried by the caller's
    // signed varint but decoded as undefined at the receiving boundary.
    let signed_offset = read_varint(&mut r)? as i64;
    let offset = (signed_offset >= 0).then_some(signed_offset);
    let seek_permission = BooleanDefaultTrue(read_optional_bool(&mut r)?);
    Ok(ListOutputsArgs {
        basket,
        tags,
        tag_query_mode,
        include,
        include_custom_instructions,
        include_tags,
        include_labels,
        limit,
        offset,
        seek_permission,
    })
}

pub fn serialize_list_outputs_result(result: &ListOutputsResult) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_varint(w, result.total_outputs as u64)?;
        // Optional BEEF
        if let Some(ref beef) = result.beef {
            write_bytes(w, beef)?;
        } else {
            write_varint(w, NEGATIVE_ONE)?;
        }
        // Outputs
        for output in &result.outputs {
            write_outpoint(w, &output.outpoint)?;
            write_varint(w, output.satoshis)?;
            if let Some(ref script) = output.locking_script {
                write_bytes(w, script)?;
            } else {
                write_varint(w, NEGATIVE_ONE)?;
            }
            write_string_optional(w, &output.custom_instructions.clone().unwrap_or_default())?;
            write_string_slice(w, &output.tags)?;
            write_string_slice(w, &output.labels)?;
        }
        Ok(())
    })
}

pub fn deserialize_list_outputs_result(data: &[u8]) -> Result<ListOutputsResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let total_outputs = read_varint(&mut r)? as u32;
    // BEEF
    let beef_len = read_varint(&mut r)?;
    let beef = if beef_len == NEGATIVE_ONE {
        None
    } else {
        Some(read_raw_bytes(&mut r, beef_len as usize)?)
    };
    let mut outputs = Vec::with_capacity(total_outputs as usize);
    for _ in 0..total_outputs {
        let outpoint = read_outpoint(&mut r)?;
        let satoshis = read_varint(&mut r)?;
        let ls_len = read_varint(&mut r)?;
        let locking_script = if ls_len == NEGATIVE_ONE {
            None
        } else {
            Some(read_raw_bytes(&mut r, ls_len as usize)?)
        };
        let custom_str = read_string(&mut r)?;
        let custom_instructions = if custom_str.is_empty() {
            None
        } else {
            Some(custom_str)
        };
        let tags = read_string_slice(&mut r)?;
        let labels = read_string_slice(&mut r)?;
        outputs.push(Output {
            satoshis,
            locking_script,
            spendable: true, // Default matches Go SDK
            custom_instructions,
            tags,
            outpoint,
            labels,
        });
    }
    Ok(ListOutputsResult {
        total_outputs,
        beef,
        outputs,
    })
}
