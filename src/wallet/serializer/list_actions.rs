//! ListActions args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

const LABEL_QUERY_MODE_ANY: u8 = 1;
const LABEL_QUERY_MODE_ALL: u8 = 2;

const ACTION_STATUS_COMPLETED: u8 = 1;
const ACTION_STATUS_UNPROCESSED: u8 = 2;
const ACTION_STATUS_SENDING: u8 = 3;
const ACTION_STATUS_UNPROVEN: u8 = 4;
const ACTION_STATUS_UNSIGNED: u8 = 5;
const ACTION_STATUS_NOSEND: u8 = 6;
const ACTION_STATUS_NONFINAL: u8 = 7;
const ACTION_STATUS_FAILED: u8 = 8;

pub fn serialize_list_actions_args(args: &ListActionsArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_string_slice(
            w,
            &if args.labels.is_empty() {
                None
            } else {
                Some(args.labels.clone())
            },
        )?;
        match args.label_query_mode {
            Some(QueryMode::Any) => write_byte(w, LABEL_QUERY_MODE_ANY)?,
            Some(QueryMode::All) => write_byte(w, LABEL_QUERY_MODE_ALL)?,
            None => write_byte(w, NEGATIVE_ONE_BYTE)?,
        }
        write_optional_bool(w, args.include_labels.0)?;
        write_optional_bool(w, args.include_inputs.0)?;
        write_optional_bool(w, args.include_input_source_locking_scripts.0)?;
        write_optional_bool(w, args.include_input_unlocking_scripts.0)?;
        write_optional_bool(w, args.include_outputs.0)?;
        write_optional_bool(w, args.include_output_locking_scripts.0)?;
        write_optional_uint32(w, args.limit)?;
        write_optional_uint32(w, args.offset)?;
        write_optional_bool(w, args.seek_permission.0)
    })
}

pub fn deserialize_list_actions_args(data: &[u8]) -> Result<ListActionsArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let labels = read_string_slice(&mut r)?.unwrap_or_default();
    let mode_byte = read_byte(&mut r)?;
    let label_query_mode = match mode_byte {
        LABEL_QUERY_MODE_ANY => Some(QueryMode::Any),
        LABEL_QUERY_MODE_ALL => Some(QueryMode::All),
        _ => None,
    };
    let include_labels = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_inputs = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_input_source_locking_scripts = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_input_unlocking_scripts = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_outputs = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let include_output_locking_scripts = BooleanDefaultFalse(read_optional_bool(&mut r)?);
    let limit = read_optional_uint32(&mut r)?;
    let offset = read_optional_uint32(&mut r)?;
    let seek_permission = BooleanDefaultTrue(read_optional_bool(&mut r)?);
    Ok(ListActionsArgs {
        labels,
        label_query_mode,
        include_labels,
        include_inputs,
        include_input_source_locking_scripts,
        include_input_unlocking_scripts,
        include_outputs,
        include_output_locking_scripts,
        limit,
        offset,
        seek_permission,
    })
}

pub fn serialize_list_actions_result(result: &ListActionsResult) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_varint(w, result.total_actions as u64)?;
        for action in &result.actions {
            // txid in display hex order (Go SDK stores internal order and uses WriteBytesReverse)
            let txid_bytes = hex_decode(&action.txid)?;
            write_raw_bytes(w, &txid_bytes)?;
            write_varint(w, action.satoshis as u64)?;
            let status_byte = match action.status {
                ActionStatus::Completed => ACTION_STATUS_COMPLETED,
                ActionStatus::Unprocessed => ACTION_STATUS_UNPROCESSED,
                ActionStatus::Sending => ACTION_STATUS_SENDING,
                ActionStatus::Unproven => ACTION_STATUS_UNPROVEN,
                ActionStatus::Unsigned => ACTION_STATUS_UNSIGNED,
                ActionStatus::NoSend => ACTION_STATUS_NOSEND,
                ActionStatus::NonFinal => ACTION_STATUS_NONFINAL,
                ActionStatus::Failed => ACTION_STATUS_FAILED,
            };
            write_byte(w, status_byte)?;
            write_optional_bool(w, Some(action.is_outgoing))?;
            write_string(w, &action.description)?;
            write_string_slice(
                w,
                &if action.labels.is_empty() {
                    None
                } else {
                    Some(action.labels.clone())
                },
            )?;
            write_varint(w, action.version as u64)?;
            write_varint(w, action.lock_time as u64)?;
            // Inputs
            if action.inputs.is_empty() {
                write_varint(w, NEGATIVE_ONE)?;
            } else {
                write_varint(w, action.inputs.len() as u64)?;
            }
            for input in &action.inputs {
                write_outpoint(w, &input.source_outpoint)?;
                write_varint(w, input.source_satoshis)?;
                // Source locking script (optional, NegativeOne if empty)
                if let Some(ref script) = input.source_locking_script {
                    write_bytes(w, script)?;
                } else {
                    write_varint(w, NEGATIVE_ONE)?;
                }
                // Unlocking script (optional)
                if let Some(ref script) = input.unlocking_script {
                    write_bytes(w, script)?;
                } else {
                    write_varint(w, NEGATIVE_ONE)?;
                }
                write_string(w, &input.input_description)?;
                write_varint(w, input.sequence_number as u64)?;
            }
            // Outputs
            if action.outputs.is_empty() {
                write_varint(w, NEGATIVE_ONE)?;
            } else {
                write_varint(w, action.outputs.len() as u64)?;
            }
            for output in &action.outputs {
                write_varint(w, output.output_index as u64)?;
                write_varint(w, output.satoshis)?;
                if let Some(ref script) = output.locking_script {
                    write_bytes(w, script)?;
                } else {
                    write_varint(w, NEGATIVE_ONE)?;
                }
                write_optional_bool(w, Some(output.spendable))?;
                write_string(w, &output.output_description)?;
                write_string(w, output.basket.as_deref().unwrap_or(""))?;
                write_string_slice(
                    w,
                    &if output.tags.is_empty() {
                        None
                    } else {
                        Some(output.tags.clone())
                    },
                )?;
                write_string_optional(w, output.custom_instructions.as_deref().unwrap_or(""))?;
            }
        }
        Ok(())
    })
}

pub fn deserialize_list_actions_result(data: &[u8]) -> Result<ListActionsResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let total_actions = read_varint(&mut r)? as u32;
    let mut actions = Vec::with_capacity(total_actions as usize);
    for _ in 0..total_actions {
        let txid_bytes = read_raw_bytes(&mut r, 32)?;
        let txid = hex_encode(&txid_bytes);
        let satoshis = read_varint(&mut r)? as i64;
        let status_byte = read_byte(&mut r)?;
        let status = match status_byte {
            ACTION_STATUS_COMPLETED => ActionStatus::Completed,
            ACTION_STATUS_UNPROCESSED => ActionStatus::Unprocessed,
            ACTION_STATUS_SENDING => ActionStatus::Sending,
            ACTION_STATUS_UNPROVEN => ActionStatus::Unproven,
            ACTION_STATUS_UNSIGNED => ActionStatus::Unsigned,
            ACTION_STATUS_NOSEND => ActionStatus::NoSend,
            ACTION_STATUS_NONFINAL => ActionStatus::NonFinal,
            ACTION_STATUS_FAILED => ActionStatus::Failed,
            _ => {
                return Err(WalletError::Internal(format!(
                    "invalid status byte: {}",
                    status_byte
                )))
            }
        };
        let is_outgoing = read_byte(&mut r)? == 1;
        let description = read_string(&mut r)?;
        let labels = read_string_slice(&mut r)?.unwrap_or_default();
        let version = read_varint(&mut r)? as u32;
        let lock_time = read_varint(&mut r)? as u32;
        // Inputs
        let input_count = read_varint(&mut r)?;
        let input_count = if input_count == NEGATIVE_ONE {
            0
        } else {
            input_count
        };
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            let source_outpoint = read_outpoint(&mut r)?;
            let source_satoshis = read_varint(&mut r)?;
            let source_locking_script = read_optional_bytes_varint(&mut r)?;
            let unlocking_script = read_optional_bytes_varint(&mut r)?;
            let input_description = read_string(&mut r)?;
            let sequence_number = read_varint(&mut r)? as u32;
            inputs.push(ActionInput {
                source_outpoint,
                source_satoshis,
                source_locking_script,
                unlocking_script,
                input_description,
                sequence_number,
            });
        }
        // Outputs
        let output_count = read_varint(&mut r)?;
        let output_count = if output_count == NEGATIVE_ONE {
            0
        } else {
            output_count
        };
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            let output_index = read_varint(&mut r)? as u32;
            let satoshis = read_varint(&mut r)?;
            let locking_script = read_optional_bytes_varint(&mut r)?;
            let spendable = read_byte(&mut r)? == 1;
            let output_description = read_string(&mut r)?;
            let basket_str = read_string(&mut r)?;
            let basket = if basket_str.is_empty() {
                None
            } else {
                Some(basket_str)
            };
            let tags = read_string_slice(&mut r)?.unwrap_or_default();
            let custom_str = read_string(&mut r)?;
            let custom_instructions = if custom_str.is_empty() {
                None
            } else {
                Some(custom_str)
            };
            outputs.push(ActionOutput {
                satoshis,
                locking_script,
                spendable,
                custom_instructions,
                tags,
                output_index,
                output_description,
                basket,
            });
        }
        actions.push(Action {
            txid,
            satoshis,
            status,
            is_outgoing,
            description,
            labels,
            version,
            lock_time,
            inputs,
            outputs,
        });
    }
    Ok(ListActionsResult {
        total_actions,
        actions,
    })
}
