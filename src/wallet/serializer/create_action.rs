//! CreateAction args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};

const TRUST_SELF_KNOWN: u8 = 1;

pub fn serialize_create_action_args(args: &CreateActionArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Description
        write_string(w, &args.description)?;
        // Input BEEF (optional)
        write_optional_bytes_varint(w, args.input_beef.as_deref())?;
        // Inputs
        if args.inputs.is_empty() {
            write_varint(w, NEGATIVE_ONE)?;
        } else {
            write_varint(w, args.inputs.len() as u64)?;
            for input in &args.inputs {
                write_outpoint(w, &input.outpoint)?;
                if let Some(ref script) = input.unlocking_script {
                    write_bytes(w, script)?;
                } else {
                    write_varint(w, NEGATIVE_ONE)?;
                    write_varint(w, input.unlocking_script_length.unwrap_or(0) as u64)?;
                }
                write_string(w, &input.input_description)?;
                write_optional_uint32(w, input.sequence_number)?;
            }
        }
        // Outputs
        if args.outputs.is_empty() {
            write_varint(w, NEGATIVE_ONE)?;
        } else {
            write_varint(w, args.outputs.len() as u64)?;
            for output in &args.outputs {
                write_bytes(w, output.locking_script.as_deref().unwrap_or(&[]))?;
                write_varint(w, output.satoshis)?;
                write_string(w, &output.output_description)?;
                write_string_optional(w, &output.basket.clone().unwrap_or_default())?;
                write_string_optional(w, &output.custom_instructions.clone().unwrap_or_default())?;
                write_string_slice(
                    w,
                    &if output.tags.is_empty() {
                        None
                    } else {
                        Some(output.tags.clone())
                    },
                )?;
            }
        }
        // LockTime, Version, Labels
        write_optional_uint32(w, args.lock_time)?;
        write_optional_uint32(w, args.version)?;
        write_string_slice(
            w,
            &if args.labels.is_empty() {
                None
            } else {
                Some(args.labels.clone())
            },
        )?;
        // Options
        if let Some(ref opts) = args.options {
            write_byte(w, 1)?;
            write_optional_bool(w, opts.sign_and_process.0)?;
            write_optional_bool(w, opts.accept_delayed_broadcast.0)?;
            // TrustSelf
            match opts.trust_self {
                Some(TrustSelf::Known) => write_byte(w, TRUST_SELF_KNOWN)?,
                None => write_byte(w, NEGATIVE_ONE_BYTE)?,
            }
            // KnownTxids
            if opts.known_txids.is_empty() {
                write_varint(w, NEGATIVE_ONE)?;
            } else {
                write_varint(w, opts.known_txids.len() as u64)?;
                for txid in &opts.known_txids {
                    let txid_bytes = hex_decode(txid)?;
                    write_raw_bytes(w, &txid_bytes)?;
                }
            }
            write_optional_bool(w, opts.return_txid_only.0)?;
            write_optional_bool(w, opts.no_send.0)?;
            // NoSendChange outpoints
            if opts.no_send_change.is_empty() {
                write_varint(w, NEGATIVE_ONE)?;
            } else {
                let mut outpoint_buf = Vec::new();
                write_varint(&mut outpoint_buf, opts.no_send_change.len() as u64)?;
                for op in &opts.no_send_change {
                    write_outpoint(&mut outpoint_buf, op)?;
                }
                write_bytes(w, &outpoint_buf)?;
            }
            // SendWith
            if opts.send_with.is_empty() {
                write_varint(w, NEGATIVE_ONE)?;
            } else {
                write_varint(w, opts.send_with.len() as u64)?;
                for txid in &opts.send_with {
                    let txid_bytes = hex_decode(txid)?;
                    write_raw_bytes(w, &txid_bytes)?;
                }
            }
            write_optional_bool(w, opts.randomize_outputs.0)?;
        } else {
            write_byte(w, 0)?;
        }
        // Reference
        if let Some(ref reference) = args.reference {
            write_string_optional(w, reference)?;
        }
        Ok(())
    })
}

pub fn deserialize_create_action_args(data: &[u8]) -> Result<CreateActionArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let description = read_string(&mut r)?;
    let input_beef = read_optional_bytes_varint(&mut r)?;
    // Inputs
    let input_count = read_varint(&mut r)?;
    let inputs = if input_count == NEGATIVE_ONE {
        Vec::new()
    } else {
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            let outpoint = read_outpoint(&mut r)?;
            let unlocking_script_len = read_varint(&mut r)?;
            let (unlocking_script, unlocking_script_length) =
                if unlocking_script_len == NEGATIVE_ONE {
                    let script_len = read_varint(&mut r)? as u32;
                    (None, Some(script_len))
                } else {
                    let script = read_raw_bytes(&mut r, unlocking_script_len as usize)?;
                    (Some(script), None)
                };
            let input_description = read_string(&mut r)?;
            let sequence_number = read_optional_uint32(&mut r)?;
            inputs.push(CreateActionInput {
                outpoint,
                input_description,
                unlocking_script,
                unlocking_script_length,
                sequence_number,
            });
        }
        inputs
    };
    // Outputs
    let output_count = read_varint(&mut r)?;
    let outputs = if output_count == NEGATIVE_ONE {
        Vec::new()
    } else {
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            let locking_script_data = read_bytes(&mut r)?;
            let locking_script = if locking_script_data.is_empty() {
                None
            } else {
                Some(locking_script_data)
            };
            let satoshis = read_varint(&mut r)?;
            let output_description = read_string(&mut r)?;
            let basket_str = read_string_optional(&mut r)?;
            let basket = if basket_str.is_empty() {
                None
            } else {
                Some(basket_str)
            };
            let custom_str = read_string_optional(&mut r)?;
            let custom_instructions = if custom_str.is_empty() {
                None
            } else {
                Some(custom_str)
            };
            let tags = read_string_slice(&mut r)?.unwrap_or_default();
            outputs.push(CreateActionOutput {
                locking_script,
                satoshis,
                output_description,
                basket,
                custom_instructions,
                tags,
            });
        }
        outputs
    };
    let lock_time = read_optional_uint32(&mut r)?;
    let version = read_optional_uint32(&mut r)?;
    let labels = read_string_slice(&mut r)?.unwrap_or_default();
    // Options
    let options_flag = read_byte(&mut r)?;
    let options = if options_flag == 1 {
        let sign_and_process = BooleanDefaultTrue(read_optional_bool(&mut r)?);
        let accept_delayed_broadcast = BooleanDefaultTrue(read_optional_bool(&mut r)?);
        let trust_self_byte = read_byte(&mut r)?;
        let trust_self = if trust_self_byte == TRUST_SELF_KNOWN {
            Some(TrustSelf::Known)
        } else {
            None
        };
        // KnownTxids
        let known_count = read_varint(&mut r)?;
        let known_txids = if known_count == NEGATIVE_ONE {
            Vec::new()
        } else {
            let mut txids = Vec::with_capacity(known_count as usize);
            for _ in 0..known_count {
                let txid_bytes = read_raw_bytes(&mut r, 32)?;
                txids.push(hex_encode(&txid_bytes));
            }
            txids
        };
        let return_txid_only = BooleanDefaultFalse(read_optional_bool(&mut r)?);
        let no_send = BooleanDefaultFalse(read_optional_bool(&mut r)?);
        // NoSendChange
        let no_send_change_data = read_optional_bytes_varint(&mut r)?;
        let no_send_change = if let Some(data) = no_send_change_data {
            let mut c = std::io::Cursor::new(data);
            let count = read_varint(&mut c)?;
            let mut outpoints = Vec::with_capacity(count as usize);
            for _ in 0..count {
                outpoints.push(read_outpoint(&mut c)?);
            }
            outpoints
        } else {
            Vec::new()
        };
        // SendWith
        let send_count = read_varint(&mut r)?;
        let send_with = if send_count == NEGATIVE_ONE {
            Vec::new()
        } else {
            let mut txids = Vec::with_capacity(send_count as usize);
            for _ in 0..send_count {
                let txid_bytes = read_raw_bytes(&mut r, 32)?;
                txids.push(hex_encode(&txid_bytes));
            }
            txids
        };
        let randomize_outputs = BooleanDefaultTrue(read_optional_bool(&mut r)?);
        Some(CreateActionOptions {
            sign_and_process,
            accept_delayed_broadcast,
            trust_self,
            known_txids,
            return_txid_only,
            no_send,
            no_send_change,
            send_with,
            randomize_outputs,
        })
    } else {
        None
    };
    // Reference (optional, only if data remains)
    let pos = r.position() as usize;
    let total = data.len();
    let reference = if pos < total {
        let s = read_string_optional(&mut r)?;
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    };
    Ok(CreateActionArgs {
        description,
        input_beef,
        inputs,
        outputs,
        lock_time,
        version,
        labels,
        options,
        reference,
    })
}

pub fn serialize_create_action_result(result: &CreateActionResult) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Txid (optional with flag, fixed 32 bytes)
        write_optional_bytes_with_flag_fixed(
            w,
            result
                .txid
                .as_ref()
                .and_then(|t| hex_decode(t).ok())
                .as_deref(),
        )?;
        // Tx (optional with flag, length-prefixed)
        write_optional_bytes_with_flag(w, result.tx.as_deref())?;
        // NoSendChange
        if result.no_send_change.is_empty() {
            write_varint(w, NEGATIVE_ONE)?;
        } else {
            let mut outpoint_buf = Vec::new();
            write_varint(&mut outpoint_buf, result.no_send_change.len() as u64)?;
            for op in &result.no_send_change {
                write_outpoint(&mut outpoint_buf, op)?;
            }
            write_bytes(w, &outpoint_buf)?;
        }
        // SendWithResults
        write_send_with_results(w, &result.send_with_results)?;
        // SignableTransaction
        if let Some(ref st) = result.signable_transaction {
            write_byte(w, 1)?;
            write_bytes(w, &st.tx)?;
            write_bytes(w, &st.reference)?;
        } else {
            write_byte(w, 0)?;
        }
        Ok(())
    })
}

pub fn deserialize_create_action_result(data: &[u8]) -> Result<CreateActionResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Txid
    let txid_bytes = read_optional_bytes_with_flag_fixed(&mut r, 32)?;
    let txid = txid_bytes.map(|b| hex_encode(&b));
    // Tx
    let tx = read_optional_bytes_with_flag(&mut r)?;
    // NoSendChange
    let no_send_change_data = read_optional_bytes_varint(&mut r)?;
    let no_send_change = if let Some(data) = no_send_change_data {
        let mut c = std::io::Cursor::new(data);
        let count = read_varint(&mut c)?;
        let mut outpoints = Vec::with_capacity(count as usize);
        for _ in 0..count {
            outpoints.push(read_outpoint(&mut c)?);
        }
        outpoints
    } else {
        Vec::new()
    };
    // SendWithResults
    let send_with_results = read_send_with_results(&mut r)?;
    // SignableTransaction
    let st_flag = read_byte(&mut r)?;
    let signable_transaction = if st_flag == 1 {
        let tx_data = read_bytes(&mut r)?;
        let reference = read_bytes(&mut r)?;
        Some(SignableTransaction {
            tx: tx_data,
            reference,
        })
    } else {
        None
    };
    Ok(CreateActionResult {
        txid,
        tx,
        no_send_change,
        send_with_results,
        signable_transaction,
    })
}

// ---------------------------------------------------------------------------
// SendWithResult helpers (shared with sign_action)
// ---------------------------------------------------------------------------

const ACTION_RESULT_STATUS_UNPROVEN: u8 = 1;
const ACTION_RESULT_STATUS_SENDING: u8 = 2;
const ACTION_RESULT_STATUS_FAILED: u8 = 3;

pub(crate) fn write_send_with_results(
    w: &mut impl std::io::Write,
    results: &[SendWithResult],
) -> Result<(), WalletError> {
    if results.is_empty() {
        write_varint(w, NEGATIVE_ONE)?;
        return Ok(());
    }
    write_varint(w, results.len() as u64)?;
    for res in results {
        let txid_bytes = hex_decode(&res.txid)?;
        write_raw_bytes(w, &txid_bytes)?;
        let status_byte = match res.status {
            ActionResultStatus::Unproven => ACTION_RESULT_STATUS_UNPROVEN,
            ActionResultStatus::Sending => ACTION_RESULT_STATUS_SENDING,
            ActionResultStatus::Failed => ACTION_RESULT_STATUS_FAILED,
        };
        write_byte(w, status_byte)?;
    }
    Ok(())
}

pub(crate) fn read_send_with_results(
    r: &mut impl std::io::Read,
) -> Result<Vec<SendWithResult>, WalletError> {
    let count = read_varint(r)?;
    if count == 0 || count == NEGATIVE_ONE {
        return Ok(Vec::new());
    }
    let mut results = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let txid_bytes = read_raw_bytes(r, 32)?;
        let txid = hex_encode(&txid_bytes);
        let status_byte = read_byte(r)?;
        let status = match status_byte {
            ACTION_RESULT_STATUS_UNPROVEN => ActionResultStatus::Unproven,
            ACTION_RESULT_STATUS_SENDING => ActionResultStatus::Sending,
            ACTION_RESULT_STATUS_FAILED => ActionResultStatus::Failed,
            _ => {
                return Err(WalletError::Internal(format!(
                    "invalid status byte: {}",
                    status_byte
                )))
            }
        };
        results.push(SendWithResult { txid, status });
    }
    Ok(results)
}
