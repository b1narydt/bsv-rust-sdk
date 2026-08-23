//! SignAction args/result serialization.

use super::create_action::{read_send_with_results, write_send_with_results};
use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::{BooleanDefaultFalse, BooleanDefaultTrue};
use std::collections::HashMap;

pub fn serialize_sign_action_args(args: &SignActionArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Spends map (sorted by key)
        write_varint(w, args.spends.len() as u64)?;
        let mut keys: Vec<u32> = args.spends.keys().copied().collect();
        keys.sort();
        for key in keys {
            let spend = &args.spends[&key];
            write_varint(w, key as u64)?;
            write_bytes(w, &spend.unlocking_script)?;
            write_optional_uint32(w, spend.sequence_number)?;
        }
        // Reference
        write_bytes(w, &args.reference)?;
        // Options
        if let Some(ref opts) = args.options {
            write_byte(w, 1)?;
            write_optional_bool(w, opts.accept_delayed_broadcast.0)?;
            write_optional_bool(w, opts.return_txid_only.0)?;
            write_optional_bool(w, opts.no_send.0)?;
            // SendWith
            if let Some(send_with) = &opts.send_with {
                write_varint(w, send_with.len() as u64)?;
                for txid in send_with {
                    let txid_bytes = hex_decode(txid)?;
                    write_raw_bytes(w, &txid_bytes)?;
                }
            } else {
                write_varint(w, NEGATIVE_ONE)?;
            }
        } else {
            write_byte(w, 0)?;
        }
        Ok(())
    })
}

pub fn deserialize_sign_action_args(data: &[u8]) -> Result<SignActionArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let spend_count = read_varint(&mut r)?;
    let mut spends = HashMap::new();
    for _ in 0..spend_count {
        let index = read_varint(&mut r)? as u32;
        let unlocking_script = read_bytes(&mut r)?;
        let sequence_number = read_optional_uint32(&mut r)?;
        spends.insert(
            index,
            SignActionSpend {
                unlocking_script,
                sequence_number,
            },
        );
    }
    let reference = read_bytes(&mut r)?;
    let options_flag = read_byte(&mut r)?;
    let options = if options_flag == 1 {
        let accept_delayed_broadcast = BooleanDefaultTrue(read_optional_bool(&mut r)?);
        let return_txid_only = BooleanDefaultFalse(read_optional_bool(&mut r)?);
        let no_send = BooleanDefaultFalse(read_optional_bool(&mut r)?);
        let send_count = read_varint(&mut r)?;
        let send_with = if send_count == NEGATIVE_ONE {
            None
        } else {
            let mut txids = Vec::with_capacity(send_count as usize);
            for _ in 0..send_count {
                let txid_bytes = read_raw_bytes(&mut r, 32)?;
                txids.push(hex_encode(&txid_bytes));
            }
            Some(txids)
        };
        Some(SignActionOptions {
            accept_delayed_broadcast,
            return_txid_only,
            no_send,
            send_with,
        })
    } else {
        None
    };
    Ok(SignActionArgs {
        reference,
        spends,
        options,
    })
}

pub fn serialize_sign_action_result(result: &SignActionResult) -> Result<Vec<u8>, WalletError> {
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
        // Tx (optional with flag)
        write_optional_bytes_with_flag(w, result.tx.as_deref())?;
        // SendWithResults
        write_send_with_results(w, &result.send_with_results)
    })
}

pub fn deserialize_sign_action_result(data: &[u8]) -> Result<SignActionResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let txid_bytes = read_optional_bytes_with_flag_fixed(&mut r, 32)?;
    let txid = txid_bytes.map(|b| hex_encode(&b));
    let tx = read_optional_bytes_with_flag(&mut r)?;
    let send_with_results = read_send_with_results(&mut r)?;
    Ok(SignActionResult {
        txid,
        tx,
        send_with_results,
    })
}
