//! InternalizeAction args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::types::BooleanDefaultTrue;

const PROTOCOL_WALLET_PAYMENT: u8 = 1;
const PROTOCOL_BASKET_INSERTION: u8 = 2;

pub fn serialize_internalize_action_args(
    args: &InternalizeActionArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Tx (length-prefixed)
        write_varint(w, args.tx.len() as u64)?;
        write_raw_bytes(w, &args.tx)?;
        // Outputs
        write_varint(w, args.outputs.len() as u64)?;
        for output in &args.outputs {
            match output {
                InternalizeOutput::WalletPayment {
                    output_index,
                    payment,
                } => {
                    write_varint(w, *output_index as u64)?;
                    write_byte(w, PROTOCOL_WALLET_PAYMENT)?;
                    write_public_key(w, &payment.sender_identity_key)?;
                    write_bytes(w, &payment.derivation_prefix)?;
                    write_bytes(w, &payment.derivation_suffix)?;
                }
                InternalizeOutput::BasketInsertion {
                    output_index,
                    insertion,
                } => {
                    write_varint(w, *output_index as u64)?;
                    write_byte(w, PROTOCOL_BASKET_INSERTION)?;
                    write_string(w, &insertion.basket)?;
                    write_string_optional(
                        w,
                        &insertion.custom_instructions.clone().unwrap_or_default(),
                    )?;
                    write_string_slice(
                        w,
                        &if insertion.tags.is_empty() {
                            None
                        } else {
                            Some(insertion.tags.clone())
                        },
                    )?;
                }
            }
        }
        // Labels, description, seekPermission
        write_string_slice(
            w,
            &if args.labels.is_empty() {
                None
            } else {
                Some(args.labels.clone())
            },
        )?;
        write_string(w, &args.description)?;
        write_optional_bool(w, args.seek_permission.0)
    })
}

pub fn deserialize_internalize_action_args(
    data: &[u8],
) -> Result<InternalizeActionArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let tx_len = read_varint(&mut r)?;
    let tx = read_raw_bytes(&mut r, tx_len as usize)?;
    let output_count = read_varint(&mut r)?;
    let mut outputs = Vec::with_capacity(output_count as usize);
    for _ in 0..output_count {
        let output_index = read_varint(&mut r)? as u32;
        let protocol_byte = read_byte(&mut r)?;
        let output = match protocol_byte {
            PROTOCOL_WALLET_PAYMENT => {
                let sender_identity_key = read_public_key(&mut r)?;
                let derivation_prefix = read_bytes(&mut r)?;
                let derivation_suffix = read_bytes(&mut r)?;
                InternalizeOutput::WalletPayment {
                    output_index,
                    payment: Payment {
                        derivation_prefix,
                        derivation_suffix,
                        sender_identity_key,
                    },
                }
            }
            PROTOCOL_BASKET_INSERTION => {
                let basket = read_string(&mut r)?;
                let custom_instructions_str = read_string(&mut r)?;
                let custom_instructions = if custom_instructions_str.is_empty() {
                    None
                } else {
                    Some(custom_instructions_str)
                };
                let tags = read_string_slice(&mut r)?.unwrap_or_default();
                InternalizeOutput::BasketInsertion {
                    output_index,
                    insertion: BasketInsertion {
                        basket,
                        custom_instructions,
                        tags,
                    },
                }
            }
            _ => {
                return Err(WalletError::Internal(format!(
                    "invalid protocol byte: {}",
                    protocol_byte
                )))
            }
        };
        outputs.push(output);
    }
    let labels = read_string_slice(&mut r)?.unwrap_or_default();
    let description = read_string(&mut r)?;
    let seek_permission = BooleanDefaultTrue(read_optional_bool(&mut r)?);
    Ok(InternalizeActionArgs {
        tx,
        description,
        labels,
        seek_permission,
        outputs,
    })
}

pub fn serialize_internalize_action_result(
    _result: &InternalizeActionResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_internalize_action_result(
    _data: &[u8],
) -> Result<InternalizeActionResult, WalletError> {
    Ok(InternalizeActionResult { accepted: true })
}
