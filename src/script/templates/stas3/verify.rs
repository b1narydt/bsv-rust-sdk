//! Engine verification — runs a STAS-3 input through the bsv-sdk script interpreter.

use super::error::Stas3Error;
use crate::script::locking_script::LockingScript;
use crate::script::spend::{Spend, SpendParams};
use crate::transaction::transaction::Transaction;

/// Run the script interpreter on input `input_index` of `tx`, validating
/// that the unlocking script (in `tx.inputs[input_index].unlocking_script`)
/// satisfies `prev_locking_script`.
///
/// Returns `Ok(true)` if the spend is valid; `Ok(false)` if interpreter
/// completed but the result is falsy; `Err(...)` if interpreter errored.
pub fn verify_input(
    tx: &Transaction,
    input_index: usize,
    prev_locking_script: &LockingScript,
    prev_satoshis: u64,
) -> Result<bool, Stas3Error> {
    let input = tx.inputs.get(input_index).ok_or_else(|| {
        Stas3Error::InvalidScript(format!(
            "input {input_index} out of range (have {})",
            tx.inputs.len()
        ))
    })?;
    let unlocking = input.unlocking_script.clone().ok_or_else(|| {
        Stas3Error::InvalidScript(format!("input {input_index} has no unlocking script"))
    })?;
    let txid = if let Some(ref t) = input.source_txid {
        t.clone()
    } else if let Some(ref src) = input.source_transaction {
        src.id()
            .map_err(|e| Stas3Error::InvalidScript(format!("compute source txid: {e}")))?
    } else {
        return Err(Stas3Error::InvalidScript(
            "input missing source txid".into(),
        ));
    };

    let other_inputs: Vec<_> = tx
        .inputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != input_index)
        .map(|(_, inp)| inp.clone())
        .collect();

    let mut spend = Spend::new(SpendParams {
        locking_script: prev_locking_script.clone(),
        unlocking_script: unlocking,
        source_txid: txid,
        source_output_index: input.source_output_index as usize,
        source_satoshis: prev_satoshis,
        transaction_version: tx.version,
        transaction_lock_time: tx.lock_time,
        transaction_sequence: input.sequence,
        other_inputs,
        other_outputs: tx.outputs.clone(),
        input_index,
    });

    spend.validate().map_err(Stas3Error::Script)
}
