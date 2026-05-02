//! STAS-3 conformance vector tests.
//!
//! Loads the canonical 12 conformance vectors from the dxs/stas3-sdk reference
//! and runs each transaction through the script interpreter, verifying that
//! the engine reaches the expected pass/fail outcome.
//!
//! Vectors fixture lives in this crate at `tests/fixtures/dstas-conformance-vectors.json`
//! (copied verbatim from `stas3-sdk/tests/fixtures/`).

use std::collections::HashMap;

use serde::Deserialize;

use bsv::script::locking_script::LockingScript;
use bsv::script::spend::{Spend, SpendParams};
use bsv::transaction::transaction::Transaction;

#[derive(Deserialize)]
struct ConformanceVector {
    id: String,
    #[serde(rename = "expectedSuccess")]
    expected_success: bool,
    #[serde(rename = "failedInputs")]
    failed_inputs: Option<Vec<usize>>,
    #[serde(rename = "txHex")]
    tx_hex: String,
    prevouts: Vec<Prevout>,
}

#[derive(Deserialize)]
struct Prevout {
    #[serde(rename = "inputIndex")]
    input_index: usize,
    #[serde(rename = "txId")]
    tx_id: String,
    vout: u32,
    #[serde(rename = "lockingScriptHex")]
    locking_script_hex: String,
    satoshis: u64,
}

/// Evaluate one input through the Spend interpreter.
fn evaluate_input(
    tx: &Transaction,
    input_index: usize,
    prev_locking_hex: &str,
    prev_satoshis: u64,
    prev_txid: &str,
    prev_vout: u32,
) -> Result<bool, String> {
    let prev_locking = LockingScript::from_hex(prev_locking_hex)
        .map_err(|e| format!("parse locking_script_hex: {e:?}"))?;
    let input = &tx.inputs[input_index];
    let unlocking = input
        .unlocking_script
        .clone()
        .ok_or_else(|| format!("input {input_index} missing unlocking_script after parse"))?;
    let other_inputs: Vec<_> = tx
        .inputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != input_index)
        .map(|(_, inp)| inp.clone())
        .collect();

    let mut spend = Spend::new(SpendParams {
        locking_script: prev_locking,
        unlocking_script: unlocking,
        source_txid: prev_txid.to_string(),
        source_output_index: prev_vout as usize,
        source_satoshis: prev_satoshis,
        transaction_version: tx.version,
        transaction_lock_time: tx.lock_time,
        transaction_sequence: input.sequence,
        other_inputs,
        other_outputs: tx.outputs.clone(),
        input_index,
    });
    spend
        .validate()
        .map_err(|e| format!("interpreter error: {e:?}"))
}

fn run_vector(v: &ConformanceVector) -> Result<(), String> {
    let tx = Transaction::from_hex(&v.tx_hex)
        .map_err(|e| format!("parse tx_hex: {e:?}"))?;

    // Index prevouts by inputIndex for clarity
    let prevouts: HashMap<usize, &Prevout> =
        v.prevouts.iter().map(|p| (p.input_index, p)).collect();

    if v.expected_success {
        // Every input must validate
        for i in 0..tx.inputs.len() {
            let prev = prevouts
                .get(&i)
                .ok_or_else(|| format!("vector {}: prevout missing for input {i}", v.id))?;
            let valid = evaluate_input(
                &tx,
                i,
                &prev.locking_script_hex,
                prev.satoshis,
                &prev.tx_id,
                prev.vout,
            )
            .map_err(|e| format!("vector {} input {i}: {e}", v.id))?;
            if !valid {
                return Err(format!(
                    "vector {} input {i}: expected success but engine returned false",
                    v.id
                ));
            }
        }
    } else {
        // Inputs listed in failed_inputs must fail; others may pass
        let failed = v.failed_inputs.clone().unwrap_or_default();
        for i in &failed {
            let prev = prevouts.get(i).ok_or_else(|| {
                format!("vector {}: prevout missing for failed input {i}", v.id)
            })?;
            let result = evaluate_input(
                &tx,
                *i,
                &prev.locking_script_hex,
                prev.satoshis,
                &prev.tx_id,
                prev.vout,
            );
            // Either Ok(false), or an interpreter error — both count as "fail"
            match &result {
                Ok(true) => {
                    return Err(format!(
                        "vector {} input {i}: expected failure but engine validated",
                        v.id
                    ));
                }
                Ok(false) => {
                    println!("  fail (Ok(false))   {} input {i}", v.id);
                }
                Err(e) => {
                    println!("  fail (engine err)  {} input {i}: {e}", v.id);
                }
            }
        }
    }

    Ok(())
}

/// Regression test: BIP-143 preimage for input_index > 0 must place the
/// current input's outpoint at its actual position in `hashPrevouts`
/// (and analogously in `hashSequence`), not at index 0. The expected
/// preimage bytes below were produced from the same vector by an
/// independent reference (Python re-implementation of BIP-143) and
/// verified to ECDSA-validate against the on-chain signature.
#[test]
fn preimage_bytes_match_reference_for_input1() {
    let json = include_str!("fixtures/dstas-conformance-vectors.json");
    let vectors: Vec<ConformanceVector> =
        serde_json::from_str(json).expect("parse conformance vectors JSON");
    let v = &vectors[0];
    assert_eq!(v.id, "transfer_regular_valid");

    let tx = Transaction::from_hex(&v.tx_hex).unwrap();
    let prev1 = v.prevouts.iter().find(|p| p.input_index == 1).unwrap();
    let prev_locking = LockingScript::from_hex(&prev1.locking_script_hex).unwrap();

    // SIGHASH_ALL | SIGHASH_FORKID = 0x41
    let preimage = tx
        .sighash_preimage(1, 0x41, prev1.satoshis, &prev_locking)
        .expect("sighash_preimage");

    let expected_hex = "010000003eeb47758ac9acc332477ff0241ea93e5f5a87bc1637b919c517eab934d741a2752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad9e12bbdb12e9b017cda270cb551f159754680bd1fcd2c424d1f52f6a4e18915b010000001976a914ffb76f52c809b14255e822c83653e4b16df7c91a88ac9e05000000000000fffffffffac4f6b828d71039aa4cfb42f69db3a329f20ed57a28fbe57724a05d8857edb10000000041000000";
    let expected = hex::decode(expected_hex).unwrap();

    assert_eq!(
        hex::encode(&preimage),
        hex::encode(&expected),
        "Transaction::sighash_preimage byte mismatch for input_index=1"
    );
}

#[test]
fn conformance_all_vectors() {
    let json = include_str!("fixtures/dstas-conformance-vectors.json");
    let vectors: Vec<ConformanceVector> =
        serde_json::from_str(json).expect("parse conformance vectors JSON");

    assert_eq!(vectors.len(), 12, "expected exactly 12 conformance vectors");

    let mut failures = Vec::new();
    for v in &vectors {
        match run_vector(v) {
            Ok(()) => println!("  PASS {}", v.id),
            Err(e) => {
                eprintln!("  FAIL {}: {e}", v.id);
                failures.push(e);
            }
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
        panic!("{} of 12 vectors failed", failures.len());
    }
}
