//! Official BSV SDK transaction and Merkle-path conformance corpus.

mod conformance_harness;

use std::io::Cursor;

use bsv::primitives::hash::hash256;
use bsv::transaction::{
    Beef, FeeModel, MerklePath, MerklePathLeaf, SatoshisPerKilobyte, Transaction, TransactionInput,
    TransactionOutput,
};
use conformance_harness::{
    bool_value, bytes, ensure, hex_string, run_corpora, string, usize_value, Corpus,
    KnownDivergence, Vector,
};

const MERKLE_PATH: &str = include_str!("../conformance/vectors/sdk/transactions/merkle-path.json");
const SERIALIZATION: &str =
    include_str!("../conformance/vectors/sdk/transactions/serialization.json");

const CORPORA: &[Corpus<'_>] = &[
    Corpus {
        category: "merkle-path",
        json: MERKLE_PATH,
        expected_count: 16,
    },
    Corpus {
        category: "serialization",
        json: SERIALIZATION,
        expected_count: 15,
    },
];
const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[KnownDivergence {
    id: "mp-compound-001",
    reason: "Rust rejects the official compound BUMP while TypeScript parses it",
    evidence: "Mismatched roots",
}];

fn merkle_root_from_display_txids(txids: &[serde_json::Value]) -> Result<String, String> {
    if txids.is_empty() {
        return Err("empty txid list".to_string());
    }
    let mut level = txids
        .iter()
        .map(|value| {
            let mut raw = bytes(value.as_str().unwrap_or(""))?;
            raw.reverse();
            Ok(raw)
        })
        .collect::<Result<Vec<_>, String>>()?;
    while level.len() > 1 {
        if !level.len().is_multiple_of(2) {
            level.push(level.last().unwrap().clone());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut joined = pair[0].clone();
                joined.extend_from_slice(&pair[1]);
                hash256(&joined).to_vec()
            })
            .collect();
    }
    level[0].reverse();
    Ok(hex_string(&level[0]))
}

fn dispatch_merkle_path(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    if !string(input, "leaf0_hash").is_empty() {
        // Mirrors sdkHelpers.ts:154-166: the duplicate flag overrides leaf1.
        let left = bytes(string(input, "leaf0_hash"))?;
        let right = if bool_value(input, "leaf1_duplicate") {
            left.clone()
        } else {
            bytes(string(input, "leaf1_hash"))?
        };
        let mut pair = left;
        pair.extend_from_slice(&right);
        let mut parent = hash256(&pair).to_vec();
        parent.reverse();
        let got = hex_string(parent);
        let want = string(expected, "computed_hash");
        if !want.is_empty() {
            return ensure(got == want, || {
                format!("expected duplicate-leaf parent {want}, got {got}")
            });
        }
        return Ok(());
    }

    let bump = {
        let direct = string(input, "bump_hex");
        if direct.is_empty() {
            string(input, "combined_bump_hex")
        } else {
            direct
        }
    };
    if bump.is_empty() {
        if input.get("height").is_some() {
            // Mirrors sdkHelpers.ts:168-180.
            let txid = string(input, "txid");
            let height = input["height"].as_u64().unwrap() as u32;
            let path = MerklePath::new(
                height,
                vec![vec![MerklePathLeaf {
                    offset: 0,
                    hash: Some(txid.to_string()),
                    txid: true,
                    duplicate: false,
                }]],
            )
            .map_err(|error| error.to_string())?;
            let want_hex = string(expected, "bump_hex");
            if !want_hex.is_empty() {
                let got = path.to_hex().map_err(|error| error.to_string())?;
                ensure(got == want_hex, || {
                    format!("expected coinbase BUMP {want_hex}, got {got}")
                })?;
            }
            if let Some(want) = expected
                .get("block_height")
                .and_then(serde_json::Value::as_u64)
            {
                ensure(path.block_height as u64 == want, || {
                    format!("expected block height {want}, got {}", path.block_height)
                })?;
            }
            let want_root = string(expected, "merkle_root");
            if !want_root.is_empty() {
                let got = path
                    .compute_root(Some(txid))
                    .map_err(|error| error.to_string())?;
                ensure(got == want_root, || {
                    format!("expected coinbase root {want_root}, got {got}")
                })?;
            }
            return Ok(());
        }
        if let Some(txids) = input.get("txids").and_then(serde_json::Value::as_array) {
            // Mirrors sdk.ts:531-545.
            let got = merkle_root_from_display_txids(txids)?;
            let want = string(expected, "merkle_root");
            return ensure(got == want, || {
                format!("expected Merkle root {want}, got {got}")
            });
        }
        if let Some(txids) = input
            .get("full_block_txids")
            .and_then(serde_json::Value::as_array)
        {
            // Mirrors sdk.ts:546-553.
            let got = merkle_root_from_display_txids(txids)?;
            let want = string(expected, "merkle_root");
            ensure(got == want, || {
                format!("expected Merkle root {want}, got {got}")
            })?;
            if bool_value(expected, "extracted_smaller_than_full") {
                ensure(txids.len() >= 2, || {
                    "full block had fewer than two txids".to_string()
                })?;
            }
            return Ok(());
        }
        // Mirrors sdk.ts:555-558 and the fallthrough: empty extraction and
        // unsupported proof-construction shapes are dispatcher no-ops.
        return Ok(());
    }

    // Mirrors sdkHelpers.ts:182-237.
    let path = MerklePath::from_hex(bump).map_err(|error| error.to_string())?;
    if let Some(want) = expected
        .get("block_height")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(path.block_height as u64 == want, || {
            format!("expected block height {want}, got {}", path.block_height)
        })?;
    }
    if let Some(want) = expected
        .get("path_levels")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(path.path.len() == want as usize, || {
            format!("expected {want} path levels, got {}", path.path.len())
        })?;
    }
    if let Some(want) = expected
        .get("path_level0_length")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(path.path[0].len() == want as usize, || {
            format!("expected {want} level-0 leaves, got {}", path.path[0].len())
        })?;
    }
    let want_hex = {
        let direct = string(expected, "toHex");
        if direct.is_empty() {
            string(expected, "serialized_bump_hex")
        } else {
            direct
        }
    };
    if !want_hex.is_empty() {
        let got = path.to_hex().map_err(|error| error.to_string())?;
        ensure(got == want_hex, || {
            format!("expected BUMP {want_hex}, got {got}")
        })?;
    }
    let txid = string(input, "txid");
    if !txid.is_empty() {
        let want = string(expected, "merkle_root");
        if !want.is_empty() {
            let got = path
                .compute_root(Some(txid))
                .map_err(|error| error.to_string())?;
            ensure(got == want, || {
                format!("expected Merkle root {want}, got {got}")
            })?;
        }
    }
    if let Some(txids) = input
        .get("txids_at_level_0")
        .and_then(serde_json::Value::as_array)
    {
        for (index, txid) in txids.iter().enumerate() {
            let key = format!("merkle_root_for_tx{index}");
            let mut want = string(expected, &key);
            if want.is_empty() {
                want = string(expected, "merkle_root_for_tx0");
            }
            if !want.is_empty() {
                let got = path
                    .compute_root(Some(txid.as_str().unwrap()))
                    .map_err(|error| error.to_string())?;
                ensure(got == want, || {
                    format!("expected root for tx {index} {want}, got {got}")
                })?;
            }
        }
    }
    let want_sparse = string(expected, "merkle_root");
    if !want_sparse.is_empty() {
        for key in ["txid_tx2", "txid_tx5", "txid_tx8"] {
            let txid = string(input, key);
            if !txid.is_empty() {
                let got = path
                    .compute_root(Some(txid))
                    .map_err(|error| error.to_string())?;
                ensure(got == want_sparse, || {
                    format!("expected sparse root {want_sparse}, got {got}")
                })?;
                break;
            }
        }
    }
    Ok(())
}

fn assert_tx_fields(tx: &Transaction, expected: &serde_json::Value) -> Result<(), String> {
    if let Some(want) = expected.get("version").and_then(serde_json::Value::as_u64) {
        ensure(tx.version as u64 == want, || {
            format!("expected version {want}, got {}", tx.version)
        })?;
    }
    if let Some(want) = expected
        .get("inputs_count")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(tx.inputs.len() == want as usize, || {
            format!("expected {want} inputs, got {}", tx.inputs.len())
        })?;
    }
    if let Some(want) = expected
        .get("outputs_count")
        .and_then(serde_json::Value::as_u64)
    {
        ensure(tx.outputs.len() == want as usize, || {
            format!("expected {want} outputs, got {}", tx.outputs.len())
        })?;
    }
    if let Some(want) = expected.get("locktime").and_then(serde_json::Value::as_u64) {
        ensure(tx.lock_time as u64 == want, || {
            format!("expected locktime {want}, got {}", tx.lock_time)
        })?;
    }
    Ok(())
}

fn dispatch_serialization_operation(vector: &Vector, operation: &str) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    match operation {
        "new_transaction" => {
            // Mirrors sdk.ts:587-593.
            assert_tx_fields(&Transaction::new(), expected)
        }
        "new_transaction_hash_hex" => {
            // Mirrors sdk.ts:649-653.
            let got = Transaction::new().id().map_err(|error| error.to_string())?;
            if let Some(want) = expected
                .get("hash_length_chars")
                .and_then(serde_json::Value::as_u64)
            {
                ensure(got.len() == want as usize, || {
                    format!("expected txid length {want}, got {}", got.len())
                })?;
            }
            Ok(())
        }
        "new_transaction_id_binary" => {
            // Mirrors sdk.ts:654-658. Rust names the raw 32-byte transaction
            // identifier `hash()` rather than overloading `id()` by encoding.
            let got = Transaction::new()
                .hash()
                .map_err(|error| error.to_string())?;
            if let Some(want) = expected
                .get("id_length_bytes")
                .and_then(serde_json::Value::as_u64)
            {
                ensure(got.len() == want as usize, || {
                    format!("expected binary id length {want}, got {}", got.len())
                })?;
            }
            Ok(())
        }
        "fromAtomicBEEF" => {
            // Mirrors sdk.ts:595-605. Rust exposes the BRC-95 predicate on
            // Beef, so pair it with subject extraction rather than calling
            // the semantically different non-atomic `Transaction::from_beef`.
            let parsed = Beef::from_hex(string(input, "beef_hex"));
            if bool_value(expected, "throws") {
                let rejected = parsed
                    .as_ref()
                    .map(|beef| !beef.is_atomic(None))
                    .unwrap_or(true);
                ensure(rejected, || {
                    "non-atomic BEEF was accepted as an AtomicBEEF transaction".to_string()
                })
            } else {
                let accepted = parsed.and_then(Beef::into_transaction).is_ok();
                ensure(accepted, || {
                    "AtomicBEEF transaction did not parse".to_string()
                })
            }
        }
        "addInput" => {
            if bool_value(expected, "throws") {
                // Mirrors sdk.ts:607-611. The missing source is representable
                // by Rust's public TransactionInput, so this exercises it.
                let mut tx = Transaction::new();
                let error = tx
                    .add_input(TransactionInput::default())
                    .expect_err("addInput accepted missing source");
                return ensure(
                    error
                        .to_string()
                        .contains(string(expected, "error_pattern")),
                    || format!("unexpected addInput error: {error}"),
                );
            }
            // Mirrors sdk.ts:612-615: this branch only asserts corpus metadata.
            if expected.get("sequence").is_some() {
                return ensure(usize_value(expected, "sequence") == 0xffff_ffff, || {
                    "expected.sequence was not 0xffffffff".to_string()
                });
            }
            Ok(())
        }
        "addOutput" => {
            if !bool_value(expected, "throws") {
                return Ok(());
            }
            if input.get("satoshis").and_then(serde_json::Value::as_i64) == Some(-1) {
                // Mirrors sdk.ts:665-669. Rust's `Option<u64>` rejects this
                // invalid input at the public type boundary, before add_output.
                return Ok(());
            }
            let mut tx = Transaction::new();
            let error = tx
                .add_output(TransactionOutput::default())
                .expect_err("addOutput accepted missing satoshis/change");
            ensure(
                error
                    .to_string()
                    .contains(string(expected, "error_pattern")),
                || format!("unexpected addOutput error: {error}"),
            )
        }
        "getFee_no_source" => {
            // Mirrors sdk.ts:618-628. A source txid is enough to add the input,
            // but it does not provide the source value needed for a fee.
            let mut tx = Transaction::new();
            tx.add_input(TransactionInput {
                source_txid: Some(string(input, "source_txid").to_string()),
                source_output_index: input["source_output_index"].as_u64().unwrap_or(0) as u32,
                ..Default::default()
            })
            .map_err(|error| error.to_string())?;
            let error = SatoshisPerKilobyte::new(1)
                .compute_fee(&tx)
                .expect_err("getFee without source value succeeded");
            ensure(
                error
                    .to_string()
                    .contains(string(expected, "error_pattern")),
                || format!("unexpected getFee error: {error}"),
            )
        }
        "parseScriptOffsets" => {
            // Mirrors sdk.ts:630-637.
            let tx = Transaction::from_hex(string(input, "raw_hex"))
                .map_err(|error| error.to_string())?;
            assert_tx_fields(&tx, expected)
        }
        _ => Ok(()),
    }
}

fn dispatch_serialization(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let operation = string(input, "operation");
    if !operation.is_empty() {
        return dispatch_serialization_operation(vector, operation);
    }
    let raw = string(input, "raw_hex");
    if !raw.is_empty() {
        // Mirrors sdkHelpers.ts:241-253.
        let tx = Transaction::from_hex(raw).map_err(|error| error.to_string())?;
        assert_tx_fields(&tx, expected)?;
        let want_id = string(expected, "txid");
        if !want_id.is_empty() {
            let got = tx.id().map_err(|error| error.to_string())?;
            ensure(got == want_id, || {
                format!("expected txid {want_id}, got {got}")
            })?;
        }
        let want_raw = string(expected, "raw_hex_roundtrip");
        if !want_raw.is_empty() {
            let got = tx.to_hex().map_err(|error| error.to_string())?;
            ensure(got == want_raw, || {
                format!("expected raw round-trip {want_raw}, got {got}")
            })?;
        }
        return Ok(());
    }
    let ef = string(input, "ef_hex");
    if !ef.is_empty() {
        // Mirrors sdkHelpers.ts:255-262.
        let tx = Transaction::from_hex_ef(ef).map_err(|error| error.to_string())?;
        return assert_tx_fields(&tx, expected);
    }
    let beef_hex = string(input, "beef_hex");
    if !beef_hex.is_empty() {
        // Mirrors sdkHelpers.ts:264-272.
        let beef = Beef::from_binary(&mut Cursor::new(bytes(beef_hex)?))
            .map_err(|error| error.to_string())?;
        let want = string(expected, "merkle_root");
        if !want.is_empty() && !beef.bumps.is_empty() {
            let got = beef.bumps[0]
                .compute_root(None)
                .map_err(|error| error.to_string())?;
            return ensure(got == want, || {
                format!("expected BEEF merkle root {want}, got {got}")
            });
        }
        return Ok(());
    }
    let bump = string(input, "bump_hex");
    if !bump.is_empty() {
        // Mirrors sdkHelpers.ts:274-281.
        let path = MerklePath::from_hex(bump).map_err(|error| error.to_string())?;
        if let Some(want) = expected
            .get("block_height")
            .and_then(serde_json::Value::as_u64)
        {
            ensure(path.block_height as u64 == want, || {
                format!("expected block height {want}, got {}", path.block_height)
            })?;
        }
        if let Some(want) = expected
            .get("path_leaf_count")
            .and_then(serde_json::Value::as_u64)
        {
            ensure(path.path[0].len() == want as usize, || {
                format!("expected {want} path leaves, got {}", path.path[0].len())
            })?;
        }
    }
    Ok(())
}

fn dispatch(category: &str, vector: &Vector) -> Result<(), String> {
    match category {
        "merkle-path" => dispatch_merkle_path(vector),
        "serialization" => dispatch_serialization(vector),
        _ => Err(format!("unknown transaction category {category}")),
    }
}

#[test]
fn official_transaction_conformance() {
    run_corpora(CORPORA, &[], KNOWN_DIVERGENCES, dispatch);
}
