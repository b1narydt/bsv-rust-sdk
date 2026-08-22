//! Official cross-language historical regression corpus.

#![cfg(feature = "network")]

mod conformance_harness;

use std::io::Cursor;

use bsv::primitives::hash::hash256;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::locking_script::LockingScript;
use bsv::script::op::Op;
use bsv::script::script::Script;
use bsv::script::script_chunk::ScriptChunk;
use bsv::services::storage::{get_hash_from_url, get_url_for_hash, is_valid_url};
use bsv::transaction::{Beef, Transaction, TransactionInput};
use conformance_harness::{
    bool_value, bytes, ensure, hex_string, number, run_corpora, string, usize_value, Corpus,
    KnownDivergence, Vector,
};

const BEEF_ISVALID: &str =
    include_str!("../conformance/vectors/regressions/beef-isvalid-hydration.json");
const BEEF_V2: &str = include_str!("../conformance/vectors/regressions/beef-v2-txid-panic.json");
const BIP276: &str = include_str!("../conformance/vectors/regressions/bip276-hex-decode.json");
const FEE_MODEL: &str = include_str!("../conformance/vectors/regressions/fee-model-mismatch.json");
const MERKLE_ODD: &str =
    include_str!("../conformance/vectors/regressions/merkle-path-odd-node.json");
const PRIVATE_MOD: &str =
    include_str!("../conformance/vectors/regressions/privatekey-modular-reduction.json");
const SCRIPT_ASM: &str =
    include_str!("../conformance/vectors/regressions/script-fromasm-numeric-token.json");
const SCRIPT_LSHIFT: &str =
    include_str!("../conformance/vectors/regressions/script-lshift-truncation.json");
const SCRIPT_SHIFT_ENDIAN: &str =
    include_str!("../conformance/vectors/regressions/script-shift-endianness.json");
const SCRIPT_WRITE_EMPTY: &str =
    include_str!("../conformance/vectors/regressions/script-writebin-empty.json");
const TX_SEQUENCE: &str =
    include_str!("../conformance/vectors/regressions/tx-sequence-zero-sighash.json");
const UHRP: &str = include_str!("../conformance/vectors/regressions/uhrp-url-parity.json");

const CORPORA: &[Corpus<'_>] = &[
    Corpus {
        category: "beef-isvalid-hydration",
        json: BEEF_ISVALID,
        expected_count: 2,
    },
    Corpus {
        category: "beef-v2-txid-panic",
        json: BEEF_V2,
        expected_count: 2,
    },
    Corpus {
        category: "bip276-hex-decode",
        json: BIP276,
        expected_count: 3,
    },
    Corpus {
        category: "fee-model-mismatch",
        json: FEE_MODEL,
        expected_count: 3,
    },
    Corpus {
        category: "merkle-path-odd-node",
        json: MERKLE_ODD,
        expected_count: 5,
    },
    Corpus {
        category: "privatekey-modular-reduction",
        json: PRIVATE_MOD,
        expected_count: 3,
    },
    Corpus {
        category: "script-fromasm-numeric-token",
        json: SCRIPT_ASM,
        expected_count: 3,
    },
    Corpus {
        category: "script-lshift-truncation",
        json: SCRIPT_LSHIFT,
        expected_count: 3,
    },
    Corpus {
        category: "script-shift-endianness",
        json: SCRIPT_SHIFT_ENDIAN,
        expected_count: 3,
    },
    Corpus {
        category: "script-writebin-empty",
        json: SCRIPT_WRITE_EMPTY,
        expected_count: 2,
    },
    Corpus {
        category: "tx-sequence-zero-sighash",
        json: TX_SEQUENCE,
        expected_count: 3,
    },
    Corpus {
        category: "uhrp-url-parity",
        json: UHRP,
        expected_count: 4,
    },
];
const KNOWN_DIVERGENCES: &[KnownDivergence<'_>] = &[
    KnownDivergence {
        id: "regression.privatekey.modular-reduction.0002",
        reason: "Rust rejects n+12 instead of reducing it to scalar 12",
        evidence: "private-key parse failed",
    },
    KnownDivergence {
        id: "regression.script.writebin-empty.0001",
        reason: "Rust renders OP_0 as 0 in ASM",
        evidence: "expected ASM OP_0, got 0",
    },
];

fn parse_beef(vector: &Vector) -> Result<Beef, String> {
    Beef::from_binary(&mut Cursor::new(bytes(string(&vector.input, "beef_hex"))?))
        .map_err(|error| error.to_string())
}

fn dispatch_beef_isvalid(vector: &Vector) -> Result<(), String> {
    let operation = string(&vector.input, "operation");
    let beef = parse_beef(vector)?;
    if operation == "NewBeefFromBytes_IsValid" {
        // Mirrors regressions.ts:156-170.
        let got = beef.is_valid(true).map_err(|error| error.to_string())?;
        let want = bool_value(&vector.expected, "is_valid");
        return ensure(got == want, || {
            format!("expected Beef.isValid={want}, got {got}")
        });
    }
    if operation == "NewTransactionFromBEEFHex_TxID" {
        // Mirrors regressions.ts:171-178: only presence of any tx is asserted.
        let got = !beef.txs.is_empty();
        let want = bool_value(&vector.expected, "txid_non_null");
        return ensure(got == want, || {
            format!("expected tx presence={want}, got {got}")
        });
    }
    Ok(())
}

fn dispatch_beef_v2(vector: &Vector) -> Result<(), String> {
    // Mirrors sdk.ts:561-583.
    let parsed = parse_beef(vector);
    let got_parse = parsed.is_ok();
    let want_parse = bool_value(&vector.expected, "parse_succeeds");
    ensure(got_parse == want_parse, || {
        format!("expected BEEF parse={want_parse}, got {got_parse}: {parsed:?}")
    })?;
    if let Ok(beef) = parsed {
        if vector.expected.get("txid_non_null").is_some() {
            let got = !beef.txs.is_empty();
            let want = bool_value(&vector.expected, "txid_non_null");
            ensure(got == want, || {
                format!("expected tx presence={want}, got {got}")
            })?;
        }
    }
    Ok(())
}

fn decode_bip276_structural(encoded: &str) -> Option<(&str, u8, u8, &str)> {
    let colon = encoded.find(':')?;
    let prefix = &encoded[..colon];
    let rest = &encoded[colon + 1..];
    if rest.len() < 12 {
        return None;
    }
    let network = u8::from_str_radix(&rest[..2], 16).ok()?;
    let version = u8::from_str_radix(&rest[2..4], 16).ok()?;
    Some((prefix, network, version, &rest[4..rest.len() - 8]))
}

fn dispatch_bip276(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let operation = string(input, "operation");
    if operation == "DecodeBIP276" {
        // Mirrors regressions.ts:220-232. This is deliberately structural and
        // does not add checksum validation that the dispatcher does not perform.
        let decoded = decode_bip276_structural(string(input, "bip276_string"))
            .ok_or("structural BIP276 decode failed")?;
        ensure(decoded.0 == string(expected, "prefix"), || {
            "prefix mismatch".to_string()
        })?;
        ensure(decoded.1 as i64 == number(expected, "network"), || {
            "network mismatch".to_string()
        })?;
        ensure(decoded.2 as i64 == number(expected, "version"), || {
            "version mismatch".to_string()
        })?;
        return ensure(decoded.3 == string(expected, "data_hex"), || {
            "data hex mismatch".to_string()
        });
    }
    if operation == "EncodeBIP276_then_Decode" {
        // Mirrors regressions.ts:192-200 and 235-247.
        let prefix = string(input, "prefix");
        let network = number(input, "network") as u8;
        let version = number(input, "version") as u8;
        let data = string(input, "data_hex");
        let payload = format!("{prefix}:{network:02x}{version:02x}{data}");
        let checksum = hex_string(&hash256(payload.as_bytes())[..4]);
        let encoded = format!("{payload}{checksum}");
        let decoded = decode_bip276_structural(&encoded).ok_or("round-trip decode failed")?;
        ensure(
            decoded.1 as i64 == number(expected, "round_trip_network"),
            || "round-trip network mismatch".to_string(),
        )?;
        ensure(
            decoded.2 as i64 == number(expected, "round_trip_version"),
            || "round-trip version mismatch".to_string(),
        )?;
        return ensure(decoded.3 == string(expected, "round_trip_data_hex"), || {
            "round-trip data mismatch".to_string()
        });
    }
    Ok(())
}

fn dispatch_fee(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:250-274: the official dispatcher computes the
    // node formula directly rather than invoking an SDK fee-model class.
    if string(&vector.input, "operation") != "compute_fee" {
        return Ok(());
    }
    let size = number(&vector.input, "size_bytes");
    let rate = number(&vector.input, "satoshis_per_kb");
    let mut got = size * rate / 1000;
    if size != 0 && rate != 0 && got == 0 {
        got = 1;
    }
    let want = number(&vector.expected, "fee_satoshis");
    ensure(got == want, || format!("expected fee {want}, got {got}"))
}

fn dispatch_merkle_odd(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:84-96.
    if string(&vector.input, "operation") != "merkle_tree_parent" {
        return Ok(());
    }
    let mut pair = bytes(string(&vector.input, "left_hex"))?;
    pair.extend_from_slice(&bytes(string(&vector.input, "right_hex"))?);
    let got = hex_string(hash256(&pair));
    let want = string(&vector.expected, "parent_hex");
    ensure(got == want, || format!("expected parent {want}, got {got}"))
}

fn dispatch_private_modular(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:126-143. Parse failures only satisfy vectors that
    // actually carry expected.error; successful WIF assertions remain exact.
    let parsed = PrivateKey::from_hex(string(&vector.input, "scalar_hex"));
    let key = match parsed {
        Ok(key) => key,
        Err(_) if !string(&vector.expected, "error").is_empty() => return Ok(()),
        Err(error) => return Err(format!("private-key parse failed: {error}")),
    };
    let want = string(&vector.expected, "wif");
    if want.is_empty() {
        return Ok(());
    }
    let got = key.to_wif(&[0x80]);
    ensure(got == want, || format!("expected WIF {want}, got {got}"))
}

fn dispatch_script_asm(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:283-293.
    if string(&vector.input, "operation") != "fromASM_toHex" {
        return Ok(());
    }
    let got = Script::from_asm(string(&vector.input, "asm")).to_hex();
    let want = string(&vector.expected, "hex");
    ensure(got == want, || {
        format!("expected script hex {want}, got {got}")
    })
}

fn compute_shift(value_hex: &str, shift: usize, left: bool) -> Result<String, String> {
    let input = bytes(value_hex)?;
    if input.is_empty() {
        return Ok(String::new());
    }
    let mut value = input
        .iter()
        .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte));
    if left {
        value <<= shift;
        let width = input.len() * 8;
        let mask = if width == 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        value &= mask;
    } else {
        value >>= shift;
    }
    Ok(format!("{value:0width$x}", width = input.len() * 2))
}

fn dispatch_script_shift(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:303-371: the dispatcher computes fixed-width,
    // big-endian shifts directly.
    let operation = string(&vector.input, "operation");
    if operation != "op_lshift" && operation != "op_rshift" {
        return Ok(());
    }
    let got = compute_shift(
        string(&vector.input, "value_hex"),
        usize_value(&vector.input, "shift_bits"),
        operation == "op_lshift",
    )?;
    let want = string(&vector.expected, "result_hex");
    ensure(got == want, || {
        format!("expected shift result {want}, got {got}")
    })?;
    ensure(
        got.len() / 2 == usize_value(&vector.expected, "result_length_bytes"),
        || "shift result length mismatch".to_string(),
    )
}

fn dispatch_script_write_empty(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:374-399. `Script::from_chunks` expresses the same
    // public OP_0 result because Rust has no mutating writeBin method.
    let script = Script::from_chunks(vec![ScriptChunk::new_opcode(Op::Op0)]);
    match string(&vector.input, "operation") {
        "script_writeBin_toASM" => {
            let got = script.to_asm();
            let want = string(&vector.expected, "asm");
            ensure(got == want, || format!("expected ASM {want}, got {got}"))
        }
        "script_writeBin_toHex" => {
            let got = script.to_hex();
            let want = string(&vector.expected, "hex");
            ensure(got == want, || {
                format!("expected script hex {want}, got {got}")
            })
        }
        _ => Ok(()),
    }
}

fn sequence_transaction(vector: &Vector) -> Transaction {
    Transaction {
        version: vector.input["version"].as_u64().unwrap_or(1) as u32,
        inputs: vec![TransactionInput {
            source_txid: Some("00".repeat(32)),
            source_output_index: 0,
            sequence: vector.input["input_sequence"].as_u64().unwrap_or(0) as u32,
            ..Default::default()
        }],
        outputs: Vec::new(),
        lock_time: vector.input["lock_time"].as_u64().unwrap_or(0) as u32,
        merkle_path: None,
    }
}

fn dispatch_tx_sequence(vector: &Vector) -> Result<(), String> {
    let operation = string(&vector.input, "operation");
    let tx = sequence_transaction(vector);
    if operation == "sighash_preimage" {
        // Mirrors regressions.ts:413-450. Rust's transaction preimage API is
        // the direct equivalent of TransactionSignature.format here.
        let preimage = tx
            .sighash_preimage(
                0,
                SIGHASH_ALL | SIGHASH_FORKID,
                0,
                &LockingScript::from_binary(&[]),
            )
            .map_err(|error| error.to_string())?;
        let sequence_offset = 4 + 32 + 32 + 32 + 4 + 1 + 8;
        let got = hex_string(&preimage.bytes()[sequence_offset..sequence_offset + 4]);
        let want = string(&vector.expected, "preimage_sequence_field_hex");
        return ensure(got == want, || {
            format!("expected preimage sequence {want}, got {got}")
        });
    }
    if operation == "serialise_input_sequence" {
        // Mirrors regressions.ts:453-472.
        let raw = tx.to_bytes().map_err(|error| error.to_string())?;
        let sequence_offset = 4 + 1 + 32 + 4 + 1;
        let got = hex_string(&raw[sequence_offset..sequence_offset + 4]);
        let want = string(&vector.expected, "serialised_sequence_hex");
        return ensure(got == want, || {
            format!("expected serialized sequence {want}, got {got}")
        });
    }
    Ok(())
}

fn dispatch_uhrp(vector: &Vector) -> Result<(), String> {
    // Mirrors regressions.ts:98-124.
    let input = &vector.input;
    let expected = &vector.expected;
    let hash = string(input, "hash_hex");
    if !hash.is_empty() {
        let raw: [u8; 32] = bytes(hash)?
            .try_into()
            .map_err(|raw: Vec<u8>| format!("expected 32-byte hash, got {}", raw.len()))?;
        let want_url = string(expected, "url");
        if !want_url.is_empty() {
            let got = get_url_for_hash(&raw);
            return ensure(got == want_url, || {
                format!("expected UHRP URL {want_url}, got {got}")
            });
        }
        if expected.get("valid").is_some() {
            let got = !get_url_for_hash(&raw).is_empty();
            let want = bool_value(expected, "valid");
            return ensure(got == want, || format!("expected valid={want}, got {got}"));
        }
    }
    let url = string(input, "url");
    if !url.is_empty() {
        let want_hash = string(expected, "hash_hex");
        if !want_hash.is_empty() {
            let got = get_hash_from_url(url)
                .map(hex_string)
                .map_err(|error| error.to_string())?;
            return ensure(got == want_hash, || {
                format!("expected UHRP hash {want_hash}, got {got}")
            });
        }
        if expected.get("valid").is_some() {
            let got = is_valid_url(url);
            let want = bool_value(expected, "valid");
            return ensure(got == want, || format!("expected valid={want}, got {got}"));
        }
    }
    Ok(())
}

fn dispatch(category: &str, vector: &Vector) -> Result<(), String> {
    match category {
        "beef-isvalid-hydration" => dispatch_beef_isvalid(vector),
        "beef-v2-txid-panic" => dispatch_beef_v2(vector),
        "bip276-hex-decode" => dispatch_bip276(vector),
        "fee-model-mismatch" => dispatch_fee(vector),
        "merkle-path-odd-node" => dispatch_merkle_odd(vector),
        "privatekey-modular-reduction" => dispatch_private_modular(vector),
        "script-fromasm-numeric-token" => dispatch_script_asm(vector),
        "script-lshift-truncation" | "script-shift-endianness" => dispatch_script_shift(vector),
        "script-writebin-empty" => dispatch_script_write_empty(vector),
        "tx-sequence-zero-sighash" => dispatch_tx_sequence(vector),
        "uhrp-url-parity" => dispatch_uhrp(vector),
        _ => Err(format!("unknown regression category {category}")),
    }
}

#[test]
fn official_regression_conformance() {
    run_corpora(CORPORA, &[], KNOWN_DIVERGENCES, dispatch);
}
