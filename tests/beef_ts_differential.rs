//! Differential replay of `test-vectors/generator/beef_ts_differential_harness.mjs`.
//!
//! The harness drives the normative @bsv/sdk (2.3.1) through call sequences
//! that the BEEF golden corpus does not pin — merges after a sort, merges of
//! graphs built with `mergeTransaction`, txid-only subjects, hostile bumps,
//! `BeefParty` trimming — and records every observable (`txs` order, bytes,
//! verdicts) in `test-vectors/beef_ts_differential.json`. This test runs the
//! same sequences here and compares.
//!
//! Where Rust deliberately does not reproduce a TS side effect, the test
//! asserts Rust's documented behavior AND the TS value it diverges from, so
//! a change on either side is caught:
//!
//! * `verify_valid` / `get_valid_txids` do not reorder `txs` (TS sorts in
//!   place), so a parsed beef's bytes after a verify are its input bytes
//!   here and the sorted bytes in TS (scenario B).
//! * A repeat `sort_txs` lists `valid` in current array order (TS memoizes
//!   the first result) (scenario H).
//! * `merge_beef_from_party` does not pre-sort `other` (TS `getValidTxids`
//!   sorts it in place); bytes agree, array order differs (scenario C).
//!
//! Set `BEEF_TS_DIFFERENTIAL_OUT=<path>` to also write the Rust observables
//! as JSON keyed like the harness output, for an external diff.

use std::collections::BTreeMap;
use std::io::Cursor;

use bsv::transaction::beef::{Beef, BEEF_V2};
use bsv::transaction::beef_party::BeefParty;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::transaction::Transaction;
use serde_json::{json, Value};

fn load_json(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}")))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse(hex: &str) -> Beef {
    Beef::from_binary(&mut Cursor::new(hex::decode(hex).unwrap())).unwrap()
}

fn to_hex(beef: &Beef) -> String {
    beef.to_hex().unwrap()
}

/// The harness's `order()`: `txid[..8]`, `(txidonly)` marker, `[b<i>]` proof.
fn order(beef: &Beef) -> Vec<String> {
    beef.txs
        .iter()
        .map(|t| {
            let mut s = t.txid[..8].to_string();
            if t.is_txid_only() {
                s.push_str("(txidonly)");
            }
            if let Some(bi) = t.bump_index {
                s.push_str(&format!("[b{bi}]"));
            }
            s
        })
        .collect()
}

fn short(txids: &[String]) -> Vec<String> {
    txids.iter().map(|t| t[..8].to_string()).collect()
}

fn sort_result_json(r: &bsv::transaction::beef::BeefSortResult) -> Value {
    json!({
        "missingInputs": r.missing_inputs,
        "notValid": r.not_valid,
        "valid": r.valid,
        "withMissingInputs": r.with_missing_inputs,
        "txidOnly": r.txid_only,
    })
}

struct Diff {
    ts: Value,
    rust: BTreeMap<String, Value>,
}

impl Diff {
    fn record(&mut self, key: &str, value: Value) {
        self.rust.insert(key.to_string(), value);
    }
    /// Rust must equal TS for this key.
    fn same(&mut self, key: &str, value: Value) {
        assert_eq!(value, self.ts[key], "scenario {key}: Rust diverges from TS");
        self.record(key, value);
    }
    /// Rust deliberately differs from TS for this key: pin both sides.
    fn documented(&mut self, key: &str, rust: Value, ts_expected: Value) {
        assert_eq!(
            self.ts[key], ts_expected,
            "scenario {key}: the TS side moved"
        );
        assert_ne!(
            rust, self.ts[key],
            "scenario {key}: now matches TS — update the docs"
        );
        self.record(key, rust);
    }
}

#[test]
fn ts_differential_scenarios() {
    let mut d = Diff {
        ts: load_json("beef_ts_differential.json"),
        rust: BTreeMap::new(),
    };
    let sort = load_json("beef_sort_order.json")["vectors"].clone();
    let s1 = &sort[0]; // already sorted chain: 92af(proven), 529a, 8df6
    let s2 = &sort[1]; // reversed chain
    let s4 = &sort[3]; // txid-only entry
    let s5 = &sort[4]; // interleaved proven families
    let input = |v: &Value| v["input_beef_hex"].as_str().unwrap().to_string();
    let valid = |v: &Value, i: usize| v["sort_result"]["valid"][i].as_str().unwrap().to_string();
    let t8 = valid(s1, 2);
    let t5 = valid(s1, 1);

    // A: a state-changing bump merged into an already-sorted beef, with and
    // without the explicit sort.
    for (label, txid) in [("A1_bump_8df6", &t8), ("A2_bump_529a", &t5)] {
        let mp = MerklePath::new(
            800_002,
            vec![vec![MerklePathLeaf {
                offset: 0,
                hash: Some(txid.clone()),
                txid: true,
                duplicate: false,
            }]],
        )
        .unwrap();
        d.same(&format!("{label}_bump_hex"), json!(mp.to_hex().unwrap()));
        let mut b = parse(&input(s1));
        b.sort_txs();
        b.merge_bump(&mp).unwrap();
        d.same(&format!("{label}_order"), json!(order(&b)));
        d.same(&format!("{label}_hex"), json!(to_hex(&b)));
        let mut c = parse(&input(s1));
        c.merge_bump(&mp).unwrap();
        d.same(&format!("{label}_nosort_hex"), json!(to_hex(&c)));
    }

    // B: verify / getValidTxids on a parsed reversed chain. TS sorts in
    // place; Rust leaves `txs` as parsed, so the bytes stay the input bytes.
    {
        let b = parse(&input(s2));
        d.same("B_parsed_order", json!(order(&b)));
        assert!(b.verify_valid(false).unwrap().valid);
        let sorted_hex = s2["expected_serialized_hex_after_sort"].as_str().unwrap();
        d.documented(
            "B_after_verify_order",
            json!(order(&b)),
            json!(["92afff0f[b0]", "529a4399", "8df60301"]),
        );
        d.documented("B_after_verify_hex", json!(to_hex(&b)), json!(sorted_hex));
        let c = parse(&input(s2));
        let _ = c.get_valid_txids();
        d.documented(
            "B_after_getValidTxids_hex",
            json!(to_hex(&c)),
            json!(sorted_hex),
        );
        d.same("B_untouched_hex", json!(to_hex(&parse(&input(s2)))));
        assert_eq!(
            d.ts["B_untouched_hex"],
            json!(input(s2)),
            "TS hands back its parse cache"
        );
    }

    // C: mergeBeefFromParty vs plain mergeBeef. TS sorts `other` in place
    // while collecting its valid txids; Rust reads them without sorting.
    for (label, v) in [("C_s2", s2), ("C_s5", s5), ("C_s4", s4)] {
        let mut bp = BeefParty::new(["a"]);
        bp.merge_beef_from_party("a", &parse(&input(v))).unwrap();
        let mut plain = Beef::new(BEEF_V2);
        plain.merge_beef(&parse(&input(v))).unwrap();
        d.same(&format!("{label}_plain_order"), json!(order(&plain)));
        d.same(&format!("{label}_plain_hex"), json!(to_hex(&plain)));
        d.same(&format!("{label}_party_hex"), json!(to_hex(&bp.beef)));
        let mut known = bp.get_known_txids_for_party("a").unwrap();
        known.sort();
        let mut ts_known: Vec<String> = d.ts[&format!("{label}_party_known")]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        ts_known.sort();
        assert_eq!(short(&known), ts_known, "{label}: known-to-party set");
        d.record(&format!("{label}_party_known_sorted"), json!(short(&known)));
        let party_order = order(&bp.beef);
        if d.ts[&format!("{label}_party_order")] == json!(party_order) {
            d.same(&format!("{label}_party_order"), json!(party_order));
        } else {
            assert_eq!(
                party_order,
                order(&plain),
                "{label}: party order is the plain merge order"
            );
            d.record(&format!("{label}_party_order"), json!(party_order));
        }
    }

    // D: mergeBeef of a beef whose entries were built from a Transaction
    // graph (TS `_tx` branch -> mergeTransactionGraph) after a public
    // removal / after make_txid_only: the graph restores the full tx.
    {
        let src = parse(&input(s1));
        let tx = src.find_atomic_transaction(&t8).unwrap();
        let mut other = Beef::new(BEEF_V2);
        other.merge_transaction(&tx).unwrap();
        d.same("D_other_order", json!(order(&other)));
        other.remove_existing_txid(&t5);
        d.same("D_other_after_remove", json!(order(&other)));
        let mut me = Beef::new(BEEF_V2);
        me.merge_beef(&other).unwrap();
        d.same("D_self_order_after_remove", json!(order(&me)));
        d.same("D_self_hex_after_remove", json!(to_hex(&me)));
        d.same(
            "D_self_valid_after_remove",
            json!(me.verify_valid(false).unwrap().valid),
        );

        let mut other2 = Beef::new(BEEF_V2);
        other2
            .merge_transaction(&src.find_atomic_transaction(&t8).unwrap())
            .unwrap();
        other2.make_txid_only(&t5);
        d.same("D2_other_after_txidonly", json!(order(&other2)));
        let mut me2 = Beef::new(BEEF_V2);
        me2.merge_beef(&other2).unwrap();
        d.same("D2_self_order", json!(order(&me2)));
        d.same("D2_self_hex", json!(to_hex(&me2)));
    }

    // E: zero-height bump. TS throws from the parse; Rust returns Err.
    {
        let zero = hex::decode("0200beef01010000").unwrap();
        let parsed = Beef::from_binary(&mut Cursor::new(zero.clone()));
        let err = parsed
            .err()
            .map(|e| e.to_string())
            .expect("zero-height BUMP must be rejected");
        for key in [
            "E_parse",
            "E_verifyValid",
            "E_mergeBeef",
            "E_toBinary",
            "E_mergeRawTx_bump0",
        ] {
            assert!(
                d.ts[key].as_str().unwrap().starts_with("THROW: "),
                "{key}: TS throws"
            );
            d.record(key, json!(format!("ERR: {err}")));
        }
        let mut s = Beef::new(BEEF_V2);
        assert!(s.merge_beef_from_binary(&zero).is_err());
    }

    // F: txid-only subject that still carries a bumpIndex.
    {
        let p = valid(s1, 0);
        let mut b = parse(&input(s1));
        b.make_txid_only(&p);
        d.same("F_order", json!(order(&b)));
        d.same(
            "F_atomic_hex",
            json!(hex::encode(b.to_binary_atomic(&p).unwrap())),
        );
        d.same("F_hex", json!(to_hex(&b)));
        d.same(
            "F_verify_false",
            json!(b.verify_valid(false).unwrap().valid),
        );
        d.same("F_verify_true", json!(b.verify_valid(true).unwrap().valid));
        d.same("F_sort", sort_result_json(&b.sort_txs()));
    }

    // H: sortTxs twice. TS returns its memoized first result; Rust reports
    // `valid` in the (now sorted) array order.
    {
        let mut b = parse(&input(s4));
        let first = short(&b.sort_txs().valid);
        d.same("H_first_valid", json!(first));
        let second = short(&b.sort_txs().valid);
        let mut a = first.clone();
        let mut c = second.clone();
        a.sort();
        c.sort();
        assert_eq!(a, c, "H: same set either way");
        d.documented(
            "H_second_valid",
            json!(second),
            json!(["92afff0f", "72b02070", "529a4399"]),
        );
    }

    // I: parse -> mergeTxidOnly(new) -> toBinary; parse -> mergeRawTx(existing).
    {
        let mut b = parse(&input(s1));
        b.merge_txid_only(&"11".repeat(32));
        d.same("I_hex", json!(to_hex(&b)));
        let mut c = parse(&input(s2));
        let raw = c.txs[0].tx.as_ref().unwrap().to_bytes().unwrap();
        c.merge_raw_tx(&raw, None).unwrap();
        d.same("I2_hex", json!(to_hex(&c)));
    }

    // J: trimKnownTxids prunes bumps; the trimmed copy does not disturb the
    // original.
    {
        let mut bp = BeefParty::new(["a"]);
        bp.merge(&parse(&input(s5))).unwrap();
        let p0 = valid(s5, 0);
        bp.beef.make_txid_only(&p0);
        bp.add_known_txids_for_party("a", std::slice::from_ref(&p0));
        d.same("J_before", json!(order(&bp.beef)));
        let trimmed = bp.get_trimmed_beef_for_party("a").unwrap();
        d.same("J_trimmed", json!(order(&trimmed)));
        d.same("J_trimmed_hex", json!(to_hex(&trimmed)));
        d.same("J_original_after_trim", json!(order(&bp.beef)));
        d.same("J_original_hex_after_trim", json!(to_hex(&bp.beef)));
        d.same(
            "J_original_valid_after_trim",
            json!(bp.beef.verify_valid(true).unwrap().valid),
        );
    }

    // Every TS key was replayed.
    let ts_keys: Vec<&String> = d.ts.as_object().unwrap().keys().collect();
    let missing: Vec<&&String> = ts_keys
        .iter()
        .filter(|k| !d.rust.contains_key(**k) && !d.rust.contains_key(&format!("{k}_sorted")))
        .collect();
    assert!(missing.is_empty(), "TS scenarios not replayed: {missing:?}");
    println!(
        "beef_ts_differential.json: {} scenario keys replayed",
        ts_keys.len()
    );

    if let Ok(path) = std::env::var("BEEF_TS_DIFFERENTIAL_OUT") {
        std::fs::write(path, serde_json::to_string_pretty(&d.rust).unwrap()).unwrap();
    }
}

/// `find_atomic_transaction` builds the proof tree TS `findAtomicTransaction`
/// does: merkle paths on proven ancestors, sources linked below unproven
/// ones, all the way down — and a parsed beef does not pre-link sources.
#[test]
fn find_atomic_transaction_links_the_whole_proof_tree() {
    let sort = load_json("beef_sort_order.json")["vectors"].clone();
    let s1 = &sort[0];
    let beef = parse(s1["input_beef_hex"].as_str().unwrap());
    for btx in &beef.txs {
        let tx = btx.tx.as_ref().unwrap();
        assert!(
            tx.inputs.iter().all(|i| i.source_transaction.is_none()),
            "a parsed BeefTx carries no source graph (TS fromReader does not link)"
        );
    }
    let t8 = s1["sort_result"]["valid"][2].as_str().unwrap();
    let tx: Transaction = beef.find_atomic_transaction(t8).unwrap();
    assert!(tx.merkle_path.is_none());
    let parent = tx.inputs[0]
        .source_transaction
        .as_deref()
        .expect("parent linked");
    assert!(parent.merkle_path.is_none(), "529a is unproven");
    let grandparent = parent.inputs[0]
        .source_transaction
        .as_deref()
        .expect("grandparent linked through the unproven parent");
    assert!(grandparent.merkle_path.is_some(), "92af carries its BUMP");
    assert!(beef
        .find_atomic_transaction("00".repeat(32).as_str())
        .is_none());

    let via_from_beef = Transaction::from_beef(s1["input_beef_hex"].as_str().unwrap()).unwrap();
    assert_eq!(via_from_beef.id().unwrap(), t8);
    assert!(via_from_beef.inputs[0]
        .source_transaction
        .as_deref()
        .unwrap()
        .inputs[0]
        .source_transaction
        .as_deref()
        .unwrap()
        .merkle_path
        .is_some());
}
