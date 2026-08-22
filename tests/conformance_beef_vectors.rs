//! TS-golden BEEF conformance corpus (`test-vectors/beef_*.json`).
//!
//! Every `expected_*` field is byte-exact output of the normative TypeScript
//! `@bsv/sdk` (2.3.1). Where this crate disagrees with a vector, this crate
//! is wrong. Assertion rules per `test-vectors/README.md`:
//!
//! * `beef_atomic_closure.json`, `beef_spend_closure.json`: `to_binary_atomic`
//!   is byte-exact, then the emitted bytes re-parse to the recorded verdict
//!   (`is_atomic`, `verify_valid`, counts). Spend-closure cases also replay
//!   the `graph_route`: the same expectation through a `Transaction` graph
//!   (`source_transaction` + `merkle_path`) and `merge_transaction`.
//! * `beef_sort_order.json`: `sort_txs` returns the recorded partitions in
//!   order, and the post-sort `to_binary` is byte-exact.
//! * `beef_invalid.json`: each case names its rule; the recorded TS verdict
//!   (parse outcome, `verify_valid`, roots) is asserted, never a stricter one
//!   of our own — the trailing-garbage case is ACCEPTED by the lenient parser
//!   and rejected only by `from_binary_strict` (see `SURPRISES.json`).
//! * `beef_merge.json`: compared STRUCTURALLY (tx set with raw bytes and
//!   txid-only status, bump set by (height, root), verdict), never
//!   byte-equal — TS's own merged bytes are not serialize-stable.
//!
//! Every case in every file is exercised; the case count per file is printed.

use std::collections::BTreeMap;

use bsv::transaction::beef::{Beef, BeefSortResult, BEEF_V2};
use bsv::transaction::transaction::Transaction;
use serde::Deserialize;

fn from_hex(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("vector hex")
}

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{name}: read failed ({e}) — vectors are committed"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"))
}

fn parse_lenient(bytes: &[u8], context: &str) -> Beef {
    let mut cursor = std::io::Cursor::new(bytes);
    Beef::from_binary(&mut cursor).unwrap_or_else(|e| panic!("{context}: BEEF parse: {e}"))
}

/// Byte-level diff report for a failed byte-exact assertion.
fn byte_diff(expected: &[u8], actual: &[u8]) -> String {
    let first = expected
        .iter()
        .zip(actual.iter())
        .position(|(e, a)| e != a)
        .unwrap_or(expected.len().min(actual.len()));
    format!(
        "first divergence at byte {first} (expected len {}, actual len {})\n  expected: {}\n  actual:   {}",
        expected.len(),
        actual.len(),
        to_hex(expected),
        to_hex(actual)
    )
}

// ---------------------------------------------------------------------------
// atomic closure + spend closure
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ClosureFile {
    id: String,
    vectors: Vec<ClosureVector>,
}

#[derive(Deserialize)]
struct ClosureVector {
    id: String,
    name: String,
    input_beef_hex: String,
    subject_txid: String,
    expected_atomic_hex: String,
    expected_verdict: ClosureVerdict,
    #[serde(default)]
    graph_route: Option<GraphRoute>,
}

#[derive(Deserialize)]
struct ClosureVerdict {
    is_atomic: bool,
    verify_valid: bool,
    bump_count: usize,
    tx_count: usize,
    #[serde(default)]
    verify_valid_allow_txid_only: Option<bool>,
}

#[derive(Deserialize)]
struct GraphRoute {
    matches_expected: bool,
}

fn assert_closure_verdict(atomic_bytes: &[u8], v: &ClosureVector) {
    let ctx = format!("{} ({})", v.id, v.name);
    let parsed = Beef::from_binary_strict(atomic_bytes)
        .unwrap_or_else(|e| panic!("{ctx}: emitted atomic bytes do not re-parse strictly: {e}"));
    let verdict = &v.expected_verdict;
    assert_eq!(
        parsed.atomic_txid.as_deref(),
        Some(v.subject_txid.as_str()),
        "{ctx}: atomic subject"
    );
    assert_eq!(parsed.bumps.len(), verdict.bump_count, "{ctx}: bump_count");
    assert_eq!(parsed.txs.len(), verdict.tx_count, "{ctx}: tx_count");
    assert_eq!(
        parsed.is_atomic(None),
        verdict.is_atomic,
        "{ctx}: is_atomic"
    );
    let vv = parsed
        .verify_valid(false)
        .unwrap_or_else(|e| panic!("{ctx}: verify_valid: {e}"));
    assert_eq!(vv.valid, verdict.verify_valid, "{ctx}: verify_valid(false)");
    if let Some(allow) = verdict.verify_valid_allow_txid_only {
        let vv = parsed
            .verify_valid(true)
            .unwrap_or_else(|e| panic!("{ctx}: verify_valid(true): {e}"));
        assert_eq!(vv.valid, allow, "{ctx}: verify_valid(true)");
    }
}

/// Rebuild the subject as an in-memory `Transaction` graph from `beef`:
/// `merkle_path` from its bump, and each input's `source_transaction`
/// linked recursively from the beef (the `graph_route` call shape).
fn graph_from_beef(beef: &Beef, txid: &str) -> Option<Transaction> {
    let btx = beef.find_txid(txid)?;
    let mut tx = btx.tx.clone()?;
    if let Some(bi) = btx.bump_index {
        tx.merkle_path = Some(beef.bumps[bi].clone());
    }
    for input in &mut tx.inputs {
        input.source_transaction = None;
        if let Some(source_txid) = input.source_txid.clone() {
            if let Some(source) = graph_from_beef(beef, &source_txid) {
                input.source_transaction = Some(Box::new(source));
            }
        }
    }
    Some(tx)
}

fn run_closure_file(name: &str, expect_id: &str) {
    let file: ClosureFile = load(name);
    assert_eq!(file.id, expect_id);
    assert!(!file.vectors.is_empty(), "{name}: empty corpus");
    for v in &file.vectors {
        let ctx = format!("{} ({})", v.id, v.name);
        let beef = parse_lenient(&from_hex(&v.input_beef_hex), &ctx);
        let atomic = beef
            .to_binary_atomic(&v.subject_txid)
            .unwrap_or_else(|e| panic!("{ctx}: to_binary_atomic failed: {e}"));
        let expected = from_hex(&v.expected_atomic_hex);
        assert!(
            atomic == expected,
            "{ctx}: to_binary_atomic diverges from TS: {}",
            byte_diff(&expected, &atomic)
        );
        assert_closure_verdict(&atomic, v);

        // An unsorted beef must give the same bytes after an explicit sort.
        let mut sorted = beef.clone();
        sorted.sort_txs();
        let atomic_sorted = sorted.to_binary_atomic(&v.subject_txid).unwrap();
        assert!(
            atomic_sorted == expected,
            "{ctx}: post-sort to_binary_atomic diverges"
        );

        if let Some(route) = &v.graph_route {
            assert!(
                route.matches_expected,
                "{ctx}: corpus says graph route diverges"
            );
            let tx = graph_from_beef(&beef, &v.subject_txid)
                .unwrap_or_else(|| panic!("{ctx}: subject not rebuildable as a graph"));
            let mut via_graph = Beef::new(BEEF_V2);
            via_graph
                .merge_transaction(&tx)
                .unwrap_or_else(|e| panic!("{ctx}: merge_transaction failed: {e}"));
            let atomic_graph = via_graph.to_binary_atomic(&v.subject_txid).unwrap();
            assert!(
                atomic_graph == expected,
                "{ctx}: graph route (merge_transaction) diverges from TS: {}",
                byte_diff(&expected, &atomic_graph)
            );
        }
    }
    println!("{name}: {} cases, all byte-exact", file.vectors.len());
}

/// toBinaryAtomic: BRC-95 dependency closure, unsorted input, unrelated-tx
/// dropping, bump pruning + reindexing, txid-only subject.
#[test]
fn atomic_closure_vectors() {
    run_closure_file(
        "beef_atomic_closure.json",
        "transaction.beef.atomic_closure",
    );
}

/// The rust-mpc#352 regression shape: a caller-named input's parent must
/// ride in the child's Atomic BEEF — and a missing parent still serializes
/// (success is not closure; only verify_valid says so).
#[test]
fn spend_closure_vectors() {
    run_closure_file("beef_spend_closure.json", "transaction.beef.spend_closure");
}

// ---------------------------------------------------------------------------
// sort order
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SortFile {
    id: String,
    vectors: Vec<SortVector>,
}

#[derive(Deserialize)]
struct SortVector {
    id: String,
    name: String,
    input_beef_hex: String,
    expected_serialized_hex_after_sort: String,
    sort_result: SortResultVector,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SortResultVector {
    missing_inputs: Vec<String>,
    not_valid: Vec<String>,
    valid: Vec<String>,
    with_missing_inputs: Vec<String>,
    txid_only: Vec<String>,
}

#[test]
fn sort_order_vectors() {
    let file: SortFile = load("beef_sort_order.json");
    assert_eq!(file.id, "transaction.beef.sort_order");
    assert!(!file.vectors.is_empty());
    for v in &file.vectors {
        let ctx = format!("{} ({})", v.id, v.name);
        let mut beef = parse_lenient(&from_hex(&v.input_beef_hex), &ctx);
        let result = beef.sort_txs();
        let expected_result = BeefSortResult {
            missing_inputs: v.sort_result.missing_inputs.clone(),
            not_valid: v.sort_result.not_valid.clone(),
            valid: v.sort_result.valid.clone(),
            with_missing_inputs: v.sort_result.with_missing_inputs.clone(),
            txid_only: v.sort_result.txid_only.clone(),
        };
        assert_eq!(result, expected_result, "{ctx}: sort result");

        let sorted_txids: Vec<String> = beef.txs.iter().map(|t| t.txid.clone()).collect();
        let expected_lead: Vec<String> = v
            .sort_result
            .with_missing_inputs
            .iter()
            .chain(&v.sort_result.not_valid)
            .chain(&v.sort_result.txid_only)
            .cloned()
            .collect();
        assert!(
            sorted_txids.starts_with(&expected_lead),
            "{ctx}: unsortable entries must lead: {sorted_txids:?}"
        );

        let mut out = Vec::new();
        beef.to_binary(&mut out).unwrap();
        let expected = from_hex(&v.expected_serialized_hex_after_sort);
        assert!(
            out == expected,
            "{ctx}: post-sort to_binary diverges from TS: {}",
            byte_diff(&expected, &out)
        );

        // A parsed, untouched beef re-emits its input bytes (TS hands back
        // its parse-time cache); once touched, to_binary sorts on its own.
        let input = from_hex(&v.input_beef_hex);
        let untouched = parse_lenient(&input, &ctx);
        let mut out_untouched = Vec::new();
        untouched.to_binary(&mut out_untouched).unwrap();
        assert!(
            out_untouched == input,
            "{ctx}: untouched parse must round-trip: {}",
            byte_diff(&input, &out_untouched)
        );
        let mut touched = parse_lenient(&input, &ctx);
        let bump = touched.bumps[0].clone();
        touched.merge_bump(&bump).unwrap();
        let mut out_touched = Vec::new();
        touched.to_binary(&mut out_touched).unwrap();
        assert!(
            out_touched == expected,
            "{ctx}: to_binary after a merge must sort without an explicit sort_txs: {}",
            byte_diff(&expected, &out_touched)
        );

        // Sorting is idempotent on the order (the report's `valid` list
        // follows array order at call time, so only its set is stable).
        let again = beef.sort_txs();
        let as_set = |r: &BeefSortResult| {
            let mut v = r.valid.clone();
            v.sort();
            (
                r.missing_inputs.clone(),
                r.not_valid.clone(),
                v,
                r.with_missing_inputs.clone(),
                r.txid_only.clone(),
            )
        };
        assert_eq!(
            as_set(&again),
            as_set(&expected_result),
            "{ctx}: second sort partitions"
        );
        assert_eq!(
            beef.txs.iter().map(|t| t.txid.clone()).collect::<Vec<_>>(),
            sorted_txids,
            "{ctx}: second sort changed the order"
        );
        let mut out_again = Vec::new();
        beef.to_binary(&mut out_again).unwrap();
        assert!(out_again == expected, "{ctx}: second sort changed bytes");
    }
    println!(
        "beef_sort_order.json: {} cases, all byte-exact",
        file.vectors.len()
    );
}

// ---------------------------------------------------------------------------
// invalid corpus
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct InvalidFile {
    id: String,
    vectors: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct InvalidVector {
    id: String,
    name: String,
    beef_hex: String,
    expect_reject_rule: String,
    ts_verdict: TsVerdict,
    #[serde(default)]
    ts_accepts: Option<bool>,
    #[serde(default)]
    ts_from_binary_view_error: Option<String>,
}

#[derive(Deserialize)]
struct TsVerdict {
    parses: bool,
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    roots: Option<BTreeMap<String, String>>,
    #[serde(default)]
    atomic_txid: Option<String>,
    #[serde(default)]
    is_atomic: Option<bool>,
}

#[test]
fn invalid_vectors() {
    let file: InvalidFile = load("beef_invalid.json");
    assert_eq!(file.id, "transaction.beef.invalid");
    assert!(!file.vectors.is_empty());
    let mut rules_seen = Vec::new();
    for v in &file.vectors {
        let ctx = format!("{} ({}) [{}]", v.id, v.name, v.expect_reject_rule);
        rules_seen.push(v.expect_reject_rule.as_str());
        let bytes = from_hex(&v.beef_hex);
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let lenient = Beef::from_binary(&mut cursor);

        assert_eq!(
            lenient.is_ok(),
            v.ts_verdict.parses,
            "{ctx}: lenient parse verdict (got {:?})",
            lenient.as_ref().err().map(|e| e.to_string())
        );
        let Ok(beef) = lenient else {
            continue;
        };

        let vv = beef
            .verify_valid(false)
            .unwrap_or_else(|e| panic!("{ctx}: verify_valid: {e}"));
        assert_eq!(
            Some(vv.valid),
            v.ts_verdict.valid,
            "{ctx}: verify_valid verdict"
        );
        if let Some(expected_roots) = &v.ts_verdict.roots {
            let got: BTreeMap<String, String> = vv
                .roots
                .iter()
                .map(|(h, r)| (h.to_string(), r.clone()))
                .collect();
            assert_eq!(&got, expected_roots, "{ctx}: roots reported");
        }
        if let Some(atomic_txid) = &v.ts_verdict.atomic_txid {
            assert_eq!(
                beef.atomic_txid.as_deref(),
                Some(atomic_txid.as_str()),
                "{ctx}"
            );
        }
        if let Some(is_atomic) = v.ts_verdict.is_atomic {
            assert_eq!(beef.is_atomic(None), is_atomic, "{ctx}: is_atomic");
        }

        // Rule-specific mechanism checks: the rejection comes from the named
        // rule, not from some incidental defect.
        match v.expect_reject_rule.as_str() {
            "missing-input" => {
                let sr = beef.clone().sort_txs();
                assert!(!sr.missing_inputs.is_empty(), "{ctx}: sort reports the gap");
                assert!(!beef.has_duplicate_txids(), "{ctx}");
            }
            "bump-leaf-mismatch" => {
                let claimed = beef
                    .txs
                    .iter()
                    .find(|t| t.bump_index.is_some())
                    .expect("claim");
                let bi = claimed.bump_index.unwrap();
                assert!(
                    !beef.bumps[bi].path[0]
                        .iter()
                        .any(|l| l.hash.as_deref() == Some(&claimed.txid)),
                    "{ctx}: bump {bi} must not carry the claimed txid"
                );
                assert!(beef.clone().sort_txs().missing_inputs.is_empty(), "{ctx}");
            }
            "duplicate-txid" => {
                assert!(beef.has_duplicate_txids(), "{ctx}");
                // The merge API never produces a duplicate: merging the
                // duplicated beef into a fresh one yields ONE copy, as TS does.
                let mut merged = Beef::new(beef.version);
                merged.merge_beef(&beef).unwrap();
                assert!(!merged.has_duplicate_txids(), "{ctx}: merge must dedupe");
                assert_eq!(
                    merged.txs.len(),
                    beef.txs.len() - 1,
                    "{ctx}: one copy survives the merge"
                );
            }
            "conflicting-roots-same-height" => {
                assert!(beef.bumps.len() >= 2, "{ctx}");
                let heights: Vec<u32> = beef.bumps.iter().map(|b| b.block_height).collect();
                assert_eq!(heights[0], heights[1], "{ctx}: same height");
                assert_ne!(
                    beef.bumps[0].compute_root(None).unwrap(),
                    beef.bumps[1].compute_root(None).unwrap(),
                    "{ctx}: different roots"
                );
            }
            "trailing-data" => {
                assert_eq!(v.ts_accepts, Some(true), "{ctx}: corpus records acceptance");
                assert!(vv.valid, "{ctx}: lenient parser accepts + verifies");
                assert!(
                    (cursor.position() as usize) < bytes.len(),
                    "{ctx}: lenient parser leaves the garbage unread"
                );
                let strict = Beef::from_binary_strict(&bytes);
                let err = strict.err().map(|e| e.to_string()).unwrap_or_else(|| {
                    panic!("{ctx}: from_binary_strict must reject trailing data")
                });
                let expected_msg = v.ts_from_binary_view_error.as_deref().unwrap();
                assert!(
                    err.contains(expected_msg),
                    "{ctx}: strict error {err:?} should carry {expected_msg:?}"
                );
            }
            "atomic-subject-missing" => {
                assert!(beef.atomic_txid.is_some(), "{ctx}");
                assert!(
                    beef.find_txid(beef.atomic_txid.as_deref().unwrap())
                        .is_none(),
                    "{ctx}"
                );
                assert!(!beef.is_atomic(None), "{ctx}");
            }
            other => panic!("{ctx}: unknown rule {other:?} — extend this test"),
        }
    }
    // The V1/txid-only splice does not parse, so it is covered by the parse
    // verdict alone; make sure it was in the corpus.
    assert!(rules_seen.contains(&"v1-cannot-express-txid-only"));
    println!(
        "beef_invalid.json: {} cases, all verdicts match TS",
        file.vectors.len()
    );
}

// ---------------------------------------------------------------------------
// merge (structural)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MergeFile {
    id: String,
    vectors: Vec<MergeVector>,
}

#[derive(Deserialize)]
struct MergeVector {
    id: String,
    name: String,
    beef_a_hex: String,
    beef_b_hex: String,
    expected_merged_hex: String,
    merged_verdict: MergeVerdict,
}

#[derive(Deserialize)]
struct MergeVerdict {
    verify_valid: bool,
    bump_count: usize,
    tx_count: usize,
    #[serde(default)]
    bump_leaf_txids: Option<Vec<String>>,
}

/// Structural equivalence: same tx set (raw bytes for full entries,
/// txid-only status, proven status), same (height, root) bump set.
fn structurally_equal(expected: &Beef, actual: &Beef) -> Result<(), String> {
    let mut exp_txids: Vec<&str> = expected.txs.iter().map(|t| t.txid.as_str()).collect();
    let mut act_txids: Vec<&str> = actual.txs.iter().map(|t| t.txid.as_str()).collect();
    exp_txids.sort_unstable();
    act_txids.sort_unstable();
    if exp_txids != act_txids {
        return Err(format!("tx set: expected {exp_txids:?}, got {act_txids:?}"));
    }
    for exp in &expected.txs {
        let act = actual.find_txid(&exp.txid).expect("set-checked");
        match (&exp.tx, &act.tx) {
            (Some(e), Some(a)) => {
                if e.to_bytes().unwrap() != a.to_bytes().unwrap() {
                    return Err(format!("raw bytes of {} diverged", exp.txid));
                }
            }
            (None, None) => {}
            _ => {
                return Err(format!(
                    "txid-only status of {} diverged (expected full: {}, got full: {})",
                    exp.txid,
                    exp.tx.is_some(),
                    act.tx.is_some()
                ))
            }
        }
        if exp.bump_index.is_some() != act.bump_index.is_some() {
            return Err(format!(
                "proven status of {} diverged (expected {}, got {})",
                exp.txid,
                exp.bump_index.is_some(),
                act.bump_index.is_some()
            ));
        }
    }
    let roots = |b: &Beef| -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> = b
            .bumps
            .iter()
            .map(|bump| (bump.block_height, bump.compute_root(None).unwrap()))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let (er, ar) = (roots(expected), roots(actual));
    if er != ar {
        return Err(format!("bump set: expected {er:?}, got {ar:?}"));
    }
    Ok(())
}

#[test]
fn merge_vectors() {
    let file: MergeFile = load("beef_merge.json");
    assert_eq!(file.id, "transaction.beef.merge");
    assert!(!file.vectors.is_empty());
    for v in &file.vectors {
        let ctx = format!("{} ({})", v.id, v.name);
        let a = parse_lenient(&from_hex(&v.beef_a_hex), &ctx);
        let b = parse_lenient(&from_hex(&v.beef_b_hex), &ctx);
        let expected = parse_lenient(&from_hex(&v.expected_merged_hex), &ctx);

        let mut merged = Beef::new(BEEF_V2);
        merged
            .merge_beef(&a)
            .unwrap_or_else(|e| panic!("{ctx}: merge a: {e}"));
        merged
            .merge_beef(&b)
            .unwrap_or_else(|e| panic!("{ctx}: merge b: {e}"));

        structurally_equal(&expected, &merged)
            .unwrap_or_else(|why| panic!("{ctx}: merged beef diverges structurally: {why}"));
        assert_eq!(
            merged.bumps.len(),
            v.merged_verdict.bump_count,
            "{ctx}: bump_count"
        );
        assert_eq!(
            merged.txs.len(),
            v.merged_verdict.tx_count,
            "{ctx}: tx_count"
        );
        assert!(!merged.has_duplicate_txids(), "{ctx}: one copy per txid");
        let vv = merged.verify_valid(false).unwrap();
        assert_eq!(
            vv.valid, v.merged_verdict.verify_valid,
            "{ctx}: verify_valid"
        );

        if let Some(leaf_txids) = &v.merged_verdict.bump_leaf_txids {
            let mut expected_leaves = leaf_txids.clone();
            expected_leaves.sort();
            let mut got: Vec<String> = merged
                .bumps
                .iter()
                .flat_map(|b| b.path[0].iter())
                .filter(|l| l.txid)
                .filter_map(|l| l.hash.clone())
                .collect();
            got.sort();
            assert_eq!(got, expected_leaves, "{ctx}: combined bump txid leaves");
            for txid in leaf_txids {
                let btx = merged.find_txid(txid).expect("leaf tx present");
                assert!(
                    btx.bump_index.is_some(),
                    "{ctx}: {txid} re-proven by the merged bump"
                );
            }
        }

        // The merged beef round-trips through bytes to the same structure.
        let mut bytes = Vec::new();
        merged.to_binary(&mut bytes).unwrap();
        let reparsed = Beef::from_binary_strict(&bytes).unwrap();
        structurally_equal(&merged, &reparsed)
            .unwrap_or_else(|why| panic!("{ctx}: merged beef not serialize-stable: {why}"));
        assert!(reparsed.verify_valid(false).unwrap().valid == v.merged_verdict.verify_valid);

        // Merging in the other order gives the same structure.
        let mut reversed = Beef::new(BEEF_V2);
        reversed.merge_beef(&b).unwrap();
        reversed.merge_beef(&a).unwrap();
        structurally_equal(&expected, &reversed)
            .unwrap_or_else(|why| panic!("{ctx}: b-then-a merge diverges: {why}"));
    }
    println!(
        "beef_merge.json: {} cases, all structurally equal",
        file.vectors.len()
    );
}
