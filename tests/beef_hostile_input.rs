//! Hostile BEEF/BUMP input must produce `Err`, never a panic.
//!
//! `MerklePath.path` is a public field and the BUMP wire format carries its
//! tree height as a byte, so an empty path can reach every consumer of
//! `path[0]` both from the wire and from a struct literal. TS throws a
//! catchable error from the `MerklePath` constructor for a zero-height
//! bump; this crate must return an error from the same places.

use std::io::Cursor;

use bsv::transaction::beef::{Beef, BEEF_V2};
use bsv::transaction::beef_tx::BeefTx;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};

/// V2 BEEF, one BUMP with tree-height byte 0, zero transactions.
const ZERO_HEIGHT_BUMP_BEEF: &str = "0200beef01010000";

fn sort_order_vector(index: usize) -> (String, Vec<String>) {
    let file: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("test-vectors/beef_sort_order.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let v = &file["vectors"][index];
    (
        v["input_beef_hex"].as_str().unwrap().to_string(),
        v["sort_result"]["valid"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect(),
    )
}

fn parse(hex: &str) -> Result<Beef, String> {
    let bytes = hex::decode(hex).unwrap();
    Beef::from_binary(&mut Cursor::new(bytes)).map_err(|e| e.to_string())
}

#[test]
fn zero_height_bump_is_an_error_not_a_panic() {
    let err = parse(ZERO_HEIGHT_BUMP_BEEF).expect_err("a zero-height BUMP must be rejected");
    assert!(
        err.to_lowercase().contains("height") || err.to_lowercase().contains("empty"),
        "error should name the empty path: {err}"
    );
    let strict = Beef::from_binary_strict(&hex::decode(ZERO_HEIGHT_BUMP_BEEF).unwrap());
    assert!(strict.is_err(), "strict parser must reject it too");
    let standalone = MerklePath::from_binary(&mut Cursor::new(hex::decode("010000").unwrap()));
    assert!(
        standalone.is_err(),
        "standalone BUMP parser must reject tree height 0"
    );
    assert!(
        MerklePath::new(1, vec![]).is_err(),
        "constructor must reject an empty path"
    );
}

#[test]
fn zero_height_bump_beef_cannot_be_merged_into_a_good_beef() {
    // TS `mergeBeef(fromBinary(zero))` throws from the parse; so does the
    // Rust `merge_beef_from_binary` — and a beef that never parsed cannot
    // reach the merge paths at all.
    let mut beef = Beef::new(BEEF_V2);
    let result = beef.merge_beef_from_binary(&hex::decode(ZERO_HEIGHT_BUMP_BEEF).unwrap());
    assert!(result.is_err());
    assert!(
        beef.bumps.is_empty() && beef.txs.is_empty(),
        "a failed merge leaves no residue"
    );
}

/// An empty path reaching a beef through the public `path` field: every
/// entry point that reads level 0 must return an error or a negative
/// verdict, never index out of bounds.
#[test]
fn empty_path_bump_through_the_public_field() {
    let (hex, valid) = sort_order_vector(0);
    let mut beef = parse(&hex).unwrap();
    let empty = MerklePath {
        block_height: 800_001,
        path: vec![],
    };

    assert!(empty.compute_root(None).is_err());
    assert!(empty.compute_root(Some(&valid[0])).is_err());
    let mut trimmed = empty.clone();
    trimmed.trim();
    assert!(trimmed.path.is_empty(), "trim on an empty path is a no-op");

    assert!(
        beef.merge_bump(&empty).is_err(),
        "merging an empty path must fail (it proves nothing and has no root)"
    );
    assert_eq!(beef.bumps.len(), 1, "a rejected bump is not appended");

    beef.bumps.push(empty);
    assert!(
        !beef.verify_valid(false).unwrap_or_default().valid,
        "an empty bump cannot prove anything"
    );
    assert!(!beef.is_atomic(Some(&valid[2])) || beef.to_binary_atomic(&valid[2]).is_ok());
    assert!(
        beef.find_bump(&valid[0]).is_some(),
        "the real bump is still found"
    );
    let mut out = Vec::new();
    beef.to_binary(&mut out).unwrap();
    assert!(
        Beef::from_binary(&mut Cursor::new(out)).is_err(),
        "it serializes as tree height 0"
    );

    // A fresh beef whose only bump is empty: merging transactions that the
    // bump could never prove must not touch level 0.
    let mut only_empty = Beef::new(BEEF_V2);
    only_empty.bumps.push(MerklePath {
        block_height: 1,
        path: vec![],
    });
    let raw = beef.txs[0].tx.as_ref().unwrap().to_bytes().unwrap();
    let merged = only_empty.merge_raw_tx(&raw, None).unwrap();
    assert!(merged.bump_index.is_none());
    let merged = only_empty.merge_raw_tx(&raw, Some(0)).unwrap();
    assert_eq!(
        merged.bump_index,
        Some(0),
        "an explicit bump_index is recorded as given"
    );
    assert!(!only_empty.verify_valid(false).unwrap_or_default().valid);
    assert!(
        only_empty.is_atomic(Some(&merged.txid)),
        "a lone subject closes over itself"
    );
    assert!(only_empty.to_binary_atomic(&merged.txid).is_ok());
    assert!(only_empty.merge_txid_only(&valid[1]).bump_index.is_none());
    assert!(only_empty.make_txid_only(&merged.txid).is_some());
    only_empty.trim_known_txids(&[valid[1].clone()]).unwrap();
}

/// A transaction claiming a bump index past the end of `bumps`: structurally
/// invalid, and a txid lookup that never indexes `bumps` with it.
#[test]
fn bump_index_out_of_range_is_invalid_not_a_panic() {
    let (hex, valid) = sort_order_vector(0);
    let good = parse(&hex).unwrap();

    let mut beef = Beef::new(BEEF_V2);
    beef.bumps.push(good.bumps[0].clone());
    for btx in &good.txs {
        let tx = btx.tx.clone().unwrap();
        let claimed = if btx.bump_index.is_some() {
            Some(7)
        } else {
            None
        };
        beef.txs.push(BeefTx::from_tx(tx, claimed).unwrap());
    }
    assert_eq!(beef.txs[0].bump_index, Some(7));

    let verdict = beef.verify_valid(false).unwrap();
    assert!(
        !verdict.valid,
        "bump_index 7 of 1 bump must fail verification"
    );
    // Closure is a graph property, independent of whether proofs hold
    // (TS `isAtomic` is the same): atomic, yet invalid.
    assert!(beef.is_atomic(Some(&valid[2])));
    let atomic = beef.to_binary_atomic(&valid[2]).unwrap();
    let reparsed = Beef::from_binary_strict(&atomic).unwrap();
    assert!(
        reparsed.bumps.is_empty(),
        "a bump index that names no bump carrying the txid is not a proof, so no bump is copied"
    );
    assert!(reparsed.txs.iter().all(|t| t.bump_index.is_none()));

    let mut bytes = Vec::new();
    beef.to_binary(&mut bytes).unwrap();
    let parsed = Beef::from_binary_strict(&bytes).unwrap();
    assert_eq!(
        parsed
            .txs
            .iter()
            .filter(|t| t.bump_index == Some(7))
            .count(),
        1
    );
    assert!(!parsed.verify_valid(false).unwrap().valid);

    let mut target = Beef::new(BEEF_V2);
    target.merge_beef(&beef).unwrap();
    assert_eq!(
        target.find_txid(&valid[0]).unwrap().bump_index,
        Some(0),
        "merge re-derives the proof against the merged bumps"
    );
    assert!(target.verify_valid(false).unwrap().valid);

    let mut by_party = bsv::transaction::beef_party::BeefParty::new(["p"]);
    by_party.merge_beef_from_party("p", &beef).unwrap();
    assert!(by_party.get_trimmed_beef_for_party("p").is_ok());

    // Ditto for a hostile bump_index arriving on the wire: a txid-only entry
    // has no inputs, so a claimed proof cannot crash the sort or the walk.
    let mut wire = Beef::new(BEEF_V2);
    wire.txs.push(BeefTx {
        tx: None,
        txid: valid[1].clone(),
        bump_index: Some(usize::MAX),
        input_txids: vec![],
    });
    assert!(!wire.verify_valid(true).unwrap().valid);
    assert!(wire.is_atomic(Some(&valid[1])));
    assert!(wire.to_binary_atomic(&valid[1]).is_ok());
    let mut leaf_only = MerklePath::new(
        1,
        vec![vec![MerklePathLeaf {
            offset: 0,
            hash: Some(valid[1].clone()),
            txid: true,
            duplicate: false,
        }]],
    )
    .unwrap();
    leaf_only.trim();
    wire.merge_bump(&leaf_only).unwrap();
    assert_eq!(
        wire.txs[0].bump_index,
        Some(usize::MAX),
        "an entry that already claims a proof is left alone (TS `tx.bumpIndex == null` guard)"
    );
}

/// Two BEEFs that both parse cleanly, name the same block height, and whose
/// BUMPs compute the SAME merkle root — but with different tree heights,
/// because `other`'s single leaf hash IS `host`'s root. `merge_bump` pairs
/// them by (height, root) and hands them to `MerklePath::combine`, which
/// walked `other`'s levels by `self`'s level count. TS reads past the end of
/// the shorter array and throws a catchable TypeError; this must not panic,
/// and the host must survive intact.
#[test]
fn combining_paths_of_different_tree_heights_is_an_error_not_a_panic() {
    const HOST: &str = "0200beef01fe00350c0002020002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb010100cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00";
    const OTHER: &str = "0200beef01fe00350c0001010002ac06ef3322727422c91237f3e8520c68b1abe69edfa44933810bc2136c52b4bf00";

    let mut host = Beef::from_hex(HOST).expect("host parses");
    let other = Beef::from_hex(OTHER).expect("other parses");
    assert_eq!(host.bumps[0].block_height, other.bumps[0].block_height);
    assert_eq!(
        host.bumps[0].compute_root(None).unwrap(),
        other.bumps[0].compute_root(None).unwrap(),
        "same root is what pairs them for combining"
    );
    assert_ne!(host.bumps[0].path.len(), other.bumps[0].path.len());

    let before = host.to_hex().unwrap();
    let err = host
        .merge_beef_from_binary(&hex::decode(OTHER).unwrap())
        .expect_err("a tree-height mismatch must be refused");
    assert!(
        err.to_string().contains("tree height"),
        "the error names the rule: {err}"
    );
    assert_eq!(
        host.to_hex().unwrap(),
        before,
        "the host survives the refusal intact"
    );
    assert_eq!(host.bumps.len(), 1);
    assert_eq!(host.bumps[0].path.len(), 2, "the host path is untouched");

    // Directly, too — `combine` is public.
    let mut path = host.bumps[0].clone();
    assert!(path.combine(&other.bumps[0]).is_err());
    assert!(
        other.bumps[0].clone().combine(&host.bumps[0]).is_err(),
        "shorter host, longer other"
    );
    assert!(
        path.combine(&host.bumps[0]).is_ok(),
        "combining equal heights still works"
    );
}
