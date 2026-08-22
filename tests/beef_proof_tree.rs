//! `Beef::find_atomic_transaction` — the proof tree TS `findAtomicTransaction`
//! builds, and the two properties the sort-order-driven build lacked:
//! independence from the order `txs` happens to be in, and a bound on the
//! size of the result.

use bsv::script::locking_script::LockingScript;
#[cfg(feature = "network")]
use bsv::services::overlay_tools::Historian;
use bsv::transaction::beef::{Beef, BEEF_V2};
use bsv::transaction::beef_tx::BeefTx;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

/// A beef whose subject C spends a proven ancestor A and an absent X, with
/// C stored BEFORE A — so C sorts into `with_missing_inputs`, ahead of the
/// ancestor it can still resolve.
const SUBJECT_BEFORE_ANCESTOR_HEX: &str = "0200beef01fe00350c0001020002a963d288e79fed3e372b248a0b10f5f6e2a0eacbaa750cfdd69052f406885ffa0100222222222222222222222222222222222222222222222222222222222222222202000100000002a963d288e79fed3e372b248a0b10f5f6e2a0eacbaa750cfdd69052f406885ffa0000000000ffffffff11111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0184030000000000000151000000000100010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000015100000000";
const SUBJECT: &str = "c4d4066af8c692b841b5ba5f2500da11641f13642dfc0337a64468b10f3f2bda";
const ANCESTOR: &str = "fa5f8806f45290d6fd0c75aacbeaa0e2f6f5100b8a242b373eed9fe788d263a9";

fn tx_with(inputs: &[(String, u32)], outputs: usize, sats: u64) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in inputs {
        tx.add_input(TransactionInput {
            source_transaction: None,
            source_txid: Some(txid.clone()),
            source_output_index: *vout,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
    }
    for _ in 0..outputs {
        tx.add_output(TransactionOutput {
            satoshis: Some(sats),
            locking_script: LockingScript::from_binary(&[0x51]),
            change: false,
        });
    }
    tx
}

/// Total nodes in an owned proof tree.
fn count_nodes(tx: &Transaction) -> usize {
    let mut n = 1;
    let mut stack: Vec<&Transaction> = vec![tx];
    while let Some(t) = stack.pop() {
        for input in &t.inputs {
            if let Some(source) = input.source_transaction.as_deref() {
                n += 1;
                stack.push(source);
            }
        }
    }
    n
}

/// A resolvable ancestor is linked even when the subject also spends an
/// input this beef does not hold, and even when the subject is stored
/// before that ancestor. The walk starts at the subject and follows
/// inputs (TS `addInputProof`); it does not consult the sort order, where
/// a subject with a missing input sorts ahead of everything it can resolve.
#[test]
fn resolvable_inputs_link_regardless_of_array_order() {
    let beef = Beef::from_hex(SUBJECT_BEFORE_ANCESTOR_HEX).expect("parses");
    assert_eq!(
        beef.txs.iter().map(|t| t.txid.as_str()).collect::<Vec<_>>(),
        vec![SUBJECT, ANCESTOR],
        "the subject is stored first"
    );
    let sorted = beef.clone().sort_txs();
    assert_eq!(sorted.with_missing_inputs, vec![SUBJECT.to_string()]);

    let tx = beef
        .find_atomic_transaction(SUBJECT)
        .expect("subject is present in full");
    let linked: Vec<bool> = tx
        .inputs
        .iter()
        .map(|i| i.source_transaction.is_some())
        .collect();
    assert_eq!(
        linked,
        vec![true, false],
        "TS gives [true, false] for this beef"
    );
    let ancestor = tx.inputs[0]
        .source_transaction
        .as_deref()
        .expect("ancestor linked");
    assert_eq!(ancestor.id().unwrap(), ANCESTOR);
    assert!(
        ancestor.merkle_path.is_some(),
        "the linked ancestor carries its BUMP"
    );
    assert!(
        !beef.verify_valid(false).unwrap().valid,
        "the absent input still fails verification"
    );

    // Same answer through the public entry points.
    let via_into = beef.clone().into_transaction().unwrap();
    assert_eq!(
        via_into.id().unwrap(),
        ANCESTOR,
        "no atomic_txid: the subject is the last tx"
    );
    let subject_last = {
        let mut b = Beef::new(BEEF_V2);
        b.bumps.push(beef.bumps[0].clone());
        b.txs.push(beef.txs[1].clone());
        b.txs.push(beef.txs[0].clone());
        b
    };
    let via_last = subject_last.into_transaction().unwrap();
    assert_eq!(via_last.id().unwrap(), SUBJECT);
    assert!(via_last.inputs[0].source_transaction.is_some());
    assert!(via_last.inputs[1].source_transaction.is_none());
}

/// A diamond DAG names exponentially many paths through its ancestors.
/// `source_transaction` owns its value, so the tree must place each
/// ancestor's ancestry once rather than expand every path: TS shares one
/// object per txid and visits 40 nodes here, and the old build cloned each
/// built ancestor into both of its dependents — 2,097,151 nodes for this
/// same 4 KB BEEF.
#[test]
fn a_diamond_dag_does_not_expand_exponentially() {
    const DEPTH: usize = 20;
    let base = tx_with(&[("00".repeat(32), 0)], 2, 5000);
    let base_txid = base.id().unwrap();
    let bump = MerklePath::new(
        800_000,
        vec![vec![
            MerklePathLeaf {
                offset: 0,
                hash: Some(base_txid.clone()),
                txid: true,
                duplicate: false,
            },
            MerklePathLeaf {
                offset: 1,
                hash: Some("22".repeat(32)),
                txid: false,
                duplicate: false,
            },
        ]],
    )
    .unwrap();

    let mut beef = Beef::new(BEEF_V2);
    beef.bumps.push(bump);
    beef.txs
        .push(BeefTx::from_tx(base.clone(), Some(0)).unwrap());
    let mut level = vec![(base_txid.clone(), 0u32), (base_txid, 1u32)];
    for depth in 0..DEPTH {
        let mut next = Vec::new();
        for which in 0..2u32 {
            let tx = tx_with(&level, 2, 4000 - depth as u64 * 10 - which as u64);
            let txid = tx.id().unwrap();
            beef.txs.push(BeefTx::from_tx(tx, None).unwrap());
            next.push((txid, which));
        }
        level = next;
    }
    let subject = level[0].0.clone();
    assert_eq!(beef.txs.len(), 1 + DEPTH * 2, "41 transactions");

    let bytes = hex::decode(beef.to_hex().unwrap()).unwrap();
    assert!(bytes.len() < 8_000, "a small BEEF: {} bytes", bytes.len());
    let parsed = Beef::from_binary_strict(&bytes).expect("round-trips");

    let started = std::time::Instant::now();
    let tx = parsed
        .find_atomic_transaction(&subject)
        .expect("subject present");
    let elapsed = started.elapsed();
    let nodes = count_nodes(&tx);

    // Bounded by (transactions + input edges): 41 + 80.
    assert!(
        nodes <= 1 + DEPTH * 2 + DEPTH * 4,
        "proof tree must stay linear in the beef, got {nodes} nodes"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "took {elapsed:?} for {nodes} nodes"
    );
    println!(
        "depth-{DEPTH} diamond: {} bytes, {nodes} nodes, {elapsed:?}",
        bytes.len()
    );

    // The spine from the subject down to the proof is complete: every step
    // resolves to its transaction, so satoshis and locking scripts are
    // available the whole way down.
    let mut node = &tx;
    let mut depth = 0;
    while node.merkle_path.is_none() {
        let input = &node.inputs[0];
        let source = input
            .source_transaction
            .as_deref()
            .expect("spine input is linked");
        assert_eq!(&source.id().unwrap(), input.source_txid.as_ref().unwrap());
        assert!(!source.outputs.is_empty());
        node = source;
        depth += 1;
    }
    assert_eq!(
        depth, DEPTH,
        "the walk reaches the proven base through every level"
    );

    // Every link anywhere in the tree names the transaction it claims to.
    let mut stack = vec![&tx];
    while let Some(t) = stack.pop() {
        for input in &t.inputs {
            if let Some(source) = input.source_transaction.as_deref() {
                assert_eq!(&source.id().unwrap(), input.source_txid.as_ref().unwrap());
                stack.push(source);
            }
        }
    }
}

/// The first placement of an ancestor carries its own ancestry; a repeat
/// placement carries the transaction and its merkle path alone, because two
/// owned copies of one subtree is what the exponential blowup was.
#[test]
fn a_repeated_ancestor_is_expanded_once() {
    let great = tx_with(&[("00".repeat(32), 0)], 2, 6000);
    let great_txid = great.id().unwrap();
    let great_proof = MerklePath::new(
        800_000,
        vec![vec![MerklePathLeaf {
            offset: 0,
            hash: Some(great_txid.clone()),
            txid: true,
            duplicate: false,
        }]],
    )
    .unwrap();
    let grandparent = tx_with(&[(great_txid.clone(), 0)], 2, 5000);
    let gp_txid = grandparent.id().unwrap();
    let parent = tx_with(&[(gp_txid.clone(), 0)], 2, 4000);
    let parent_txid = parent.id().unwrap();
    // The subject spends the parent AND the grandparent directly, so the
    // grandparent is reached by two different inputs.
    let subject = tx_with(&[(parent_txid.clone(), 0), (gp_txid.clone(), 1)], 1, 3000);
    let subject_txid = subject.id().unwrap();

    let mut beef = Beef::new(BEEF_V2);
    beef.bumps.push(great_proof);
    beef.txs.push(BeefTx::from_tx(great, Some(0)).unwrap());
    beef.txs.push(BeefTx::from_tx(grandparent, None).unwrap());
    beef.txs.push(BeefTx::from_tx(parent, None).unwrap());
    beef.txs.push(BeefTx::from_tx(subject, None).unwrap());

    let tx = beef.find_atomic_transaction(&subject_txid).unwrap();
    let via_parent = tx.inputs[0].source_transaction.as_deref().unwrap();
    let direct = tx.inputs[1].source_transaction.as_deref().unwrap();
    assert_eq!(via_parent.id().unwrap(), parent_txid);
    assert_eq!(
        direct.id().unwrap(),
        gp_txid,
        "both inputs resolve to their transaction"
    );

    // The subject's own input reaches the grandparent first, so that
    // placement carries the great-grandparent; the parent's input to the
    // same grandparent is the repeat and stops there.
    let ancestry_of = |gp: &Transaction| gp.inputs[0].source_transaction.is_some();
    assert!(
        ancestry_of(direct),
        "the first placement carries its ancestry"
    );
    let repeat = via_parent.inputs[0].source_transaction.as_deref().unwrap();
    assert_eq!(repeat.id().unwrap(), gp_txid);
    assert!(!ancestry_of(repeat), "the repeat placement is a leaf");
    assert_eq!(
        count_nodes(&tx),
        5,
        "subject + parent + two grandparent placements + one great-grandparent"
    );

    // The bounded tree is still a complete graph when placements are keyed by
    // txid: the direct grandparent placement resolves `great`, even though the
    // leaf placement reached through `parent` does not. The TS collector also
    // deduplicates by txid, so this must not depend on which placement is read
    // first.
    let input_hex = beef.to_hex().unwrap();
    let parsed = Transaction::from_beef(&input_hex).expect("from_beef should build proof tree");
    let output = parsed
        .to_beef()
        .expect("a complete repeated-ancestor DAG should serialize");
    let output_hex = hex::encode(&output);
    let round_trip_beef = Beef::from_binary_strict(&output).expect("round-trip BEEF parses");
    assert!(round_trip_beef.verify_valid(false).unwrap().valid);
    assert_eq!(round_trip_beef.txs.len(), 4, "each txid is emitted once");
    let round_trip = Transaction::from_beef(&output_hex).expect("round-trip transaction parses");
    assert_eq!(round_trip.id().unwrap(), subject_txid);

    // The other recursive consumers must also resolve through the complete
    // placement instead of treating the first leaf placement as definitive.
    let mut merged = Beef::new(BEEF_V2);
    merged
        .merge_transaction(&parsed)
        .expect("merge_transaction resolves repeated placements");
    assert!(merged.find_txid(&great_txid).is_some());

    #[cfg(feature = "network")]
    {
        let mut historian: Historian<String, ()> = Historian::new(Box::new(|tx, output, _| {
            (output == 0).then(|| tx.id().unwrap())
        }));
        let history = historian.build_history(&parsed, None);
        assert!(
            history.contains(&great_txid),
            "history reaches ancestry held by the complete placement"
        );
    }
}
