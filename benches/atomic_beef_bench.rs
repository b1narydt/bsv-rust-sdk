//! Benchmark: Atomic BEEF serialization/deserialization.
//!
//! Mirrors ts-sdk/benchmarks/atomic-beef-bench.js with chain depth=200.
//! Builds a deep transaction chain, serializes to Atomic BEEF format,
//! then benchmarks round-trip serialization.

use criterion::{criterion_group, criterion_main, Criterion};
use std::io::Cursor;
use std::time::Duration;

use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
use bsv::transaction::beef::{Beef, BEEF_V1};
use bsv::transaction::beef_tx::BeefTx;
use bsv::transaction::merkle_path::{MerklePath, MerklePathLeaf};
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

/// Resolve a future that is ready on the first poll, without a runtime.
///
/// [`bsv::script::templates::ScriptTemplateUnlock`] is async so that
/// wallet-backed templates can reach a key that is not local. P2PKH's key IS
/// local, so its future never yields and one poll finishes it. Standing up a
/// tokio runtime per signature would put the runtime inside the measurement.
fn now_or_never<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => {
            panic!("a local-key template must resolve without yielding")
        }
    }
}

const SCOPE: u32 = SIGHASH_ALL | SIGHASH_FORKID;
const CHAIN_DEPTH: usize = 200;

fn make_merkle_path(txid: &str) -> MerklePath {
    let path = vec![
        vec![
            MerklePathLeaf {
                offset: 0,
                hash: Some(txid.to_string()),
                txid: true,
                duplicate: false,
            },
            MerklePathLeaf {
                offset: 1,
                hash: Some("aa".repeat(32)),
                txid: false,
                duplicate: false,
            },
        ],
        vec![MerklePathLeaf {
            offset: 1,
            hash: Some("bb".repeat(32)),
            txid: false,
            duplicate: false,
        }],
    ];
    MerklePath::new(1631619, path).expect("valid merkle path")
}

/// Build a chain of transactions of the given depth, collecting all txs
/// for BEEF packaging. Returns (all_transactions, final_txid, merkle_path).
fn build_chain(depth: usize) -> (Vec<Transaction>, String, MerklePath) {
    let key = PrivateKey::from_hex("1").unwrap();
    let p2pkh = P2PKH::from_private_key(key.clone());
    let locking_script = p2pkh.lock().unwrap();

    let mut all_txs = Vec::with_capacity(depth + 1);

    // Base transaction
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput {
        satoshis: Some(100000),
        locking_script: locking_script.clone(),
        change: false,
    });
    let base_txid = tx.id().unwrap();
    let merkle_path = make_merkle_path(&base_txid);
    tx.merkle_path = Some(merkle_path.clone());
    all_txs.push(tx.clone());

    for i in 1..depth {
        let mut new_tx = Transaction::new();
        new_tx.add_input(TransactionInput {
            source_transaction: Some(Box::new(tx.clone())),
            source_txid: Some(tx.id().unwrap()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        new_tx.add_output(TransactionOutput {
            satoshis: Some(100000u64.saturating_sub(i as u64)),
            locking_script: locking_script.clone(),
            change: false,
        });

        let source_satoshis = tx.outputs[0].satoshis.unwrap();
        let source_ls = tx.outputs[0].locking_script.clone();
        now_or_never(new_tx.sign(0, &p2pkh, SCOPE, source_satoshis, &source_ls)).unwrap();

        tx = new_tx;
        all_txs.push(tx.clone());
    }

    let final_txid = tx.id().unwrap();
    (all_txs, final_txid, merkle_path)
}

/// Build a Beef holding the whole chain; `to_binary_atomic(final_txid)`
/// frames it as Atomic BEEF (the prefix is a serialization choice, not
/// beef state).
fn build_chain_beef(all_txs: &[Transaction], merkle_path: &MerklePath) -> Beef {
    let mut beef = Beef::new(BEEF_V1);

    // Add the merkle path for the base (proven) transaction
    beef.bumps.push(merkle_path.clone());

    // Add all transactions as BeefTx entries.
    // The first tx (base) has a bump index; the rest do not.
    for (i, tx) in all_txs.iter().enumerate() {
        let bump_index = if i == 0 { Some(0) } else { None };
        let beef_tx = BeefTx::from_tx(tx.clone(), bump_index).unwrap();
        beef.txs.push(beef_tx);
    }

    beef
}

fn bench_atomic_beef(c: &mut Criterion) {
    // Build the chain once (expensive setup)
    let (all_txs, final_txid, merkle_path) = build_chain(CHAIN_DEPTH);

    let beef = build_chain_beef(&all_txs, &merkle_path);

    // Serialize once for setup
    let serialized = beef.to_binary_atomic(&final_txid).unwrap();

    // Correctness: round-trip preserves data
    {
        let mut cursor = Cursor::new(&serialized);
        let deserialized = Beef::from_binary(&mut cursor).unwrap();
        assert_eq!(
            deserialized.txs.len(),
            beef.txs.len(),
            "round-trip must preserve transaction count"
        );
        assert_eq!(
            deserialized.bumps.len(),
            beef.bumps.len(),
            "round-trip must preserve bump count"
        );

        // Re-serialize and compare bytes
        let reserialized = deserialized.to_binary_atomic(&final_txid).unwrap();
        assert_eq!(
            serialized, reserialized,
            "double round-trip must produce identical bytes"
        );
    }

    let mut group = c.benchmark_group("atomic_beef");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    group.bench_function("to_atomic_beef", |b| {
        b.iter(|| beef.to_binary_atomic(&final_txid).unwrap())
    });

    group.bench_function("from_atomic_beef", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(&serialized);
            Beef::from_binary(&mut cursor).unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_atomic_beef);
criterion_main!(benches);
