//! Benchmark: Transaction signing chains.
//!
//! Mirrors ts-sdk/benchmarks/transaction-bench.js with matching scenario
//! parameters (deep chain, wide input, large tx, nested inputs).
//!
//! NOTE: The Rust SDK script interpreter (SCPT-08) is not yet implemented,
//! so `tx.verify('scripts only')` is not available. These benchmarks measure
//! transaction construction and signing only. Verification is omitted and
//! documented as a gap.

use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::transaction_signature::{SIGHASH_ALL, SIGHASH_FORKID};
use bsv::script::templates::p2pkh::P2PKH;
use bsv::script::templates::ScriptTemplateLock;
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

/// Create a MerklePath with the standard 2-level structure used in the TS benchmarks.
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

/// Build a deep chain of transactions, each spending the previous.
/// Matches TS `deepInputChain` with depth=100.
fn deep_chain_sign(depth: usize) {
    let key = PrivateKey::from_hex("1").unwrap();
    let p2pkh = P2PKH::from_private_key(key.clone());
    let locking_script = p2pkh.lock().unwrap();

    // Base transaction
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput {
        satoshis: Some(100000),
        locking_script: locking_script.clone(),
        change: false,
    });
    let txid = tx.id().unwrap();
    tx.merkle_path = Some(make_merkle_path(&txid));

    for i in 1..=depth {
        let mut new_tx = Transaction::new();
        new_tx.add_input(TransactionInput {
            source_transaction: Some(Box::new(tx.clone())),
            source_txid: Some(tx.id().unwrap()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        new_tx.add_output(TransactionOutput {
            satoshis: Some(100000 - (i as u64) * 10),
            locking_script: locking_script.clone(),
            change: false,
        });

        let source_satoshis = tx.outputs[0].satoshis.unwrap();
        let source_ls = tx.outputs[0].locking_script.clone();
        now_or_never(new_tx.sign(0, &p2pkh, SCOPE, source_satoshis, &source_ls)).unwrap();

        tx = new_tx;
    }

    // Verify the final tx serializes without error
    let _ = tx.to_bytes().unwrap();
}

/// Create a transaction spending many source transactions.
/// Matches TS `wideInputSet` with 100 inputs.
fn wide_transaction_sign(input_count: usize) {
    let key = PrivateKey::from_hex("1").unwrap();
    let p2pkh = P2PKH::from_private_key(key.clone());
    let locking_script = p2pkh.lock().unwrap();

    let mut source_txs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let mut source_tx = Transaction::new();
        source_tx.add_output(TransactionOutput {
            satoshis: Some(1000),
            locking_script: locking_script.clone(),
            change: false,
        });
        let txid = source_tx.id().unwrap();
        source_tx.merkle_path = Some(make_merkle_path(&txid));
        source_txs.push(source_tx);
    }

    let mut tx = Transaction::new();
    for source_tx in &source_txs {
        tx.add_input(TransactionInput {
            source_transaction: Some(Box::new(source_tx.clone())),
            source_txid: Some(source_tx.id().unwrap()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
    }
    tx.add_output(TransactionOutput {
        satoshis: Some((input_count as u64) * 1000 - 1000),
        locking_script: locking_script.clone(),
        change: false,
    });

    for i in 0..input_count {
        let source_satoshis = source_txs[i].outputs[0].satoshis.unwrap();
        let source_ls = source_txs[i].outputs[0].locking_script.clone();
        now_or_never(tx.sign(i, &p2pkh, SCOPE, source_satoshis, &source_ls)).unwrap();
    }

    let _ = tx.to_bytes().unwrap();
}

/// Create a transaction with many inputs and many outputs.
/// Matches TS `largeInputsOutputs` with 50 inputs, 50 outputs.
fn large_tx_sign(input_count: usize, output_count: usize) {
    let key = PrivateKey::from_hex("1").unwrap();
    let p2pkh = P2PKH::from_private_key(key.clone());
    let locking_script = p2pkh.lock().unwrap();

    let mut source_txs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let mut source_tx = Transaction::new();
        source_tx.add_output(TransactionOutput {
            satoshis: Some(2000),
            locking_script: locking_script.clone(),
            change: false,
        });
        let txid = source_tx.id().unwrap();
        source_tx.merkle_path = Some(make_merkle_path(&txid));
        source_txs.push(source_tx);
    }

    let mut tx = Transaction::new();
    for source_tx in &source_txs {
        tx.add_input(TransactionInput {
            source_transaction: Some(Box::new(source_tx.clone())),
            source_txid: Some(source_tx.id().unwrap()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
    }
    for _ in 0..output_count {
        tx.add_output(TransactionOutput {
            satoshis: Some(1000),
            locking_script: locking_script.clone(),
            change: false,
        });
    }

    for i in 0..input_count {
        let source_satoshis = source_txs[i].outputs[0].satoshis.unwrap();
        let source_ls = source_txs[i].outputs[0].locking_script.clone();
        now_or_never(tx.sign(i, &p2pkh, SCOPE, source_satoshis, &source_ls)).unwrap();
    }

    let _ = tx.to_bytes().unwrap();
}

/// Build a tree of transactions with fan-out at each level.
/// Matches TS `nestedInputs` with depth=5, fanOut=3.
fn nested_inputs_sign(depth: usize, fan_out: usize) {
    let key = PrivateKey::from_hex("1").unwrap();
    let p2pkh = P2PKH::from_private_key(key.clone());
    let locking_script = p2pkh.lock().unwrap();

    // Base transactions
    let mut txs: Vec<Transaction> = Vec::with_capacity(fan_out);
    for _ in 0..fan_out {
        let mut base_tx = Transaction::new();
        base_tx.add_output(TransactionOutput {
            satoshis: Some(100000),
            locking_script: locking_script.clone(),
            change: false,
        });
        let txid = base_tx.id().unwrap();
        base_tx.merkle_path = Some(make_merkle_path(&txid));
        txs.push(base_tx);
    }

    for _ in 0..depth {
        let mut new_txs = Vec::new();
        for tx in &txs {
            let mut new_tx = Transaction::new();
            // The TS version adds fan_out inputs all from the same source tx
            for _ in 0..fan_out {
                new_tx.add_input(TransactionInput {
                    source_transaction: Some(Box::new(tx.clone())),
                    source_txid: Some(tx.id().unwrap()),
                    source_output_index: 0,
                    unlocking_script: None,
                    sequence: 0xffffffff,
                });
            }
            let prev_sats = tx.outputs[0].satoshis.unwrap_or(0);
            new_tx.add_output(TransactionOutput {
                satoshis: Some(prev_sats.saturating_sub(1000 * fan_out as u64)),
                locking_script: locking_script.clone(),
                change: false,
            });

            let source_satoshis = tx.outputs[0].satoshis.unwrap();
            let source_ls = tx.outputs[0].locking_script.clone();
            for i in 0..fan_out {
                now_or_never(new_tx.sign(i, &p2pkh, SCOPE, source_satoshis, &source_ls))
                    .unwrap();
            }

            new_txs.push(new_tx);
        }
        txs = new_txs;
    }

    // Verify the final tx serializes
    let _ = txs[0].to_bytes().unwrap();
}

fn bench_transaction(c: &mut Criterion) {
    // Correctness: verify a simple signed transaction produces valid serialized output
    {
        let key = PrivateKey::from_hex("1").unwrap();
        let p2pkh = P2PKH::from_private_key(key);
        let locking_script = p2pkh.lock().unwrap();

        let mut source_tx = Transaction::new();
        source_tx.add_output(TransactionOutput {
            satoshis: Some(50000),
            locking_script: locking_script.clone(),
            change: false,
        });

        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_transaction: Some(Box::new(source_tx.clone())),
            source_txid: Some(source_tx.id().unwrap()),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffffffff,
        });
        tx.add_output(TransactionOutput {
            satoshis: Some(49000),
            locking_script: locking_script.clone(),
            change: false,
        });
        now_or_never(tx.sign(
            0,
            &p2pkh,
            SCOPE,
            50000,
            &source_tx.outputs[0].locking_script,
        ))
        .unwrap();

        let bytes = tx.to_bytes().unwrap();
        assert!(
            !bytes.is_empty(),
            "signed transaction should produce non-empty bytes"
        );
        assert!(bytes.len() > 100, "signed P2PKH tx should be > 100 bytes");
    }

    let mut group = c.benchmark_group("transaction");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    group.bench_function("deep_chain_sign_100", |b| b.iter(|| deep_chain_sign(100)));

    group.bench_function("wide_transaction_sign_100", |b| {
        b.iter(|| wide_transaction_sign(100))
    });

    group.bench_function("large_tx_sign_50x50", |b| b.iter(|| large_tx_sign(50, 50)));

    group.bench_function("nested_inputs_sign_d5_f3", |b| {
        b.iter(|| nested_inputs_sign(5, 3))
    });

    group.finish();
}

criterion_group!(benches, bench_transaction);
criterion_main!(benches);
