use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::primitives::base_point::BasePoint;
use bsv::primitives::big_number::BigNumber;
use bsv::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use bsv::primitives::hash::sha256;

fn ecdsa_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));

    // Same key material as ecc_scalar_bench and TS ecdsa-bench.js
    let priv_hex = "8a2f85e08360a04c8a36b7c22c5e9e9a0d3bcf2f95c97db2b8bd90fc5f5ff66a";
    let priv_bn = BigNumber::from_hex(priv_hex).expect("valid priv key hex");

    let base_point = BasePoint::instance();
    let pub_point = base_point.mul(&priv_bn);

    // Message hash (SHA-256 of "deadbeefcafebabe" matching TS msg)
    let msg_hash: [u8; 32] = sha256(b"deadbeefcafebabe");

    // Correctness: round-trip sign then verify
    let sig = ecdsa_sign(&msg_hash, &priv_bn, true).expect("signing must succeed");
    assert!(
        ecdsa_verify(&msg_hash, &sig, &pub_point).unwrap(),
        "signature must verify"
    );

    // Bench "sign"
    group.bench_function("sign", |bencher| {
        bencher.iter(|| {
            criterion::black_box(ecdsa_sign(&msg_hash, &priv_bn, true).unwrap());
        });
    });

    // Bench "verify" (mirrors TS: sign then verify in each iteration)
    group.bench_function("verify", |bencher| {
        bencher.iter(|| {
            let s = ecdsa_sign(&msg_hash, &priv_bn, true).unwrap();
            criterion::black_box(ecdsa_verify(&msg_hash, &s, &pub_point).unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, ecdsa_benchmarks);
criterion_main!(benches);
