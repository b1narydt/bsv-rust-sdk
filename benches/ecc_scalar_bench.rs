use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::primitives::base_point::BasePoint;
use bsv::primitives::big_number::BigNumber;
use bsv::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use bsv::primitives::hash::sha256;

fn ecc_scalar_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecc_scalar");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(1));

    // Same scalar and key hex as TS ecc-scalar-bench.js
    let scalar =
        BigNumber::from_hex("1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5")
            .expect("valid scalar hex");

    let priv_hex = "8a2f85e08360a04c8a36b7c22c5e9e9a0d3bcf2f95c97db2b8bd90fc5f5ff66a";
    let priv_bn = BigNumber::from_hex(priv_hex).expect("valid priv key hex");

    // Message hash for ECDSA -- use SHA-256 of "deadbeefcafebabe" to get a proper 32-byte hash
    // (TS ECDSA.sign takes a BigNumber directly; Rust ecdsa_sign takes a [u8; 32] message hash)
    let msg_hash: [u8; 32] = sha256(b"deadbeefcafebabe");

    let base_point = BasePoint::instance();

    // Correctness: verify signature is valid before benchmarking
    let sig = ecdsa_sign(&msg_hash, &priv_bn, true).expect("signing must succeed");
    let pub_point = base_point.mul(&priv_bn);
    assert!(
        ecdsa_verify(&msg_hash, &sig, &pub_point).unwrap(),
        "signature must verify"
    );

    // Bench "point_mul": base_point.mul(&scalar)
    group.bench_function("point_mul", |bencher| {
        bencher.iter(|| {
            criterion::black_box(base_point.mul(&scalar));
        });
    });

    // Bench "ecdsa_sign"
    group.bench_function("ecdsa_sign", |bencher| {
        bencher.iter(|| {
            criterion::black_box(ecdsa_sign(&msg_hash, &priv_bn, true).unwrap());
        });
    });

    // Bench "ecdsa_verify"
    group.bench_function("ecdsa_verify", |bencher| {
        let sig = ecdsa_sign(&msg_hash, &priv_bn, true).unwrap();
        let pub_point = base_point.mul(&priv_bn);
        bencher.iter(|| {
            criterion::black_box(ecdsa_verify(&msg_hash, &sig, &pub_point).unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, ecc_scalar_benchmarks);
criterion_main!(benches);
