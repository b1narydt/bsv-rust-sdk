use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

use bsv::compat::ecies::ECIES;
use bsv::primitives::private_key::PrivateKey;

fn ecies_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecies");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));

    // PrivateKey(1) as sender, PrivateKey(2) as receiver -- matching TS ecies-bench.js
    let sender =
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("valid key 1");
    let receiver =
        PrivateKey::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
            .expect("valid key 2");
    let receiver_pub = receiver.to_public_key();

    // Three sizes matching TS ecies-bench.js: 32B, 1KB, 64KB
    let small: Vec<u8> = (0..32u32).map(|i| (i & 0xff) as u8).collect();
    let medium: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
    let large: Vec<u8> = (0..65536u32).map(|i| (i & 0xff) as u8).collect();

    // Pre-encrypt for decrypt benchmarks
    let electrum_enc_small =
        ECIES::electrum_encrypt(&small, &receiver_pub, Some(&sender), false).expect("encrypt");
    let electrum_enc_medium =
        ECIES::electrum_encrypt(&medium, &receiver_pub, Some(&sender), false).expect("encrypt");
    let electrum_enc_large =
        ECIES::electrum_encrypt(&large, &receiver_pub, Some(&sender), false).expect("encrypt");

    let bitcore_enc_small =
        ECIES::bitcore_encrypt(&small, &receiver_pub, Some(&sender)).expect("encrypt");
    let bitcore_enc_medium =
        ECIES::bitcore_encrypt(&medium, &receiver_pub, Some(&sender)).expect("encrypt");
    let bitcore_enc_large =
        ECIES::bitcore_encrypt(&large, &receiver_pub, Some(&sender)).expect("encrypt");

    // Correctness: round-trip
    let dec = ECIES::electrum_decrypt(&electrum_enc_small, &receiver, None).expect("decrypt");
    assert_eq!(dec, small, "Electrum round-trip must match");
    let dec = ECIES::bitcore_decrypt(&bitcore_enc_small, &receiver).expect("decrypt");
    assert_eq!(dec, small, "Bitcore round-trip must match");

    // ---- Electrum encrypt ----
    group.throughput(Throughput::Bytes(32));
    group.bench_function("electrum_encrypt_32B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_encrypt(&small, &receiver_pub, Some(&sender), false).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("electrum_encrypt_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_encrypt(&medium, &receiver_pub, Some(&sender), false).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("electrum_encrypt_64KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_encrypt(&large, &receiver_pub, Some(&sender), false).unwrap(),
            );
        });
    });

    // ---- Electrum decrypt ----
    group.throughput(Throughput::Bytes(32));
    group.bench_function("electrum_decrypt_32B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_decrypt(&electrum_enc_small, &receiver, None).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("electrum_decrypt_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_decrypt(&electrum_enc_medium, &receiver, None).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("electrum_decrypt_64KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::electrum_decrypt(&electrum_enc_large, &receiver, None).unwrap(),
            );
        });
    });

    // ---- Bitcore encrypt ----
    group.throughput(Throughput::Bytes(32));
    group.bench_function("bitcore_encrypt_32B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::bitcore_encrypt(&small, &receiver_pub, Some(&sender)).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("bitcore_encrypt_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::bitcore_encrypt(&medium, &receiver_pub, Some(&sender)).unwrap(),
            );
        });
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("bitcore_encrypt_64KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(
                ECIES::bitcore_encrypt(&large, &receiver_pub, Some(&sender)).unwrap(),
            );
        });
    });

    // ---- Bitcore decrypt ----
    group.throughput(Throughput::Bytes(32));
    group.bench_function("bitcore_decrypt_32B", |bencher| {
        bencher.iter(|| {
            criterion::black_box(ECIES::bitcore_decrypt(&bitcore_enc_small, &receiver).unwrap());
        });
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("bitcore_decrypt_1KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(ECIES::bitcore_decrypt(&bitcore_enc_medium, &receiver).unwrap());
        });
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("bitcore_decrypt_64KB", |bencher| {
        bencher.iter(|| {
            criterion::black_box(ECIES::bitcore_decrypt(&bitcore_enc_large, &receiver).unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, ecies_benchmarks);
criterion_main!(benches);
