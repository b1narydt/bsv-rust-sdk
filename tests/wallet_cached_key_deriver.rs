//! Integration tests for CachedKeyDeriver, ported from ts-sdk CachedKeyDeriver.test.ts.
//!
//! Covers: cache hit/miss behavior, different parameter combinations,
//! cache eviction, and behavioral equivalence with KeyDeriver.
//!
//! Note: Since Rust does not support jest.fn() mocking, we test behavioral
//! equivalence -- calling CachedKeyDeriver multiple times and verifying
//! results match KeyDeriver results.

use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::cached_key_deriver::CachedKeyDeriver;
use bsv::wallet::key_deriver::KeyDeriver;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn root_key() -> PrivateKey {
    PrivateKey::from_hex("01").unwrap()
}

fn protocol_0(name: &str) -> Protocol {
    Protocol {
        security_level: 0,
        protocol: name.to_string(),
    }
}

fn protocol_1(name: &str) -> Protocol {
    Protocol {
        security_level: 1,
        protocol: name.to_string(),
    }
}

fn protocol_2(name: &str) -> Protocol {
    Protocol {
        security_level: 2,
        protocol: name.to_string(),
    }
}

fn self_counterparty() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Self_,
        public_key: None,
    }
}

fn anyone_counterparty() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Anyone,
        public_key: None,
    }
}

// ---------------------------------------------------------------------------
// 1. derive_public_key: cache hit returns same result
// ---------------------------------------------------------------------------

#[test]
fn derive_public_key_should_cache_and_return_same_result() {
    let pk = root_key();
    let pk2 = root_key();
    let ckd = CachedKeyDeriver::new(pk, None);
    let kd = KeyDeriver::new(pk2);
    let protocol = protocol_0("testprotocol");
    let cp = self_counterparty();

    // First call
    let result1 = ckd
        .derive_public_key(&protocol, "key1", &cp, false)
        .unwrap();

    // Second call with same params -- should return cached result
    let result2 = ckd
        .derive_public_key(&protocol, "key1", &cp, false)
        .unwrap();

    assert_eq!(
        result1.to_der_hex(),
        result2.to_der_hex(),
        "cached result should match first result"
    );

    // Should also match uncached KeyDeriver
    let uncached = kd.derive_public_key(&protocol, "key1", &cp, false).unwrap();
    assert_eq!(
        result1.to_der_hex(),
        uncached.to_der_hex(),
        "cached result should match uncached KeyDeriver"
    );
}

// ---------------------------------------------------------------------------
// 2. derive_public_key: different params produce different results
// ---------------------------------------------------------------------------

#[test]
fn derive_public_key_should_handle_different_parameters_correctly() {
    let ckd = CachedKeyDeriver::new(root_key(), None);

    let protocol1 = protocol_0("protocol1test");
    let protocol2 = protocol_1("protocol2test");

    let result1 = ckd
        .derive_public_key(&protocol1, "key1", &self_counterparty(), false)
        .unwrap();
    let result2 = ckd
        .derive_public_key(&protocol2, "key2", &anyone_counterparty(), false)
        .unwrap();

    assert_ne!(
        result1.to_der_hex(),
        result2.to_der_hex(),
        "different parameters should produce different results"
    );
}

// ---------------------------------------------------------------------------
// 3. derive_private_key: cache hit behavior
// ---------------------------------------------------------------------------

#[test]
fn derive_private_key_should_cache_and_return_same_result() {
    let pk = root_key();
    let pk2 = root_key();
    let ckd = CachedKeyDeriver::new(pk, None);
    let kd = KeyDeriver::new(pk2);
    let protocol = protocol_1("testprotocol");
    let cp = anyone_counterparty();

    let result1 = ckd.derive_private_key(&protocol, "key1", &cp).unwrap();
    let result2 = ckd.derive_private_key(&protocol, "key1", &cp).unwrap();

    assert_eq!(
        result1.to_hex(),
        result2.to_hex(),
        "cached private key should match"
    );

    let uncached = kd.derive_private_key(&protocol, "key1", &cp).unwrap();
    assert_eq!(result1.to_hex(), uncached.to_hex());
}

// ---------------------------------------------------------------------------
// 4. derive_private_key: different protocol_id/key differentiates cache entries
// ---------------------------------------------------------------------------

#[test]
fn derive_private_key_should_differentiate_cache_entries_based_on_parameters() {
    let ckd = CachedKeyDeriver::new(root_key(), None);
    let protocol = protocol_1("testprotocol");
    let cp = anyone_counterparty();

    let result1 = ckd.derive_private_key(&protocol, "key1", &cp).unwrap();
    let result2 = ckd.derive_private_key(&protocol, "key2", &cp).unwrap();

    assert_ne!(
        result1.to_hex(),
        result2.to_hex(),
        "different key IDs should produce different private keys"
    );
}

// ---------------------------------------------------------------------------
// 5. derive_symmetric_key: cache hit behavior
// ---------------------------------------------------------------------------

#[test]
fn derive_symmetric_key_should_cache_and_return_same_result() {
    let pk = root_key();
    let pk2 = root_key();
    let ckd = CachedKeyDeriver::new(pk, None);
    let kd = KeyDeriver::new(pk2);
    let protocol = protocol_2("testprotocol");
    let cp = self_counterparty();

    let result1 = ckd.derive_symmetric_key(&protocol, "key1", &cp).unwrap();
    let result2 = ckd.derive_symmetric_key(&protocol, "key1", &cp).unwrap();

    assert_eq!(
        result1.to_hex(),
        result2.to_hex(),
        "cached symmetric key should match"
    );

    let uncached = kd.derive_symmetric_key(&protocol, "key1", &cp).unwrap();
    assert_eq!(result1.to_hex(), uncached.to_hex());
}

// ---------------------------------------------------------------------------
// 6. derive_symmetric_key: different counterparties
// ---------------------------------------------------------------------------

#[test]
fn derive_symmetric_key_should_handle_different_counterparties() {
    // Use a root key that is NOT PrivateKey(1), so self != anyone
    let pk = PrivateKey::from_hex("abcd").unwrap();
    let ckd = CachedKeyDeriver::new(pk, None);
    let protocol = protocol_2("testprotocol");

    let result_self = ckd
        .derive_symmetric_key(&protocol, "key1", &self_counterparty())
        .unwrap();
    let result_anyone = ckd
        .derive_symmetric_key(&protocol, "key1", &anyone_counterparty())
        .unwrap();

    assert_ne!(
        result_self.to_hex(),
        result_anyone.to_hex(),
        "different counterparties should produce different symmetric keys"
    );
}

// ---------------------------------------------------------------------------
// 7. Cache management: eviction with small cache size
// ---------------------------------------------------------------------------

#[test]
fn cache_eviction_should_clear_and_continue_working() {
    let ckd = CachedKeyDeriver::new(root_key(), Some(3));
    let protocol = protocol_0("testprotocol");
    let cp = self_counterparty();

    // Fill cache beyond max (3 entries, then add a 4th)
    let _r0 = ckd
        .derive_public_key(&protocol, "key0", &cp, false)
        .unwrap();
    let _r1 = ckd
        .derive_public_key(&protocol, "key1", &cp, false)
        .unwrap();
    let _r2 = ckd
        .derive_public_key(&protocol, "key2", &cp, false)
        .unwrap();

    // This should trigger clear-all eviction, then insert key3
    let r3 = ckd
        .derive_public_key(&protocol, "key3", &cp, false)
        .unwrap();

    // Verify key3 still produces a correct result
    let kd = KeyDeriver::new(root_key());
    let expected = kd.derive_public_key(&protocol, "key3", &cp, false).unwrap();
    assert_eq!(
        r3.to_der_hex(),
        expected.to_der_hex(),
        "after eviction, result should still be correct"
    );

    // Re-derive key0 -- should still produce correct result even though
    // it was evicted from cache
    let r0_again = ckd
        .derive_public_key(&protocol, "key0", &cp, false)
        .unwrap();
    let expected_r0 = kd.derive_public_key(&protocol, "key0", &cp, false).unwrap();
    assert_eq!(
        r0_again.to_der_hex(),
        expected_r0.to_der_hex(),
        "re-derived key after eviction should be correct"
    );
}

// ---------------------------------------------------------------------------
// 8. Verify cache stores results correctly for repeated calls
// ---------------------------------------------------------------------------

#[test]
fn cache_should_store_results_correctly_for_repeated_calls() {
    let ckd = CachedKeyDeriver::new(root_key(), None);
    let protocol = protocol_0("testprotocol");
    let cp = self_counterparty();

    // Call the same derivation 10 times -- all should return identical results
    let mut results = Vec::new();
    for _ in 0..10 {
        let r = ckd
            .derive_public_key(&protocol, "repeated", &cp, false)
            .unwrap();
        results.push(r.to_der_hex());
    }

    let first = &results[0];
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r, first, "call {} should produce same result as call 0", i);
    }
}

// ---------------------------------------------------------------------------
// 9. Identity key delegates correctly
// ---------------------------------------------------------------------------

#[test]
fn identity_key_should_delegate_correctly() {
    let pk = root_key();
    let pk2 = root_key();
    let kd = KeyDeriver::new(pk);
    let ckd = CachedKeyDeriver::new(pk2, None);

    assert_eq!(
        kd.identity_key_hex(),
        ckd.identity_key_hex(),
        "identity key should match between KeyDeriver and CachedKeyDeriver"
    );
}
