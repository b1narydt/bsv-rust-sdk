//! Integration tests for KeyDeriver, ported from ts-sdk KeyDeriver.test.ts.
//!
//! Covers: invoice number computation, counterparty normalization,
//! key derivation (public, private, symmetric), shared secret revelation,
//! specific secret revelation, and comprehensive input validation.

use std::sync::Arc;

use bsv::primitives::hash::sha256_hmac;
use bsv::primitives::private_key::PrivateKey;
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::cached_key_deriver::CachedKeyDeriver;
use bsv::wallet::key_deriver::KeyDeriver;
use bsv::wallet::key_deriver_api::KeyDeriverApi;
use bsv::wallet::types::{anyone_pubkey, Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn root_private_key() -> PrivateKey {
    PrivateKey::from_hex("2a").unwrap() // decimal 42
}

fn counterparty_private_key() -> PrivateKey {
    PrivateKey::from_hex("45").unwrap() // decimal 69
}

fn anyone_private_key() -> PrivateKey {
    PrivateKey::from_hex("01").unwrap() // decimal 1
}

fn test_protocol() -> Protocol {
    Protocol {
        security_level: 0,
        protocol: "testprotocol".to_string(),
    }
}

fn counterparty_other(pub_key: &PublicKey) -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Other,
        public_key: Some(pub_key.clone()),
    }
}

fn counterparty_self() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Self_,
        public_key: None,
    }
}

fn counterparty_anyone() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Anyone,
        public_key: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Invoice number computation
// ---------------------------------------------------------------------------

#[test]
fn should_compute_the_correct_invoice_number() {
    // Equivalent to ts-sdk: computeInvoiceNumber([0, 'testprotocol'], '12345')
    // Invoice number = "0-testprotocol-12345"
    // We test by deriving a public key and verifying the derivation path matches.
    // Since compute_invoice_number is private, we verify through derivation.
    let kd = KeyDeriver::new(root_private_key());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    // derive_public_key should succeed, confirming "0-testprotocol-12345" is valid
    let result = kd.derive_public_key(&test_protocol(), "12345", &cp, false);
    assert!(
        result.is_ok(),
        "derivation should succeed with valid protocol/keyID"
    );

    // Verify explicitly that the derivation matches manual child derivation
    // counterpartyPub.deriveChild(rootPriv, "0-testprotocol-12345")
    let expected = counterparty_pub
        .derive_child(&root_private_key(), "0-testprotocol-12345")
        .unwrap();
    assert_eq!(
        result.unwrap().to_der_hex(),
        expected.to_der_hex(),
        "derived key should match manual derivation with invoice '0-testprotocol-12345'"
    );
}

// ---------------------------------------------------------------------------
// 2-6. Counterparty normalization tests
// ---------------------------------------------------------------------------

#[test]
fn should_error_if_no_counterparty_public_key_for_other_type() {
    let kd = KeyDeriver::new(root_private_key());
    let bad_cp = Counterparty {
        counterparty_type: CounterpartyType::Other,
        public_key: None,
    };
    let result = kd.derive_public_key(&test_protocol(), "12345", &bad_cp, false);
    assert!(
        result.is_err(),
        "should error when Other counterparty has no public key"
    );
}

#[test]
fn should_normalize_counterparty_correctly_for_self() {
    let root = root_private_key();
    let root_pub = root.to_public_key();
    let kd = KeyDeriver::new(root);

    // for_self=true with self counterparty: derives own private child -> pubkey
    // for_self=false with self counterparty: derives own pubkey child
    // Both should produce valid but different keys.
    // The identity key should be the root pubkey.
    assert_eq!(
        kd.identity_key().to_der_hex(),
        root_pub.to_der_hex(),
        "identity key should be root public key"
    );

    // Derive with self counterparty should succeed
    let result = kd.derive_public_key(&test_protocol(), "12345", &counterparty_self(), false);
    assert!(
        result.is_ok(),
        "derivation with self counterparty should succeed"
    );
}

#[test]
fn should_normalize_counterparty_correctly_for_anyone() {
    let kd = KeyDeriver::new(root_private_key());
    let anyone_pub = anyone_pubkey();

    // Derive with anyone counterparty
    let cp_anyone = counterparty_anyone();
    let cp_other_anyone = counterparty_other(&anyone_pub);

    // Deriving with Anyone should produce a valid key
    let result_anyone = kd.derive_public_key(&test_protocol(), "12345", &cp_anyone, false);
    assert!(result_anyone.is_ok());

    // Deriving with the actual anyone pubkey as Other should produce the same key
    let result_other = kd.derive_public_key(&test_protocol(), "12345", &cp_other_anyone, false);
    assert!(result_other.is_ok());

    assert_eq!(
        result_anyone.unwrap().to_der_hex(),
        result_other.unwrap().to_der_hex(),
        "Anyone and Other(anyone_pubkey) should produce the same derived key"
    );
}

#[test]
fn should_normalize_counterparty_correctly_when_given_as_hex_string() {
    let kd = KeyDeriver::new(root_private_key());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    // Parse the hex back to a PublicKey and use it
    let hex_str = counterparty_pub.to_der_hex();
    let parsed_pub = PublicKey::from_string(&hex_str).unwrap();
    let cp_from_hex = counterparty_other(&parsed_pub);

    let result1 = kd
        .derive_public_key(&test_protocol(), "12345", &cp, false)
        .unwrap();
    let result2 = kd
        .derive_public_key(&test_protocol(), "12345", &cp_from_hex, false)
        .unwrap();

    assert_eq!(
        result1.to_der_hex(),
        result2.to_der_hex(),
        "derivation with PublicKey and hex-parsed PublicKey should match"
    );
}

#[test]
fn should_normalize_counterparty_correctly_when_given_as_public_key() {
    let kd = KeyDeriver::new(root_private_key());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let result = kd.derive_public_key(&test_protocol(), "12345", &cp, false);
    assert!(
        result.is_ok(),
        "derivation with PublicKey counterparty should succeed"
    );
}

// ---------------------------------------------------------------------------
// 7. Anyone key deriver support
// ---------------------------------------------------------------------------

#[test]
fn should_allow_public_key_derivation_as_anyone() {
    let anyone_deriver = KeyDeriver::new_anyone();
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let derived = anyone_deriver
        .derive_public_key(&test_protocol(), "12345", &cp, false)
        .unwrap();

    // Should match: counterpartyPub.deriveChild(PrivateKey(1), "0-testprotocol-12345")
    let expected = counterparty_pub
        .derive_child(&anyone_private_key(), "0-testprotocol-12345")
        .unwrap();

    assert_eq!(
        derived.to_der_hex(),
        expected.to_der_hex(),
        "anyone deriver should derive using PrivateKey(1)"
    );
}

// ---------------------------------------------------------------------------
// 8. Derive public key for counterparty (for_self=false)
// ---------------------------------------------------------------------------

#[test]
fn should_derive_the_correct_public_key_for_counterparty() {
    let kd = KeyDeriver::new(root_private_key());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let derived = kd
        .derive_public_key(&test_protocol(), "12345", &cp, false)
        .unwrap();

    // Expected: counterpartyPub.deriveChild(rootPriv, "0-testprotocol-12345")
    let expected = counterparty_pub
        .derive_child(&root_private_key(), "0-testprotocol-12345")
        .unwrap();

    assert_eq!(derived.to_der_hex(), expected.to_der_hex());
}

// ---------------------------------------------------------------------------
// 9. Derive public key for self (for_self=true)
// ---------------------------------------------------------------------------

#[test]
fn should_derive_the_correct_public_key_for_self() {
    let root = root_private_key();
    let kd = KeyDeriver::new(root.clone());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let derived = kd
        .derive_public_key(&test_protocol(), "12345", &cp, true)
        .unwrap();

    // Expected: rootPriv.deriveChild(counterpartyPub, "0-testprotocol-12345").toPublicKey()
    let expected = root
        .derive_child(&counterparty_pub, "0-testprotocol-12345")
        .unwrap()
        .to_public_key();

    assert_eq!(derived.to_der_hex(), expected.to_der_hex());
}

// ---------------------------------------------------------------------------
// 10. Derive private key
// ---------------------------------------------------------------------------

#[test]
fn should_derive_the_correct_private_key() {
    let root = root_private_key();
    let kd = KeyDeriver::new(root.clone());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let derived = kd
        .derive_private_key(&test_protocol(), "12345", &cp)
        .unwrap();

    // Expected: rootPriv.deriveChild(counterpartyPub, "0-testprotocol-12345")
    let expected = root
        .derive_child(&counterparty_pub, "0-testprotocol-12345")
        .unwrap();

    assert_eq!(derived.to_hex(), expected.to_hex());
}

// ---------------------------------------------------------------------------
// 11. Derive symmetric key
// ---------------------------------------------------------------------------

#[test]
fn should_derive_the_correct_symmetric_key() {
    let root = root_private_key();
    let kd = KeyDeriver::new(root.clone());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let derived_sym = kd
        .derive_symmetric_key(&test_protocol(), "12345", &cp)
        .unwrap();

    // The symmetric key is derived from the ECDH shared secret x-coordinate
    // between derived_priv and derived_pub:
    let derived_priv = root
        .derive_child(&counterparty_pub, "0-testprotocol-12345")
        .unwrap();
    let derived_pub = counterparty_pub
        .derive_child(&root, "0-testprotocol-12345")
        .unwrap();
    let shared = derived_priv.derive_shared_secret(&derived_pub).unwrap();
    let x_bytes = shared
        .x
        .to_array(bsv::primitives::big_number::Endian::Big, Some(32));

    assert_eq!(
        derived_sym.to_hex(),
        hex::encode(&x_bytes),
        "symmetric key should be the x-coordinate of the ECDH shared secret"
    );
}

#[test]
fn should_be_able_to_derive_symmetric_key_with_anyone() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_anyone();

    let result = kd.derive_symmetric_key(&test_protocol(), "12345", &cp);
    assert!(
        result.is_ok(),
        "symmetric key derivation with anyone should succeed"
    );
}

// ---------------------------------------------------------------------------
// 12. Reveal counterparty shared secret
// ---------------------------------------------------------------------------

#[test]
fn should_reveal_the_correct_counterparty_shared_secret() {
    let root = root_private_key();
    let kd = KeyDeriver::new(root.clone());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let revealed = kd.reveal_counterparty_secret(&cp).unwrap();
    let revealed_bytes = revealed.to_der(); // compressed encoding

    // Expected: rootPriv.deriveSharedSecret(counterpartyPub).encode(true)
    let expected_point = root.derive_shared_secret(&counterparty_pub).unwrap();
    let expected_bytes = expected_point.to_der(true);

    assert_eq!(revealed_bytes, expected_bytes);
    assert!(!revealed_bytes.is_empty());
}

#[test]
fn should_not_reveal_shared_secret_for_self() {
    let root = root_private_key();
    let root_pub = root.to_public_key();
    let kd = KeyDeriver::new(root);

    // By type Self_
    let cp_self = counterparty_self();
    assert!(
        kd.reveal_counterparty_secret(&cp_self).is_err(),
        "should not reveal shared secret for Self_ counterparty type"
    );

    // By actual own public key as Other
    let cp_own_pub = counterparty_other(&root_pub);
    assert!(
        kd.reveal_counterparty_secret(&cp_own_pub).is_err(),
        "should not reveal shared secret when counterparty is own public key"
    );
}

// ---------------------------------------------------------------------------
// 13. Reveal specific key association secret
// ---------------------------------------------------------------------------

#[test]
fn should_reveal_the_specific_key_association() {
    let root = root_private_key();
    let kd = KeyDeriver::new(root.clone());
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let specific_secret = kd
        .reveal_specific_secret(&cp, &test_protocol(), "12345")
        .unwrap();

    assert!(!specific_secret.is_empty());

    // Expected: HMAC-SHA256(sharedSecret.encode(true), invoiceNumberBin)
    let shared_secret = root.derive_shared_secret(&counterparty_pub).unwrap();
    let shared_secret_compressed = shared_secret.to_der(true);
    let invoice_number = "0-testprotocol-12345";
    let expected = sha256_hmac(&shared_secret_compressed, invoice_number.as_bytes());

    assert_eq!(specific_secret, expected.to_vec());
}

// ---------------------------------------------------------------------------
// 14-17. Validation: invalid protocol names and key IDs
// ---------------------------------------------------------------------------

#[test]
fn should_reject_key_id_too_long() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let long_key_id = "a".repeat(801);
    let result = kd.derive_public_key(&test_protocol(), &long_key_id, &cp, false);
    assert!(result.is_err(), "key_id over 800 chars should be rejected");
}

#[test]
fn should_reject_key_id_empty() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let result = kd.derive_public_key(&test_protocol(), "", &cp, false);
    assert!(result.is_err(), "empty key_id should be rejected");
}

#[test]
fn should_reject_invalid_security_level() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let bad_protocol = Protocol {
        security_level: 3,
        protocol: "testprotocol".to_string(),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(result.is_err(), "security level 3 should be rejected");
}

#[test]
fn should_reject_double_spaces_in_protocol_name() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let bad_protocol = Protocol {
        security_level: 2,
        protocol: "double  space".to_string(),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "protocol with double spaces should be rejected"
    );
}

#[test]
fn should_reject_empty_protocol_name() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let bad_protocol = Protocol {
        security_level: 0,
        protocol: "".to_string(),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "empty protocol name should be rejected (< 5 chars)"
    );
}

#[test]
fn should_reject_protocol_name_with_leading_space() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    // After trim(), " a" becomes "a" which is < 5 chars
    let bad_protocol = Protocol {
        security_level: 0,
        protocol: " a".to_string(),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "protocol name with only leading space should be too short after trim"
    );
}

#[test]
fn should_reject_protocol_name_too_long() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let bad_protocol = Protocol {
        security_level: 0,
        protocol: format!("long{}", "a".repeat(400)),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "protocol name over 400 chars should be rejected"
    );
}

#[test]
fn should_reject_protocol_name_ending_with_protocol() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let bad_protocol = Protocol {
        security_level: 2,
        protocol: "redundant protocol protocol".to_string(),
    };
    let result = kd.derive_public_key(&bad_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "protocol name ending with ' protocol' should be rejected"
    );
}

#[test]
fn should_reject_protocol_name_with_non_ascii_chars() {
    let kd = KeyDeriver::new(root_private_key());
    let cp = counterparty_self();
    let invalid_protocol = Protocol {
        security_level: 2,
        protocol: "hello-world test1".to_string(), // hyphen is invalid
    };
    let result = kd.derive_public_key(&invalid_protocol, "12345", &cp, false);
    assert!(
        result.is_err(),
        "protocol with invalid characters should be rejected"
    );
}

// ---------------------------------------------------------------------------
// 18. CachedKeyDeriver secret revelation (delegates uncached to KeyDeriver)
// ---------------------------------------------------------------------------

#[test]
fn cached_deriver_should_reveal_the_correct_counterparty_shared_secret() {
    let root = root_private_key();
    let ckd = CachedKeyDeriver::new(root.clone(), None);
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let revealed = ckd.reveal_counterparty_secret(&cp).unwrap();
    let expected_point = root.derive_shared_secret(&counterparty_pub).unwrap();

    assert_eq!(revealed.to_der(), expected_point.to_der(true));

    // Repeating must be stable, and must not populate the derived-key cache —
    // revelation delegates straight through.
    let revealed_again = ckd.reveal_counterparty_secret(&cp).unwrap();
    assert_eq!(revealed_again.to_der(), revealed.to_der());
}

#[test]
fn cached_deriver_should_not_reveal_shared_secret_for_self() {
    let root = root_private_key();
    let root_pub = root.to_public_key();
    let ckd = CachedKeyDeriver::new(root, None);

    let cp_self = counterparty_self();
    assert!(
        ckd.reveal_counterparty_secret(&cp_self).is_err(),
        "should not reveal shared secret for Self_ counterparty type"
    );

    let cp_own_pub = counterparty_other(&root_pub);
    assert!(
        ckd.reveal_counterparty_secret(&cp_own_pub).is_err(),
        "should not reveal shared secret when counterparty is own public key"
    );
}

#[test]
fn cached_deriver_should_reveal_the_specific_key_association() {
    let root = root_private_key();
    let ckd = CachedKeyDeriver::new(root.clone(), None);
    let counterparty_pub = counterparty_private_key().to_public_key();
    let cp = counterparty_other(&counterparty_pub);

    let specific_secret = ckd
        .reveal_specific_secret(&cp, &test_protocol(), "12345")
        .unwrap();

    let shared_secret = root.derive_shared_secret(&counterparty_pub).unwrap();
    let expected = sha256_hmac(&shared_secret.to_der(true), b"0-testprotocol-12345");

    assert_eq!(specific_secret, expected.to_vec());
}

#[test]
fn cached_deriver_revelation_should_match_key_deriver() {
    let kd = KeyDeriver::new(root_private_key());
    let ckd = CachedKeyDeriver::new(root_private_key(), None);
    let cp = counterparty_other(&counterparty_private_key().to_public_key());

    assert_eq!(
        ckd.reveal_counterparty_secret(&cp).unwrap().to_der(),
        kd.reveal_counterparty_secret(&cp).unwrap().to_der()
    );
    assert_eq!(
        ckd.reveal_specific_secret(&cp, &test_protocol(), "12345")
            .unwrap(),
        kd.reveal_specific_secret(&cp, &test_protocol(), "12345")
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// 19. KeyDeriverApi trait: object safety and delegation fidelity
// ---------------------------------------------------------------------------

/// Exercises the full seven-member surface behind a trait object. Taking the
/// deriver as `Arc<dyn KeyDeriverApi + Send + Sync>` is the shape downstream
/// callers use, so this both proves object safety and pins the erased results
/// for comparison against the inherent methods.
fn derive_everything_through_trait_object(
    deriver: Arc<dyn KeyDeriverApi + Send + Sync>,
    cp: &Counterparty,
) -> (String, String, String, String, String, Vec<u8>) {
    let protocol = test_protocol();
    (
        deriver.root_key().to_hex(),
        deriver.identity_key_hex(),
        deriver
            .derive_public_key(&protocol, "12345", cp, false)
            .unwrap()
            .to_der_hex(),
        deriver
            .derive_private_key(&protocol, "12345", cp)
            .unwrap()
            .to_hex(),
        deriver
            .derive_symmetric_key(&protocol, "12345", cp)
            .unwrap()
            .to_hex(),
        deriver
            .reveal_specific_secret(cp, &protocol, "12345")
            .unwrap(),
    )
}

#[test]
fn key_deriver_api_is_object_safe_for_both_derivers() {
    let cp = counterparty_other(&counterparty_private_key().to_public_key());

    let via_key_deriver =
        derive_everything_through_trait_object(Arc::new(KeyDeriver::new(root_private_key())), &cp);
    let via_cached = derive_everything_through_trait_object(
        Arc::new(CachedKeyDeriver::new(root_private_key(), None)),
        &cp,
    );

    assert_eq!(
        via_key_deriver, via_cached,
        "both derivers must agree behind the trait object"
    );
}

#[test]
fn key_deriver_api_matches_inherent_methods() {
    let cp = counterparty_other(&counterparty_private_key().to_public_key());
    let protocol = test_protocol();

    // KeyDeriver: trait dispatch must equal the inherent method.
    let kd = KeyDeriver::new(root_private_key());
    let inherent = kd
        .derive_public_key(&protocol, "12345", &cp, false)
        .unwrap()
        .to_der_hex();
    let erased: Arc<dyn KeyDeriverApi + Send + Sync> =
        Arc::new(KeyDeriver::new(root_private_key()));
    assert_eq!(
        KeyDeriverApi::derive_public_key(&*erased, &protocol, "12345", &cp, false)
            .unwrap()
            .to_der_hex(),
        inherent
    );
    assert_eq!(erased.identity_key_hex(), kd.identity_key_hex());
    assert_eq!(erased.root_key().to_hex(), kd.root_key().to_hex());
    assert_eq!(
        erased.reveal_counterparty_secret(&cp).unwrap().to_der(),
        kd.reveal_counterparty_secret(&cp).unwrap().to_der()
    );

    // CachedKeyDeriver: same, through its own caching path.
    let ckd = CachedKeyDeriver::new(root_private_key(), None);
    let inherent_cached = ckd
        .derive_private_key(&protocol, "12345", &cp)
        .unwrap()
        .to_hex();
    let erased_cached: Arc<dyn KeyDeriverApi + Send + Sync> =
        Arc::new(CachedKeyDeriver::new(root_private_key(), None));
    assert_eq!(
        KeyDeriverApi::derive_private_key(&*erased_cached, &protocol, "12345", &cp)
            .unwrap()
            .to_hex(),
        inherent_cached
    );
    assert_eq!(erased_cached.identity_key_hex(), ckd.identity_key_hex());
    assert_eq!(erased_cached.root_key().to_hex(), ckd.root_key().to_hex());
    assert_eq!(
        erased_cached
            .reveal_specific_secret(&cp, &protocol, "12345")
            .unwrap(),
        ckd.reveal_specific_secret(&cp, &protocol, "12345").unwrap()
    );
}
