//! Integration tests for ProtoWallet, ported from ts-sdk ProtoWallet.test.ts.
//!
//! Covers: encrypt/decrypt round-trip, cross-wallet interop, signature
//! creation/verification, HMAC creation/verification, BRC-2/BRC-3 compliance
//! vectors, key linkage revelation, default counterparty behavior,
//! and constant-time HMAC comparison.

use bsv::primitives::hash::sha256_hmac;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_private_key(seed: &str) -> PrivateKey {
    // Use deterministic keys derived from a seed hex for reproducibility
    PrivateKey::from_hex(seed).unwrap()
}

fn make_wallet(seed: &str) -> (PrivateKey, ProtoWallet) {
    let pk = random_private_key(seed);
    let wallet = ProtoWallet::new(pk.clone());
    (pk, wallet)
}

fn protocol_2_tests() -> Protocol {
    Protocol {
        security_level: 2,
        protocol: "tests".to_string(),
    }
}

fn protocol_0_tests() -> Protocol {
    Protocol {
        security_level: 0,
        protocol: "tests".to_string(),
    }
}

fn counterparty_of(pub_hex: &str) -> Counterparty {
    let pk = bsv::primitives::public_key::PublicKey::from_string(pub_hex).unwrap();
    Counterparty {
        counterparty_type: CounterpartyType::Other,
        public_key: Some(pk),
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

fn uninit_counterparty() -> Counterparty {
    Counterparty {
        counterparty_type: CounterpartyType::Uninitialized,
        public_key: None,
    }
}

const SAMPLE_DATA: &[u8] = &[3, 1, 4, 1, 5, 9];

// ---------------------------------------------------------------------------
// 1. BRC-3 compliance vector
// ---------------------------------------------------------------------------

#[test]
fn validates_the_brc3_compliance_vector() {
    let wallet = ProtoWallet::anyone();
    let signature: Vec<u8> = vec![
        48, 68, 2, 32, 43, 34, 58, 156, 219, 32, 50, 70, 29, 240, 155, 137, 88, 60, 200, 95, 243,
        198, 201, 21, 56, 82, 141, 112, 69, 196, 170, 73, 156, 6, 44, 48, 2, 32, 118, 125, 254,
        201, 44, 87, 177, 170, 93, 11, 193, 134, 18, 70, 9, 31, 234, 27, 170, 177, 54, 96, 181,
        140, 166, 196, 144, 14, 230, 118, 106, 105,
    ];
    let data: Vec<u8> = "BRC-3 Compliance Validated!".bytes().collect();
    let protocol = Protocol {
        security_level: 2,
        protocol: "brc3 test".to_string(),
    };
    let counterparty =
        counterparty_of("0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1");

    let valid = wallet
        .verify_signature_sync(&data, &signature, &protocol, "42", &counterparty, false)
        .unwrap();
    assert!(valid, "BRC-3 compliance vector should verify");
}

// ---------------------------------------------------------------------------
// 2. BRC-2 HMAC compliance vector
// ---------------------------------------------------------------------------

#[test]
fn validates_the_brc2_hmac_compliance_vector() {
    let wallet = ProtoWallet::new(
        PrivateKey::from_hex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
            .unwrap(),
    );
    let data: Vec<u8> = "BRC-2 HMAC Compliance Validated!".bytes().collect();
    let hmac: Vec<u8> = vec![
        81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76, 254, 103, 46, 182,
        86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14,
    ];
    let protocol = Protocol {
        security_level: 2,
        protocol: "brc2 test".to_string(),
    };
    let counterparty =
        counterparty_of("0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1");

    let valid = wallet
        .verify_hmac_sync(&data, &hmac, &protocol, "42", &counterparty)
        .unwrap();
    assert!(valid, "BRC-2 HMAC compliance vector should verify");
}

// ---------------------------------------------------------------------------
// 3. BRC-2 Encryption compliance vector
// ---------------------------------------------------------------------------

#[test]
fn validates_the_brc2_encryption_compliance_vector() {
    let wallet = ProtoWallet::new(
        PrivateKey::from_hex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
            .unwrap(),
    );
    let ciphertext: Vec<u8> = vec![
        252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43, 61, 236, 184, 67,
        54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9, 188, 195, 196, 39, 120, 130, 213, 95,
        186, 89, 64, 28, 1, 80, 20, 213, 159, 133, 98, 253, 128, 105, 113, 247, 197, 152, 236, 64,
        166, 207, 113, 134, 65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84, 186, 72, 95, 35,
        154, 112, 178, 55, 72, 124,
    ];
    let protocol = Protocol {
        security_level: 2,
        protocol: "brc2 test".to_string(),
    };
    let counterparty =
        counterparty_of("0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1");

    let plaintext = wallet
        .decrypt_sync(&ciphertext, &protocol, "42", &counterparty)
        .unwrap();
    let plaintext_str = String::from_utf8(plaintext).unwrap();
    assert_eq!(
        plaintext_str, "BRC-2 Encryption Compliance Validated!",
        "BRC-2 encryption compliance vector should decrypt correctly"
    );
}

// ---------------------------------------------------------------------------
// 4. Encrypt messages decryptable by counterparty (cross-wallet)
// ---------------------------------------------------------------------------

#[test]
fn encrypts_messages_decryptable_by_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let ciphertext = user
        .encrypt_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    let plaintext = counterparty_wallet
        .decrypt_sync(&ciphertext, &protocol_2_tests(), "4", &cp_for_counterparty)
        .unwrap();

    assert_eq!(plaintext, SAMPLE_DATA);
    assert_ne!(ciphertext, SAMPLE_DATA);
}

// ---------------------------------------------------------------------------
// 5. Fails to decrypt with wrong protocol, key, counterparty
// ---------------------------------------------------------------------------

#[test]
fn fails_to_decrypt_with_wrong_protocol_key_or_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();
    let user_pub_hex = user_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let ciphertext = user
        .encrypt_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    // Wrong protocol security level
    let wrong_protocol = Protocol {
        security_level: 1,
        protocol: "tests".to_string(),
    };
    assert!(
        counterparty_wallet
            .decrypt_sync(&ciphertext, &wrong_protocol, "4", &cp_for_counterparty)
            .is_err(),
        "should fail with wrong protocol"
    );

    // Wrong key ID
    assert!(
        counterparty_wallet
            .decrypt_sync(&ciphertext, &protocol_2_tests(), "5", &cp_for_counterparty)
            .is_err(),
        "should fail with wrong key ID"
    );

    // Wrong counterparty
    let wrong_cp = counterparty_of(&cp_pub_hex); // counterparty's own key instead of user's
    assert!(
        counterparty_wallet
            .decrypt_sync(&ciphertext, &protocol_2_tests(), "4", &wrong_cp)
            .is_err(),
        "should fail with wrong counterparty"
    );
}

// ---------------------------------------------------------------------------
// 6. Correctly derives keys for a counterparty
// ---------------------------------------------------------------------------

#[test]
fn correctly_derives_keys_for_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    // Identity key
    let identity = user
        .get_public_key_sync(&protocol_2_tests(), "4", &self_counterparty(), false, true)
        .unwrap();
    assert_eq!(identity.to_der_hex(), user_pub_hex);

    // Derived for counterparty (user derives for counterparty)
    let cp_for_user = counterparty_of(&cp_pub_hex);
    let derived_for_cp = user
        .get_public_key_sync(&protocol_2_tests(), "4", &cp_for_user, false, false)
        .unwrap();

    // Derived by counterparty (counterparty derives for self against user)
    let cp_for_cp = counterparty_of(&user_pub_hex);
    let derived_by_cp = counterparty_wallet
        .get_public_key_sync(&protocol_2_tests(), "4", &cp_for_cp, true, false)
        .unwrap();

    assert_eq!(
        derived_for_cp.to_der_hex(),
        derived_by_cp.to_der_hex(),
        "user.derive_for_counterparty should equal counterparty.derive_for_self"
    );
}

// ---------------------------------------------------------------------------
// 7. Signs messages verifiable by the counterparty
// ---------------------------------------------------------------------------

#[test]
fn signs_messages_verifiable_by_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let signature = user
        .create_signature_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();
    assert!(!signature.is_empty());

    let valid = counterparty_wallet
        .verify_signature_sync(
            SAMPLE_DATA,
            &signature,
            &protocol_2_tests(),
            "4",
            &cp_for_counterparty,
            false,
        )
        .unwrap();
    assert!(valid, "counterparty should verify user's signature");
}

// ---------------------------------------------------------------------------
// 8. Fails to verify signature for wrong data, protocol, key, counterparty
// ---------------------------------------------------------------------------

#[test]
fn fails_to_verify_signature_for_wrong_data_protocol_key_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let signature = user
        .create_signature_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    // Wrong data
    let wrong_data = &[0, 3, 1, 4, 1, 5, 9];
    let result = counterparty_wallet.verify_signature_sync(
        wrong_data,
        &signature,
        &protocol_2_tests(),
        "4",
        &cp_for_counterparty,
        false,
    );
    // May return Ok(false) or Err depending on implementation
    assert!(
        result.is_err() || !result.unwrap(),
        "should fail to verify with wrong data"
    );

    // Wrong protocol
    let wrong_protocol = Protocol {
        security_level: 2,
        protocol: "wrong".to_string(),
    };
    let result = counterparty_wallet.verify_signature_sync(
        SAMPLE_DATA,
        &signature,
        &wrong_protocol,
        "4",
        &cp_for_counterparty,
        false,
    );
    assert!(
        result.is_err() || !result.unwrap(),
        "should fail to verify with wrong protocol"
    );

    // Wrong key ID
    let result = counterparty_wallet.verify_signature_sync(
        SAMPLE_DATA,
        &signature,
        &protocol_2_tests(),
        "2",
        &cp_for_counterparty,
        false,
    );
    assert!(
        result.is_err() || !result.unwrap(),
        "should fail to verify with wrong keyID"
    );

    // Wrong counterparty
    let wrong_cp = counterparty_of(&cp_pub_hex);
    let result = counterparty_wallet.verify_signature_sync(
        SAMPLE_DATA,
        &signature,
        &protocol_2_tests(),
        "4",
        &wrong_cp,
        false,
    );
    assert!(
        result.is_err() || !result.unwrap(),
        "should fail to verify with wrong counterparty"
    );
}

// ---------------------------------------------------------------------------
// 9. HMAC creation: returns 32-byte value, verifiable by counterparty
// ---------------------------------------------------------------------------

#[test]
fn computes_hmac_verifiable_by_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let hmac = user
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();
    assert_eq!(hmac.len(), 32, "HMAC should be 32 bytes");

    let valid = counterparty_wallet
        .verify_hmac_sync(
            SAMPLE_DATA,
            &hmac,
            &protocol_2_tests(),
            "4",
            &cp_for_counterparty,
        )
        .unwrap();
    assert!(valid, "counterparty should verify user's HMAC");
}

// ---------------------------------------------------------------------------
// 10. Fails to verify HMAC for wrong data, protocol, key, counterparty
// ---------------------------------------------------------------------------

#[test]
fn fails_to_verify_hmac_for_wrong_data_protocol_key_counterparty() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let hmac = user
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    // Wrong data
    let wrong_data = &[0, 3, 1, 4, 1, 5, 9];
    let valid = counterparty_wallet
        .verify_hmac_sync(
            wrong_data,
            &hmac,
            &protocol_2_tests(),
            "4",
            &cp_for_counterparty,
        )
        .unwrap();
    assert!(!valid, "HMAC should fail with wrong data");

    // Wrong protocol
    let wrong_protocol = Protocol {
        security_level: 2,
        protocol: "wrong".to_string(),
    };
    let result = counterparty_wallet.verify_hmac_sync(
        SAMPLE_DATA,
        &hmac,
        &wrong_protocol,
        "4",
        &cp_for_counterparty,
    );
    assert!(
        result.is_err() || !result.unwrap(),
        "HMAC should fail with wrong protocol"
    );

    // Wrong key ID
    let result = counterparty_wallet.verify_hmac_sync(
        SAMPLE_DATA,
        &hmac,
        &protocol_2_tests(),
        "2",
        &cp_for_counterparty,
    );
    assert!(
        result.is_err() || !result.unwrap(),
        "HMAC should fail with wrong key ID"
    );

    // Wrong counterparty
    let wrong_cp = counterparty_of(&cp_pub_hex);
    let result =
        counterparty_wallet.verify_hmac_sync(SAMPLE_DATA, &hmac, &protocol_2_tests(), "4", &wrong_cp);
    assert!(
        result.is_err() || !result.unwrap(),
        "HMAC should fail with wrong counterparty"
    );
}

// ---------------------------------------------------------------------------
// 11. Default counterparty: anyone for signatures, self for other ops
// ---------------------------------------------------------------------------

#[test]
fn uses_anyone_for_signatures_and_self_for_other_ops_when_no_counterparty() {
    let (user_key, user) = make_wallet("cc");

    // HMAC with no counterparty (defaults to self)
    let hmac = user
        .create_hmac_sync(
            SAMPLE_DATA,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
        )
        .unwrap();
    let valid = user
        .verify_hmac_sync(
            SAMPLE_DATA,
            &hmac,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
        )
        .unwrap();
    assert!(valid, "HMAC with uninitialized counterparty should verify");

    // Explicit self should also verify
    let valid_explicit = user
        .verify_hmac_sync(
            SAMPLE_DATA,
            &hmac,
            &protocol_2_tests(),
            "4",
            &self_counterparty(),
        )
        .unwrap();
    assert!(valid_explicit, "HMAC with explicit self should also verify");
    assert_eq!(hmac.len(), 32);

    // Signature with no counterparty (defaults to anyone)
    let anyone_sig = user
        .create_signature_sync(
            SAMPLE_DATA,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
        )
        .unwrap();

    // Anyone wallet should verify it
    let anyone_wallet = ProtoWallet::anyone();
    let user_pub_hex = user_key.to_public_key().to_der_hex();
    let cp_user = counterparty_of(&user_pub_hex);
    let valid_anyone = anyone_wallet
        .verify_signature_sync(
            SAMPLE_DATA,
            &anyone_sig,
            &protocol_2_tests(),
            "4",
            &cp_user,
            false,
        )
        .unwrap();
    assert!(
        valid_anyone,
        "anyone should verify signature created with default counterparty"
    );

    // Self signature
    let self_sig = user
        .create_signature_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    let valid_self = user
        .verify_signature_sync(
            SAMPLE_DATA,
            &self_sig,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
            true,
        )
        .unwrap();
    assert!(
        valid_self,
        "self signature should verify with uninitialized counterparty"
    );

    let valid_explicit_self = user
        .verify_signature_sync(
            SAMPLE_DATA,
            &self_sig,
            &protocol_2_tests(),
            "4",
            &self_counterparty(),
            true,
        )
        .unwrap();
    assert!(
        valid_explicit_self,
        "self signature should verify with explicit self"
    );

    // Get public key with no counterparty vs explicit self
    let pub_uninit = user
        .get_public_key_sync(
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
            false,
            false,
        )
        .unwrap();
    let pub_self = user
        .get_public_key_sync(&protocol_2_tests(), "4", &self_counterparty(), false, false)
        .unwrap();
    assert_eq!(
        pub_uninit.to_der_hex(),
        pub_self.to_der_hex(),
        "public key with uninit counterparty should equal explicit self"
    );

    // Encrypt/decrypt with no counterparty (defaults to self)
    let ciphertext = user
        .encrypt_sync(
            SAMPLE_DATA,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
        )
        .unwrap();
    let plaintext = user
        .decrypt_sync(
            &ciphertext,
            &protocol_2_tests(),
            "4",
            &uninit_counterparty(),
        )
        .unwrap();
    let plaintext_explicit_self = user
        .decrypt_sync(&ciphertext, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    assert_eq!(plaintext, plaintext_explicit_self);
    assert_eq!(plaintext, SAMPLE_DATA);
}

// ---------------------------------------------------------------------------
// 12. Counterparty key linkage revelation
// ---------------------------------------------------------------------------

#[test]
fn validates_counterparty_key_linkage_revelation() {
    let (prover_key, prover_wallet) = make_wallet("dd");
    let counterparty_key = random_private_key("ee");
    let (verifier_key, verifier_wallet) = make_wallet("ff");

    let counterparty_pub = counterparty_key.to_public_key();
    let verifier_pub = verifier_key.to_public_key();
    let prover_pub = prover_key.to_public_key();

    let cp = Counterparty {
        counterparty_type: CounterpartyType::Other,
        public_key: Some(counterparty_pub.clone()),
    };

    let revelation = prover_wallet
        .reveal_counterparty_key_linkage_sync(&cp, &verifier_pub)
        .unwrap();

    // Verifier decrypts the linkage
    let prover_cp = counterparty_of(&prover_pub.to_der_hex());
    let linkage_protocol = Protocol {
        security_level: 2,
        protocol: "counterparty linkage revelation".to_string(),
    };
    let linkage = verifier_wallet
        .decrypt_sync(
            &revelation.encrypted_linkage,
            &linkage_protocol,
            &revelation.revelation_time,
            &prover_cp,
        )
        .unwrap();

    // Expected: proverKey.deriveSharedSecret(counterpartyPub).encode(true)
    let expected = prover_key
        .derive_shared_secret(&counterparty_pub)
        .unwrap()
        .to_der(true);

    assert_eq!(
        linkage, expected,
        "decrypted linkage should match expected shared secret"
    );
}

// ---------------------------------------------------------------------------
// 13. Specific key linkage revelation
// ---------------------------------------------------------------------------

#[test]
fn validates_specific_key_linkage_revelation() {
    let (prover_key, prover_wallet) = make_wallet("dd");
    let counterparty_key = random_private_key("ee");
    let (verifier_key, verifier_wallet) = make_wallet("ff");

    let counterparty_pub = counterparty_key.to_public_key();
    let verifier_pub = verifier_key.to_public_key();
    let prover_pub = prover_key.to_public_key();

    let cp = Counterparty {
        counterparty_type: CounterpartyType::Other,
        public_key: Some(counterparty_pub.clone()),
    };

    let protocol = protocol_0_tests();
    let key_id = "test key id";

    let revelation = prover_wallet
        .reveal_specific_key_linkage_sync(&cp, &verifier_pub, &protocol, key_id)
        .unwrap();

    // Verifier decrypts the linkage
    let prover_cp = counterparty_of(&prover_pub.to_der_hex());
    let encrypt_protocol = Protocol {
        security_level: 2,
        protocol: format!(
            "specific linkage revelation {} {}",
            protocol.security_level, protocol.protocol
        ),
    };
    let linkage = verifier_wallet
        .decrypt_sync(
            &revelation.encrypted_linkage,
            &encrypt_protocol,
            key_id,
            &prover_cp,
        )
        .unwrap();

    // Compute expected: HMAC-SHA256(sharedSecret, invoiceNumberBin)
    let shared_secret = prover_key
        .derive_shared_secret(&counterparty_pub)
        .unwrap()
        .to_der(true);
    let invoice_number = format!(
        "{}-{}-{}",
        protocol.security_level, protocol.protocol, key_id
    );
    let expected = sha256_hmac(&shared_secret, invoice_number.as_bytes());

    assert_eq!(
        linkage,
        expected.to_vec(),
        "decrypted specific linkage should match expected HMAC"
    );
}

// ---------------------------------------------------------------------------
// 14. Constant-time HMAC: wrong-but-same-length HMAC fails
// ---------------------------------------------------------------------------

#[test]
fn fails_constant_time_hmac_validation_for_wrong_same_length_hmac() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();
    let user_pub_hex = user_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let correct_hmac = user
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    // Create a wrong HMAC with same length
    let mut wrong = correct_hmac.clone();
    wrong[0] = (wrong[0].wrapping_add(1)) & 0xff;

    let valid = counterparty_wallet
        .verify_hmac_sync(
            SAMPLE_DATA,
            &wrong,
            &protocol_2_tests(),
            "4",
            &cp_for_counterparty,
        )
        .unwrap();
    assert!(
        !valid,
        "wrong HMAC with same length should fail verification"
    );
}

// ---------------------------------------------------------------------------
// 15. Correct HMAC via constant-time comparison path
// ---------------------------------------------------------------------------

#[test]
fn validates_correct_hmac_using_constant_time_comparison() {
    let (user_key, user) = make_wallet("aa");
    let (counterparty_key, counterparty_wallet) = make_wallet("bb");

    let cp_pub_hex = counterparty_key.to_public_key().to_der_hex();
    let user_pub_hex = user_key.to_public_key().to_der_hex();

    let cp_for_user = counterparty_of(&cp_pub_hex);
    let cp_for_counterparty = counterparty_of(&user_pub_hex);

    let hmac = user
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &cp_for_user)
        .unwrap();

    let valid = counterparty_wallet
        .verify_hmac_sync(
            SAMPLE_DATA,
            &hmac,
            &protocol_2_tests(),
            "4",
            &cp_for_counterparty,
        )
        .unwrap();
    assert!(valid, "correct HMAC should pass constant-time verification");
}

// ---------------------------------------------------------------------------
// 16. Signature creation returns non-empty bytes
// ---------------------------------------------------------------------------

#[test]
fn signature_creation_returns_non_empty_bytes() {
    let (_key, wallet) = make_wallet("aa");
    let sig = wallet
        .create_signature_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    assert!(!sig.is_empty(), "signature should be non-empty");
}

// ---------------------------------------------------------------------------
// 17. Signature verification succeeds with correct params
// ---------------------------------------------------------------------------

#[test]
fn signature_verification_succeeds_with_correct_params() {
    let (_key, wallet) = make_wallet("aa");
    let sig = wallet
        .create_signature_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    let valid = wallet
        .verify_signature_sync(
            SAMPLE_DATA,
            &sig,
            &protocol_2_tests(),
            "4",
            &self_counterparty(),
            true,
        )
        .unwrap();
    assert!(valid);
}

// ---------------------------------------------------------------------------
// 18. Signature verification fails with wrong data
// ---------------------------------------------------------------------------

#[test]
fn signature_verification_fails_with_wrong_data() {
    let (_key, wallet) = make_wallet("aa");
    let sig = wallet
        .create_signature_sync(
            b"correct data",
            &protocol_2_tests(),
            "4",
            &self_counterparty(),
        )
        .unwrap();
    let valid = wallet
        .verify_signature_sync(
            b"wrong data",
            &sig,
            &protocol_2_tests(),
            "4",
            &self_counterparty(),
            true,
        )
        .unwrap();
    assert!(!valid, "signature should not verify for wrong data");
}

// ---------------------------------------------------------------------------
// 19. HMAC is deterministic
// ---------------------------------------------------------------------------

#[test]
fn hmac_is_deterministic() {
    let (_key, wallet) = make_wallet("aa");
    let hmac1 = wallet
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    let hmac2 = wallet
        .create_hmac_sync(SAMPLE_DATA, &protocol_2_tests(), "4", &self_counterparty())
        .unwrap();
    assert_eq!(hmac1, hmac2, "HMAC should be deterministic");
}
