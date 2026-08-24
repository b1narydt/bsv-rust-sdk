//! Test vector validation for wallet wire protocol serializers.
//!
//! Reads 62 JSON test vectors from testdata/wallet/ and validates that
//! Rust serializers produce byte-identical output to the Go SDK.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::*;
use bsv::wallet::serializer::frame::*;
use bsv::wallet::serializer::*;
use bsv::wallet::types::*;
use indexmap::IndexMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("wallet")
}

fn read_vector(filename: &str) -> (serde_json::Value, Vec<u8>) {
    let path = testdata_dir().join(format!("{filename}.json"));
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let wire_hex = parsed["wire"].as_str().unwrap();
    let wire = hex_decode(wire_hex).unwrap();
    (parsed, wire)
}

/// Strip request frame from wire bytes, return (call_byte, params).
fn strip_request_frame(wire: &[u8]) -> (u8, Vec<u8>) {
    let frame = read_request_frame(wire).expect("Failed to read request frame");
    (frame.call, frame.params)
}

/// Strip result frame from wire bytes, return params.
fn strip_result_frame(wire: &[u8]) -> Vec<u8> {
    read_result_frame(wire).expect("Failed to read result frame")
}

/// Wrap params in request frame (call byte, empty originator).
fn wrap_request_frame(call: u8, params: &[u8]) -> Vec<u8> {
    write_request_frame(&RequestFrame {
        call,
        originator: String::new(),
        params: params.to_vec(),
    })
}

/// Wrap params in result frame (success).
fn wrap_result_frame(params: &[u8]) -> Vec<u8> {
    write_result_frame(Some(params), None)
}

fn pk_from_hex(hex: &str) -> PublicKey {
    let bytes = hex_decode(hex).unwrap();
    PublicKey::from_der_bytes(&bytes).unwrap()
}

fn type_from_base64(b64: &str) -> CertificateType {
    let bytes = base64_std_decode(b64);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CertificateType(arr)
}

fn serial_from_base64(b64: &str) -> SerialNumber {
    let bytes = base64_std_decode(b64);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    SerialNumber(arr)
}

fn base64_std_decode(s: &str) -> Vec<u8> {
    // Standard base64 with padding - manual decode
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let chars: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && c != b'\n' && c != b'\r')
        .collect();
    let mut result = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let val = |c: u8| -> u32 { CHARS.iter().position(|&x| x == c).unwrap_or(0) as u32 };
        let a = val(chars[i]);
        let b = if i + 1 < chars.len() {
            val(chars[i + 1])
        } else {
            0
        };
        let c = if i + 2 < chars.len() {
            val(chars[i + 2])
        } else {
            0
        };
        let d = if i + 3 < chars.len() {
            val(chars[i + 3])
        } else {
            0
        };
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((n >> 16) as u8);
        if i + 2 < chars.len() {
            result.push((n >> 8) as u8);
        }
        if i + 3 < chars.len() {
            result.push(n as u8);
        }
        i += 4;
    }
    result
}

fn sig_from_hex(hex: &str) -> Vec<u8> {
    hex_decode(hex).unwrap()
}

// ---------------------------------------------------------------------------
// Macro for roundtrip testing
// ---------------------------------------------------------------------------

macro_rules! test_args_vector {
    ($name:ident, $filename:expr, $call_byte:expr, $serialize_fn:expr, $deserialize_fn:expr, $build_obj:expr) => {
        #[test]
        fn $name() {
            let (_, wire) = read_vector($filename);
            let (call, params) = strip_request_frame(&wire);
            assert_eq!(call, $call_byte, "Call byte mismatch");

            // Serialize our object
            let obj = $build_obj;
            let serialized = $serialize_fn(&obj).expect("Serialize failed");

            // Compare: our serialized + frame == wire
            let framed = wrap_request_frame($call_byte, &serialized);
            assert_eq!(framed, wire, "Serialized wire mismatch for {}", $filename);

            // Deserialize from params
            let _deserialized = $deserialize_fn(&params).expect("Deserialize failed");
        }
    };
}

macro_rules! test_result_vector {
    ($name:ident, $filename:expr, $serialize_fn:expr, $deserialize_fn:expr, $build_obj:expr) => {
        #[test]
        fn $name() {
            let (_, wire) = read_vector($filename);
            let params = strip_result_frame(&wire);

            // Serialize our object
            let obj = $build_obj;
            let serialized = $serialize_fn(&obj).expect("Serialize failed");

            // Compare: our serialized + result frame == wire
            let framed = wrap_result_frame(&serialized);
            assert_eq!(framed, wire, "Serialized wire mismatch for {}", $filename);

            // Deserialize from params
            let _deserialized = $deserialize_fn(&params).expect("Deserialize failed");
        }
    };
}

// ---------------------------------------------------------------------------
// Common test data
// ---------------------------------------------------------------------------

const COUNTERPARTY_HEX: &str = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1";
const VERIFIER_HEX: &str = "03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee";
const PROVER_HEX: &str = "02e14bb4fbcd33d02a0bad2b60dcd14c36506fa15599e3c28ec87eff440a97a2b8";
const PUB_KEY_HEX: &str = "025ad43a22ac38d0bc1f8bacaabb323b5d634703b7a774c4268f6a09e4ddf79097";
const TYPE_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0ZXN0LXR5cGU=";
const SERIAL_B64: &str = "AAAAAAAAAAAAAAAAAAB0ZXN0LXNlcmlhbC1udW1iZXI=";
const SIG_HEX: &str = "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a";
const OUTPOINT_STR: &str = "aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d.0";
const TXID_HEX: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const LOCKING_SCRIPT_HEX: &str = "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac";
const LOCK_SCRIPT_HEX: &str = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
const RESULT_TX_HEX: &str = "01000000017cd347a6a099f82cde68faec941e888ebc3489b25403e3ffedd3280f3fa4cc03000000006b483045022100f269c3f340a9cfae580b057429f91e1fcb2d0afccb5a3b9d194d705b4decfbda0220725a74244d4618654335f3e14b9fceb50ada1f679bb8a00c087571643eb974714121034d2d6d23fbcb6eefe3e80c47044e36797dcb80d0ac5e96e732ef03c3c550a116ffffffff01e7030000000000001976a9143cf53c49c322d9d811728182939aee2dca087f9888ac00000000";
const RESULT_TXID: &str = "03895fb984362a4196bc9931629318fcbb2aeba7c6293638119ea653fa31d119";

// ---------------------------------------------------------------------------
// AbortAction
// ---------------------------------------------------------------------------

test_args_vector!(
    test_abort_action_simple_args,
    "abortAction-simple-args",
    CALL_ABORT_ACTION,
    abort_action::serialize_abort_action_args,
    abort_action::deserialize_abort_action_args,
    AbortActionArgs {
        reference: base64_std_decode("dGVzdA=="),
    }
);

test_result_vector!(
    test_abort_action_simple_result,
    "abortAction-simple-result",
    abort_action::serialize_abort_action_result,
    abort_action::deserialize_abort_action_result,
    AbortActionResult { aborted: true }
);

// ---------------------------------------------------------------------------
// SignAction
// ---------------------------------------------------------------------------

test_args_vector!(
    test_sign_action_simple_args,
    "signAction-simple-args",
    CALL_SIGN_ACTION,
    sign_action::serialize_sign_action_args,
    sign_action::deserialize_sign_action_args,
    {
        let mut spends = HashMap::new();
        spends.insert(
            0u32,
            SignActionSpend {
                unlocking_script: hex_decode(LOCK_SCRIPT_HEX).unwrap(),
                sequence_number: None,
            },
        );
        SignActionArgs {
            reference: base64_std_decode("dGVzdA=="),
            spends,
            options: None,
        }
    }
);

// ---------------------------------------------------------------------------
// CreateAction
// ---------------------------------------------------------------------------

test_args_vector!(
    test_create_action_1_out_args,
    "createAction-1-out-args",
    CALL_CREATE_ACTION,
    create_action::serialize_create_action_args,
    create_action::deserialize_create_action_args,
    CreateActionArgs {
        description: "Test action description".to_string(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: Some(hex_decode(LOCKING_SCRIPT_HEX).unwrap()),
            satoshis: 999,
            output_description: "Test output".to_string(),
            basket: Some("test-basket".to_string()),
            custom_instructions: Some("Test instructions".to_string()),
            tags: Some(vec!["test-tag".to_string()]),
        }]),
        lock_time: None,
        version: None,
        labels: Some(vec!["test-label".to_string()]),
        options: None,
        reference: None,
    }
);

// ---------------------------------------------------------------------------
// ListActions
// ---------------------------------------------------------------------------

test_args_vector!(
    test_list_actions_simple_args,
    "listActions-simple-args",
    CALL_LIST_ACTIONS,
    list_actions::serialize_list_actions_args,
    list_actions::deserialize_list_actions_args,
    ListActionsArgs {
        labels: vec!["test-label".to_string()],
        label_query_mode: None,
        include_labels: BooleanDefaultFalse(None),
        include_inputs: BooleanDefaultFalse(None),
        include_input_source_locking_scripts: BooleanDefaultFalse(None),
        include_input_unlocking_scripts: BooleanDefaultFalse(None),
        include_outputs: BooleanDefaultFalse(Some(true)),
        include_output_locking_scripts: BooleanDefaultFalse(None),
        limit: Some(10),
        offset: None,
        seek_permission: BooleanDefaultTrue(None),
    }
);

test_result_vector!(
    test_list_actions_simple_result,
    "listActions-simple-result",
    list_actions::serialize_list_actions_result,
    list_actions::deserialize_list_actions_result,
    ListActionsResult {
        total_actions: 1,
        actions: vec![Action {
            txid: TXID_HEX.to_string(),
            satoshis: 1000,
            status: ActionStatus::Completed,
            is_outgoing: true,
            description: "Test transaction 1".to_string(),
            labels: None,
            version: 1,
            lock_time: 10,
            inputs: None,
            outputs: Some(vec![ActionOutput {
                output_index: 1,
                output_description: "Test output".to_string(),
                basket: Some("basket1".to_string()),
                spendable: true,
                tags: vec!["tag1".to_string(), "tag2".to_string()],
                satoshis: 1000,
                locking_script: Some(hex_decode(LOCKING_SCRIPT_HEX).unwrap()),
                custom_instructions: None,
            }]),
        }],
    }
);

// ---------------------------------------------------------------------------
// InternalizeAction
// ---------------------------------------------------------------------------

test_args_vector!(
    test_internalize_action_simple_args,
    "internalizeAction-simple-args",
    CALL_INTERNALIZE_ACTION,
    internalize_action::serialize_internalize_action_args,
    internalize_action::deserialize_internalize_action_args,
    InternalizeActionArgs {
        tx: vec![1, 2, 3, 4],
        outputs: vec![
            InternalizeOutput::WalletPayment {
                output_index: 0,
                payment: Payment {
                    derivation_prefix: b"prefix".to_vec(),
                    derivation_suffix: b"suffix".to_vec(),
                    sender_identity_key: pk_from_hex(VERIFIER_HEX),
                },
            },
            InternalizeOutput::BasketInsertion {
                output_index: 1,
                insertion: BasketInsertion {
                    basket: "test-basket".to_string(),
                    custom_instructions: Some("instruction".to_string()),
                    tags: vec!["tag1".to_string(), "tag2".to_string()],
                },
            },
        ],
        description: "test transaction".to_string(),
        labels: Some(vec!["label1".to_string(), "label2".to_string()]),
        seek_permission: BooleanDefaultTrue(Some(true)),
    }
);

test_result_vector!(
    test_internalize_action_simple_result,
    "internalizeAction-simple-result",
    internalize_action::serialize_internalize_action_result,
    internalize_action::deserialize_internalize_action_result,
    InternalizeActionResult { accepted: true }
);

// ---------------------------------------------------------------------------
// ListOutputs
// ---------------------------------------------------------------------------

test_args_vector!(
    test_list_outputs_simple_args,
    "listOutputs-simple-args",
    CALL_LIST_OUTPUTS,
    list_outputs::serialize_list_outputs_args,
    list_outputs::deserialize_list_outputs_args,
    ListOutputsArgs {
        basket: "test-basket".to_string(),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        tag_query_mode: Some(QueryMode::Any),
        include: Some(OutputInclude::LockingScripts),
        include_custom_instructions: BooleanDefaultFalse(None),
        include_tags: BooleanDefaultFalse(Some(true)),
        include_labels: BooleanDefaultFalse(None),
        limit: Some(10),
        offset: None,
        seek_permission: BooleanDefaultTrue(None),
    }
);

test_result_vector!(
    test_list_outputs_simple_result,
    "listOutputs-simple-result",
    list_outputs::serialize_list_outputs_result,
    list_outputs::deserialize_list_outputs_result,
    ListOutputsResult {
        total_outputs: 2,
        beef: Some(vec![1, 2, 3, 4]),
        outputs: vec![
            Output {
                satoshis: 1000,
                locking_script: None,
                spendable: true,
                custom_instructions: None,
                tags: None,
                outpoint: format!("{TXID_HEX}.0"),
                labels: None,
            },
            Output {
                satoshis: 5000,
                locking_script: None,
                spendable: true,
                custom_instructions: None,
                tags: None,
                outpoint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2"
                    .to_string(),
                labels: None,
            },
        ],
    }
);

// ---------------------------------------------------------------------------
// RelinquishOutput
// ---------------------------------------------------------------------------

test_args_vector!(
    test_relinquish_output_simple_args,
    "relinquishOutput-simple-args",
    CALL_RELINQUISH_OUTPUT,
    relinquish_output::serialize_relinquish_output_args,
    relinquish_output::deserialize_relinquish_output_args,
    RelinquishOutputArgs {
        basket: "test-basket".to_string(),
        output: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2".to_string(),
    }
);

test_result_vector!(
    test_relinquish_output_simple_result,
    "relinquishOutput-simple-result",
    relinquish_output::serialize_relinquish_output_result,
    relinquish_output::deserialize_relinquish_output_result,
    RelinquishOutputResult { relinquished: true }
);

// ---------------------------------------------------------------------------
// GetPublicKey
// ---------------------------------------------------------------------------

test_args_vector!(
    test_get_public_key_simple_args,
    "getPublicKey-simple-args",
    CALL_GET_PUBLIC_KEY,
    get_public_key::serialize_get_public_key_args,
    get_public_key::deserialize_get_public_key_args,
    GetPublicKeyArgs {
        identity_key: false,
        protocol_id: Some(Protocol {
            security_level: 2,
            protocol: "tests".to_string(),
        }),
        key_id: Some("test-key-id".to_string()),
        counterparty: Some(Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pk_from_hex(COUNTERPARTY_HEX)),
        }),
        privileged: true,
        privileged_reason: Some("privileged reason".to_string()),
        for_self: None,
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_get_public_key_simple_result,
    "getPublicKey-simple-result",
    get_public_key::serialize_get_public_key_result,
    get_public_key::deserialize_get_public_key_result,
    GetPublicKeyResult {
        public_key: pk_from_hex(PUB_KEY_HEX),
    }
);

// ---------------------------------------------------------------------------
// RevealCounterpartyKeyLinkage
// ---------------------------------------------------------------------------

test_args_vector!(
    test_reveal_counterparty_key_linkage_simple_args,
    "revealCounterpartyKeyLinkage-simple-args",
    CALL_REVEAL_COUNTERPARTY_KEY_LINKAGE,
    reveal_counterparty_key_linkage::serialize_reveal_counterparty_key_linkage_args,
    reveal_counterparty_key_linkage::deserialize_reveal_counterparty_key_linkage_args,
    RevealCounterpartyKeyLinkageArgs {
        counterparty: pk_from_hex(COUNTERPARTY_HEX),
        verifier: pk_from_hex(VERIFIER_HEX),
        privileged: Some(true),
        privileged_reason: Some("test-reason".to_string()),
    }
);

test_result_vector!(
    test_reveal_counterparty_key_linkage_simple_result,
    "revealCounterpartyKeyLinkage-simple-result",
    reveal_counterparty_key_linkage::serialize_reveal_counterparty_key_linkage_result,
    reveal_counterparty_key_linkage::deserialize_reveal_counterparty_key_linkage_result,
    RevealCounterpartyKeyLinkageResult {
        prover: pk_from_hex(PROVER_HEX),
        counterparty: pk_from_hex(COUNTERPARTY_HEX),
        verifier: pk_from_hex(VERIFIER_HEX),
        revelation_time: "2023-01-01T00:00:00Z".to_string(),
        encrypted_linkage: vec![1, 2, 3, 4],
        encrypted_linkage_proof: vec![5, 6, 7, 8],
    }
);

// ---------------------------------------------------------------------------
// RevealSpecificKeyLinkage
// ---------------------------------------------------------------------------

test_args_vector!(
    test_reveal_specific_key_linkage_simple_args,
    "revealSpecificKeyLinkage-simple-args",
    CALL_REVEAL_SPECIFIC_KEY_LINKAGE,
    reveal_specific_key_linkage::serialize_reveal_specific_key_linkage_args,
    reveal_specific_key_linkage::deserialize_reveal_specific_key_linkage_args,
    RevealSpecificKeyLinkageArgs {
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pk_from_hex(COUNTERPARTY_HEX)),
        },
        verifier: pk_from_hex(VERIFIER_HEX),
        protocol_id: Protocol {
            security_level: 2,
            protocol: "tests".to_string(),
        },
        key_id: "test-key-id".to_string(),
        privileged: Some(true),
        privileged_reason: Some("test-reason".to_string()),
    }
);

test_result_vector!(
    test_reveal_specific_key_linkage_simple_result,
    "revealSpecificKeyLinkage-simple-result",
    reveal_specific_key_linkage::serialize_reveal_specific_key_linkage_result,
    reveal_specific_key_linkage::deserialize_reveal_specific_key_linkage_result,
    RevealSpecificKeyLinkageResult {
        encrypted_linkage: vec![1, 2, 3, 4],
        encrypted_linkage_proof: vec![5, 6, 7, 8],
        prover: pk_from_hex(PROVER_HEX),
        verifier: pk_from_hex(VERIFIER_HEX),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pk_from_hex(COUNTERPARTY_HEX)),
        },
        protocol_id: Protocol {
            security_level: 2,
            protocol: "tests".to_string(),
        },
        key_id: "test-key-id".to_string(),
        proof_type: 1,
    }
);

#[test]
fn reveal_specific_key_linkage_sentinel_results_round_trip() {
    for counterparty_type in [CounterpartyType::Self_, CounterpartyType::Anyone] {
        let result = RevealSpecificKeyLinkageResult {
            encrypted_linkage: vec![1],
            encrypted_linkage_proof: vec![2],
            prover: pk_from_hex(PROVER_HEX),
            verifier: pk_from_hex(VERIFIER_HEX),
            counterparty: Counterparty {
                counterparty_type: counterparty_type.clone(),
                public_key: None,
            },
            protocol_id: Protocol {
                security_level: 2,
                protocol: "tests".to_string(),
            },
            key_id: "test-key-id".to_string(),
            proof_type: 0,
        };

        let encoded =
            reveal_specific_key_linkage::serialize_reveal_specific_key_linkage_result(&result)
                .unwrap();
        let decoded =
            reveal_specific_key_linkage::deserialize_reveal_specific_key_linkage_result(&encoded)
                .unwrap();
        assert_eq!(decoded.counterparty.counterparty_type, counterparty_type);
        assert!(decoded.counterparty.public_key.is_none());
    }
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

test_args_vector!(
    test_encrypt_simple_args,
    "encrypt-simple-args",
    CALL_ENCRYPT,
    encrypt::serialize_encrypt_args,
    encrypt::deserialize_encrypt_args,
    EncryptArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        plaintext: vec![1, 2, 3, 4],
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_encrypt_simple_result,
    "encrypt-simple-result",
    encrypt::serialize_encrypt_result,
    encrypt::deserialize_encrypt_result,
    EncryptResult {
        ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8]
    }
);

test_args_vector!(
    test_decrypt_simple_args,
    "decrypt-simple-args",
    CALL_DECRYPT,
    decrypt::serialize_decrypt_args,
    decrypt::deserialize_decrypt_args,
    DecryptArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8],
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_decrypt_simple_result,
    "decrypt-simple-result",
    decrypt::serialize_decrypt_result,
    decrypt::deserialize_decrypt_result,
    DecryptResult {
        plaintext: vec![1, 2, 3, 4]
    }
);

// ---------------------------------------------------------------------------
// CreateHmac / VerifyHmac
// ---------------------------------------------------------------------------

test_args_vector!(
    test_create_hmac_simple_args,
    "createHmac-simple-args",
    CALL_CREATE_HMAC,
    create_hmac::serialize_create_hmac_args,
    create_hmac::deserialize_create_hmac_args,
    CreateHmacArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        data: vec![10, 20, 30, 40],
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_create_hmac_simple_result,
    "createHmac-simple-result",
    create_hmac::serialize_create_hmac_result,
    create_hmac::deserialize_create_hmac_result,
    CreateHmacResult {
        hmac: vec![
            50, 60, 70, 80, 90, 100, 110, 120, 50, 60, 70, 80, 90, 100, 110, 120, 50, 60, 70, 80,
            90, 100, 110, 120, 50, 60, 70, 80, 90, 100, 110, 120
        ],
    }
);

test_args_vector!(
    test_verify_hmac_simple_args,
    "verifyHmac-simple-args",
    CALL_VERIFY_HMAC,
    verify_hmac::serialize_verify_hmac_args,
    verify_hmac::deserialize_verify_hmac_args,
    VerifyHmacArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        data: vec![10, 20, 30, 40],
        hmac: vec![
            50, 60, 70, 80, 90, 100, 110, 120, 50, 60, 70, 80, 90, 100, 110, 120, 50, 60, 70, 80,
            90, 100, 110, 120, 50, 60, 70, 80, 90, 100, 110, 120
        ],
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_verify_hmac_simple_result,
    "verifyHmac-simple-result",
    verify_hmac::serialize_verify_hmac_result,
    verify_hmac::deserialize_verify_hmac_result,
    VerifyHmacResult { valid: true }
);

// ---------------------------------------------------------------------------
// CreateSignature / VerifySignature
// ---------------------------------------------------------------------------

test_args_vector!(
    test_create_signature_simple_args,
    "createSignature-simple-args",
    CALL_CREATE_SIGNATURE,
    create_signature::serialize_create_signature_args,
    create_signature::deserialize_create_signature_args,
    CreateSignatureArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        data: Some(vec![11, 22, 33, 44]),
        hash_to_directly_sign: None,
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_create_signature_simple_result,
    "createSignature-simple-result",
    create_signature::serialize_create_signature_result,
    create_signature::deserialize_create_signature_result,
    CreateSignatureResult {
        signature: sig_from_hex(
            "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101"
        ),
    }
);

test_args_vector!(
    test_verify_signature_simple_args,
    "verifySignature-simple-args",
    CALL_VERIFY_SIGNATURE,
    verify_signature::serialize_verify_signature_args,
    verify_signature::deserialize_verify_signature_args,
    VerifySignatureArgs {
        protocol_id: Protocol {
            security_level: 1,
            protocol: "test-protocol".to_string()
        },
        key_id: "test-key".to_string(),
        counterparty: Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None
        },
        data: Some(vec![11, 22, 33, 44]),
        hash_to_directly_verify: None,
        signature: sig_from_hex(
            "302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41020101"
        ),
        for_self: None,
        privileged: true,
        privileged_reason: Some("test reason".to_string()),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_verify_signature_simple_result,
    "verifySignature-simple-result",
    verify_signature::serialize_verify_signature_result,
    verify_signature::deserialize_verify_signature_result,
    VerifySignatureResult { valid: true }
);

// ---------------------------------------------------------------------------
// AcquireCertificate
// ---------------------------------------------------------------------------

test_args_vector!(
    test_acquire_certificate_simple_args,
    "acquireCertificate-simple-args",
    CALL_ACQUIRE_CERTIFICATE,
    acquire_certificate::serialize_acquire_certificate_args,
    acquire_certificate::deserialize_acquire_certificate_args,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        let mut keyring = HashMap::new();
        keyring.insert("field1".to_string(), "key1".to_string());
        keyring.insert("field2".to_string(), "key2".to_string());
        AcquireCertificateArgs {
            cert_type: type_from_base64(TYPE_B64),
            certifier: pk_from_hex(COUNTERPARTY_HEX),
            acquisition_protocol: AcquisitionProtocol::Direct,
            fields,
            serial_number: Some(serial_from_base64(SERIAL_B64)),
            revocation_outpoint: Some(OUTPOINT_STR.to_string()),
            signature: Some(sig_from_hex(SIG_HEX)),
            certifier_url: None,
            keyring_revealer: Some(KeyringRevealer::PubKey(pk_from_hex(PUB_KEY_HEX))),
            keyring_for_subject: Some(keyring),
            privileged: false,
            privileged_reason: None,
        }
    }
);

test_args_vector!(
    test_acquire_certificate_issuance_args,
    "acquireCertificate-issuance-args",
    CALL_ACQUIRE_CERTIFICATE,
    acquire_certificate::serialize_acquire_certificate_args,
    acquire_certificate::deserialize_acquire_certificate_args,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        AcquireCertificateArgs {
            cert_type: type_from_base64(TYPE_B64),
            certifier: pk_from_hex(COUNTERPARTY_HEX),
            acquisition_protocol: AcquisitionProtocol::Issuance,
            fields,
            serial_number: None,
            revocation_outpoint: None,
            signature: None,
            certifier_url: Some("https://certifier.example.com".to_string()),
            keyring_revealer: None,
            keyring_for_subject: None,
            privileged: false,
            privileged_reason: None,
        }
    }
);

// AcquireCertificate result is a Certificate
test_result_vector!(
    test_acquire_certificate_simple_result,
    "acquireCertificate-simple-result",
    certificate_ser::serialize_certificate,
    certificate_ser::deserialize_certificate,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        Certificate {
            cert_type: type_from_base64(TYPE_B64),
            serial_number: serial_from_base64(SERIAL_B64),
            subject: pk_from_hex(PUB_KEY_HEX),
            certifier: pk_from_hex(COUNTERPARTY_HEX),
            revocation_outpoint: Some(OUTPOINT_STR.to_string()),
            fields: Some(fields.into_iter().collect()),
            signature: Some(sig_from_hex(SIG_HEX)),
        }
    }
);

// ---------------------------------------------------------------------------
// ListCertificates
// ---------------------------------------------------------------------------

test_args_vector!(
    test_list_certificates_simple_args,
    "listCertificates-simple-args",
    CALL_LIST_CERTIFICATES,
    list_certificates::serialize_list_certificates_args,
    list_certificates::deserialize_list_certificates_args,
    ListCertificatesArgs {
        certifiers: vec![pk_from_hex(COUNTERPARTY_HEX), pk_from_hex(VERIFIER_HEX)],
        types: vec![
            type_from_base64("dGVzdC10eXBlMSAgICAgICAgICAgICAgICAgICAgICA="),
            type_from_base64("dGVzdC10eXBlMiAgICAgICAgICAgICAgICAgICAgICA="),
        ],
        limit: Some(5),
        offset: Some(0),
        privileged: BooleanDefaultFalse(Some(true)),
        privileged_reason: Some("list-cert-reason".to_string()),
        partial: None,
    }
);

test_result_vector!(
    test_list_certificates_simple_result,
    "listCertificates-simple-result",
    list_certificates::serialize_list_certificates_result,
    list_certificates::deserialize_list_certificates_result,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        ListCertificatesResult {
            total_certificates: 1,
            certificates: vec![CertificateResult {
                certificate: Certificate {
                    cert_type: type_from_base64(TYPE_B64),
                    serial_number: serial_from_base64(SERIAL_B64),
                    subject: pk_from_hex(PUB_KEY_HEX),
                    certifier: pk_from_hex(COUNTERPARTY_HEX),
                    revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                    fields: Some(fields.into_iter().collect()),
                    signature: Some(sig_from_hex(SIG_HEX)),
                },
                keyring: None,
                verifier: None,
            }],
        }
    }
);

#[test]
fn test_list_certificates_legacy_verifier_bytes_decode_like_typescript() {
    let (_, wire) = read_vector("listCertificates-full-result");
    let params = strip_result_frame(&wire);
    let decoded = list_certificates::deserialize_list_certificates_result(&params).unwrap();
    let legacy_bytes = hex_decode(VERIFIER_HEX).unwrap();
    let expected = String::from_utf8_lossy(&legacy_bytes);
    assert_eq!(
        decoded.certificates[0].verifier.as_deref(),
        Some(expected.as_ref())
    );
}

// ---------------------------------------------------------------------------
// ProveCertificate
// ---------------------------------------------------------------------------

test_args_vector!(
    test_prove_certificate_simple_args,
    "proveCertificate-simple-args",
    CALL_PROVE_CERTIFICATE,
    prove_certificate::serialize_prove_certificate_args,
    prove_certificate::deserialize_prove_certificate_args,
    {
        let mut fields = HashMap::new();
        fields.insert("email".to_string(), "alice@example.com".to_string());
        fields.insert("name".to_string(), "Alice".to_string());
        ProveCertificateArgs {
            certificate: Certificate {
                cert_type: type_from_base64(TYPE_B64),
                serial_number: serial_from_base64(SERIAL_B64),
                subject: pk_from_hex(PUB_KEY_HEX),
                certifier: pk_from_hex(COUNTERPARTY_HEX),
                revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                fields: Some(fields.into_iter().collect()),
                signature: Some(sig_from_hex(SIG_HEX)),
            }
            .into(),
            fields_to_reveal: vec!["name".to_string()],
            verifier: pk_from_hex(VERIFIER_HEX),
            privileged: BooleanDefaultFalse(Some(false)),
            privileged_reason: Some("prove-reason".to_string()),
        }
    }
);

test_result_vector!(
    test_prove_certificate_simple_result,
    "proveCertificate-simple-result",
    prove_certificate::serialize_prove_certificate_result,
    prove_certificate::deserialize_prove_certificate_result,
    {
        let mut keyring = IndexMap::new();
        keyring.insert("name".to_string(), "bmFtZS1rZXk=".to_string());
        ProveCertificateResult {
            keyring_for_verifier: keyring,
            certificate: None,
            verifier: None,
        }
    }
);

// ---------------------------------------------------------------------------
// RelinquishCertificate
// ---------------------------------------------------------------------------

test_args_vector!(
    test_relinquish_certificate_simple_args,
    "relinquishCertificate-simple-args",
    CALL_RELINQUISH_CERTIFICATE,
    relinquish_certificate::serialize_relinquish_certificate_args,
    relinquish_certificate::deserialize_relinquish_certificate_args,
    RelinquishCertificateArgs {
        cert_type: type_from_base64(TYPE_B64),
        serial_number: serial_from_base64(SERIAL_B64),
        certifier: pk_from_hex(COUNTERPARTY_HEX),
    }
);

test_result_vector!(
    test_relinquish_certificate_simple_result,
    "relinquishCertificate-simple-result",
    relinquish_certificate::serialize_relinquish_certificate_result,
    relinquish_certificate::deserialize_relinquish_certificate_result,
    RelinquishCertificateResult { relinquished: true }
);

// ---------------------------------------------------------------------------
// DiscoverByIdentityKey
// ---------------------------------------------------------------------------

test_args_vector!(
    test_discover_by_identity_key_simple_args,
    "discoverByIdentityKey-simple-args",
    CALL_DISCOVER_BY_IDENTITY_KEY,
    discover_by_identity_key::serialize_discover_by_identity_key_args,
    discover_by_identity_key::deserialize_discover_by_identity_key_args,
    DiscoverByIdentityKeyArgs {
        identity_key: pk_from_hex(COUNTERPARTY_HEX),
        limit: Some(10),
        offset: Some(0),
        seek_permission: Some(true),
    }
);

test_result_vector!(
    test_discover_by_identity_key_simple_result,
    "discoverByIdentityKey-simple-result",
    discover_certificates_result::serialize_discover_certificates_result,
    discover_certificates_result::deserialize_discover_certificates_result,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        let mut pub_keyring = IndexMap::new();
        pub_keyring.insert(
            "pubField".to_string(),
            "AlrUOiKsONC8H4usqrsyO11jRwO3p3TEJo9qCeTd95CX".to_string(),
        );
        let mut decrypted = IndexMap::new();
        decrypted.insert("name".to_string(), "Alice".to_string());
        DiscoverCertificatesResult {
            total_certificates: 1,
            certificates: vec![IdentityCertificate {
                certificate: Certificate {
                    cert_type: type_from_base64(TYPE_B64),
                    serial_number: serial_from_base64(SERIAL_B64),
                    subject: pk_from_hex(PUB_KEY_HEX),
                    certifier: pk_from_hex(COUNTERPARTY_HEX),
                    revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                    fields: Some(fields.into_iter().collect()),
                    signature: Some(sig_from_hex(SIG_HEX)),
                },
                certifier_info: IdentityCertifier {
                    name: "Test Certifier".to_string(),
                    icon_url: "https://example.com/icon.png".to_string(),
                    description: "Certifier description".to_string(),
                    trust: 5,
                },
                publicly_revealed_keyring: pub_keyring,
                decrypted_fields: decrypted,
            }],
        }
    }
);

// ---------------------------------------------------------------------------
// DiscoverByAttributes
// ---------------------------------------------------------------------------

test_args_vector!(
    test_discover_by_attributes_simple_args,
    "discoverByAttributes-simple-args",
    CALL_DISCOVER_BY_ATTRIBUTES,
    discover_by_attributes::serialize_discover_by_attributes_args,
    discover_by_attributes::deserialize_discover_by_attributes_args,
    {
        let mut attributes = HashMap::new();
        attributes.insert("email".to_string(), "alice@example.com".to_string());
        attributes.insert("role".to_string(), "admin".to_string());
        DiscoverByAttributesArgs {
            attributes,
            limit: Some(5),
            offset: Some(0),
            seek_permission: Some(false),
        }
    }
);

test_result_vector!(
    test_discover_by_attributes_simple_result,
    "discoverByAttributes-simple-result",
    discover_certificates_result::serialize_discover_certificates_result,
    discover_certificates_result::deserialize_discover_certificates_result,
    {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());
        let mut pub_keyring = IndexMap::new();
        pub_keyring.insert(
            "pubField".to_string(),
            "AlrUOiKsONC8H4usqrsyO11jRwO3p3TEJo9qCeTd95CX".to_string(),
        );
        let mut decrypted = IndexMap::new();
        decrypted.insert("name".to_string(), "Alice".to_string());
        DiscoverCertificatesResult {
            total_certificates: 1,
            certificates: vec![IdentityCertificate {
                certificate: Certificate {
                    cert_type: type_from_base64(TYPE_B64),
                    serial_number: serial_from_base64(SERIAL_B64),
                    subject: pk_from_hex(PUB_KEY_HEX),
                    certifier: pk_from_hex(COUNTERPARTY_HEX),
                    revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                    fields: Some(fields.into_iter().collect()),
                    signature: Some(sig_from_hex(SIG_HEX)),
                },
                certifier_info: IdentityCertifier {
                    name: "Test Certifier".to_string(),
                    icon_url: "https://example.com/icon.png".to_string(),
                    description: "Certifier description".to_string(),
                    trust: 5,
                },
                publicly_revealed_keyring: pub_keyring,
                decrypted_fields: decrypted,
            }],
        }
    }
);

// ---------------------------------------------------------------------------
// Auth/Info methods
// ---------------------------------------------------------------------------

// isAuthenticated args - just frame with call byte and empty originator
#[test]
fn test_is_authenticated_simple_args() {
    let (_, wire) = read_vector("isAuthenticated-simple-args");
    let (call, params) = strip_request_frame(&wire);
    assert_eq!(call, CALL_IS_AUTHENTICATED);
    assert!(params.is_empty(), "isAuthenticated args should be empty");
}

test_result_vector!(
    test_is_authenticated_simple_result,
    "isAuthenticated-simple-result",
    authenticated::serialize_is_authenticated_result,
    authenticated::deserialize_is_authenticated_result,
    AuthenticatedResult {
        authenticated: true
    }
);

// waitForAuthentication args - just frame with call byte
#[test]
fn test_wait_for_authentication_simple_args() {
    let (_, wire) = read_vector("waitForAuthentication-simple-args");
    let (call, params) = strip_request_frame(&wire);
    assert_eq!(call, CALL_WAIT_FOR_AUTHENTICATION);
    assert!(
        params.is_empty(),
        "waitForAuthentication args should be empty"
    );
}

#[test]
fn identity_certificate_maps_preserve_insertion_order() {
    let certificate = Certificate {
        cert_type: type_from_base64(TYPE_B64),
        serial_number: serial_from_base64(SERIAL_B64),
        subject: pk_from_hex(PUB_KEY_HEX),
        certifier: pk_from_hex(COUNTERPARTY_HEX),
        revocation_outpoint: Some(OUTPOINT_STR.to_string()),
        fields: None,
        signature: Some(sig_from_hex(SIG_HEX)),
    };
    let mut publicly_revealed_keyring = IndexMap::new();
    publicly_revealed_keyring.insert("zeta".to_string(), "eg==".to_string());
    publicly_revealed_keyring.insert("alpha".to_string(), "YQ==".to_string());
    publicly_revealed_keyring.insert("middle".to_string(), "bQ==".to_string());
    let mut decrypted_fields = IndexMap::new();
    decrypted_fields.insert("zeta".to_string(), "z".to_string());
    decrypted_fields.insert("alpha".to_string(), "a".to_string());
    decrypted_fields.insert("middle".to_string(), "m".to_string());
    let identity = IdentityCertificate {
        certificate,
        certifier_info: IdentityCertifier {
            name: "certifier".to_string(),
            icon_url: String::new(),
            description: String::new(),
            trust: 1,
        },
        publicly_revealed_keyring,
        decrypted_fields,
    };

    let encoded = certificate_ser::serialize_identity_certificate(&identity).unwrap();
    let decoded =
        certificate_ser::deserialize_identity_certificate(&mut std::io::Cursor::new(encoded))
            .unwrap();

    assert_eq!(
        decoded
            .publicly_revealed_keyring
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "middle"]
    );
    assert_eq!(
        decoded
            .decrypted_fields
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "middle"]
    );
}

#[test]
fn prove_certificate_keyring_preserves_insertion_order() {
    let mut keyring_for_verifier = IndexMap::new();
    keyring_for_verifier.insert("zeta".to_string(), "eg==".to_string());
    keyring_for_verifier.insert("alpha".to_string(), "YQ==".to_string());
    keyring_for_verifier.insert("middle".to_string(), "bQ==".to_string());
    let result = ProveCertificateResult {
        keyring_for_verifier,
        certificate: None,
        verifier: None,
    };

    let encoded = prove_certificate::serialize_prove_certificate_result(&result).unwrap();
    let decoded = prove_certificate::deserialize_prove_certificate_result(&encoded).unwrap();

    assert_eq!(
        decoded
            .keyring_for_verifier
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "middle"]
    );
}

test_result_vector!(
    test_wait_for_authentication_simple_result,
    "waitForAuthentication-simple-result",
    authenticated::serialize_wait_authenticated_result,
    authenticated::deserialize_wait_authenticated_result,
    AuthenticatedResult {
        authenticated: true
    }
);

// getHeight args - just frame with call byte
#[test]
fn test_get_height_simple_args() {
    let (_, wire) = read_vector("getHeight-simple-args");
    let (call, params) = strip_request_frame(&wire);
    assert_eq!(call, CALL_GET_HEIGHT);
    assert!(params.is_empty(), "getHeight args should be empty");
}

test_result_vector!(
    test_get_height_simple_result,
    "getHeight-simple-result",
    get_height::serialize_get_height_result,
    get_height::deserialize_get_height_result,
    GetHeightResult { height: 850000 }
);

test_args_vector!(
    test_get_header_for_height_simple_args,
    "getHeaderForHeight-simple-args",
    CALL_GET_HEADER_FOR_HEIGHT,
    get_header::serialize_get_header_args,
    get_header::deserialize_get_header_args,
    GetHeaderArgs { height: 850000 }
);

test_result_vector!(
    test_get_header_for_height_simple_result,
    "getHeaderForHeight-simple-result",
    get_header::serialize_get_header_result,
    get_header::deserialize_get_header_result,
    GetHeaderResult {
        header: hex_decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap(),
    }
);

test_result_vector!(
    test_get_network_simple_result,
    "getNetwork-simple-result",
    get_network::serialize_get_network_result,
    get_network::deserialize_get_network_result,
    GetNetworkResult {
        network: Network::Mainnet
    }
);

test_result_vector!(
    test_get_version_simple_result,
    "getVersion-simple-result",
    get_version::serialize_get_version_result,
    get_version::deserialize_get_version_result,
    GetVersionResult {
        version: "1.0.0".to_string()
    }
);

// ---------------------------------------------------------------------------
// Regression: keyring Some(empty) binary round-trip (H1)
// ---------------------------------------------------------------------------
//
// `CertificateResult.keyring` is `Option<HashMap<String, String>>`, so three
// states must survive the wire format:
//   None         -> absent
//   Some(empty)  -> present but empty
//   Some(map)    -> present with entries
//
// Before the fix, the serializer folded `Some(empty)` into the same flag-byte
// as `None` (`write_byte(0)`), silently stripping the "present but empty"
// marker on binary round-trip. This test exercises all three states and would
// fail on the `Some(empty)` case before the fix.
#[test]
fn test_list_certificates_keyring_three_state_roundtrip() {
    fn make_cert(keyring: Option<HashMap<String, String>>) -> ListCertificatesResult {
        ListCertificatesResult {
            total_certificates: 1,
            certificates: vec![CertificateResult {
                certificate: Certificate {
                    cert_type: type_from_base64(TYPE_B64),
                    serial_number: serial_from_base64(SERIAL_B64),
                    subject: pk_from_hex(PUB_KEY_HEX),
                    certifier: pk_from_hex(COUNTERPARTY_HEX),
                    revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                    fields: None,
                    signature: Some(sig_from_hex(SIG_HEX)),
                },
                keyring,
                verifier: None,
            }],
        }
    }

    // (A) None -> flag byte 0, deserializes to None.
    let none_input = make_cert(None);
    let none_bytes = list_certificates::serialize_list_certificates_result(&none_input).unwrap();
    let none_out = list_certificates::deserialize_list_certificates_result(&none_bytes).unwrap();
    assert!(
        none_out.certificates[0].keyring.is_none(),
        "None keyring must round-trip as None"
    );

    // (B) Some(empty) -> flag byte 1, varint 0, deserializes to Some(empty).
    // This is the regression case: the pre-fix serializer wrote flag=0 here,
    // causing deserialize to return None and silently collapsing the type.
    let empty_input = make_cert(Some(HashMap::new()));
    let empty_bytes = list_certificates::serialize_list_certificates_result(&empty_input).unwrap();
    let empty_out = list_certificates::deserialize_list_certificates_result(&empty_bytes).unwrap();
    let empty_roundtripped = empty_out.certificates[0]
        .keyring
        .as_ref()
        .expect("Some(empty) keyring must round-trip as Some(_), not None");
    assert!(
        empty_roundtripped.is_empty(),
        "round-tripped empty keyring must still be empty"
    );
    // Binary distinction: None vs Some(empty) must produce different bytes.
    assert_ne!(
        none_bytes, empty_bytes,
        "None and Some(empty) keyring must serialize to distinct byte sequences"
    );

    // (C) Some(populated) -> flag byte 1, full map, round-trips intact.
    let mut populated = HashMap::new();
    populated.insert("field1".to_string(), "a2V5MQ==".to_string());
    populated.insert("field2".to_string(), "a2V5Mg==".to_string());
    let populated_input = make_cert(Some(populated.clone()));
    let populated_bytes =
        list_certificates::serialize_list_certificates_result(&populated_input).unwrap();
    let populated_out =
        list_certificates::deserialize_list_certificates_result(&populated_bytes).unwrap();
    let populated_roundtripped = populated_out.certificates[0]
        .keyring
        .as_ref()
        .expect("Some(populated) keyring must round-trip as Some(_)");
    assert_eq!(populated_roundtripped, &populated);
}

fn empty_create_action_args() -> CreateActionArgs {
    CreateActionArgs {
        description: "test action".to_string(),
        input_beef: None,
        inputs: None,
        outputs: None,
        lock_time: None,
        version: None,
        labels: None,
        options: None,
        reference: None,
    }
}

#[test]
fn create_action_optional_arrays_preserve_absent_and_empty() {
    let absent = empty_create_action_args();
    let absent_bytes = create_action::serialize_create_action_args(&absent).unwrap();
    let absent_out = create_action::deserialize_create_action_args(&absent_bytes).unwrap();
    assert!(absent_out.inputs.is_none());
    assert!(absent_out.outputs.is_none());
    assert!(absent_out.labels.is_none());

    let mut with_inputs = absent.clone();
    with_inputs.inputs = Some(vec![]);
    let bytes = create_action::serialize_create_action_args(&with_inputs).unwrap();
    assert_ne!(bytes, absent_bytes);
    assert_eq!(
        create_action::deserialize_create_action_args(&bytes)
            .unwrap()
            .inputs
            .unwrap()
            .len(),
        0
    );

    let mut with_outputs = absent.clone();
    with_outputs.outputs = Some(vec![]);
    let bytes = create_action::serialize_create_action_args(&with_outputs).unwrap();
    assert_ne!(bytes, absent_bytes);
    assert_eq!(
        create_action::deserialize_create_action_args(&bytes)
            .unwrap()
            .outputs
            .unwrap()
            .len(),
        0
    );

    let mut with_labels = absent.clone();
    with_labels.labels = Some(vec![]);
    let bytes = create_action::serialize_create_action_args(&with_labels).unwrap();
    assert_ne!(bytes, absent_bytes);
    assert_eq!(
        create_action::deserialize_create_action_args(&bytes)
            .unwrap()
            .labels
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn create_action_nested_optional_arrays_preserve_absent_and_empty() {
    let output = CreateActionOutput {
        locking_script: Some(vec![0x51]),
        satoshis: 1,
        output_description: "test output".to_string(),
        basket: None,
        custom_instructions: None,
        tags: None,
    };
    let mut absent_tags = empty_create_action_args();
    absent_tags.outputs = Some(vec![output.clone()]);
    let absent_tag_bytes = create_action::serialize_create_action_args(&absent_tags).unwrap();
    assert!(
        create_action::deserialize_create_action_args(&absent_tag_bytes)
            .unwrap()
            .outputs
            .unwrap()[0]
            .tags
            .is_none()
    );
    let mut empty_tags = absent_tags;
    empty_tags.outputs.as_mut().unwrap()[0].tags = Some(vec![]);
    let empty_tag_bytes = create_action::serialize_create_action_args(&empty_tags).unwrap();
    assert_ne!(empty_tag_bytes, absent_tag_bytes);
    assert_eq!(
        create_action::deserialize_create_action_args(&empty_tag_bytes)
            .unwrap()
            .outputs
            .unwrap()[0]
            .tags
            .as_ref()
            .unwrap()
            .len(),
        0
    );

    for field in ["known_txids", "no_send_change", "send_with"] {
        let mut absent_options = empty_create_action_args();
        absent_options.options = Some(CreateActionOptions::default());
        let absent_bytes = create_action::serialize_create_action_args(&absent_options).unwrap();
        let mut empty_options = absent_options;
        let options = empty_options.options.as_mut().unwrap();
        match field {
            "known_txids" => options.known_txids = Some(vec![]),
            "no_send_change" => options.no_send_change = Some(vec![]),
            "send_with" => options.send_with = Some(vec![]),
            _ => unreachable!(),
        }
        let empty_bytes = create_action::serialize_create_action_args(&empty_options).unwrap();
        assert_ne!(empty_bytes, absent_bytes, "{field}");
        let decoded = create_action::deserialize_create_action_args(&empty_bytes)
            .unwrap()
            .options
            .unwrap();
        let is_empty = match field {
            "known_txids" => decoded.known_txids.unwrap().is_empty(),
            "no_send_change" => decoded.no_send_change.unwrap().is_empty(),
            "send_with" => decoded.send_with.unwrap().is_empty(),
            _ => unreachable!(),
        };
        assert!(is_empty, "{field}");
    }
}

#[test]
fn sign_internalize_and_result_optional_arrays_preserve_empty() {
    let sign_args = SignActionArgs {
        reference: vec![],
        spends: HashMap::new(),
        options: Some(SignActionOptions::default()),
    };
    let absent_bytes = sign_action::serialize_sign_action_args(&sign_args).unwrap();
    let mut empty_sign_args = sign_args;
    empty_sign_args.options.as_mut().unwrap().send_with = Some(vec![]);
    let empty_bytes = sign_action::serialize_sign_action_args(&empty_sign_args).unwrap();
    assert_ne!(empty_bytes, absent_bytes);
    assert!(sign_action::deserialize_sign_action_args(&empty_bytes)
        .unwrap()
        .options
        .unwrap()
        .send_with
        .unwrap()
        .is_empty());

    let internalize = InternalizeActionArgs {
        tx: vec![],
        description: "test action".to_string(),
        labels: None,
        seek_permission: BooleanDefaultTrue(None),
        outputs: vec![],
    };
    let absent_bytes = internalize_action::serialize_internalize_action_args(&internalize).unwrap();
    let mut empty_internalize = internalize;
    empty_internalize.labels = Some(vec![]);
    let empty_bytes =
        internalize_action::serialize_internalize_action_args(&empty_internalize).unwrap();
    assert_ne!(empty_bytes, absent_bytes);
    assert!(
        internalize_action::deserialize_internalize_action_args(&empty_bytes)
            .unwrap()
            .labels
            .unwrap()
            .is_empty()
    );

    let insertion = InternalizeActionArgs {
        tx: vec![],
        description: "test action".to_string(),
        labels: None,
        seek_permission: BooleanDefaultTrue(None),
        outputs: vec![InternalizeOutput::BasketInsertion {
            output_index: 0,
            insertion: BasketInsertion {
                basket: "default".to_string(),
                custom_instructions: None,
                tags: vec![],
            },
        }],
    };
    let insertion_bytes =
        internalize_action::serialize_internalize_action_args(&insertion).unwrap();
    let mut insertion_reader = std::io::Cursor::new(insertion_bytes);
    assert_eq!(read_varint(&mut insertion_reader).unwrap(), 0); // tx
    assert_eq!(read_varint(&mut insertion_reader).unwrap(), 1); // outputs
    assert_eq!(read_varint(&mut insertion_reader).unwrap(), 0); // output index
    assert_eq!(read_byte(&mut insertion_reader).unwrap(), 2); // basket insertion
    assert_eq!(read_string(&mut insertion_reader).unwrap(), "default");
    assert_eq!(read_string(&mut insertion_reader).unwrap(), "");
    assert_eq!(
        read_varint(&mut insertion_reader).unwrap(),
        0,
        "omitted/empty TS insertion tags use a zero count"
    );

    let create_result = CreateActionResult {
        txid: None,
        tx: None,
        no_send_change: None,
        send_with_results: None,
        signable_transaction: None,
    };
    let absent_bytes = create_action::serialize_create_action_result(&create_result).unwrap();
    let mut empty_result = create_result.clone();
    empty_result.no_send_change = Some(vec![]);
    let empty_bytes = create_action::serialize_create_action_result(&empty_result).unwrap();
    assert_ne!(empty_bytes, absent_bytes);
    assert!(
        create_action::deserialize_create_action_result(&empty_bytes)
            .unwrap()
            .no_send_change
            .unwrap()
            .is_empty()
    );
    empty_result = create_result;
    empty_result.send_with_results = Some(vec![]);
    let empty_bytes = create_action::serialize_create_action_result(&empty_result).unwrap();
    assert_ne!(empty_bytes, absent_bytes);
    assert!(
        create_action::deserialize_create_action_result(&empty_bytes)
            .unwrap()
            .send_with_results
            .unwrap()
            .is_empty()
    );

    let sign_result = SignActionResult {
        txid: None,
        tx: None,
        send_with_results: Some(vec![]),
    };
    let bytes = sign_action::serialize_sign_action_result(&sign_result).unwrap();
    assert!(sign_action::deserialize_sign_action_result(&bytes)
        .unwrap()
        .send_with_results
        .unwrap()
        .is_empty());
}

#[test]
fn list_outputs_matches_collapsed_tags_and_signed_offset_wire() {
    let args = ListOutputsArgs {
        basket: "default".to_string(),
        tags: vec![],
        tag_query_mode: None,
        include: None,
        include_custom_instructions: BooleanDefaultFalse(None),
        include_tags: BooleanDefaultFalse(None),
        include_labels: BooleanDefaultFalse(None),
        limit: None,
        offset: Some(-2),
        seek_permission: BooleanDefaultTrue(None),
    };
    let bytes = list_outputs::serialize_list_outputs_args(&args).unwrap();
    assert_eq!(bytes[8], 0, "empty/omitted TS tags use a zero count");
    assert_eq!(
        &bytes[bytes.len() - 10..bytes.len() - 1],
        &[0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    let decoded = list_outputs::deserialize_list_outputs_args(&bytes).unwrap();
    assert!(decoded.tags.is_empty());
    assert_eq!(
        decoded.offset, None,
        "TS processor discards negative offsets"
    );
}

#[test]
fn list_result_optional_arrays_preserve_absent_and_empty() {
    let action = Action {
        txid: "00".repeat(32),
        satoshis: 0,
        status: ActionStatus::Completed,
        is_outgoing: false,
        description: "test action".to_string(),
        labels: None,
        version: 0,
        lock_time: 0,
        inputs: None,
        outputs: None,
    };
    let absent = ListActionsResult {
        total_actions: 1,
        actions: vec![action],
    };
    let absent_bytes = list_actions::serialize_list_actions_result(&absent).unwrap();
    let absent_out = list_actions::deserialize_list_actions_result(&absent_bytes).unwrap();
    assert!(absent_out.actions[0].labels.is_none());
    assert!(absent_out.actions[0].inputs.is_none());
    assert!(absent_out.actions[0].outputs.is_none());
    for field in ["labels", "inputs", "outputs"] {
        let mut present = absent.clone();
        let action = &mut present.actions[0];
        match field {
            "labels" => action.labels = Some(vec![]),
            "inputs" => action.inputs = Some(vec![]),
            "outputs" => action.outputs = Some(vec![]),
            _ => unreachable!(),
        }
        let bytes = list_actions::serialize_list_actions_result(&present).unwrap();
        assert_ne!(bytes, absent_bytes, "{field}");
        let decoded = list_actions::deserialize_list_actions_result(&bytes).unwrap();
        let action = &decoded.actions[0];
        let is_empty = match field {
            "labels" => action.labels.as_ref().unwrap().is_empty(),
            "inputs" => action.inputs.as_ref().unwrap().is_empty(),
            "outputs" => action.outputs.as_ref().unwrap().is_empty(),
            _ => unreachable!(),
        };
        assert!(is_empty, "{field}");
    }

    let output = Output {
        satoshis: 1,
        locking_script: None,
        spendable: true,
        custom_instructions: None,
        tags: None,
        outpoint: format!("{}.0", "00".repeat(32)),
        labels: None,
    };
    let absent = ListOutputsResult {
        total_outputs: 1,
        beef: None,
        outputs: vec![output],
    };
    let absent_bytes = list_outputs::serialize_list_outputs_result(&absent).unwrap();
    let absent_out = list_outputs::deserialize_list_outputs_result(&absent_bytes).unwrap();
    assert!(absent_out.outputs[0].tags.is_none());
    assert!(absent_out.outputs[0].labels.is_none());
    for field in ["tags", "labels"] {
        let mut present = absent.clone();
        match field {
            "tags" => present.outputs[0].tags = Some(vec![]),
            "labels" => present.outputs[0].labels = Some(vec![]),
            _ => unreachable!(),
        }
        let bytes = list_outputs::serialize_list_outputs_result(&present).unwrap();
        assert_ne!(bytes, absent_bytes, "{field}");
        let decoded = list_outputs::deserialize_list_outputs_result(&bytes).unwrap();
        let output = &decoded.outputs[0];
        let is_empty = match field {
            "tags" => output.tags.as_ref().unwrap().is_empty(),
            "labels" => output.labels.as_ref().unwrap().is_empty(),
            _ => unreachable!(),
        };
        assert!(is_empty, "{field}");
    }
}

#[test]
fn list_certificates_verifier_is_utf8_on_wire_and_in_json() {
    let result = ListCertificatesResult {
        total_certificates: 1,
        certificates: vec![CertificateResult {
            certificate: Certificate {
                cert_type: type_from_base64(TYPE_B64),
                serial_number: serial_from_base64(SERIAL_B64),
                subject: pk_from_hex(PUB_KEY_HEX),
                certifier: pk_from_hex(COUNTERPARTY_HEX),
                revocation_outpoint: Some(OUTPOINT_STR.to_string()),
                fields: None,
                signature: None,
            },
            keyring: None,
            verifier: Some("hi".to_string()),
        }],
    };
    let bytes = list_certificates::serialize_list_certificates_result(&result).unwrap();
    assert_eq!(&bytes[bytes.len() - 3..], &[2, 0x68, 0x69]);
    let decoded = list_certificates::deserialize_list_certificates_result(&bytes).unwrap();
    assert_eq!(decoded.certificates[0].verifier.as_deref(), Some("hi"));
    #[cfg(feature = "serde")]
    let json = serde_json::to_value(&decoded.certificates[0]).unwrap();
    #[cfg(feature = "serde")]
    assert_eq!(json["verifier"], "hi");
}

// ---------------------------------------------------------------------------
// GetNetwork args (empty args, like isAuthenticated)
// ---------------------------------------------------------------------------

#[test]
fn test_get_network_simple_args() {
    let (_, wire) = read_vector("getNetwork-simple-args");
    let (call, params) = strip_request_frame(&wire);
    assert_eq!(call, CALL_GET_NETWORK);
    assert!(params.is_empty(), "getNetwork args should be empty");
}

// ---------------------------------------------------------------------------
// GetVersion args (empty args, like isAuthenticated)
// ---------------------------------------------------------------------------

#[test]
fn test_get_version_simple_args() {
    let (_, wire) = read_vector("getVersion-simple-args");
    let (call, params) = strip_request_frame(&wire);
    assert_eq!(call, CALL_GET_VERSION);
    assert!(params.is_empty(), "getVersion args should be empty");
}

// ---------------------------------------------------------------------------
// CreateAction with options.signAndProcess = false
// ---------------------------------------------------------------------------

test_args_vector!(
    test_create_action_no_sign_and_process_args,
    "createAction-no-signAndProcess-args",
    CALL_CREATE_ACTION,
    create_action::serialize_create_action_args,
    create_action::deserialize_create_action_args,
    CreateActionArgs {
        description: "Test action description with trust self and no-send".to_string(),
        input_beef: None,
        inputs: None,
        outputs: Some(vec![CreateActionOutput {
            locking_script: Some(hex_decode(LOCKING_SCRIPT_HEX).unwrap()),
            satoshis: 999,
            output_description: "Test output".to_string(),
            basket: Some("test-basket".to_string()),
            custom_instructions: Some("Test instructions".to_string()),
            tags: Some(vec!["test-tag".to_string()]),
        }]),
        lock_time: None,
        version: None,
        labels: Some(vec!["test-label".to_string()]),
        options: Some(CreateActionOptions {
            sign_and_process: BooleanDefaultTrue(Some(false)),
            accept_delayed_broadcast: BooleanDefaultTrue(None),
            trust_self: None,
            known_txids: None,
            return_txid_only: BooleanDefaultFalse(None),
            no_send: BooleanDefaultFalse(None),
            no_send_change: None,
            send_with: None,
            randomize_outputs: BooleanDefaultTrue(None),
        }),
        reference: None,
    }
);

// ---------------------------------------------------------------------------
// CreateAction result (1-out, with txid and tx)
// ---------------------------------------------------------------------------

test_result_vector!(
    test_create_action_1_out_result,
    "createAction-1-out-result",
    create_action::serialize_create_action_result,
    create_action::deserialize_create_action_result,
    CreateActionResult {
        txid: Some(RESULT_TXID.to_string()),
        tx: Some(hex_decode(RESULT_TX_HEX).unwrap()),
        no_send_change: None,
        send_with_results: None,
        signable_transaction: None,
    }
);

// ---------------------------------------------------------------------------
// CreateAction result (no signAndProcess, returns signableTransaction)
// ---------------------------------------------------------------------------

test_result_vector!(
    test_create_action_no_sign_and_process_result,
    "createAction-no-signAndProcess-result",
    create_action::serialize_create_action_result,
    create_action::deserialize_create_action_result,
    CreateActionResult {
        txid: None,
        tx: None,
        no_send_change: None,
        send_with_results: None,
        signable_transaction: Some(SignableTransaction {
            tx: hex_decode(RESULT_TX_HEX).unwrap(),
            reference: base64_std_decode("dGVzdA=="),
        }),
    }
);

// ---------------------------------------------------------------------------
// SignAction result (with txid and tx)
// ---------------------------------------------------------------------------

test_result_vector!(
    test_sign_action_simple_result,
    "signAction-simple-result",
    sign_action::serialize_sign_action_result,
    sign_action::deserialize_sign_action_result,
    SignActionResult {
        txid: Some(RESULT_TXID.to_string()),
        tx: Some(hex_decode(RESULT_TX_HEX).unwrap()),
        send_with_results: None,
    }
);

// ---------------------------------------------------------------------------
// AcquireCertificate issuance result (Certificate)
// ---------------------------------------------------------------------------

test_result_vector!(
    test_acquire_certificate_issuance_result,
    "acquireCertificate-issuance-result",
    certificate_ser::serialize_certificate,
    certificate_ser::deserialize_certificate,
    {
        let mut fields = HashMap::new();
        fields.insert("email".to_string(), "alice@example.com".to_string());
        fields.insert("name".to_string(), "Alice".to_string());
        Certificate {
            cert_type: type_from_base64(TYPE_B64),
            serial_number: serial_from_base64(SERIAL_B64),
            subject: pk_from_hex(PUB_KEY_HEX),
            certifier: pk_from_hex(COUNTERPARTY_HEX),
            revocation_outpoint: Some(OUTPOINT_STR.to_string()),
            fields: Some(fields.into_iter().collect()),
            signature: Some(sig_from_hex(SIG_HEX)),
        }
    }
);

// ---------------------------------------------------------------------------
// ListCertificates full args
// ---------------------------------------------------------------------------

test_args_vector!(
    test_list_certificates_full_args,
    "listCertificates-full-args",
    CALL_LIST_CERTIFICATES,
    list_certificates::serialize_list_certificates_args,
    list_certificates::deserialize_list_certificates_args,
    ListCertificatesArgs {
        certifiers: vec![pk_from_hex(COUNTERPARTY_HEX), pk_from_hex(VERIFIER_HEX)],
        types: vec![
            type_from_base64("dGVzdC10eXBlMSAgICAgICAgICAgICAgICAgICAgICA="),
            type_from_base64("dGVzdC10eXBlMiAgICAgICAgICAgICAgICAgICAgICA="),
        ],
        limit: Some(5),
        offset: Some(0),
        privileged: BooleanDefaultFalse(Some(true)),
        privileged_reason: Some("list-cert-reason".to_string()),
        partial: None,
    }
);
