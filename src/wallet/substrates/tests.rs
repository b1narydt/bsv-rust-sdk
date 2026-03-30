//! Tests for wallet substrates: mock wallet, round-trip through
//! WalletWireTransceiver -> WalletWireProcessor pipeline.

use std::collections::HashMap;

use crate::primitives::public_key::PublicKey;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;
use crate::wallet::substrates::wallet_wire_calls::WalletWireCall;
use crate::wallet::substrates::{WalletWireProcessor, WalletWireTransceiver};
use crate::wallet::types::*;

// ---------------------------------------------------------------------------
// Mock wallet: returns known values for each method
// ---------------------------------------------------------------------------

struct MockWallet;

#[async_trait::async_trait]
impl WalletInterface for MockWallet {
    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        Ok(CreateActionResult {
            txid: Some("abcd1234".repeat(8)),
            tx: None,
            no_send_change: vec![],
            send_with_results: vec![],
            signable_transaction: None,
        })
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _originator: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        Ok(SignActionResult {
            txid: Some("signed123".to_string()),
            tx: None,
            send_with_results: vec![],
        })
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        Ok(AbortActionResult { aborted: true })
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        Ok(ListActionsResult {
            total_actions: 0,
            actions: vec![],
        })
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        Ok(InternalizeActionResult { accepted: true })
    }

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        Ok(ListOutputsResult {
            total_outputs: 0,
            beef: None,
            outputs: vec![],
        })
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        Ok(RelinquishOutputResult { relinquished: true })
    }

    async fn get_public_key(
        &self,
        _args: GetPublicKeyArgs,
        _originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        Ok(GetPublicKeyResult {
            public_key: anyone_pubkey(),
        })
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        let pk = anyone_pubkey();
        Ok(RevealCounterpartyKeyLinkageResult {
            prover: pk.clone(),
            counterparty: pk.clone(),
            verifier: pk,
            revelation_time: "2026-01-01T00:00:00Z".to_string(),
            encrypted_linkage: vec![1, 2, 3],
            encrypted_linkage_proof: vec![4, 5, 6],
        })
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        let pk = anyone_pubkey();
        Ok(RevealSpecificKeyLinkageResult {
            encrypted_linkage: vec![7, 8, 9],
            encrypted_linkage_proof: vec![10, 11],
            prover: pk.clone(),
            verifier: pk.clone(),
            counterparty: pk,
            protocol_id: Protocol {
                security_level: 2,
                protocol: "test".to_string(),
            },
            key_id: "key1".to_string(),
            proof_type: 1,
        })
    }

    async fn encrypt(
        &self,
        args: EncryptArgs,
        _originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        // Mock: return plaintext reversed as "ciphertext"
        let mut ct = args.plaintext.clone();
        ct.reverse();
        Ok(EncryptResult { ciphertext: ct })
    }

    async fn decrypt(
        &self,
        args: DecryptArgs,
        _originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        let mut pt = args.ciphertext.clone();
        pt.reverse();
        Ok(DecryptResult { plaintext: pt })
    }

    async fn create_hmac(
        &self,
        _args: CreateHmacArgs,
        _originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        Ok(CreateHmacResult {
            hmac: vec![0xAA; 32],
        })
    }

    async fn verify_hmac(
        &self,
        _args: VerifyHmacArgs,
        _originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        Ok(VerifyHmacResult { valid: true })
    }

    async fn create_signature(
        &self,
        _args: CreateSignatureArgs,
        _originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        Ok(CreateSignatureResult {
            signature: vec![0xBB; 64],
        })
    }

    async fn verify_signature(
        &self,
        _args: VerifySignatureArgs,
        _originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        Ok(VerifySignatureResult { valid: true })
    }

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        Ok(Certificate {
            cert_type: CertificateType([0u8; 32]),
            serial_number: SerialNumber([1u8; 32]),
            subject: anyone_pubkey(),
            certifier: anyone_pubkey(),
            revocation_outpoint: None,
            fields: Some(HashMap::new()),
            signature: None,
        })
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        Ok(ListCertificatesResult {
            total_certificates: 0,
            certificates: vec![],
        })
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        Ok(ProveCertificateResult {
            keyring_for_verifier: HashMap::new(),
            certificate: None,
            verifier: None,
        })
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        Ok(RelinquishCertificateResult { relinquished: true })
    }

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Ok(DiscoverCertificatesResult {
            total_certificates: 0,
            certificates: vec![],
        })
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Ok(DiscoverCertificatesResult {
            total_certificates: 0,
            certificates: vec![],
        })
    }

    async fn is_authenticated(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(
        &self,
        _originator: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _originator: Option<&str>) -> Result<GetHeightResult, WalletError> {
        Ok(GetHeightResult { height: 850000 })
    }

    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        _originator: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        Ok(GetHeaderResult {
            header: vec![0u8; 80],
        })
    }

    async fn get_network(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetNetworkResult, WalletError> {
        Ok(GetNetworkResult {
            network: Network::Mainnet,
        })
    }

    async fn get_version(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetVersionResult, WalletError> {
        Ok(GetVersionResult {
            version: "0.1.3".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helper: create a transceiver wired through a processor to the mock wallet
// ---------------------------------------------------------------------------

fn make_transceiver() -> WalletWireTransceiver<WalletWireProcessor<MockWallet>> {
    let processor = WalletWireProcessor::new(MockWallet);
    WalletWireTransceiver::new(processor)
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_encrypt_round_trip() {
    let t = make_transceiver();
    let result = t
        .encrypt(
            EncryptArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "test-protocol".to_string(),
                },
                key_id: "key1".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                plaintext: vec![1, 2, 3, 4, 5],
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            Some("test-app"),
        )
        .await
        .unwrap();
    // MockWallet reverses plaintext
    assert_eq!(result.ciphertext, vec![5, 4, 3, 2, 1]);
}

#[tokio::test]
async fn test_decrypt_round_trip() {
    let t = make_transceiver();
    let result = t
        .decrypt(
            DecryptArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "test-protocol".to_string(),
                },
                key_id: "key1".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                ciphertext: vec![10, 20, 30],
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.plaintext, vec![30, 20, 10]);
}

#[tokio::test]
async fn test_is_authenticated_round_trip() {
    let t = make_transceiver();
    let result = t.is_authenticated(Some("app")).await.unwrap();
    assert!(result.authenticated);
}

#[tokio::test]
async fn test_get_height_round_trip() {
    let t = make_transceiver();
    let result = t.get_height(None).await.unwrap();
    assert_eq!(result.height, 850000);
}

#[tokio::test]
async fn test_get_version_round_trip() {
    let t = make_transceiver();
    let result = t.get_version(None).await.unwrap();
    assert_eq!(result.version, "0.1.3");
}

#[tokio::test]
async fn test_get_network_round_trip() {
    let t = make_transceiver();
    let result = t.get_network(None).await.unwrap();
    assert_eq!(result.network, Network::Mainnet);
}

#[tokio::test]
async fn test_abort_action_round_trip() {
    let t = make_transceiver();
    let result = t
        .abort_action(
            AbortActionArgs {
                reference: vec![1, 2, 3],
            },
            None,
        )
        .await
        .unwrap();
    assert!(result.aborted);
}

#[tokio::test]
async fn test_create_hmac_round_trip() {
    let t = make_transceiver();
    let result = t
        .create_hmac(
            CreateHmacArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "hmac-test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: vec![1, 2, 3],
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.hmac, vec![0xAA; 32]);
}

#[tokio::test]
async fn test_verify_hmac_round_trip() {
    let t = make_transceiver();
    let result = t
        .verify_hmac(
            VerifyHmacArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "hmac-test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: vec![1, 2, 3],
                hmac: vec![0xAA; 32],
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert!(result.valid);
}

#[tokio::test]
async fn test_create_signature_round_trip() {
    let t = make_transceiver();
    let result = t
        .create_signature(
            CreateSignatureArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "sig-test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: Some(vec![1, 2, 3]),
                hash_to_directly_sign: None,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.signature, vec![0xBB; 64]);
}

#[tokio::test]
async fn test_verify_signature_round_trip() {
    let t = make_transceiver();
    let result = t
        .verify_signature(
            VerifySignatureArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "sig-test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                data: Some(vec![1, 2, 3]),
                hash_to_directly_verify: None,
                signature: vec![0xBB; 64],
                for_self: None,
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert!(result.valid);
}

#[tokio::test]
async fn test_get_public_key_round_trip() {
    let t = make_transceiver();
    let result = t
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                privileged: false,
                privileged_reason: None,
                for_self: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    // Should get the anyone pubkey back
    assert_eq!(result.public_key.to_der(), anyone_pubkey().to_der());
}

#[tokio::test]
async fn test_get_header_for_height_round_trip() {
    let t = make_transceiver();
    let result = t
        .get_header_for_height(GetHeaderArgs { height: 100 }, None)
        .await
        .unwrap();
    assert_eq!(result.header.len(), 80);
}

#[tokio::test]
async fn test_wait_for_authentication_round_trip() {
    let t = make_transceiver();
    let result = t.wait_for_authentication(None).await.unwrap();
    assert!(result.authenticated);
}

// ---------------------------------------------------------------------------
// WalletClient tests: validation rejects before wire call
// ---------------------------------------------------------------------------

use crate::wallet::substrates::WalletClient;

fn make_client() -> WalletClient<WalletWireProcessor<MockWallet>> {
    let processor = WalletWireProcessor::new(MockWallet);
    WalletClient::new(processor)
}

#[tokio::test]
async fn test_wallet_client_validation_rejects_empty_plaintext() {
    let client = make_client();
    let result = client
        .encrypt(
            EncryptArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                plaintext: vec![], // Empty -- should be rejected
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        WalletError::InvalidParameter(_) => {} // expected
        other => panic!("expected InvalidParameter, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_wallet_client_valid_encrypt_passes_through() {
    let client = make_client();
    let result = client
        .encrypt(
            EncryptArgs {
                protocol_id: Protocol {
                    security_level: 2,
                    protocol: "test".to_string(),
                },
                key_id: "k".to_string(),
                counterparty: Counterparty {
                    counterparty_type: CounterpartyType::Self_,
                    public_key: None,
                },
                plaintext: vec![1, 2, 3],
                privileged: false,
                privileged_reason: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.ciphertext, vec![3, 2, 1]); // MockWallet reverses
}

#[tokio::test]
async fn test_wallet_client_is_authenticated_delegates() {
    let client = make_client();
    let result = client.is_authenticated(None).await.unwrap();
    assert!(result.authenticated);
}

#[tokio::test]
async fn test_wallet_client_get_version_delegates() {
    let client = make_client();
    let result = client.get_version(None).await.unwrap();
    assert_eq!(result.version, "0.1.3");
}

// ---------------------------------------------------------------------------
// WalletWireCall tests (already in wallet_wire_calls.rs but extra coverage)
// ---------------------------------------------------------------------------

#[test]
fn test_call_code_round_trip_all() {
    for code in 1u8..=28 {
        let call = WalletWireCall::try_from(code).unwrap();
        assert_eq!(call as u8, code);
        // Verify path is non-empty
        assert!(!call.to_call_path().is_empty());
    }
}

// ---------------------------------------------------------------------------
// JSON round-trip tests for serde serialization (network feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "network")]
mod json_round_trip {
    use crate::wallet::interfaces::*;
    use crate::wallet::types::*;
    use std::collections::HashMap;

    #[test]
    fn test_encrypt_args_json_round_trip() {
        let args = EncryptArgs {
            protocol_id: Protocol {
                security_level: 2,
                protocol: "test-protocol".to_string(),
            },
            key_id: "key1".to_string(),
            counterparty: Counterparty {
                counterparty_type: CounterpartyType::Self_,
                public_key: None,
            },
            plaintext: vec![1, 2, 3, 4, 5],
            privileged: false,
            privileged_reason: None,
            seek_permission: None,
        };

        let json = serde_json::to_string(&args).unwrap();
        let deserialized: EncryptArgs = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.key_id, "key1");
        assert_eq!(deserialized.plaintext, vec![1, 2, 3, 4, 5]);
        assert_eq!(deserialized.protocol_id.security_level, 2);
        assert_eq!(deserialized.protocol_id.protocol, "test-protocol");
        assert_eq!(
            deserialized.counterparty.counterparty_type,
            CounterpartyType::Self_
        );
    }

    #[test]
    fn test_protocol_json_as_array() {
        let proto = Protocol {
            security_level: 2,
            protocol: "test".to_string(),
        };
        let json = serde_json::to_string(&proto).unwrap();
        assert_eq!(json, r#"[2,"test"]"#);

        let deserialized: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.security_level, 2);
        assert_eq!(deserialized.protocol, "test");
    }

    #[test]
    fn test_counterparty_json_self() {
        let cp = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert_eq!(json, r#""self""#);

        let deserialized: Counterparty = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.counterparty_type, CounterpartyType::Self_);
    }

    #[test]
    fn test_counterparty_json_anyone() {
        let cp = Counterparty {
            counterparty_type: CounterpartyType::Anyone,
            public_key: None,
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert_eq!(json, r#""anyone""#);

        let deserialized: Counterparty = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.counterparty_type, CounterpartyType::Anyone);
    }

    #[test]
    fn test_counterparty_json_other_pubkey() {
        let pk = anyone_pubkey();
        let cp = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pk.clone()),
        };
        let json = serde_json::to_string(&cp).unwrap();
        // Should be a hex pubkey string
        let hex: String = serde_json::from_str(&json).unwrap();
        assert!(hex.len() == 66); // compressed DER hex is 33 bytes = 66 hex chars

        let deserialized: Counterparty = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.counterparty_type, CounterpartyType::Other);
        assert!(deserialized.public_key.is_some());
        assert_eq!(deserialized.public_key.unwrap().to_der(), pk.to_der());
    }

    #[test]
    fn test_get_public_key_args_json_round_trip() {
        let args = GetPublicKeyArgs {
            identity_key: true,
            protocol_id: Some(Protocol {
                security_level: 1,
                protocol: "identity".to_string(),
            }),
            key_id: Some("default".to_string()),
            counterparty: None,
            privileged: false,
            privileged_reason: None,
            for_self: None,
            seek_permission: None,
        };

        let json = serde_json::to_string(&args).unwrap();
        // Verify protocolID uses correct JSON field name
        assert!(json.contains(r#""protocolID":[1,"identity"]"#));
        assert!(json.contains(r#""keyID":"default""#));
        assert!(json.contains(r#""identityKey":true"#));

        let deserialized: GetPublicKeyArgs = serde_json::from_str(&json).unwrap();
        assert!(deserialized.identity_key);
        assert_eq!(deserialized.protocol_id.unwrap().security_level, 1);
    }

    #[test]
    fn test_create_action_args_json_round_trip() {
        let args = CreateActionArgs {
            description: "test action".to_string(),
            input_beef: None,
            inputs: vec![],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec!["label1".to_string()],
            options: None,
            reference: None,
        };

        let json = serde_json::to_string(&args).unwrap();
        let deserialized: CreateActionArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.description, "test action");
        assert_eq!(deserialized.labels, vec!["label1".to_string()]);
    }

    #[test]
    fn test_list_actions_args_json_round_trip() {
        let args = ListActionsArgs {
            labels: vec!["payment".to_string()],
            label_query_mode: Some(QueryMode::Any),
            include_labels: BooleanDefaultFalse(None),
            include_inputs: BooleanDefaultFalse(Some(true)),
            include_input_source_locking_scripts: BooleanDefaultFalse(None),
            include_input_unlocking_scripts: BooleanDefaultFalse(None),
            include_outputs: BooleanDefaultFalse(None),
            include_output_locking_scripts: BooleanDefaultFalse(None),
            limit: Some(25),
            offset: None,
            seek_permission: BooleanDefaultTrue(None),
        };

        let json = serde_json::to_string(&args).unwrap();
        let deserialized: ListActionsArgs = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.labels, vec!["payment".to_string()]);
        assert_eq!(deserialized.limit, Some(25));
    }

    #[test]
    fn test_action_status_json_serialization() {
        let statuses = vec![
            (ActionStatus::Completed, "\"completed\""),
            (ActionStatus::Unprocessed, "\"unprocessed\""),
            (ActionStatus::Sending, "\"sending\""),
            (ActionStatus::Unproven, "\"unproven\""),
            (ActionStatus::Unsigned, "\"unsigned\""),
            (ActionStatus::NoSend, "\"nosend\""),
            (ActionStatus::NonFinal, "\"nonfinal\""),
            (ActionStatus::Failed, "\"failed\""),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(
                json, expected,
                "ActionStatus::{:?} serialized incorrectly",
                status
            );
            let deserialized: ActionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_query_mode_json_serialization() {
        let json = serde_json::to_string(&QueryMode::Any).unwrap();
        assert_eq!(json, "\"any\"");
        let json = serde_json::to_string(&QueryMode::All).unwrap();
        assert_eq!(json, "\"all\"");
    }

    #[test]
    fn test_network_json_serialization() {
        let json = serde_json::to_string(&Network::Mainnet).unwrap();
        assert_eq!(json, "\"mainnet\"");
        let deserialized: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Network::Mainnet);

        let json = serde_json::to_string(&Network::Testnet).unwrap();
        assert_eq!(json, "\"testnet\"");
    }

    #[test]
    fn test_certificate_type_json_base64_round_trip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01;
        bytes[1] = 0x02;
        bytes[31] = 0xFF;
        let ct = CertificateType(bytes);

        let json = serde_json::to_string(&ct).unwrap();
        // Should be a base64 string
        let s: String = serde_json::from_str(&json).unwrap();
        assert!(!s.is_empty());

        let deserialized: CertificateType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.0, bytes);
    }

    #[test]
    fn test_serial_number_json_base64_round_trip() {
        let bytes = [0xAA; 32];
        let sn = SerialNumber(bytes);

        let json = serde_json::to_string(&sn).unwrap();
        let deserialized: SerialNumber = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.0, bytes);
    }

    #[test]
    fn test_keyring_revealer_json_certifier() {
        let kr = KeyringRevealer::Certifier;
        let json = serde_json::to_string(&kr).unwrap();
        assert_eq!(json, r#""certifier""#);

        let deserialized: KeyringRevealer = serde_json::from_str(&json).unwrap();
        match deserialized {
            KeyringRevealer::Certifier => {}
            _ => panic!("expected Certifier"),
        }
    }

    #[test]
    fn test_keyring_revealer_json_pubkey() {
        let pk = anyone_pubkey();
        let kr = KeyringRevealer::PubKey(pk.clone());
        let json = serde_json::to_string(&kr).unwrap();

        let deserialized: KeyringRevealer = serde_json::from_str(&json).unwrap();
        match deserialized {
            KeyringRevealer::PubKey(deserialized_pk) => {
                assert_eq!(deserialized_pk.to_der(), pk.to_der());
            }
            _ => panic!("expected PubKey"),
        }
    }

    #[test]
    fn test_output_include_json_serialization() {
        let json = serde_json::to_string(&OutputInclude::LockingScripts).unwrap();
        assert_eq!(json, r#""locking scripts""#);
        let json = serde_json::to_string(&OutputInclude::EntireTransactions).unwrap();
        assert_eq!(json, r#""entire transactions""#);
    }

    #[test]
    fn test_internalize_protocol_json_serialization() {
        let json = serde_json::to_string(&InternalizeProtocol::WalletPayment).unwrap();
        assert_eq!(json, r#""wallet payment""#);
        let json = serde_json::to_string(&InternalizeProtocol::BasketInsertion).unwrap();
        assert_eq!(json, r#""basket insertion""#);
    }

    #[test]
    fn test_authenticated_result_json_round_trip() {
        let result = AuthenticatedResult {
            authenticated: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(json, r#"{"authenticated":true}"#);
        let deserialized: AuthenticatedResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.authenticated);
    }

    #[test]
    fn test_get_height_result_json_round_trip() {
        let result = GetHeightResult { height: 850000 };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GetHeightResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.height, 850000);
    }

    #[test]
    fn test_get_version_result_json_round_trip() {
        let result = GetVersionResult {
            version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GetVersionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, "1.0.0");
    }

    #[test]
    fn test_get_network_result_json_round_trip() {
        let result = GetNetworkResult {
            network: Network::Mainnet,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"mainnet\""));
        let deserialized: GetNetworkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.network, Network::Mainnet);
    }

    #[test]
    fn test_get_header_result_json_hex() {
        let result = GetHeaderResult {
            header: vec![0x00, 0xFF, 0xAB],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"00ffab\""));
        let deserialized: GetHeaderResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.header, vec![0x00, 0xFF, 0xAB]);
    }

    #[test]
    fn test_public_key_json_hex_round_trip() {
        let pk = anyone_pubkey();
        let result = GetPublicKeyResult {
            public_key: pk.clone(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GetPublicKeyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.public_key.to_der(), pk.to_der());
    }

    #[test]
    fn test_encrypt_result_json_round_trip() {
        let result = EncryptResult {
            ciphertext: vec![10, 20, 30],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: EncryptResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ciphertext, vec![10, 20, 30]);
    }

    #[test]
    fn test_create_signature_result_array_round_trip() {
        let result = CreateSignatureResult {
            signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let json = serde_json::to_string(&result).unwrap();
        // Signature serializes as a JSON number array (matching TS Byte[] and Go BytesList),
        // not as a hex string — BSV Desktop returns [222,173,190,239] not "deadbeef".
        assert!(json.contains("[222,173,190,239]"));
        let deserialized: CreateSignatureResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.signature, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_acquisition_protocol_json() {
        let json = serde_json::to_string(&AcquisitionProtocol::Direct).unwrap();
        assert_eq!(json, "\"direct\"");
        let json = serde_json::to_string(&AcquisitionProtocol::Issuance).unwrap();
        assert_eq!(json, "\"issuance\"");
    }
}
