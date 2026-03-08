//! Dispatch overhead benchmark: RPITIT vs async-trait for WalletInterface.
//!
//! Measures the per-call overhead of dynamic dispatch (async-trait with
//! `Pin<Box<dyn Future + Send>>`) vs static dispatch (RPITIT / direct call)
//! for wallet interface methods.
//!
//! This benchmark is part of the Phase 10 object-safety evaluation for
//! WalletInterface and WalletWire traits.

use async_trait::async_trait;
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, Certificate, CreateActionArgs,
    CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult,
    WalletInterface,
};
use bsv::wallet::types::Protocol;

// ---------------------------------------------------------------------------
// NoOpWallet: minimal WalletInterface impl returning default/empty results
// ---------------------------------------------------------------------------

struct NoOpWallet;

#[allow(async_fn_in_trait)]
impl WalletInterface for NoOpWallet {
    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        Ok(CreateActionResult {
            txid: None,
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
            txid: None,
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
            public_key: bsv::primitives::public_key::PublicKey::from_private_key(
                &bsv::primitives::private_key::PrivateKey::from_hex("1")
                    .expect("valid hex"),
            ),
        })
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        Err(WalletError::NotImplemented(
            "reveal_counterparty_key_linkage".into(),
        ))
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
        _originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        Err(WalletError::NotImplemented(
            "reveal_specific_key_linkage".into(),
        ))
    }

    async fn encrypt(
        &self,
        _args: EncryptArgs,
        _originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        Ok(EncryptResult {
            ciphertext: vec![0u8; 32],
        })
    }

    async fn decrypt(
        &self,
        _args: DecryptArgs,
        _originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        Ok(DecryptResult {
            plaintext: vec![0u8; 32],
        })
    }

    async fn create_hmac(
        &self,
        _args: CreateHmacArgs,
        _originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        Ok(CreateHmacResult {
            hmac: vec![0u8; 32],
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
            signature: vec![0u8; 64],
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
        Err(WalletError::NotImplemented("acquire_certificate".into()))
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
        Err(WalletError::NotImplemented("prove_certificate".into()))
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
    ) -> Result<bsv::wallet::interfaces::AuthenticatedResult, WalletError> {
        Ok(bsv::wallet::interfaces::AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(
        &self,
        _originator: Option<&str>,
    ) -> Result<bsv::wallet::interfaces::AuthenticatedResult, WalletError> {
        Ok(bsv::wallet::interfaces::AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetHeightResult, WalletError> {
        Ok(GetHeightResult { height: 800000 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
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
            network: bsv::wallet::interfaces::Network::Mainnet,
        })
    }

    async fn get_version(
        &self,
        _originator: Option<&str>,
    ) -> Result<GetVersionResult, WalletError> {
        Ok(GetVersionResult {
            version: "0.1.0".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// WalletInterfaceBoxed: async-trait version for comparison
// ---------------------------------------------------------------------------

/// A minimal trait using `#[async_trait]` with a single method matching
/// `WalletInterface::get_public_key`. This creates the full boxing +
/// dynamic dispatch overhead without modifying the real WalletInterface trait.
#[async_trait]
trait WalletInterfaceBoxed: Send + Sync {
    async fn get_public_key_boxed(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError>;
}

#[async_trait]
impl WalletInterfaceBoxed for NoOpWallet {
    async fn get_public_key_boxed(
        &self,
        _args: GetPublicKeyArgs,
        _originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        Ok(GetPublicKeyResult {
            public_key: bsv::primitives::public_key::PublicKey::from_private_key(
                &bsv::primitives::private_key::PrivateKey::from_hex("1")
                    .expect("valid hex"),
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Helper: build a GetPublicKeyArgs for benchmarking
// ---------------------------------------------------------------------------

fn make_get_pk_args() -> GetPublicKeyArgs {
    GetPublicKeyArgs {
        identity_key: false,
        protocol_id: Some(Protocol {
            protocol: "tests".into(),
            security_level: 2,
        }),
        key_id: Some("bench-key".into()),
        counterparty: None,
        privileged: false,
        privileged_reason: None,
        for_self: Some(false),
        seek_permission: None,
    }
}

// ---------------------------------------------------------------------------
// Generic caller for RPITIT (static dispatch through monomorphization)
// ---------------------------------------------------------------------------

async fn call_rpitit_generic<W: WalletInterface>(w: &W) -> GetPublicKeyResult {
    let args = make_get_pk_args();
    w.get_public_key(args, None).await.expect("no-op should succeed")
}

// ---------------------------------------------------------------------------
// Dynamic dispatch caller for async-trait (virtual dispatch via vtable)
// ---------------------------------------------------------------------------

async fn call_boxed_dyn(w: &dyn WalletInterfaceBoxed) -> GetPublicKeyResult {
    let args = make_get_pk_args();
    w.get_public_key_boxed(args, None).await.expect("no-op should succeed")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn dispatch_benchmarks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut group = c.benchmark_group("dispatch_bench");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(2));

    let wallet = NoOpWallet;

    // 1. Direct call on concrete type (RPITIT baseline)
    group.bench_function("rpitit_direct", |bencher| {
        bencher.iter(|| {
            rt.block_on(async {
                let args = make_get_pk_args();
                criterion::black_box(
                    wallet
                        .get_public_key(args, None)
                        .await
                        .expect("no-op should succeed"),
                )
            })
        });
    });

    // 2. Generic function call (RPITIT generic dispatch / monomorphization)
    group.bench_function("rpitit_generic", |bencher| {
        bencher.iter(|| {
            rt.block_on(async {
                criterion::black_box(call_rpitit_generic(&wallet).await)
            })
        });
    });

    // 3. Dynamic dispatch via async-trait boxed future (dyn WalletInterfaceBoxed)
    let wallet_boxed: &dyn WalletInterfaceBoxed = &wallet;
    group.bench_function("async_trait_dyn", |bencher| {
        bencher.iter(|| {
            rt.block_on(async {
                criterion::black_box(call_boxed_dyn(wallet_boxed).await)
            })
        });
    });

    group.finish();
}

criterion_group!(benches, dispatch_benchmarks);
criterion_main!(benches);
