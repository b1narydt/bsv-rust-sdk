//! Microbenchmark isolating the per-message cost of the BRC-103 mutual-auth
//! path in the BSV Rust SDK, with NO network involved.
//!
//! Goal: determine whether the ~66 ms/message observed on the remote relay is
//! the SDK's per-message crypto, or whether it is network/relay/DB.
//!
//! All work runs in-process over a `MockTransport` (tokio mpsc channels). The
//! handshake is performed ONCE, outside every timed loop; the timed loops only
//! exercise the warm-session create/verify path and the underlying primitives.
//!
//! Requires the `network` feature (the `auth::peer` module is gated on it):
//!   cargo bench --features network --bench auth_message_bench

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use async_trait::async_trait;
use tokio::sync::mpsc;

use bsv::auth::peer::Peer;
use bsv::auth::transports::Transport;
use bsv::auth::types::AuthMessage;
use bsv::auth::AuthError;

use bsv::primitives::base_point::BasePoint;
use bsv::primitives::big_number::BigNumber;
use bsv::primitives::ecdsa::{ecdsa_sign, ecdsa_verify};
use bsv::primitives::hash::sha256;
use bsv::primitives::private_key::PrivateKey;

use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::*;
use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol as WalletProtocol};
use bsv::wallet::ProtoWallet;

// ---------------------------------------------------------------------------
// TestWallet: WalletInterface wrapper around ProtoWallet
// (mirrors the #[cfg(test)] TestWallet in src/auth/peer.rs; only the methods
//  the auth path actually calls are implemented, the rest are stubs.)
// ---------------------------------------------------------------------------

struct TestWallet {
    inner: ProtoWallet,
}

impl TestWallet {
    fn new(pk: PrivateKey) -> Self {
        TestWallet {
            inner: ProtoWallet::new(pk),
        }
    }
}

macro_rules! stub_method {
    ($name:ident, $args:ty, $ret:ty) => {
        fn $name<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _args: $args,
            _originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                unimplemented!(concat!(stringify!($name), " not needed for auth bench"))
            })
        }
    };
    ($name:ident, $ret:ty) => {
        fn $name<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _originator: Option<&'life1 str>,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = Result<$ret, WalletError>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                unimplemented!(concat!(stringify!($name), " not needed for auth bench"))
            })
        }
    };
}

#[async_trait::async_trait]
impl WalletInterface for TestWallet {
    stub_method!(create_action, CreateActionArgs, CreateActionResult);
    stub_method!(sign_action, SignActionArgs, SignActionResult);
    stub_method!(abort_action, AbortActionArgs, AbortActionResult);
    stub_method!(list_actions, ListActionsArgs, ListActionsResult);
    stub_method!(
        internalize_action,
        InternalizeActionArgs,
        InternalizeActionResult
    );
    stub_method!(list_outputs, ListOutputsArgs, ListOutputsResult);
    stub_method!(
        relinquish_output,
        RelinquishOutputArgs,
        RelinquishOutputResult
    );

    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        _originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        let protocol = args.protocol_id.unwrap_or(WalletProtocol {
            security_level: 0,
            protocol: String::new(),
        });
        let key_id = args.key_id.unwrap_or_default();
        let counterparty = args.counterparty.unwrap_or(Counterparty {
            counterparty_type: CounterpartyType::Uninitialized,
            public_key: None,
        });
        let pk = self.inner.get_public_key_sync(
            &protocol,
            &key_id,
            &counterparty,
            args.for_self.unwrap_or(false),
            args.identity_key,
        )?;
        Ok(GetPublicKeyResult { public_key: pk })
    }

    stub_method!(
        reveal_counterparty_key_linkage,
        RevealCounterpartyKeyLinkageArgs,
        RevealCounterpartyKeyLinkageResult
    );
    stub_method!(
        reveal_specific_key_linkage,
        RevealSpecificKeyLinkageArgs,
        RevealSpecificKeyLinkageResult
    );

    async fn encrypt(
        &self,
        args: EncryptArgs,
        _originator: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        let ciphertext = self.inner.encrypt_sync(
            &args.plaintext,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(EncryptResult { ciphertext })
    }

    async fn decrypt(
        &self,
        args: DecryptArgs,
        _originator: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        let plaintext = self.inner.decrypt_sync(
            &args.ciphertext,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(DecryptResult { plaintext })
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        _originator: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        let hmac = self.inner.create_hmac_sync(
            &args.data,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(CreateHmacResult { hmac })
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        _originator: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        let valid = self.inner.verify_hmac_sync(
            &args.data,
            &args.hmac,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(VerifyHmacResult { valid })
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        _originator: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        let signature = self.inner.create_signature_sync(
            args.data.as_deref(),
            args.hash_to_directly_sign.as_deref(),
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
        )?;
        Ok(CreateSignatureResult { signature })
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        _originator: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        let valid = self.inner.verify_signature_sync(
            args.data.as_deref(),
            args.hash_to_directly_verify.as_deref(),
            &args.signature,
            &args.protocol_id,
            &args.key_id,
            &args.counterparty,
            args.for_self.unwrap_or(false),
        )?;
        Ok(VerifySignatureResult { valid })
    }

    stub_method!(acquire_certificate, AcquireCertificateArgs, Certificate);
    stub_method!(
        list_certificates,
        ListCertificatesArgs,
        ListCertificatesResult
    );
    stub_method!(
        prove_certificate,
        ProveCertificateArgs,
        ProveCertificateResult
    );
    stub_method!(
        relinquish_certificate,
        RelinquishCertificateArgs,
        RelinquishCertificateResult
    );
    stub_method!(
        discover_by_identity_key,
        DiscoverByIdentityKeyArgs,
        DiscoverCertificatesResult
    );
    stub_method!(
        discover_by_attributes,
        DiscoverByAttributesArgs,
        DiscoverCertificatesResult
    );
    stub_method!(is_authenticated, AuthenticatedResult);
    stub_method!(wait_for_authentication, AuthenticatedResult);
    stub_method!(get_height, GetHeightResult);
    stub_method!(get_header_for_height, GetHeaderArgs, GetHeaderResult);
    stub_method!(get_network, GetNetworkResult);
    stub_method!(get_version, GetVersionResult);
}

// ---------------------------------------------------------------------------
// MockTransport: in-memory transport that routes between two peers
// (mirrors the #[cfg(test)] MockTransport in src/auth/peer.rs)
// ---------------------------------------------------------------------------

struct MockTransport {
    peer_tx: mpsc::Sender<AuthMessage>,
    incoming_rx: StdMutex<Option<mpsc::Receiver<AuthMessage>>>,
}

fn create_mock_transport_pair() -> (Arc<MockTransport>, Arc<MockTransport>) {
    let (tx_a, rx_a) = mpsc::channel(64);
    let (tx_b, rx_b) = mpsc::channel(64);

    let transport_a = Arc::new(MockTransport {
        peer_tx: tx_b,
        incoming_rx: StdMutex::new(Some(rx_a)),
    });
    let transport_b = Arc::new(MockTransport {
        peer_tx: tx_a,
        incoming_rx: StdMutex::new(Some(rx_b)),
    });
    (transport_a, transport_b)
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        self.peer_tx
            .send(message)
            .await
            .map_err(|e| AuthError::TransportError(format!("mock send failed: {}", e)))
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        self.incoming_rx
            .lock()
            .unwrap()
            .take()
            .expect("subscribe() already called on MockTransport")
    }
}

// ---------------------------------------------------------------------------
// Helpers: identity key for a wallet, and an established two-peer session.
// ---------------------------------------------------------------------------

async fn identity_key(wallet: &TestWallet) -> String {
    wallet
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
        .unwrap()
        .public_key
        .to_der_hex()
}

/// Perform a full handshake ONCE over the mock transport and return the two
/// peers plus their identity keys, with an authenticated session in place on
/// both sides. This is the warm-session starting point for the timed loops.
async fn establish_session() -> (
    Arc<Peer<TestWallet>>,
    Arc<Peer<TestWallet>>,
    String, // identity_a
    String, // identity_b
) {
    let wallet_a = TestWallet::new(PrivateKey::from_random().unwrap());
    let wallet_b = TestWallet::new(PrivateKey::from_random().unwrap());

    let identity_a = identity_key(&wallet_a).await;
    let identity_b = identity_key(&wallet_b).await;

    let (transport_a, transport_b) = create_mock_transport_pair();
    let peer_a = Arc::new(Peer::new(wallet_a, transport_a));
    let peer_b = Arc::new(Peer::new(wallet_b, transport_b));

    // Drain peer B's general-message channel so the bounded channel never
    // backpressures during the handshake's general message.
    let _msg_rx_b = peer_b.on_general_message().unwrap();

    // Peer A initiates by sending a message; this blocks on the handshake until
    // B replies. Drive both sides manually with process_pending() in a loop.
    let peer_a2 = peer_a.clone();
    let identity_b2 = identity_b.clone();
    let send_handle = tokio::task::spawn_local(async move {
        peer_a2
            .send_message(&identity_b2, b"warmup-handshake".to_vec())
            .await
            .unwrap();
    });

    // Pump messages between the two peers until the handshake completes.
    // (initialRequest -> B; initialResponse -> A; general -> B)
    for _ in 0..50 {
        tokio::task::yield_now().await;
        let _ = peer_b.process_pending().await.unwrap();
        let _ = peer_a.process_pending().await.unwrap();
        if send_handle.is_finished() {
            // Final drain so B ingests the trailing general message.
            let _ = peer_b.process_pending().await.unwrap();
            break;
        }
    }
    send_handle.await.unwrap();

    // Sanity: both sides authenticated.
    let sa = peer_a.sessions_for_identity(&identity_b).await;
    let sb = peer_b.sessions_for_identity(&identity_a).await;
    assert!(
        sa.iter().any(|s| s.is_authenticated),
        "peer A must have an authenticated session"
    );
    assert!(
        sb.iter().any(|s| s.is_authenticated),
        "peer B must have an authenticated session"
    );

    (peer_a, peer_b, identity_a, identity_b)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn auth_benchmarks(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    // ---- 1. Warm-session round trip: create on A, verify on B ------------
    {
        // A creates messages addressed to B; the session identifier is B's
        // identity key (the session A holds for its counterparty B).
        let (peer_a, peer_b, _identity_a, identity_b) = local.block_on(&rt, establish_session());
        let session_id = identity_b;

        // B verifies by `your_nonce`; let A create a message and confirm B
        // verifies it once outside the loop (validates the warm path).
        let probe = local.block_on(&rt, async {
            peer_a
                .create_general_message(&session_id, b"probe".to_vec())
                .await
                .unwrap()
        });
        local.block_on(&rt, async {
            peer_b.verify_general_message(probe).await.unwrap();
        });

        let payload = b"hello from peer A over a warm session".to_vec();

        let mut group = c.benchmark_group("auth_warm_session");
        group.measurement_time(Duration::from_secs(8));
        group.sample_size(50);

        // The realistic target: full per-message round trip (sign + verify).
        group.bench_function("roundtrip_create_then_verify", |b| {
            b.iter(|| {
                local.block_on(&rt, async {
                    let msg = peer_a
                        .create_general_message(&session_id, payload.clone())
                        .await
                        .unwrap();
                    peer_b
                        .verify_general_message(criterion::black_box(msg))
                        .await
                        .unwrap();
                });
            });
        });

        // Outbound only: create_general_message (sign).
        group.bench_function("create_general_message_only", |b| {
            b.iter(|| {
                local.block_on(&rt, async {
                    let msg = peer_a
                        .create_general_message(&session_id, payload.clone())
                        .await
                        .unwrap();
                    criterion::black_box(msg);
                });
            });
        });

        // Inbound only: verify_general_message (HMAC nonce verify + sig verify).
        // Pre-create a batch of messages so verify is isolated from create.
        let prebuilt: Vec<AuthMessage> = local.block_on(&rt, async {
            let mut v = Vec::with_capacity(256);
            for _ in 0..256 {
                v.push(
                    peer_a
                        .create_general_message(&session_id, payload.clone())
                        .await
                        .unwrap(),
                );
            }
            v
        });
        let idx = std::cell::Cell::new(0usize);
        group.bench_function("verify_general_message_only", |b| {
            b.iter(|| {
                local.block_on(&rt, async {
                    let i = idx.get();
                    idx.set((i + 1) % prebuilt.len());
                    peer_b
                        .verify_general_message(criterion::black_box(prebuilt[i].clone()))
                        .await
                        .unwrap();
                });
            });
        });

        group.finish();
    }

    // ---- 2. Primitives in isolation, via ProtoWallet sync API ------------
    {
        use bsv::wallet::types::{Counterparty, CounterpartyType, Protocol};

        let sk_a = PrivateKey::from_random().unwrap();
        let sk_b = PrivateKey::from_random().unwrap();
        let pub_b = sk_b.to_public_key();
        let pub_a = sk_a.to_public_key();
        let w_a = ProtoWallet::new(sk_a);
        let w_b = ProtoWallet::new(sk_b);

        // Mirror the exact protocol/keyID/counterparty shape used by the auth
        // general-message path (security level 2, AUTH protocol, peer counterparty,
        // fresh nonce-ish keyID).
        let proto = Protocol {
            security_level: 2,
            protocol: "auth message signature".to_string(),
        };
        let key_id = "abc123nonce def456nonce".to_string();
        let cp_to_b = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pub_b.clone()),
        };
        let cp_to_a = Counterparty {
            counterparty_type: CounterpartyType::Other,
            public_key: Some(pub_a.clone()),
        };
        let payload = b"hello from peer A over a warm session".to_vec();

        // Produce a signature A->B that B can verify (B derives pub from A as
        // counterparty). Sanity-check it round-trips.
        let sig = w_a
            .create_signature_sync(Some(&payload), None, &proto, &key_id, &cp_to_b)
            .unwrap();
        let ok = w_b
            .verify_signature_sync(Some(&payload), None, &sig, &proto, &key_id, &cp_to_a, false)
            .unwrap();
        assert!(ok, "primitive sig must verify across the two wallets");

        let mut group = c.benchmark_group("auth_primitives");
        group.measurement_time(Duration::from_secs(6));
        group.sample_size(50);

        // wallet.create_signature (includes Type-42 derive_private_key + ECDSA sign)
        group.bench_function("wallet_create_signature", |b| {
            b.iter(|| {
                criterion::black_box(
                    w_a.create_signature_sync(Some(&payload), None, &proto, &key_id, &cp_to_b)
                        .unwrap(),
                );
            });
        });

        // wallet.verify_signature (includes Type-42 derive_public_key + ECDSA verify)
        group.bench_function("wallet_verify_signature", |b| {
            b.iter(|| {
                criterion::black_box(
                    w_b.verify_signature_sync(
                        Some(&payload),
                        None,
                        &sig,
                        &proto,
                        &key_id,
                        &cp_to_a,
                        false,
                    )
                    .unwrap(),
                );
            });
        });

        // The HMAC nonce path: create_hmac + verify_hmac (security level 2, Self_).
        let hmac_proto = Protocol {
            security_level: 2,
            protocol: "server hmac".to_string(),
        };
        let hmac_kid = "nonce-key-id".to_string();
        let cp_self = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };
        let hmac_data = bsv::primitives::random::random_bytes(16);
        let mac = w_a
            .create_hmac_sync(&hmac_data, &hmac_proto, &hmac_kid, &cp_self)
            .unwrap();

        group.bench_function("wallet_create_hmac", |b| {
            b.iter(|| {
                criterion::black_box(
                    w_a.create_hmac_sync(&hmac_data, &hmac_proto, &hmac_kid, &cp_self)
                        .unwrap(),
                );
            });
        });
        group.bench_function("wallet_verify_hmac", |b| {
            b.iter(|| {
                criterion::black_box(
                    w_a.verify_hmac_sync(&hmac_data, &mac, &hmac_proto, &hmac_kid, &cp_self)
                        .unwrap(),
                );
            });
        });

        group.finish();
    }

    // ---- 3. Raw secp256k1 ECDSA, no key derivation ----------------------
    {
        let priv_bn =
            BigNumber::from_hex("8a2f85e08360a04c8a36b7c22c5e9e9a0d3bcf2f95c97db2b8bd90fc5f5ff66a")
                .unwrap();
        let base = BasePoint::instance();
        let pub_point = base.mul(&priv_bn);
        let msg_hash: [u8; 32] = sha256(b"hello from peer A over a warm session");
        let sig = ecdsa_sign(&msg_hash, &priv_bn, true).unwrap();
        assert!(ecdsa_verify(&msg_hash, &sig, &pub_point));

        let mut group = c.benchmark_group("auth_raw_ecdsa");
        group.measurement_time(Duration::from_secs(5));
        group.sample_size(50);

        group.bench_function("raw_ecdsa_sign", |b| {
            b.iter(|| {
                criterion::black_box(ecdsa_sign(&msg_hash, &priv_bn, true).unwrap());
            });
        });
        group.bench_function("raw_ecdsa_verify", |b| {
            b.iter(|| {
                criterion::black_box(ecdsa_verify(&msg_hash, &sig, &pub_point));
            });
        });

        group.finish();
    }

    // ---- 4. Full handshake (initiate -> complete), for reference --------
    {
        let mut group = c.benchmark_group("auth_handshake");
        group.measurement_time(Duration::from_secs(8));
        group.sample_size(20);

        group.bench_function("full_handshake_initiate_to_complete", |b| {
            b.iter(|| {
                local.block_on(&rt, async {
                    let (_a, _b, _ia, _ib) = establish_session().await;
                    criterion::black_box(());
                });
            });
        });

        group.finish();
    }
}

criterion_group!(benches, auth_benchmarks);
criterion_main!(benches);
