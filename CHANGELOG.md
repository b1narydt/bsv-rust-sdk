# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-03-08

### Added
- Certificate exchange support in AuthFetch and Peer -- enables authenticated certificate acquisition and proving over HTTP transport

### Fixed
- Normalize `content-type` header in AuthFetch request serialization to prevent case-sensitivity mismatches
- Use `std::sync::Mutex` instead of `tokio::sync::Mutex` for `subscribe()` in HTTP transport, fixing potential deadlocks in sync contexts
- Add `process_pending` call in AuthFetch to flush queued messages before sending requests

## [0.1.1] - 2026-03-08

### Changed
- **WalletInterface and WalletWire traits migrated to `#[async_trait]`** for object safety -- `dyn WalletInterface` and `dyn WalletWire` now compile and work with `Box`, `Arc`, and trait objects (Phase 10)
- All 10 `impl WalletInterface` / `impl WalletWire` blocks annotated with `#[async_trait::async_trait]`
- 4 internal macros (`stub_method!`, `impl_json_method!`, `impl_wire_method!`, `impl_validated_method!`) desugared to produce async-trait compatible `Pin<Box<dyn Future>>` signatures

### Added
- `async-trait` as a required dependency
- Dispatch overhead benchmark (`benches/dispatch_bench.rs`) comparing RPITIT vs async-trait (~10ns delta, negligible)
- Technical report: `docs/wallet-interface-object-safety.md` with Send audit, benchmark data, and cross-SDK comparison

### Fixed
- Production hardening: removed all `unwrap()`/`panic!()` from library code (Phase 9)
- Clippy clean with zero warnings
- Visibility audit: only public API items are `pub`

## [0.1.0] - 2026-03-07

### Added
- Pure Rust cryptographic primitives: BigNumber, SHA-256, SHA-512, RIPEMD-160, HMAC, AES-CBC, AES-GCM, ECDSA, Schnorr
- secp256k1 elliptic curve with Jacobian coordinates, wNAF multiplication, Shamir's trick
- PrivateKey/PublicKey with WIF, DER, and address derivation
- Script engine with full opcode support, stack machine interpreter, and script templates (P2PKH, R-Puzzle, RPuzzle)
- Transaction builder with BEEF serialization, Merkle path validation, and fee models
- BIP-32 HD key derivation and BIP-39 mnemonic support
- BRC-42/43 key derivation, BRC-77 signed messages, BRC-78 encrypted messages
- WalletInterface trait (BRC-100) with 28 wallet operations
- Wallet substrates: ProtoWallet, WalletWireProcessor, WalletWireTransceiver, WalletClient, HttpWalletJson
- Auth module: Peer (BRC-31 handshake), SessionManager, transport layer (HTTP, WebSocket)
- Certificate system: CertificateManager, MasterCertificate, CompoundMerkleTree
- Services: IdentityClient, ContactsManager, Storage (UHRP), KVStore, OverlayTools
- Benchmark infrastructure with Criterion (primitives, crypto, script, transactions, BEEF)
- Performance optimizations: Montgomery CIOS, Karatsuba multiplication, cached neg tables
- 12 offline examples covering keys, signing, encryption, transactions, certificates, and wallet operations
- Comprehensive rustdoc on all public API items
