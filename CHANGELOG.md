# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.75] - 2026-03-19

### Fixed

- **`CertificateType::from_string` now decodes base64 and hex** -- Previously
  only accepted raw byte strings <=32 chars, rejecting base64-encoded types
  (44 chars) which caused certificate lookups to silently fall back to all-zeros.

### Added

- **`partial` field on `ListCertificatesArgs`** -- Optional `PartialCertificate`
  filter for exact certificate matching by type, serialNumber, certifier, and
  subject. Required by `proveCertificate` which calls `listCertificates` with
  a partial filter to find the unique matching certificate.

## [0.1.74] - 2026-03-19

### Fixed

- **`Peer::dispatch_message` is now public** -- Allows middleware to verify
  individual auth messages directly without draining the entire transport
  channel via `process_pending`, preventing request serialization bottlenecks.

- **`handle_general_message` uses non-blocking channel send** -- Changed
  `general_message_tx.send().await` to `try_send()` to prevent deadlock when
  the general message channel fills up (buffer=32) and nobody consumes from it.
  Previously, after 32 authenticated requests the Peer Mutex would deadlock.

## [0.1.73] - 2026-03-15

### Changed
- **`ProveCertificateArgs.certificate`** -- now uses `PartialCertificate` (all fields optional) instead of `Certificate`, matching TS SDK's `Partial<WalletCertificate>`
- **`ProveCertificateResult`** -- added optional `certificate` and `verifier` fields

## [0.1.72] - 2026-03-10

### Fixed
- **Auth payload deserialization overflow** -- `deserialize_request_payload` now correctly handles varint(-1) sentinel (two's complement `u64::MAX`) as "absent/empty" for query string, body, and header count fields. Previously caused `attempt to add with overflow` panic when parsing payloads serialized with the corrected varint(-1) encoding.

## [0.1.71] - 2026-03-10

### Fixed
- **`ProveCertificateArgs.certificate` type mismatch** -- added `.into()` conversion from `Certificate` to `PartialCertificate` in identity client, fixing compilation with `network` feature enabled

## [0.1.7] - 2026-03-10

### Fixed
- **BRC-100 compliance** -- merged PR #5 (sirdeggen): align wallet interface with TS SDK and BRC-100 spec
- **`verify_signature_sync` now properly handles `hash_to_directly_verify`** -- previously ignored the parameter and only used `data`
- **`verify_signature` accepts `Option<&[u8]>` for both `data` and `hash_to_directly_verify`** -- callers must provide at least one
- **`prove_certificate` serialization** -- updated to match TS SDK wire format
- **`list_actions` serialization** -- added missing fields
- **`create_signature` / `verify_signature` serialization** -- aligned with BRC-100 spec

## [0.1.6] - 2026-03-09

### Added
- **`PushDrop::decode()`** -- decodes a PushDrop script back into its component fields and locking key, with 4 unit tests
- **`Transaction::from_beef()`** -- constructs a Transaction from BEEF binary data, resolving source transactions from the BEEF structure
- **`Beef::into_transaction()`** -- extracts the subject transaction from a BEEF container as a fully-resolved Transaction
- **`Beef::sort_txs()`** -- topologically sorts BEEF transactions so dependencies appear before dependents, with 4 unit tests
- **`SerialNumber::from_string()`** -- parses a serial number from its string representation, with 5 unit tests
- **`BeefParty::new()` iterator API** -- accepts any `IntoIterator<Item = Beef>` instead of requiring a pre-built `Vec`, with 3 unit tests

### Changed
- **`BooleanDefaultTrue` / `BooleanDefaultFalse` converted from type aliases to newtypes** -- now proper structs with `Default` (returning `true`/`false` respectively), `Deref<Target = bool>`, `From<bool>`, and serde support. Enables correct default semantics in wallet option types.
- **`InternalizeOutput` converted from struct to enum** -- now `InternalizeOutput::Change` and `InternalizeOutput::NoChange` variants matching TypeScript SDK semantics
- **`ProtoWallet` inherent methods renamed with `_sync` suffix** -- `get_public_key` -> `get_public_key_sync`, `encrypt` -> `encrypt_sync`, etc. (9 methods total). Eliminates name collision between inherent methods and `WalletInterface` trait methods, enabling correct trait dispatch.
- **`WalletInterface` generic bounds relaxed with `?Sized`** -- added to certificate operations, identity client, contacts manager, and registry client generics, enabling `dyn WalletInterface` usage in more contexts
- **`Default` derives added to `CreateActionOptions` and `SignActionOptions`** -- enables `..Default::default()` builder pattern
- **`WalletError` now implements `From<String>`** -- enables `?` operator with string error sources

## [0.1.5] - 2026-03-09

### Added
- **`CachedKeyDeriver::root_key()` accessor** -- exposes a `&PrivateKey` reference to the root key, eliminating the need to store root key material separately for BRC-29 key derivation
- **`KeyDeriver::root_key()` accessor** -- same root key accessor on the underlying deriver
- **`Transaction::sign_all_inputs()` bulk signing** -- signs all unsigned inputs in one call by resolving source satoshis and locking scripts from each input's `source_transaction`, reducing the verbose per-input signing loop

### Changed
- **`CachedKeyDeriver` now uses interior mutability** -- internal cache changed from `HashMap` to `RwLock<HashMap>`, so all `derive_*` methods now take `&self` instead of `&mut self`. This allows `Arc<CachedKeyDeriver>` to be shared directly without wrapping in `Arc<Mutex<CachedKeyDeriver>>`

## [0.1.4] - 2026-03-09

### Added
- **BEEF merge and atomic serialization methods** matching TypeScript SDK:
  - `Beef::merge_beef()` -- merge another Beef (bumps deduplicated by block height + root, transactions by txid)
  - `Beef::merge_raw_tx()` -- merge a raw serialized transaction with optional bump index
  - `Beef::to_binary_atomic()` -- serialize as Atomic BEEF (BRC-95) targeting a specific txid
  - `Beef::merge_beef_from_binary()` -- convenience method to merge from raw bytes
  - `Beef::merge_bump()` -- merge a MerklePath with deduplication and transaction bump assignment
  - `Beef::find_txid()` -- look up a BeefTx by txid
- 9 new unit tests for BEEF merge and atomic serialization

### Fixed
- Removed stale "Stub for Task 1" comment from beef.rs module documentation

## [0.1.3] - 2026-03-08

### Fixed
- **Critical: prevent unsigned overflow panic in `truncate_to_n`** -- use `saturating_sub` for `msg.byte_length() * 8 - n_bit_length` in ECDSA signature truncation. SHA-256 hashes with leading zero bytes (byte_length < 32) would cause a subtract-with-overflow panic. Matches TypeScript SDK behavior where negative delta harmlessly skips the shift.

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
