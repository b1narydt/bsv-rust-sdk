# Codebase Structure

**Analysis Date:** 2026-03-24

## Directory Layout

```
bsv-rust-sdk/
├── src/                        # Library source (crate root: src/lib.rs)
│   ├── lib.rs                  # Public module declarations
│   ├── primitives/             # Cryptographic primitives
│   ├── script/                 # Bitcoin script engine
│   ├── transaction/            # Transaction types + network traits
│   ├── wallet/                 # Wallet interface + key derivation + wire protocol
│   ├── auth/                   # BRC-31 Authrite mutual authentication
│   ├── services/               # Overlay network service clients
│   └── compat/                 # Legacy BIP-32/39, BSM, ECIES compatibility
├── tests/                      # Integration tests (Rust integration test files)
├── examples/                   # Runnable example binaries
├── benches/                    # Criterion benchmarks
├── benchmarks/                 # Benchmark result artifacts
│   └── results/
├── test-vectors/               # JSON test vector files for protocol compliance
├── testdata/                   # Binary/fixture test data
│   └── wallet/
├── docs/                       # Internal design notes
├── Cargo.toml                  # Package manifest + feature flags
├── .github/workflows/          # CI configuration
└── .planning/codebase/         # GSD analysis documents
```

## Directory Purposes

**`src/primitives/`:**
- Purpose: All low-level cryptographic building blocks; no BSV-specific logic
- Contains: `BigNumber`, `Point` (affine + Jacobian), `PrivateKey`, `PublicKey`, `Signature`, `SymmetricKey`, ECDSA, Schnorr, AES-CBC, AES-GCM, SHA256, HMAC-SHA256, DRBG, random, key shares (Shamir), polynomial utilities
- Key files: `src/primitives/private_key.rs`, `src/primitives/public_key.rs`, `src/primitives/ecdsa.rs`, `src/primitives/hash.rs`, `src/primitives/big_number.rs`
- Internal-only types: `jacobian_point.rs`, `k256.rs`, `montgomery.rs`, `reduction_context.rs` (all `pub(crate)`)

**`src/script/`:**
- Purpose: Bitcoin script types and full opcode interpreter
- Contains: `Script`, `LockingScript`, `UnlockingScript`, `ScriptChunk`, `Op` (opcode enum), `Spend` interpreter, `Address`, `ScriptTemplateLock`/`ScriptTemplateUnlock` traits, standard templates, inscription support, BIP-276
- Key files: `src/script/spend.rs` (interpreter), `src/script/templates/mod.rs`, `src/script/locking_script.rs`
- Templates: `src/script/templates/p2pkh.rs`, `src/script/templates/push_drop.rs`, `src/script/templates/r_puzzle.rs`

**`src/transaction/`:**
- Purpose: Transaction construction, all serialization formats, SPV proofs, network abstraction traits
- Contains: `Transaction`, `TransactionInput`, `TransactionOutput`, `MerklePath`, `Beef`, `BeefTx`, `BeefParty`, `FeeModel`/`SatoshisPerKilobyte`, `Broadcaster` trait, `ChainTracker` trait
- Key files: `src/transaction/transaction.rs`, `src/transaction/beef.rs`, `src/transaction/broadcaster.rs`, `src/transaction/chain_tracker.rs`
- Broadcasters: `src/transaction/broadcasters/arc.rs`, `src/transaction/broadcasters/whats_on_chain.rs`
- Chain trackers: `src/transaction/chaintrackers/whats_on_chain.rs`, `src/transaction/chaintrackers/headers_client.rs`
- Shared encoding utilities: varint read/write helpers in `src/transaction/mod.rs`

**`src/wallet/`:**
- Purpose: Complete wallet abstraction layer
- Contains: `WalletInterface` trait (28 async methods), all arg/result types, `KeyDeriver`, `CachedKeyDeriver`, `ProtoWallet`, wire serializer, wire substrates
- Key files: `src/wallet/interfaces.rs` (the trait + all types), `src/wallet/key_deriver.rs`, `src/wallet/proto_wallet.rs`, `src/wallet/validation.rs`
- Serializer: `src/wallet/serializer/mod.rs` — one file per wallet method (28 files + `frame.rs`)
- Substrates: `src/wallet/substrates/wallet_client.rs`, `src/wallet/substrates/wallet_wire_transceiver.rs`, `src/wallet/substrates/wallet_wire_processor.rs`, `src/wallet/substrates/http_wallet_wire.rs` (network-gated), `src/wallet/substrates/http_wallet_json.rs` (network-gated)

**`src/auth/`:**
- Purpose: BRC-31 Authrite mutual authentication
- Contains: `Peer`, `SessionManager`, certificate types, transport implementations, `AuthFetch`
- Key files: `src/auth/peer.rs` (network-gated), `src/auth/session_manager.rs`, `src/auth/types.rs`
- Certificates: `src/auth/certificates/certificate.rs`, `src/auth/certificates/master.rs`, `src/auth/certificates/verifiable.rs`, `src/auth/certificates/compound.rs`
- Transports: `src/auth/transports/http.rs`, `src/auth/transports/websocket.rs`

**`src/services/`:**
- Purpose: Typed async clients for BSV overlay network services
- Contains: `overlay_tools/` (lookup resolver, topic broadcaster, host reputation, historian, admin token template), `identity/`, `registry/`, `kvstore/`, `storage/`, `messages/`
- All submodules except `messages` are network-gated
- Key files: `src/services/overlay_tools/lookup_resolver.rs`, `src/services/overlay_tools/topic_broadcaster.rs`

**`src/compat/`:**
- Purpose: Backward-compatibility layer for legacy Bitcoin protocols
- Contains: `bip32.rs` (HD wallets), `bip39.rs` + `bip39_wordlists/` (mnemonics), `bsm.rs` (Bitcoin Signed Message), `ecies.rs` (ECIES encryption)
- Not the preferred approach for new code; BRC-42/43/77/78 are the modern equivalents

**`tests/`:**
- Purpose: Rust integration tests (run with `cargo test`)
- Key files: `tests/wallet_client.rs`, `tests/wallet_key_deriver.rs`, `tests/wallet_proto_wallet.rs`, `tests/wallet_cached_key_deriver.rs`, `tests/wallet_serializer_vectors.rs`

**`test-vectors/`:**
- Purpose: JSON files with protocol compliance test vectors (not compiled)
- Used by integration tests to verify binary serialization and protocol correctness

**`benches/`:**
- Purpose: Criterion benchmark binaries
- Each bench file corresponds to a `[[bench]]` entry in `Cargo.toml`
- Key files: `benches/transaction_bench.rs`, `benches/ecdsa_bench.rs`, `benches/atomic_beef_bench.rs`

## Key File Locations

**Entry Points:**
- `src/lib.rs`: Crate root; declares all public modules

**Core Traits:**
- `src/wallet/interfaces.rs`: `WalletInterface` — the central wallet contract
- `src/transaction/broadcaster.rs`: `Broadcaster` — network broadcast abstraction
- `src/transaction/chain_tracker.rs`: `ChainTracker` — SPV verification abstraction
- `src/wallet/substrates/mod.rs`: `WalletWire` — binary transport abstraction
- `src/script/mod.rs`: `ScriptTemplateLock`, `ScriptTemplateUnlock` — script template traits

**Configuration:**
- `Cargo.toml`: All dependencies, feature flags, bench/example declarations
- `.github/workflows/`: CI pipeline definitions

**Core Types:**
- `src/primitives/private_key.rs`: `PrivateKey`
- `src/primitives/public_key.rs`: `PublicKey`
- `src/primitives/signature.rs`: `Signature`
- `src/transaction/transaction.rs`: `Transaction`
- `src/transaction/beef.rs`: `Beef`
- `src/wallet/types.rs`: `Protocol`, `Counterparty`, `CounterpartyType` + semantic type aliases

**Testing:**
- `tests/`: Integration tests per module
- `test-vectors/`: JSON test vectors for serialization compliance

## Naming Conventions

**Files:**
- `snake_case.rs` for all source files
- One primary type or trait per file, named to match the file (e.g. `private_key.rs` → `PrivateKey`)
- `mod.rs` in each directory for module declaration and re-exports
- `error.rs` in each module for that module's error enum

**Directories:**
- `snake_case/` for all directories
- Plural names for groups of implementations (e.g. `broadcasters/`, `chaintrackers/`, `templates/`, `substrates/`)

**Types:**
- `PascalCase` structs and enums
- `snake_case` functions and methods
- `SCREAMING_SNAKE_CASE` constants
- Error enums named `{Module}Error` (e.g. `WalletError`, `TransactionError`)

## Where to Add New Code

**New cryptographic primitive:**
- Implementation: `src/primitives/{name}.rs`
- Register in: `src/primitives/mod.rs`

**New script template (new output type):**
- Implementation: `src/script/templates/{name}.rs`
- Register in: `src/script/templates/mod.rs`
- Implement both `ScriptTemplateLock` and `ScriptTemplateUnlock`

**New broadcaster (new broadcast service):**
- Implementation: `src/transaction/broadcasters/{service_name}.rs`
- Register in: `src/transaction/broadcasters/mod.rs`
- Implement `Broadcaster` trait; gate with `#[cfg(feature = "network")]`

**New chain tracker:**
- Implementation: `src/transaction/chaintrackers/{service_name}.rs`
- Register in: `src/transaction/chaintrackers/mod.rs`
- Implement `ChainTracker` trait; gate with `#[cfg(feature = "network")]`

**New wallet wire substrate:**
- Implementation: `src/wallet/substrates/{name}.rs`
- Register in: `src/wallet/substrates/mod.rs`
- Implement `WalletWire` trait

**New overlay service client:**
- Implementation: `src/services/{service_name}/`
- Register in: `src/services/mod.rs`
- Gate with `#[cfg(feature = "network")]`

**New integration test:**
- File: `tests/{module_name}.rs`
- Reference test vectors from `test-vectors/` or `testdata/`

**New example:**
- File: `examples/{example_name}.rs`
- Register `[[example]]` in `Cargo.toml`; add `required-features = ["network"]` if needed

## Special Directories

**`test-vectors/`:**
- Purpose: JSON files with protocol compliance vectors
- Generated: No (manually curated, sourced from reference TS/Go SDKs)
- Committed: Yes

**`testdata/`:**
- Purpose: Binary fixture data for wallet integration tests
- Generated: No
- Committed: Yes

**`benchmarks/results/`:**
- Purpose: Stored benchmark result artifacts for comparison
- Generated: Yes (by Criterion)
- Committed: Yes (for historical tracking)

**`.planning/codebase/`:**
- Purpose: GSD codebase analysis documents consumed by plan/execute commands
- Generated: Yes (by GSD map-codebase)
- Committed: As needed

---

*Structure analysis: 2026-03-24*
