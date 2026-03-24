# Testing Patterns

**Analysis Date:** 2026-03-24

## Test Framework

**Runner:**
- Rust's built-in test harness (`cargo test`)
- No separate test runner configuration file

**Async Runtime:**
- `tokio` with `rt-multi-thread` and `macros` features (dev-dependency)
- Async tests use `#[tokio::test]`

**HTTP Mocking:**
- `wiremock = "0.6"` (dev-dependency) for mocking HTTP servers in async tests

**Benchmarks:**
- `criterion = "0.5"` with `html_reports` feature
- 13 benchmark suites in `benches/`

**Assertion Library:**
- Standard `assert_eq!`, `assert!`, `assert_ne!` macros
- No third-party assertion crates

**Run Commands:**
```bash
cargo test                          # Run all tests (unit + integration)
cargo test --features network       # Run tests including network-gated code
cargo test --verbose                # Verbose output (used in CI)
cargo bench                         # Run all benchmarks
cargo bench --bench bignumber_bench # Run a specific benchmark
```

## Test File Organization

**Location:**
- **Unit tests:** Co-located in source files using `#[cfg(test)] mod tests { ... }` at the bottom of each `.rs` file — 88 such modules across `src/`
- **Integration tests:** Separate files in `tests/` directory — 5 files covering wallet layer
- **Benchmark tests:** Separate files in `benches/` directory — 13 files

**Naming (unit tests):**
- Test module always named `tests` (`mod tests`)
- Test functions prefixed `test_` (e.g., `test_from_binary_round_trip`, `test_txid`)
- Integration test functions may use descriptive names without prefix (e.g., `should_compute_the_correct_invoice_number`, `create_action_rejects_description_too_short`)

**Structure:**
```
bsv-rust-sdk/
├── src/
│   ├── primitives/
│   │   ├── big_number.rs     # #[cfg(test)] mod tests at line ~2050
│   │   ├── hash.rs           # #[cfg(test)] mod tests at line ~795
│   │   ├── ecdsa.rs          # #[cfg(test)] mod tests
│   │   └── private_key.rs    # #[cfg(test)] mod tests
│   ├── transaction/
│   │   ├── transaction.rs    # #[cfg(test)] mod tests at line 718
│   │   ├── beef.rs           # #[cfg(test)] mod tests at line 490
│   │   ├── merkle_path.rs    # #[cfg(test)] mod tests at line 486
│   │   └── broadcasters/
│   │       └── arc.rs        # #[cfg(test)] mod tests at line 87 (async, wiremock)
│   └── wallet/
│       └── substrates/
│           └── tests.rs      # Separate tests file within module (not inline)
├── tests/
│   ├── wallet_client.rs           # Validation function tests
│   ├── wallet_key_deriver.rs      # Key derivation integration tests
│   ├── wallet_cached_key_deriver.rs
│   ├── wallet_proto_wallet.rs
│   └── wallet_serializer_vectors.rs  # Wire protocol byte-exact validation
├── test-vectors/                   # 27 JSON files with cryptographic test vectors
└── testdata/
    └── wallet/                     # Wallet wire protocol test vectors (JSON)
```

## Test Structure

**Unit test suite organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // ---------------------------------------------------------------------------
    // Helper structs for deserializing JSON test vectors
    // ---------------------------------------------------------------------------

    #[derive(Deserialize)]
    struct TestVector {
        description: String,
        hex: String,
        txid: String,
    }

    fn load_test_vectors() -> Vec<TestVector> {
        let json = include_str!("../../test-vectors/transaction_valid.json");
        serde_json::from_str(json).expect("failed to parse transaction_valid.json")
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_from_binary_round_trip() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let tx = Transaction::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.description, e));
            // assertions...
        }
    }
}
```

**Patterns:**
- `use super::*` — always imported in test modules to access parent module items
- Section comments (`// ---...---`) divide test files into logical groups
- Test vectors loaded via `include_str!("../../test-vectors/filename.json")` — embedded at compile time
- Helper functions (`fn load_test_vectors()`) defined at module scope, not inside individual tests

## Mocking

**Framework:** `wiremock = "0.6"` for HTTP server mocking

**Pattern for async HTTP tests:**
```rust
#[tokio::test]
async fn test_arc_broadcast_success() {
    let mock_server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/v1/tx"))
        .and(matchers::header("Content-Type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123def456",
            "message": "Transaction accepted"
        })))
        .mount(&mock_server)
        .await;

    let arc = ARC::new(&mock_server.uri(), None);
    let result = arc.broadcast(&tx).await;
    assert!(result.is_ok());
}
```

**Locations using wiremock:**
- `src/transaction/broadcasters/arc.rs` — ARC broadcaster HTTP tests
- `src/transaction/broadcasters/whats_on_chain.rs` — WhatsOnChain broadcaster tests
- `src/transaction/chaintrackers/whats_on_chain.rs` — chain tracker tests
- `src/transaction/chaintrackers/headers_client.rs` — headers client tests
- `src/auth/transports/http.rs` — HTTP auth transport tests
- `src/auth/clients/auth_fetch.rs` — auth fetch client tests

**Mock wallets:** For wallet layer tests, full `WalletInterface` implementations are created inline using either:

1. Struct implementing all trait methods with `unimplemented!()` stubs for unused methods — via a `stub_method!` macro:
```rust
macro_rules! stub_method {
    ($name:ident, $args:ty, $ret:ty) => {
        fn $name<'life0, 'life1, 'async_trait>(/* ... */) -> Pin<Box<dyn Future<...>>> {
            Box::pin(async move {
                unimplemented!(concat!(stringify!($name), " not needed for cert tests"))
            })
        }
    };
}
```
Used in: `src/auth/certificates/master.rs`, `src/auth/utils/certificates.rs`, `src/auth/utils/nonce.rs`, `src/auth/peer.rs`

2. Full `MockWallet` struct with all methods returning `Ok(...)` with dummy data — used in `src/wallet/substrates/tests.rs`

**What to Mock:**
- External HTTP services (broadcasters, chain trackers, identity services)
- `WalletInterface` implementations when testing layers that depend on wallet but don't need real key operations

**What NOT to Mock:**
- Cryptographic primitives — tested directly against test vectors
- Serialization — tested via round-trip byte comparison

## Fixtures and Factories

**Test Data — JSON Test Vectors:**
All cryptographic test vectors are stored as JSON files in `test-vectors/` and loaded at compile time with `include_str!`:

```rust
// Pattern used in src/primitives/hash.rs, src/transaction/transaction.rs, etc.
let data = include_str!("../../test-vectors/sha256.json");
let vectors: Vec<Sha256Vector> = serde_json::from_str(data).unwrap();
```

**Available test vector files:**
- `test-vectors/transaction_valid.json` — Bitcoin transaction round-trip + txid
- `test-vectors/beef_valid.json` — BEEF v1/v2 parsing and round-trip
- `test-vectors/bump_valid.json`, `bump_invalid.json` — Merkle path verification
- `test-vectors/sha256.json`, `sha512.json`, `ripemd160.json` — Hash function NIST vectors
- `test-vectors/hmac_sha256.json`, `hmac_sha512.json` — HMAC vectors
- `test-vectors/ecdsa_sign.json`, `ecdsa_verify.json` — ECDSA sign/verify
- `test-vectors/big_number.json` — BigNumber arithmetic and conversion
- `test-vectors/bip32_vectors.json`, `bip39_vectors.json` — BIP32/39 derivation
- `test-vectors/private_key_wif.json`, `public_key_der.json` — Key encoding
- `test-vectors/aes_cbc.json`, `aes_gcm.json`, `ecies_vectors.json` — Symmetric crypto
- `test-vectors/script_tests.json`, `sighash.json`, `signature_der.json` — Script/sig vectors
- `test-vectors/drbg.json`, `pbkdf2_vectors.json`, `point_operations.json`, `schnorr.json`, `bsm_vectors.json`
- `testdata/wallet/` — Wire protocol serialization vectors (loaded at runtime with `fs::read_to_string`)

**Helper functions in integration tests:**
```rust
// tests/wallet_client.rs — factory pattern for test args
fn valid_args() -> CreateActionArgs {
    CreateActionArgs {
        description: "12345".to_string(),
        inputs: vec![],
        outputs: vec![],
        // ...
    }
}

// tests/wallet_key_deriver.rs — named fixtures
fn root_private_key() -> PrivateKey { PrivateKey::from_hex("2a").unwrap() }
fn counterparty_private_key() -> PrivateKey { PrivateKey::from_hex("45").unwrap() }
fn test_protocol() -> Protocol { Protocol { security_level: 0, protocol: "testprotocol".to_string() } }
```

**Location:**
- Compile-time vectors: `test-vectors/` (JSON, 27 files)
- Runtime vectors: `testdata/wallet/` (JSON, loaded with `fs::read_to_string` and `env!("CARGO_MANIFEST_DIR")`)

## Coverage

**Requirements:** None enforced — no `cargo-tarpaulin` or coverage threshold configuration detected.

**CI runs:** `cargo test --verbose` on every push/PR to `main`, but no coverage reporting.

**View Coverage (manual):**
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

## Test Types

**Unit Tests (88 modules in src/):**
- Scope: Individual functions and types within a single module
- Test vectors loaded via `include_str!` for deterministic cryptographic testing
- Round-trip serialization: parse → serialize → compare bytes
- Property testing: bit_length, byte_length, is_zero, is_negative checks

**Integration Tests (5 files in tests/):**
- Scope: Cross-module behavior; wallet layer end-to-end
- `tests/wallet_client.rs` — validation logic for `CreateActionArgs` and wallet methods
- `tests/wallet_key_deriver.rs` — Type-42 key derivation against known test values
- `tests/wallet_cached_key_deriver.rs` — Caching behavior on top of key deriver
- `tests/wallet_proto_wallet.rs` — ProtoWallet operations
- `tests/wallet_serializer_vectors.rs` — Wire protocol byte-exact comparison against Go SDK output

**E2E / Network Tests:**
- No end-to-end tests connecting to live BSV network
- Network behavior tested via `wiremock` mock servers

**Benchmarks (13 files in benches/):**
- Criterion benchmarks mirroring TS SDK performance benchmarks
- Benchmark names reference TS SDK equivalents (e.g., `"mul_large_numbers"` matches TS `mulIterations`)

## Common Patterns

**Async Testing:**
```rust
#[tokio::test]
async fn test_arc_broadcast_success() {
    let mock_server = MockServer::start().await;
    // set up mocks...
    let result = some_async_fn().await;
    assert!(result.is_ok());
}
```

**Error Testing:**
```rust
// Pattern 1: assert error variant and message content
fn assert_invalid_parameter(result: Result<(), WalletError>, field_substring: &str) {
    match result {
        Err(WalletError::InvalidParameter(msg)) => {
            assert!(msg.contains(field_substring), "expected '{}', got: {}", field_substring, msg);
        }
        Err(other) => panic!("expected InvalidParameter containing '{}', got: {:?}", field_substring, other),
        Ok(()) => panic!("expected InvalidParameter containing '{}', got Ok", field_substring),
    }
}

// Pattern 2: unwrap_or_else with descriptive panic
let tx = Transaction::from_hex(&v.hex)
    .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.description, e));
```

**Round-trip Testing:**
```rust
// Parse → serialize → compare to original
let beef = Beef::from_hex(&v.hex)
    .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.name, e));
let result_hex = beef.to_hex()
    .unwrap_or_else(|e| panic!("failed to serialize '{}': {}", v.name, e));
assert_eq!(result_hex, v.hex, "round-trip failed for '{}'", v.name);
```

**Vector Iteration Testing:**
```rust
// Iterate all vectors, include vector name/description in panic messages
for v in &vectors {
    let result = some_op(&v.input)
        .unwrap_or_else(|e| panic!("failed for '{}': {}", v.description, e));
    assert_eq!(result, v.expected, "mismatch for '{}'", v.description);
}
```

**Test Helpers for Path Resolution:**
```rust
// Integration tests use CARGO_MANIFEST_DIR for runtime file loading
fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("wallet")
}
```

---

*Testing analysis: 2026-03-24*
