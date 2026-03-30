# BSV SDK (Rust)

Pure Rust implementation of the BSV Blockchain SDK, providing cryptographic primitives, transaction building, script interpretation, wallet operations, and authenticated overlay network services -- all without external crypto dependencies.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bsv-sdk = "0.2.1"
```

To enable async HTTP and WebSocket functionality (wallet services, overlay networks):

```toml
[dependencies]
bsv-sdk = { version = "0.2.0", features = ["network"] }
```

## Quick Start

```rust
use bsv::primitives::{PrivateKey, PublicKey};
use bsv::script::Address;

fn main() {
    // Import a private key from WIF format
    let wif = "L3yMBjkWMnBcFcqdaMSPK8gSvNiEGgRo5bBrfFabqdRTGVRjcwJR";
    let private_key = PrivateKey::from_wif(wif).expect("valid WIF");

    // Derive the public key and address
    let public_key = PublicKey::from_private_key(&private_key);
    let address = Address::from_public_key(&public_key).expect("valid address");

    println!("Address: {}", address);
}
```

## Module Overview

| Module | Description | Key Types |
|--------|-------------|-----------|
| `primitives` | Core cryptographic primitives: keys, hashing, ECDSA, AES-GCM, Shamir secret sharing | `PrivateKey`, `PublicKey`, `BigNumber`, `Point`, `SymmetricKey`, `KeyShares` |
| `script` | Bitcoin script parsing, execution, and template matching | `Script`, `LockingScript`, `UnlockingScript`, `Address`, `Inscription` |
| `transaction` | Transaction building, serialization, BEEF/Merkle proofs | `Transaction`, `TransactionInput`, `TransactionOutput`, `Beef`, `MerklePath` |
| `wallet` | BRC-100 wallet interface, Type-42 key derivation, serialization | `ProtoWallet`, `WalletClient`, `HttpWalletJson`, `CachedKeyDeriver` |
| `auth` | BRC-31 authenticated transport, certificates, peer communication | `Peer`, `AuthFetch`, `Certificate`, `Transport` |
| `compat` | Compatibility modules: BIP32, BIP39, BSM, ECIES | `ExtendedKey`, `Mnemonic`, `Bsm`, `ElectrumEcies`, `BitcoreEcies` |
| `services` | Overlay network services: lookup, broadcast, identity | `LookupResolver`, `TopicBroadcaster`, `IdentityClient`, `GlobalKVStore` |
| `remittance` | Peer-to-peer remittance protocol with BRC-29 settlement | `RemittanceManager`, `BasicBRC29Module`, `Thread`, `CommsLayer` |

## Examples

The SDK includes 14 runnable examples demonstrating common workflows:

### Offline Examples (no external services)

| Example | Description | Command |
|---------|-------------|---------|
| `address_from_wif` | Import WIF private key, derive public key and address | `cargo run --example address_from_wif` |
| `create_wallet` | BIP39 mnemonic generation and BIP32 HD wallet creation | `cargo run --example create_wallet` |
| `create_signature` | Create and verify Type-42 signatures with ProtoWallet | `cargo run --example create_signature` |
| `encrypt_decrypt` | AES-GCM symmetric encryption and decryption | `cargo run --example encrypt_decrypt` |
| `create_hmac` | HMAC creation and verification | `cargo run --example create_hmac` |
| `keyshares_backup` | Shamir secret sharing: split key into shares, reconstruct | `cargo run --example keyshares_backup` |
| `hd_key_derivation` | BIP32 hierarchical deterministic key derivation chains | `cargo run --example hd_key_derivation` |
| `ecies_encrypt` | ECIES encryption (Electrum and Bitcore variants) | `cargo run --example ecies_encrypt` |
| `p2pkh_transaction` | Build, sign, and serialize a P2PKH transaction | `cargo run --example p2pkh_transaction` |
| `op_return_transaction` | Embed data on-chain with OP_RETURN outputs | `cargo run --example op_return_transaction` |
| `inscription_transaction` | Create content-typed inscriptions (OP_FALSE OP_RETURN) | `cargo run --example inscription_transaction` |
| `verify_beef` | BEEF V1 serialization round-trip and verification | `cargo run --example verify_beef` |
| `certificate_operations` | BRC-52 certificate construction and field management | `cargo run --example certificate_operations` |

### Network Examples (requires `--features network`)

| Example | Description | Command |
|---------|-------------|---------|
| `wallet_client_action` | BRC-100 wallet workflow: getPublicKey, createAction, signAction via JSON API | `cargo run --example wallet_client_action --features network` |

The `wallet_client_action` example connects to a BRC-100 wallet service via `HttpWalletJson` (JSON API, default `http://localhost:3321`). Set the `WALLET_URL` environment variable to use a custom endpoint.

## Performance

Benchmarked against the TypeScript BSV SDK across 57 operations. The Rust SDK is faster in 55 of 57 benchmarks.

### Highlights

| Operation | TS (ms) | Rust (ms) | Speedup |
|-----------|---------|-----------|---------|
| BigNumber add (large) | 30.08 | 1.11 | 27.2x |
| BN toArray (big-endian) | 0.80 | 0.01 | 67.6x |
| BN toArray (little-endian) | 0.85 | 0.01 | 57.5x |
| SHA-256 32B | 0.0015 | 0.0002 | 8.6x |
| SHA-512 32B | 0.0027 | 0.0002 | 11.1x |
| ECDSA sign | 0.81 | 0.48 | 1.7x |
| ECDSA verify | 1.54 | 1.06 | 1.5x |
| SymmetricKey encrypt 2MB | 849.40 | 131.02 | 6.5x |
| SymmetricKey decrypt 2MB | 823.64 | 130.57 | 6.3x |
| ECIES Electrum encrypt 64KB | 4.51 | 0.50 | 9.1x |
| Transaction signing (deep chain) | 176.09 | 51.78 | 3.4x |
| Script findAndDelete (8K chunks) | 0.70 | 0.07 | 10.4x |
| Reader/Writer large payloads | 17.13 | 1.62 | 10.5x |
| Atomic BEEF serialize | 0.64 | 0.10 | 6.2x |
| HMAC-SHA512 1KB | 0.016 | 0.003 | 5.9x |

### Areas at Parity or Slower

| Operation | TS (ms) | Rust (ms) | Ratio | Notes |
|-----------|---------|-----------|-------|-------|
| BigNumber mul (large) | 0.78 | 1.79 | 0.4x | BN.js comb algorithm is highly optimized for this case |
| ECIES Electrum decrypt 32B | 0.03 | 0.07 | 0.5x | Degenerate small-payload key derivation overhead |
| ECC Point.mul | 0.36 | 0.43 | 0.9x | Near parity |

Full benchmark report: [`Rust-vs-TS-performance.md`](Rust-vs-TS-performance.md)

## Feature Flags

| Feature | Description |
|---------|-------------|
| `network` | Enables async HTTP/WebSocket functionality via tokio, reqwest, and tungstenite. Required for `HttpWalletJson`, `LookupResolver`, `TopicBroadcaster`, and other network-dependent types. |
| *(default)* | Pure cryptography and data structures. No async runtime, no network I/O. |

## Minimum Supported Rust Version

**MSRV: 1.87**

Required for stabilized `is_multiple_of`, `div_ceil`, and other standard library features used throughout the crate.

## License

Open BSV License. See [LICENSE](LICENSE) for details.
