# Architecture

**Analysis Date:** 2026-03-24

## Pattern Overview

**Overall:** Layered library crate with trait-based abstractions and optional async networking

**Key Characteristics:**
- Pure-Rust translation of the official TypeScript and Go BSV SDK reference implementations
- Feature-gated async/network layer (`network` feature flag) — core cryptographic primitives compile without any async runtime
- Trait objects (`dyn WalletInterface`, `dyn Broadcaster`, `dyn ChainTracker`, `dyn WalletWire`) enable runtime polymorphism over wallet backends and network transports
- All public interfaces use `#[async_trait]` for object safety when async is required
- Error types are module-local, derived via `thiserror`, with one `*Error` enum per module

## Layers

**Primitives Layer:**
- Purpose: Zero-dependency cryptographic building blocks
- Location: `src/primitives/`
- Contains: Big number arithmetic, ECC (secp256k1), ECDSA, Schnorr, AES-CBC/GCM, HMAC-SHA256, key types, Shamir secret sharing, DRBG, random
- Depends on: `getrandom` only
- Used by: All other layers

**Script Layer:**
- Purpose: Bitcoin script types, opcode set, and interpreter
- Location: `src/script/`
- Contains: `Script`, `LockingScript`, `UnlockingScript`, `Op` (opcodes), `Spend` interpreter, `Address`, standard templates (P2PKH, PushDrop, RPuzzle), BIP-276 encoding, inscription support
- Depends on: `primitives`
- Used by: `transaction`, `wallet`, application code

**Transaction Layer:**
- Purpose: Transaction construction, serialization, SPV proofs, fee models, network broadcast
- Location: `src/transaction/`
- Contains: `Transaction`, `TransactionInput`, `TransactionOutput`, `MerklePath`, `Beef` (BEEF V1/V2/Atomic), `Broadcaster` trait, `ChainTracker` trait, concrete implementations in `broadcasters/` and `chaintrackers/`
- Depends on: `primitives`, `script`
- Used by: `wallet`, `services`, application code

**Wallet Layer:**
- Purpose: BRC-100-compliant wallet abstraction, Type-42 key derivation, wire protocol
- Location: `src/wallet/`
- Contains:
  - `WalletInterface` trait (28-method async contract, `src/wallet/interfaces.rs`)
  - `KeyDeriver` (BRC-42 Type-42 derivation, `src/wallet/key_deriver.rs`)
  - `CachedKeyDeriver` (memoized version, `src/wallet/cached_key_deriver.rs`)
  - `ProtoWallet` (crypto-only offline impl, `src/wallet/proto_wallet.rs`)
  - `serializer/` — binary wire serialization for all 28 wallet methods
  - `substrates/` — `WalletWire` trait, `WalletWireTransceiver` (client), `WalletWireProcessor` (server dispatch), `WalletClient` (validated client), `HttpWalletWire`, `HttpWalletJson`
- Depends on: `primitives`, `script`, `transaction`
- Used by: `auth`, `services`, application code

**Auth Layer:**
- Purpose: BRC-31 Authrite mutual authentication protocol
- Location: `src/auth/`
- Contains:
  - `Peer` — handshake orchestrator (`src/auth/peer.rs`, network-gated)
  - `SessionManager` — session state (`src/auth/session_manager.rs`)
  - `certificates/` — `Certificate`, `MasterCertificate`, `VerifiableCertificate`, `CompoundCertificate`
  - `transports/` — `Transport` trait with HTTP and WebSocket implementations
  - `clients/` — `AuthFetch`, `AuthFetchResponse` (network-gated)
- Depends on: `primitives`, `wallet`
- Used by: `services`

**Services Layer:**
- Purpose: High-level overlay network service clients
- Location: `src/services/`
- Contains: `overlay_tools/` (lookup resolver, topic broadcaster, reputation, historian), `identity/`, `kvstore/`, `storage/`, `registry/`, `messages/`
- Depends on: `primitives`, `wallet`, `auth`, `transaction`
- Used by: application code

**Compat Layer:**
- Purpose: Legacy protocol compatibility (BIP-32, BIP-39, BSM, ECIES)
- Location: `src/compat/`
- Contains: `bip32.rs`, `bip39.rs`, `bsm.rs`, `ecies.rs`
- Depends on: `primitives`
- Note: These are backward-compatibility features; modern equivalents are BRC-42/43/77/78

## Data Flow

**Transaction Signing Flow:**

1. Caller constructs `Transaction` with `TransactionInput`/`TransactionOutput` using `src/transaction/transaction.rs`
2. Each input references a `LockingScript` from a prior output and provides a `ScriptTemplateUnlock` implementation
3. `Transaction` computes BIP-143 sighash preimage for each input
4. `WalletInterface::create_signature` or direct `ecdsa_sign` produces a `Signature`
5. `UnlockingScript` is assembled and attached to the input
6. `Transaction::to_binary()` / `to_ef()` serializes to wire format
7. `Broadcaster::broadcast()` submits to network

**Wallet Wire Protocol Flow:**

1. Application calls method on `WalletClient<W>` (e.g. `create_action`)
2. `WalletClient` validates args via `src/wallet/validation.rs`
3. `WalletWireTransceiver` serializes call using `src/wallet/serializer/` (binary varint framing)
4. `WalletWire::transmit_to_wallet` sends bytes over transport (`HttpWalletWire` or `HttpWalletJson`)
5. Remote `WalletWireProcessor` deserializes, dispatches to `WalletInterface` impl
6. Response serialized back and deserialized by transceiver

**BRC-31 Auth Handshake Flow:**

1. `Peer::connect()` initiates mutual authentication over `Transport`
2. `SessionManager` stores nonce and session state
3. Both sides sign challenges using `WalletInterface::create_signature`
4. After handshake, `AuthFetch` wraps HTTP calls with auth headers
5. Certificate exchange optionally occurs during handshake

**BEEF SPV Proof Flow:**

1. `Beef` container holds `MerklePath` bumps + `BeefTx` chain
2. `ChainTracker::is_valid_root_for_height` verifies Merkle roots against chain
3. `Transaction` extracts from `Beef::from_binary()` for verification

## Key Abstractions

**WalletInterface:**
- Purpose: 28-method async contract for all wallet operations (key ops, signing, encryption, tx management, certificate management, blockchain queries)
- Examples: `src/wallet/interfaces.rs`, `src/wallet/proto_wallet.rs` (offline impl), `src/wallet/substrates/wallet_client.rs` (remote impl)
- Pattern: `#[async_trait]` trait; all impls are generic over the method set; `ProtoWallet` returns `NotImplemented` for methods it doesn't support

**Broadcaster:**
- Purpose: Abstraction for submitting transactions to the BSV network
- Examples: `src/transaction/broadcaster.rs` (trait), `src/transaction/broadcasters/arc.rs` (ARC), `src/transaction/broadcasters/whats_on_chain.rs`
- Pattern: `#[async_trait]` trait returning `Result<BroadcastResponse, BroadcastFailure>`

**ChainTracker:**
- Purpose: Abstraction for SPV Merkle root verification
- Examples: `src/transaction/chain_tracker.rs` (trait), `src/transaction/chaintrackers/whats_on_chain.rs`, `src/transaction/chaintrackers/headers_client.rs`
- Pattern: `#[async_trait]` trait; `current_height()` has default impl returning `NotImplemented`

**WalletWire:**
- Purpose: Binary transport abstraction for remote wallet communication
- Examples: `src/wallet/substrates/mod.rs` (trait), `src/wallet/substrates/http_wallet_wire.rs`, `src/wallet/substrates/http_wallet_json.rs`
- Pattern: Single method `transmit_to_wallet(&[u8]) -> Result<Vec<u8>, WalletError>`

**ScriptTemplateLock / ScriptTemplateUnlock:**
- Purpose: Pair of traits for producing locking and unlocking scripts
- Examples: `src/script/templates/` — `p2pkh.rs`, `push_drop.rs`, `r_puzzle.rs`
- Pattern: `ScriptTemplateLock` produces `LockingScript`; `ScriptTemplateUnlock` produces `UnlockingScript` given a sighash preimage

## Entry Points

**Library Crate Root:**
- Location: `src/lib.rs`
- Triggers: Imported as `bsv` crate by downstream users
- Responsibilities: Re-exports all public modules (`primitives`, `script`, `transaction`, `wallet`, `auth`, `compat`, `services`)

**Examples (runnable binaries):**
- Location: `examples/`
- Key examples: `examples/wallet_client_action.rs` (full wallet action flow), `examples/token_lifecycle.rs` (overlay token lifecycle)
- Require: `network` feature (`required-features = ["network"]`)

**Benchmarks:**
- Location: `benches/`
- Harness: Criterion
- Covers: BigNumber, ECC scalar, ECDSA, hashing, ECIES, scripts, transactions, BEEF, serialization, dispatch

## Error Handling

**Strategy:** Module-local error enums via `thiserror`; no global error type; callers match on specific module errors

**Patterns:**
- Each module has an `error.rs` file with a `*Error` enum (e.g. `PrimitivesError`, `TransactionError`, `WalletError`, `AuthError`, `ScriptError`, `ServicesError`, `CompatError`)
- `WalletError` is the top-level error for wallet/wire operations; other errors convert into it at module boundaries
- Async methods return `Result<T, ModuleError>`; sync methods also use `Result<T, ModuleError>`
- `BroadcastFailure` (for `Broadcaster`) is a plain struct, not an error type, since broadcast failures carry structured data

## Cross-Cutting Concerns

**Logging:** None — no logging framework present; debug output via `eprintln!` in tests only
**Validation:** Argument validation concentrated in `src/wallet/validation.rs`; called by `WalletClient` before wire dispatch
**Authentication:** `auth` module provides BRC-31 Authrite; used by `services` clients; wires into `WalletInterface` for signing
**Feature Gating:** All network I/O (tokio, reqwest, tokio-tungstenite, serde/serde_json) is behind the `network` feature; core primitives and types are always available without it

---

*Architecture analysis: 2026-03-24*
