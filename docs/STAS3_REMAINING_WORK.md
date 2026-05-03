# STAS-3 Remaining Work — Handoff Guide

Status as of this handoff: **898 lib tests + 129 stas3 tests + 12 conformance vectors all passing, zero ignored**. All 10 canonical operations engine-verify end-to-end. The bridge crate at `src/script/templates/stas3/` is production-functional for the canonical EAC lifecycle (issue, transfer, split, merge, redeem, freeze, unfreeze, confiscate, swap_mark, swap_cancel, swap_execute).

This doc lists what's left, by priority. Items in **P1** are immediately useful for MetaWatt; **P2** is quality/polish; **P3** is upstream PR work; **P4** is forward-looking.

---

## How to read this guide

Each item has:
- **What** — concrete deliverable
- **Why** — what unblocks or improves
- **Files** — primary code paths to touch
- **Reference** — TS/Rust implementations to consult
- **Gate** — how to know it's done
- **Scope** — rough size estimate

The agent who picks this up should:
1. Read `docs/stas3-implementation-spec.md` first (the master spec, locked decisions, type-42 policy)
2. Read `docs/STAS3_INTEGRATION.md` in `~/METAWATT/METAWATT-code/metawatt-edge/docs/` (the consumer-side integration guide — explains how MetaWatt uses this crate)
3. Run `cargo test --lib && cargo test --test conformance_vectors` to confirm green baseline before changes
4. Pick a single item, implement, gate, ship. Don't pile up uncommitted work.

---

# P1 — Immediately useful for MetaWatt

## P1.1 — STAS-3 ↔ BSV (P2PKH) atomic swap

**What.** Extend `swap_execute` to handle the case where the counterparty side is a P2PKH UTXO (BSV satoshis), not a STAS-3 token. The canonical engine supports this — `requested_script_hash` can be SHA256 of any script, and the spec's "counterparty asset" need not be STAS-3.

**Why.** Energy markets typically pair an EAC (STAS-3) with a stablecoin or BSV payment. STAS-3 ↔ STAS-3 covers cert-for-cert trades. STAS-3 ↔ BSV is needed for "sell EAC for cash" flows.

**Files.**
- `src/script/templates/stas3/factory/swap_execute.rs` — generalize input expectation (one STAS, one P2PKH)
- `src/script/templates/stas3/wallet.rs::Stas3Wallet::swap_execute_with_bsv` (new method)
- `mod.rs::integration_tests` — new test exercising STAS↔BSV swap end-to-end

**Reference.**
- Spec v0.2 §9.5 (counterparty script is supplied as trailing param — no constraint on what it is)
- `dxs-bsv-token-sdk/src/transaction/build/input-builder.ts::_swapCounterpartyScript` — how the counterparty script is captured
- The current swap_execute already pushes a counterparty_script in the trailing params; the change is in the test setup + ensuring the `requested_script_hash` matches a P2PKH lock template

**Gate.** New integration test `test_factory_swap_execute_with_bsv_engine_verifies` passes; existing swap_execute test still passes.

**Scope.** ~150 lines of factory variant + ~100 lines of test setup. Maybe 30-60 min.

---

## P1.2 — MPKH (multisig) ownership signing in Stas3Wallet

**What.** Stas3Wallet currently signs only P2PKH-style auth (single key). Add support for P2MPKH (m-of-n multisig) ownership: collect signatures from M signer wallets, assemble the multisig redeem script + signature array, emit `AuthzWitness::P2mpkh`.

**Why.** Authority keys (freeze, confiscation) are typically multisig in production. Currently every authority must be a single key.

**Files.**
- `src/script/templates/stas3/wallet.rs` — add `Stas3Wallet::transfer_mpkh`, `freeze_mpkh`, etc., or add a `signers: Vec<KeyTriple>` parameter to existing methods
- `src/script/templates/stas3/factory/types.rs` — `SigningKey` enum (currently planned in spec §11 but only `P2PKH` is wired); add `Multi { triples, multisig: MultisigScript }`
- New module `src/script/templates/stas3/multisig.rs` — port `MultisigScript` from Bittoku (the multisig redeem-script construction + MPKH calculation)

**Reference.**
- Bittoku's `crates/bsv-tokens/src/types.rs::SigningKey::Multi`
- Bittoku's `crates/bsv-transaction/src/template/p2mpkh.rs::MultisigScript` (port a minimal version)
- Spec v0.2 §10.2 (P2MPKH unlocking format: `OP_0 <sig_1> ... <sig_m> <redeem_script>`)
- The existing `factory/common.rs::build_p2mpkh_locking_script` already builds the 70-byte template; reuse the encoding

**Gate.** New integration test `test_factory_transfer_with_mpkh_owner_engine_verifies` passes — token owned by 2-of-3 MPKH, transfer signed with 2 wallets.

**Scope.** ~300-400 lines (MultisigScript + factory variants + tests). 90-120 min.

---

## P1.3 — Fee calculator for Stas3Wallet

**What.** Currently the caller passes `change_satoshis` explicitly. Add a fee calculator that computes change automatically from `funding_input.satoshis`, the estimated tx size, and the configured `fee_rate_sats_per_kb`.

**Why.** Caller convenience. Eliminates manual fee math, a common source of off-by-N-sats bugs.

**Files.**
- `src/script/templates/stas3/wallet.rs` — add `compute_change(funding, est_size) -> u64` private helper
- `src/script/templates/stas3/wallet.rs::Stas3Wallet::*` — add `auto_change` variants for each method, or convert existing methods to compute change automatically

**Reference.**
- Bittoku's `crates/bsv-tokens/src/factory/stas3.rs::estimate_size` and `add_fee_change`
- Compute fee as `(est_size * fee_rate_sats_per_kb).div_ceil(1000)`

**Gate.** New unit tests verify change calculation for known tx shapes (transfer, split-3, merge, etc.). Integration tests still engine-verify with auto-computed change.

**Scope.** ~150 lines. 45 min.

---

## P1.4 — find_token_with_source helper

**What.** `Stas3Wallet::find_token` returns a `TokenInput` without `source_tx_bytes`. Merge requires source bytes for piece reconstruction. Add `find_token_with_source(outpoint) -> TokenInput` that calls `list_outputs(include: EntireTransactions)` to fetch parent BEEF and extracts the source-tx serialization.

**Why.** Without this, callers must manually fetch source-tx bytes for merge — error-prone and inconvenient.

**Files.**
- `src/script/templates/stas3/wallet.rs::Stas3Wallet::find_token_with_source`
- `src/script/templates/stas3/factory/types.rs::TokenInput` — add `source_tx_bytes: Option<Vec<u8>>` field if not already there

**Reference.**
- `bsv::wallet::interfaces::ListOutputsArgs::include = OutputInclude::EntireTransactions` (read `src/wallet/interfaces.rs` for the exact enum variant)
- Result includes BEEF; extract the specific source-tx by txid

**Gate.** Integration test that builds a merge tx using `find_token_with_source` instead of manually-constructed `TokenInput`s. Engine-verifies.

**Scope.** ~100 lines. 30-45 min.

---

# P2 — Quality and polish

## P2.1 — Recursive swap chain construction helpers

**What.** `NextVar2::Swap(inner)` is fully wired in encoding/decoding. But constructing chained-swap descriptors with proper `requested_script_hash` linkage at each hop is fiddly. Add a builder API:

```rust
SwapChainBuilder::new()
    .leg(LegConfig { target_lock, receive_addr, rate_num, rate_den })
    .leg(LegConfig { ... })
    .build() -> SwapDescriptor
```

**Why.** Multi-hop atomic swaps in a single tx are a STAS-3 differentiator. Current API requires manually constructing the recursive `next` chain.

**Files.**
- `src/script/templates/stas3/swap_chain.rs` (new)
- `src/script/templates/stas3/mod.rs` — re-export `SwapChainBuilder`

**Reference.**
- Spec v0.2 §6.3 (recursive `next` semantics)
- `factory/swap_execute.rs` for how the engine consumes chained descriptors

**Gate.** Unit tests for 2-hop and 3-hop chains; integration test for a 2-hop swap that engine-verifies.

**Scope.** ~200 lines + tests. 60-90 min.

---

## P2.2 — BEEF assembly helpers for chain-of-custody

**What.** `Transaction` objects returned from factories don't include BEEF anchor data. Add a helper that wraps a returned tx + its input parent txs into a BEEF blob suitable for SPV verification.

**Why.** Real-world consumers (overlays, light wallets) verify STAS-3 spends via SPV against a BEEF chain. Without this, callers must assemble BEEFs manually.

**Files.**
- `src/script/templates/stas3/wallet.rs::Stas3Wallet::build_beef_for_tx(tx, parent_txs)` (new method)
- Possibly `src/script/templates/stas3/beef.rs` if the helper is large

**Reference.**
- `bsv::transaction::transaction::Transaction::from_beef`/`to_beef` if they exist
- Existing BEEF infrastructure in `src/transaction/`

**Gate.** Round-trip test: build tx → build BEEF → parse BEEF → verify each tx's parent chain.

**Scope.** ~150 lines. 60 min. (Larger if BEEF infrastructure needs to be added to the SDK first.)

---

## P2.3 — Other-counterparty support in CustomInstructions

**What.** `CustomInstructions::to_triple` currently rejects `Counterparty::Other` (a specific peer's pubkey hex) with an error. For multi-party flows (swap escrow, joint accounts), `Other` must round-trip cleanly through the JSON.

**Why.** Blocks any STAS-3 operation involving keys derived against a specific counterparty pubkey (BRC-42 supports this; we just don't serialize it).

**Files.**
- `src/script/templates/stas3/wallet.rs::CustomInstructions` — extend the JSON shape to include a "counterparty" field that's `"self" | "anyone" | hex_pubkey_string`

**Reference.**
- BRC-42 derivation rules for counterparty=Other
- `Counterparty { counterparty_type: CounterpartyType::Other, public_key: Some(PublicKey) }`

**Gate.** Round-trip JSON test for `Other`; integration test with a counterparty-specific token.

**Scope.** ~50 lines + tests. 30 min.

---

## P2.4 — Doc tests and rustdoc examples

**What.** Every public function in `src/script/templates/stas3/` should have a `# Examples` section with a runnable doc test. Currently only top-level module docs have a quick-start example.

**Why.** Discoverability and learning. Doc tests are also CI-enforced — they catch API drift.

**Files.**
- All `src/script/templates/stas3/**/*.rs` public APIs

**Reference.**
- The integration guide at `~/METAWATT/METAWATT-code/metawatt-edge/docs/STAS3_INTEGRATION.md` — translate each example to a doc test

**Gate.** `cargo test --doc --lib` passes. `cargo doc --no-deps --lib` generates without warnings.

**Scope.** ~50-100 doc test additions. 90-120 min.

---

## P2.5 — Stas3Error variant expansion

**What.** `Stas3Error` is minimal (a few variants). Add specific variants for common failure modes so callers can match precisely:

```rust
pub enum Stas3Error {
    // Existing
    InvalidScript(String),
    InvalidState(String),
    MissingKeyTriple(String),
    FreezableNotSet,
    ConfiscatableNotSet,
    FrozenToken,
    AmountMismatch { inputs: u64, outputs: u64 },
    NoteDataTooLarge(usize),
    Script(ScriptError),

    // New
    InsufficientFunding { needed: u64, available: u64 },
    InvalidSwapDescriptor(SwapDescriptorError),  // wrap SwapDescriptorError directly
    OwnerMismatch { expected: [u8; 20], actual: [u8; 20] },
    AuthorityMismatch { expected: [u8; 20], actual: [u8; 20] },
    NotIssuer { owner: [u8; 20], protoid: [u8; 20] },
    UnsupportedOpcodeSequence(String),
    Wallet(WalletError),  // wrap wallet errors
}
```

**Why.** Callers can write specific recovery logic; better error messages.

**Files.**
- `src/script/templates/stas3/error.rs`
- Update factory functions to return the more specific variants

**Gate.** All existing tests still pass; one or two new unit tests check that specific error variants are produced.

**Scope.** ~100 lines + careful refactor. 60 min.

---

## P2.6 — Criterion benchmarks for STAS-3 ops

**What.** Add benchmarks for the hot paths: `build_locking_script`, `decode_locking_script`, `build_unlocking_script`, `verify_input` for each op type, full factory builds.

**Why.** Performance baseline. The crate already has criterion benches for primitives; STAS-3 should be measured too.

**Files.**
- `benches/stas3_bench.rs` (new)
- `Cargo.toml` — add `[[bench]] name = "stas3_bench"`

**Reference.**
- `benches/bignumber_bench.rs` (existing pattern in this crate)

**Gate.** `cargo bench` runs cleanly; report numbers in a comment in the benchmark file.

**Scope.** ~200 lines. 60 min.

---

# P3 — Upstream contributions to b1narydt

These are real bug fixes / features in the bsv-sdk core that should go upstream. Each is a separate PR.

## P3.1 — PR: spend_ops.rs OP_RETURN as success terminator

**What.** Top-level `OP_RETURN` should successfully terminate execution per post-Genesis BSV semantics. Currently lives at `src/script/spend_ops.rs:121-142`. Removed the `is_relaxed()` guard during this work — covenant scripts (STAS-3 and others) end with `OP_RETURN` as a success marker regardless of tx version.

**Why upstream.** Any covenant work in bsv-sdk hits this immediately. Without the fix, you can't write covenants. With it, all conformance tests pass.

**Files.**
- `src/script/spend_ops.rs` (the change is already in place — just needs to be a clean PR with rationale)
- `src/script/spend.rs::test_op_return_terminates_successfully` (the updated test, already in place)

**Reference.**
- dxs-bsv-token-sdk has `allowOpReturn: true` flag on its evaluator — the same semantic
- Post-Genesis BSV: OP_RETURN is permitted in scripts and doesn't fail the tx

**Gate.** PR opened on b1narydt/bsv-rust-sdk with this commit isolated. CI passes.

**Scope.** Already done locally. PR write-up + push: 30 min.

---

## P3.2 — PR: sighash_preimage input ordering fix

**What.** `Spend::sighash_preimage` (the script-interpreter-side preimage builder) was placing the current input's outpoint at index 0 in `hashPrevouts` and `hashSequence`, regardless of `input_index`. Broke verification for any multi-input tx where signing input != input 0. Fixed in `src/script/spend_ops.rs::sighash_preimage`.

**Why upstream.** Anyone running the bsv-sdk script interpreter to verify multi-input txs hits this. The standalone `Transaction::sighash_preimage` was always correct; this duplicated implementation in the interpreter just had the bug.

**Files.**
- `src/script/spend_ops.rs::sighash_preimage` (fix already in place)
- `src/script/spend.rs::sighash_preimage_orders_by_input_index` (regression test, already in place)

**Reference.**
- BIP-143 spec: hashPrevouts/hashSequence are over ALL inputs in their declared order
- The bug only manifested for `input_index > 0`, hence why it survived single-input tests

**Gate.** PR opened. CI passes.

**Scope.** Already done locally. PR write-up + push: 30 min.

---

## P3.3 — PR: build.rs ASM compile check pattern

**What.** The `build.rs` in this crate compiles `.ref/STAS-3-script-templates/Template STAS 3.0` from ASM and asserts byte-equality with `src/script/templates/stas3/stas3_body.bin`. This pattern (canonical-source-of-truth check at build time) might be useful as a general bsv-sdk feature for any embedded covenant body.

**Why upstream.** Optional. Not strictly necessary, but signals build-time provenance for any embedded script template.

**Files.**
- `build.rs` (already in place)
- Possibly factor into `bsv::script::asm::compile` as a public function callers can use in their own build.rs

**Gate.** PR opened with the build.rs and a doc note. CI passes.

**Scope.** Already done locally for STAS-3. Generalizing as a public API: 60-90 min.

---

# P4 — Architectural / forward-looking

## P4.1 — Move STAS-3 to its own crate (workspace member)

**What.** Currently `stas3` lives inside the monolithic `bsv-sdk` crate. For the long term, it might be cleaner as `bsv-tokens-stas3` — a separate workspace member that depends on `bsv-sdk` for primitives.

**Why.** Separation of concerns. Tokens are a layer above the protocol primitives. Faster compile times for users who don't need STAS-3.

**Files.**
- Restructure `Cargo.toml` to a workspace
- Move `src/script/templates/stas3/` to `crates/bsv-tokens-stas3/src/`
- Update imports throughout

**Reference.**
- Bittoku's repo structure: `crates/bsv-tokens` is a separate workspace member

**Gate.** All tests still pass. Both crates build independently.

**Scope.** Mostly mechanical refactor. ~3-4 hours.

**Risk.** Affects upstream PR strategy — if you do this BEFORE upstreaming the SDK fixes, the PRs need to coordinate. Better to do P3 first, then this.

---

## P4.2 — WASM compilation support

**What.** Make the STAS-3 module compile to `wasm32-unknown-unknown` so it can run in browser-based wallets (BRC-100 web wallets, demos, etc.).

**Why.** A real STAS-3 user-facing wallet UI needs WASM. The existing `bsv-sdk` may already support this; STAS-3 needs to be checked for any non-WASM-compatible dependencies (e.g., `tokio` is gated, but verify everything else).

**Files.**
- All of `src/script/templates/stas3/`
- `Cargo.toml` features

**Gate.** `cargo build --target wasm32-unknown-unknown --features wasm` succeeds.

**Scope.** Investigation + dep audit + likely a few hours of fixes. 4-8 hours.

---

## P4.3 — Async runtime audit

**What.** `Stas3Wallet` methods are `async fn`. They internally call wallet methods (also async). For deterministic embedded targets (ESP32 in MetaWatt's Level A profile), confirm that the STAS-3 module's async usage doesn't pull in heavy runtime dependencies.

**Why.** MetaWatt's Level A profile (ESP32-C3, no tokio) needs to compile against the STAS-3 layer for evidence-only signing flows. If our async usage drags in tokio/reqwest, it breaks Level A.

**Files.**
- `src/script/templates/stas3/wallet.rs`
- `Cargo.toml` features

**Gate.** Crate compiles with `default-features = false` (no `network` feature) and produces a binary with no tokio/reqwest in the dep tree (`cargo tree`).

**Scope.** Audit + minor fixes. 60-90 min.

---

# Things deliberately NOT on this list

- **Reverting `OP_RETURN` semantics or adding feature flags.** The post-Genesis behavior is correct. Pre-Genesis is dead; don't keep two code paths.
- **Adding alternative engine bodies (Bittoku 2,812-byte beta).** Canonical 2,899 is the only supported body. Multiple bodies = compatibility nightmare.
- **Generic "tokens" abstraction over STAS-3 + future protocols.** Premature. Build STAS-3 right, then refactor when a second token protocol is real.
- **REST API server / CLI tool.** Out of scope for a library. Build separately if needed.

---

# How to pick up this work

1. Fresh clone (or pull main) of `b1narydt/bsv-rust-sdk` (this fork)
2. `cargo test --lib && cargo test --test conformance_vectors` — confirm 898+12 green
3. Read `docs/stas3-implementation-spec.md` (master spec) and `~/METAWATT/METAWATT-code/metawatt-edge/docs/STAS3_INTEGRATION.md` (consumer view)
4. Pick ONE item from this guide (start with P1 if MetaWatt-blocking, P3 if upstream-focused)
5. Implement, gate, ship as a single focused commit
6. Update this doc to mark the item DONE (or remove it)

Don't try to bundle multiple items into one branch unless they're tightly coupled (e.g., P1.2 MPKH and P2.5 Error variants — error variants make sense alongside the new MPKH-related failure modes).

# Reference paths

| Path | Purpose |
|---|---|
| `docs/stas3-implementation-spec.md` | Master spec + locked decisions |
| `~/METAWATT/METAWATT-code/metawatt-edge/docs/STAS3_INTEGRATION.md` | Consumer-side integration guide |
| `~/Downloads/STAS 3 spec v0.2.docx` | STAS-3 protocol spec (canonical source) |
| `.ref/STAS-3-script-templates/Template STAS 3.0` | Official ASM (compiles to 2,899 bytes) |
| `.ref/bsv-sdk-rust/crates/bsv-tokens/` | Bittoku reference — Rust patterns only, NOT body bytes |
| `~/METAWATT/METAWATT-code/dxs-bsv-token-sdk/` | dxs production TS reference |
| `~/METAWATT/METAWATT-code/stas3-sdk/` | TS port (canonical conformance vectors live here) |
