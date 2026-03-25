---
phase: 04-basic-brc29-module
plan: 01
subsystem: payments
tags: [brc29, remittance, p2pkh, serde, async-trait, wire-format]

# Dependency graph
requires:
  - phase: 03-remittancemanager
    provides: RemittanceModule trait, ErasedRemittanceModule, RemittanceError, ModuleContext, WalletInterface
  - phase: 02-interface-traits
    provides: CommsLayer, IdentityLayer traits and erased pattern
provides:
  - Brc29RemittanceModule implementing RemittanceModule trait
  - Wire-format types (Brc29OptionTerms, Brc29SettlementArtifact, Brc29ReceiptData) with camelCase serde matching TS SDK
  - Brc29RemittanceModuleConfig with TS-matching defaults
  - Injectable NonceProvider and LockingScriptProvider traits (Arc<dyn>)
  - DefaultNonceProvider (delegates to auth::utils::nonce::create_nonce)
  - DefaultLockingScriptProvider (P2PKH via PublicKey.to_hash)
  - ensure_valid_option and ensure_valid_settlement validation helpers
  - is_atomic_beef placeholder check
  - 29 integration tests verifying all contracts
affects:
  - 04-02 (build_settlement and accept_settlement implementations)
  - any future module that follows the same injectable trait pattern

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injectable trait pattern: providers live in config struct (Arc<dyn Trait>), not on module struct directly"
    - "Wire-format TDD: test JSON shape with serde_json::to_value assertions before implementing logic"
    - "todo!(\"Plan 02\") stubs for deferred implementation — compiles and checks cleanly"

key-files:
  created:
    - src/remittance/modules/mod.rs
    - src/remittance/modules/brc29.rs
    - tests/remittance_brc29.rs
  modified:
    - src/remittance/mod.rs

key-decisions:
  - "Providers (NonceProvider, LockingScriptProvider) stored in config struct not module struct — matches TS constructor options pattern"
  - "CustomInstructionsPayload is private (not pub) — only used inside build_settlement (Plan 02), not part of external API"
  - "Vec<u8> default serde serializes as number array matching TS number[] — no custom serde helper needed for transaction field"
  - "DefaultNonceProvider ignores originator parameter — create_nonce uses Self_ counterparty, no originator support in underlying API"

patterns-established:
  - "Module integration tests use locally-defined MockWallet (consistent with remittance_manager.rs pattern)"
  - "All module files gated with #![cfg(feature = \"network\")] inner attribute, mod.rs uses #[cfg(feature = \"network\")] pub mod"

requirements-completed: [BRC29-01, BRC29-04, BRC29-05, BRC29-06, BRC29-07]

# Metrics
duration: 8min
completed: 2026-03-25
---

# Phase 4 Plan 01: BRC-29 Module Skeleton Summary

**Brc29RemittanceModule skeleton with camelCase wire-format types matching TS SDK, injectable provider traits (NonceProvider, LockingScriptProvider), config defaults matching TS constructors, and validation helpers — 29 tests green**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-25T00:51:00Z
- **Completed:** 2026-03-25T00:59:45Z
- **Tasks:** 1 (TDD: RED → GREEN)
- **Files modified:** 4

## Accomplishments

- Created `src/remittance/modules/brc29.rs` (265 lines) with full type system, config, injectable traits, and validation — all gated behind `network` feature
- Wire-format types serialize with camelCase field names exactly matching TS SDK `Brc29OptionTerms`, `Brc29SettlementArtifact`, `Brc29ReceiptData` interfaces; optional fields omitted when `None`
- `Brc29RemittanceModuleConfig::default()` matches TS defaults: `protocolID=[2,"3241645161d8"]`, `labels=["brc29"]`, descriptions identical to TS constructor strings
- `DefaultLockingScriptProvider` uses verified chain: `PublicKey::from_string` → `to_hash()` → `P2PKH::from_public_key_hash` → `lock()` → `to_hex()`
- `build_settlement` and `accept_settlement` are `todo!("Plan 02")` stubs that compile cleanly under `cargo check`

## Task Commits

1. **Task 1: Create brc29.rs with types, config, injectable traits, validation** - `d706a7f` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/remittance/modules/mod.rs` - Module registry, declares `pub mod brc29` gated behind network feature
- `src/remittance/modules/brc29.rs` - Module implementation: types, config, injectable traits, DefaultProviders, validation helpers, RemittanceModule impl with todo! stubs
- `tests/remittance_brc29.rs` - 29 integration tests: metadata, wire-format roundtrips, config defaults, mock provider injection, validation
- `src/remittance/mod.rs` - Added `pub mod modules` declaration

## Decisions Made

- Providers live in `Brc29RemittanceModuleConfig` (not directly on `Brc29RemittanceModule`) — matches TS pattern where providers are constructor options, enabling injection via `..Default::default()` struct update syntax
- `CustomInstructionsPayload` is a private struct — used only inside `build_settlement` (Plan 02), not part of the public API
- `Vec<u8>` default serde serialization produces `[239, 190, ...]` number array, which matches TS `number[]` exactly — no custom serde attribute needed
- `DefaultNonceProvider` silently ignores the `originator` parameter because `create_nonce` only uses `Self_` counterparty with no originator support

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Plan 02 can implement `build_settlement` and `accept_settlement` against concrete types immediately
- `self.config.nonce_provider` and `self.config.locking_script_provider` are ready to call
- All wire-format contracts verified by roundtrip tests — Plan 02 changes cannot silently break serialization

---
*Phase: 04-basic-brc29-module*
*Completed: 2026-03-25*

## Self-Check: PASSED

- src/remittance/modules/brc29.rs: FOUND
- src/remittance/modules/mod.rs: FOUND
- tests/remittance_brc29.rs: FOUND
- .planning/phases/04-basic-brc29-module/04-01-SUMMARY.md: FOUND
- Commit d706a7f: FOUND
