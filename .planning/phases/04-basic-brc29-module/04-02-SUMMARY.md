---
phase: 04-basic-brc29-module
plan: 02
subsystem: payments
tags: [brc29, remittance, p2pkh, settlement, wallet-interface, tdd]

# Dependency graph
requires:
  - phase: 04-01
    provides: Brc29RemittanceModule skeleton, types, injectable traits, validation helpers
  - phase: 03-remittancemanager
    provides: RemittanceModule trait, BuildSettlementResult, AcceptSettlementResult, ModuleContext, WalletInterface

provides:
  - build_settlement: full implementation creating P2PKH settlement transactions
  - accept_settlement: full implementation internalizing payment via wallet
  - CapturingMockWallet for arg-shape verification tests
  - IncrementingNonceProvider for two-nonce verification

affects:
  - any downstream test that exercises Brc29RemittanceModule end-to-end

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Inner-function error-catching: build_settlement_inner returns Result; outer build_settlement maps Err to Terminate with code brc29.build_failed, matching TS try/catch pattern"
    - "CapturingMockWallet: Arc<Mutex<Vec<Args>>> captures wallet calls for precise arg-shape assertions in tests"
    - "IncrementingNonceProvider: counter-based mock returns mock-nonce-1, mock-nonce-2 — enables verification that two distinct nonces flow correctly through key_id"

key-files:
  modified:
    - src/remittance/modules/brc29.rs
    - tests/remittance_brc29.rs

key-decisions:
  - "build_settlement_inner is a separate private method on Brc29RemittanceModule (not a closure) — async closures with captured self are awkward in Rust; inner method compiles cleanly"
  - "ensure_valid_option failure returns Terminate directly from build_settlement_inner (not Err) so it is not caught by the outer build_failed handler — matches TS brc29.invalid_option code"
  - "accept_settlement does NOT use an inner method pattern — internalize errors are caught inline with match on the await result, simpler than nesting"

# Metrics
duration: 6min
completed: 2026-03-25
---

# Phase 4 Plan 02: BRC-29 Settlement Implementation Summary

**build_settlement and accept_settlement implemented with exact TS BasicBRC29 flow: two-nonce key derivation, P2PKH locking script, create_action with randomize_outputs=false, internalize_action with Payment bytes — 38 tests green**

## Performance

- **Duration:** ~6 min
- **Started:** 2026-03-25T01:02:36Z
- **Completed:** 2026-03-25T01:08:42Z
- **Tasks:** 2 (both TDD: RED -> GREEN)
- **Files modified:** 2

## Accomplishments

- Replaced `todo!("Plan 02")` stubs in `build_settlement` and `accept_settlement` with full implementations matching TS BasicBRC29.ts behavior exactly
- `build_settlement` flow: validate option -> create two nonces -> get_public_key with protocol/key_id/counterparty -> locking script hex decoded to bytes -> create_action with P2PKH output (randomize_outputs=false) -> extract tx (with signableTransaction fallback) -> return Brc29SettlementArtifact
- `accept_settlement` flow: validate artifact -> internalize_action with Payment{derivation_prefix/suffix as UTF-8 bytes, sender_identity_key as PublicKey} -> catch error -> return Accept or Terminate
- All five termination codes match TS: `brc29.invalid_option`, `brc29.missing_tx`, `brc29.build_failed`, `brc29.internalize_failed`
- `CapturingMockWallet` with `Arc<Mutex<Vec<Args>>>` enables precise assertions on exact argument shapes sent to wallet interface methods
- `IncrementingNonceProvider` enables verification that two distinct nonces flow correctly as prefix/suffix

## Task Commits

1. **Task 1 + Task 2: TDD RED+GREEN for build_settlement and accept_settlement** - `8db983e` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/remittance/modules/brc29.rs` — build_settlement_inner impl block added (~160 lines), build_settlement and accept_settlement stubs replaced with full implementations; added imports for CreateActionArgs, CreateActionOutput, CreateActionOptions, GetPublicKeyArgs, InternalizeActionArgs, InternalizeOutput, Payment, BooleanDefaultTrue, Counterparty, CounterpartyType
- `tests/remittance_brc29.rs` — CapturingMockWallet added with configurable error modes; IncrementingNonceProvider added; 9 new tests for build_settlement (5) and accept_settlement (3 success + 2 failure variants)

## Decisions Made

- `build_settlement_inner` is a separate private `impl Brc29RemittanceModule` method — async closures capturing `&self` are awkward in Rust, separate method compiles cleanly with no lifetime issues
- `ensure_valid_option` failure returns `Terminate` directly from the inner method (not `Err`) so the outer `build_failed` catch-all does not intercept it — exactly matching TS behavior where `ensureValidOption` throws a specifically-coded error vs the generic catch
- `accept_settlement` catches internalize errors inline with `match` on the `.await` result rather than an inner method pattern — simpler since there is only one fallible wallet call

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Phase 4 is complete — Brc29RemittanceModule is fully functional
- Phase 5 (JSON wire-format vector tests against TS SDK) can proceed once TS test vectors are generated

---
*Phase: 04-basic-brc29-module*
*Completed: 2026-03-25*

## Self-Check: PASSED

- src/remittance/modules/brc29.rs: FOUND
- tests/remittance_brc29.rs: FOUND
- .planning/phases/04-basic-brc29-module/04-02-SUMMARY.md: FOUND
- Commit 8db983e: FOUND
