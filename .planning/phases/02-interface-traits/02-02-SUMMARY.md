---
phase: 02-interface-traits
plan: 02
subsystem: remittance
tags: [rust, async-trait, serde_json, type-erasure, object-safe]

# Dependency graph
requires:
  - phase: 02-01
    provides: CommsLayer and IdentityLayer traits (wired into mod.rs in this plan)
  - phase: 01-foundation-types
    provides: Invoice, Settlement, Termination, ModuleContext from types.rs

provides:
  - RemittanceModule typed public trait with 3 associated types and 8 methods
  - ErasedRemittanceModule pub(crate) object-safe trait using serde_json::Value boundary
  - Blanket impl bridging typed and erased traits via serde_json round-trip
  - BuildSettlementResult and AcceptSettlementResult public enums
  - BuildSettlementErased and AcceptSettlementErased pub(crate) erased structs
  - All Phase 2 traits re-exported from mod.rs behind cfg(feature = "network")

affects:
  - 03-remittance-manager (stores modules as HashMap<String, Box<dyn ErasedRemittanceModule>>)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Erased-trait pattern: typed public trait with associated types + pub(crate) object-safe
      mirror using serde_json::Value + blanket impl bridging both
    - Integration tests in tests/ directory to avoid pre-existing wallet test compilation errors
    - cfg(feature = "network") gating for all async/serde-dependent code

key-files:
  created:
    - src/remittance/remittance_module.rs
    - tests/remittance_module.rs
  modified:
    - src/remittance/mod.rs

key-decisions:
  - "Inline tests moved to tests/remittance_module.rs — pre-existing wallet test compilation errors prevent lib test target from building (consistent with Phase 1 pattern)"
  - "ErasedRemittanceModule is pub(crate) only — not re-exported from mod.rs, as it is an internal implementation detail for Phase 3"
  - "serde_json::from_value requires clone of the input Value reference — documented in blanket impl with inline comment"
  - "process_termination_erased takes Option<&Settlement> (concrete type), not serde_json::Value — no erasure needed since Settlement is a concrete wire-format struct, matching TS exactly"

patterns-established:
  - "Erased-trait pattern: pub trait Foo<A, B, C> + pub(crate) trait ErasedFoo + impl<T: Foo> ErasedFoo for T"
  - "Integration test files in tests/ for all remittance module tests"

requirements-completed:
  - TRAIT-06
  - TRAIT-07
  - TRAIT-08
  - TRAIT-09
  - TRAIT-10
  - TRAIT-11
  - TRAIT-12

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 2 Plan 02: RemittanceModule Trait Summary

**RemittanceModule typed trait with 3 associated types + ErasedRemittanceModule object-safe internal variant using serde_json::Value boundary + blanket impl, wired into mod.rs with all Phase 2 re-exports**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T21:43:03Z
- **Completed:** 2026-03-24T21:49:54Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- RemittanceModule trait with 3 associated types (OptionTerms, SettlementArtifact, ReceiptData),
  3 required sync getters, 2 required async methods, and 3 optional async methods with default impls
- ErasedRemittanceModule pub(crate) object-safe trait + blanket impl enabling
  `HashMap<String, Box<dyn ErasedRemittanceModule>>` in Phase 3
- All Phase 2 traits (CommsLayer, IdentityLayer, RemittanceModule) re-exported from mod.rs
- 7 integration tests covering object-safety, HashMap storage, default method behaviour, and result enum variants

## Task Commits

1. **Task 1: Create RemittanceModule and ErasedRemittanceModule traits** - `4590c2c` (feat)
2. **Task 2: Wire Phase 2 traits into mod.rs** - `5980ac1` (feat)

## Files Created/Modified

- `src/remittance/remittance_module.rs` - RemittanceModule trait, ErasedRemittanceModule, blanket impl, erased structs
- `tests/remittance_module.rs` - Integration tests for all trait behaviour
- `src/remittance/mod.rs` - Added remittance_module module declaration and re-exports for all Phase 2 traits

## Decisions Made

- Inline tests moved to `tests/remittance_module.rs` — pre-existing wallet test compilation errors
  prevent lib test target from building (consistent with Phase 1 pattern established in 01-01)
- `ErasedRemittanceModule` is `pub(crate)` only, intentionally not re-exported from `mod.rs`
- `serde_json::from_value` requires ownership so we clone the `&serde_json::Value` reference —
  documented inline in blanket impl
- `process_termination_erased` takes `Option<&Settlement>` (concrete type) not `serde_json::Value`,
  because Settlement is a concrete wire-format struct — no erasure needed, matches TS exactly

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Moved tests to integration test file**

- **Found during:** Task 1 (after writing inline tests)
- **Issue:** Pre-existing wallet/auth compilation errors prevent `cargo test --lib` from building;
  inline `#[cfg(test)]` tests in `remittance_module.rs` would not run
- **Fix:** Removed inline test block, created `tests/remittance_module.rs` integration test file
  consistent with the pattern established in Phase 1 (STATE.md decision [01-01])
- **Files modified:** `src/remittance/remittance_module.rs`, `tests/remittance_module.rs`
- **Verification:** `cargo test --features network --test remittance_module` passes (7/7)
- **Committed in:** `4590c2c` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary for tests to actually run. No scope creep — same tests, different location.

## Issues Encountered

- WalletInterface mock required correct types from `crate::wallet::interfaces` (not `crate::wallet::types`)
  and several method signatures differed from assumptions (is_authenticated/wait_for_authentication
  take only `originator`, not args struct; acquire_certificate returns `Certificate` not a result type)
  — fixed by reading the actual trait definition before writing mock impl.

## Next Phase Readiness

- Phase 3 (RemittanceManager) can now use `Box<dyn ErasedRemittanceModule>` for module storage
- All three Phase 2 traits are available via `bsv::remittance::{CommsLayer, IdentityLayer, RemittanceModule}`
- `ErasedRemittanceModule` accessible within crate for Phase 3 implementation

---
*Phase: 02-interface-traits*
*Completed: 2026-03-24*

## Self-Check: PASSED

- src/remittance/remittance_module.rs — FOUND
- tests/remittance_module.rs — FOUND
- src/remittance/mod.rs — FOUND
- .planning/phases/02-interface-traits/02-02-SUMMARY.md — FOUND
- commit 4590c2c — FOUND
- commit 5980ac1 — FOUND
