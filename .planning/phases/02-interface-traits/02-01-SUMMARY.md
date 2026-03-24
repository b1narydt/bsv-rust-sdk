---
phase: 02-interface-traits
plan: 01
subsystem: remittance
tags: [async-trait, rust, trait, object-safety, comms, identity]

# Dependency graph
requires:
  - phase: 01-foundation-types
    provides: PeerMessage, IdentityVerificationRequest, IdentityVerificationResponse, IdentityVerificationAcknowledgment, Termination, ModuleContext, RemittanceError
provides:
  - CommsLayer async trait (5 methods: 3 required + 2 optional with Protocol defaults)
  - IdentityLayer async trait (3 required methods)
  - RespondToRequestResult enum (Respond | Terminate)
  - AssessIdentityResult enum (Acknowledge | Terminate)
affects: [03-remittance-manager, 04-payment-modules]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "#[cfg(feature = \"network\")] file-level gate via inner attribute on trait files"
    - "Arc<dyn Fn(...)> for retained callbacks instead of Box<dyn Fn(...)>"
    - "Default trait methods returning Protocol error for optional transport capabilities"
    - "Integration test file for trait tests (pre-existing wallet compilation errors prevent lib test target)"

key-files:
  created:
    - src/remittance/comms_layer.rs
    - src/remittance/identity_layer.rs
    - tests/remittance_traits.rs
  modified:
    - src/remittance/mod.rs

key-decisions:
  - "listen_for_live_messages uses Arc<dyn Fn> not Box<dyn Fn> — transport retains callback across reconnects, matching TS listener pattern"
  - "RespondToRequestResult and AssessIdentityResult defined in identity_layer.rs not types.rs — they are trait-specific contracts, not wire-format types"
  - "assess_received_certificate_sufficiency omits ctx parameter per TS source — assessment relies only on received response and thread_id"
  - "Trait tests placed in tests/remittance_traits.rs integration file — consistent with [01-01] and [01-02] decision due to pre-existing wallet module compilation errors"

patterns-established:
  - "Pattern: #[cfg(feature = \"network\")] inner attribute at top of file gates entire module without wrapping every item"
  - "Pattern: Optional trait methods suppress unused-variable warnings via let _ = (param1, param2, ...)"

requirements-completed: [TRAIT-01, TRAIT-02, TRAIT-03, TRAIT-04, TRAIT-05]

# Metrics
duration: 3min
completed: 2026-03-24
---

# Phase 2 Plan 01: Interface Traits Summary

**Two object-safe async traits (CommsLayer, IdentityLayer) with Arc<dyn T> verified, default optional-method Protocol errors, and TS-matched return enums**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-24T21:37:16Z
- **Completed:** 2026-03-24T21:39:54Z
- **Tasks:** 2
- **Files modified:** 4 (2 created, 1 created integration tests, 1 modified)

## Accomplishments
- CommsLayer async trait with 3 required methods + 2 optional live-message methods that default to Protocol error
- IdentityLayer async trait with 3 required methods matching TS source signatures exactly
- RespondToRequestResult and AssessIdentityResult enums covering both union arms from TypeScript
- 6 integration tests proving object safety (Arc<dyn T>), default method behavior, and enum variant pattern matching

## Task Commits

Each task was committed atomically:

1. **Task 1: Create CommsLayer trait** - `ab454df` (feat)
2. **Task 2: Create IdentityLayer trait** - `85e33dc` (feat)

## Files Created/Modified
- `src/remittance/comms_layer.rs` - CommsLayer async trait with 5 methods (3 required, 2 optional)
- `src/remittance/identity_layer.rs` - IdentityLayer async trait + RespondToRequestResult + AssessIdentityResult
- `tests/remittance_traits.rs` - Integration tests for object safety and trait behavior
- `src/remittance/mod.rs` - Added `pub mod comms_layer` and `pub mod identity_layer` under network feature

## Decisions Made
- Used `Arc<dyn Fn(PeerMessage) + Send + Sync>` (not `Box`) for the `listen_for_live_messages` callback so transports can retain and reuse the handler across reconnects, matching the TypeScript SDK behavior where the listener holds a reference to the callback.
- Return enums (`RespondToRequestResult`, `AssessIdentityResult`) live in `identity_layer.rs` rather than `types.rs` — they are trait contracts, not wire-format protocol types.
- `assess_received_certificate_sufficiency` intentionally omits `ctx: &ModuleContext` per the TypeScript source — sufficiency assessment is a pure data decision from the received response.
- Tests placed in integration file `tests/remittance_traits.rs` following the established pattern from Phase 1 (pre-existing wallet module compilation errors prevent the lib test target from building).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Moved trait tests to integration file**
- **Found during:** Task 1 (CommsLayer verification)
- **Issue:** Pre-existing wallet/auth compilation errors prevent `cargo test` lib target from building, so inline `#[cfg(test)]` blocks in the new files would never run
- **Fix:** Created `tests/remittance_traits.rs` with all 6 tests; kept inline test modules in the source files for IDE tooling but added the runnable integration file as the authoritative test target
- **Files modified:** tests/remittance_traits.rs (created)
- **Verification:** `cargo test --features network --test remittance_traits` — 6/6 pass
- **Committed in:** 85e33dc (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking)
**Impact on plan:** Required to get tests running; consistent with pre-existing Phase 1 pattern. No scope creep.

## Issues Encountered
- Pre-existing wallet/auth compilation errors surface on `cargo test` lib target — same issue documented in Phase 1. Addressed by using integration test file.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Both traits compile cleanly under `--features network`
- `Arc<dyn CommsLayer>` and `Arc<dyn IdentityLayer>` confirmed object-safe
- Ready for Phase 3: RemittanceManager to consume these traits as `Arc<dyn CommsLayer>` and `Arc<dyn IdentityLayer>` fields

---
*Phase: 02-interface-traits*
*Completed: 2026-03-24*

## Self-Check: PASSED

- src/remittance/comms_layer.rs — FOUND
- src/remittance/identity_layer.rs — FOUND
- tests/remittance_traits.rs — FOUND
- .planning/phases/02-interface-traits/02-01-SUMMARY.md — FOUND
- Commit ab454df — FOUND
- Commit 85e33dc — FOUND
