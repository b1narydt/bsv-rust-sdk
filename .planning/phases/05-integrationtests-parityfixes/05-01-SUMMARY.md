---
phase: 05-integrationtests-parityfixes
plan: 01
subsystem: remittance
tags: [rust, tokio, serde, remittance-protocol, parity]

# Dependency graph
requires:
  - phase: 04-basic-brc29-module
    provides: RemittanceManager with BRC-29 module integration

provides:
  - WaitReceiptResult and WaitSettlementResult enums for graceful termination handling
  - timeout_ms on all wait methods (wait_for_state, wait_for_receipt, wait_for_settlement, wait_for_identity)
  - find_invoices_payable and find_receivable_invoices return Vec<InvoiceHandle> with counterparty filter
  - Display impl for RemittanceKind with camelCase strings
  - pub(crate) handle_inbound_message (no longer public API)
  - sync_threads logs errors via config.logger

affects: [05-integrationtests-parityfixes]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "WaitResult enums pattern: wait methods return enum with Receipt/Terminated or Settlement/Terminated arms instead of erroring on termination"
    - "timeout_ms: Option<u64> on all async wait methods, wrapping inner future with tokio::time::timeout when Some"
    - "find_invoices returns InvoiceHandle wrappers, not raw Thread structs"

key-files:
  created: []
  modified:
    - src/remittance/types.rs
    - src/remittance/manager.rs
    - src/remittance/mod.rs
    - tests/remittance_manager.rs
    - tests/remittance_types.rs

key-decisions:
  - "WaitReceiptResult/WaitSettlementResult variants named Receipt/Terminated and Settlement/Terminated — match TS SDK semantics where termination is a valid outcome, not an error"
  - "timeout_ms: Option<u64> propagated to all wait_for_* wrappers including ThreadHandle — consistent API surface"
  - "find_invoices_payable/find_receivable_invoices return Vec<InvoiceHandle> not Vec<Thread> — InvoiceHandle provides pay() and invoice() methods without requiring caller to hold a manager reference"
  - "handle_inbound_message is pub(crate) not pub — external callers use sync_threads (batch) or start_listening (live)"
  - "All 5 test call sites migrated to comms.set_queued_messages + sync_threads before visibility change"

patterns-established:
  - "Pattern 1: test_wait_for_receipt_notify uses set_queued_messages + sync_threads in spawned task instead of handle_inbound_message directly"

requirements-completed: [PARITY-01, PARITY-03, PARITY-04, PARITY-05]

# Metrics
duration: 15min
completed: 2026-03-25
---

# Phase 05 Plan 01: Parity Fixes (PARITY-01/03/04/05) Summary

**Remittance API parity fixes: WaitResult enums, timeout_ms on wait methods, InvoiceHandle-returning find_invoices, Display for RemittanceKind, and pub(crate) handle_inbound_message**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-03-25T12:51:00Z
- **Completed:** 2026-03-25T13:06:16Z
- **Tasks:** 1
- **Files modified:** 5

## Accomplishments

- Added `WaitReceiptResult` and `WaitSettlementResult` enums — wait methods now return `Terminated(Termination)` arm instead of erroring when counterparty terminates
- Added `timeout_ms: Option<u64>` to `wait_for_state`, propagated through `wait_for_receipt`, `wait_for_settlement`, `wait_for_identity`, and all `ThreadHandle` wrappers
- Changed `find_invoices_payable` and `find_receivable_invoices` to accept `counterparty: Option<&str>` filter and return `Vec<InvoiceHandle>` instead of `Vec<Thread>`
- Added `Display` impl for `RemittanceKind` producing camelCase strings matching serde rename values
- Changed `handle_inbound_message` from `pub` to `pub(crate)` after migrating all 5 test call sites to `sync_threads`
- `sync_threads` now logs errors via `config.logger` instead of silently swallowing them
- Exported `WaitReceiptResult` and `WaitSettlementResult` from `mod.rs`

## Task Commits

1. **Task 1: PARITY-05 + PARITY-01 + PARITY-03 + PARITY-04 parity fixes** - `02fba3d` (feat)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `src/remittance/types.rs` - Added `Display impl for RemittanceKind`
- `src/remittance/manager.rs` - WaitReceiptResult/WaitSettlementResult enums, timeout_ms on wait methods, InvoiceHandle-returning find_invoices, pub(crate) handle_inbound_message, logger-based sync_threads error handling
- `src/remittance/mod.rs` - Added WaitReceiptResult and WaitSettlementResult to re-exports
- `tests/remittance_manager.rs` - Updated test_find_invoices_payable, test_wait_for_receipt_notify; migrated 5 handle_inbound_message call sites to sync_threads
- `tests/remittance_types.rs` - Added test_kind_display test

## Decisions Made

- `WaitReceiptResult::Receipt` and `WaitReceiptResult::Terminated` variant names chosen to match TS SDK semantics — termination is a valid outcome, not an error
- `timeout_ms: Option<u64>` propagated to all public wait methods including `ThreadHandle` wrappers — gives callers a uniform timeout API at every level
- `find_invoices_payable`/`find_receivable_invoices` return `Vec<InvoiceHandle>` — caller gets `pay()` and `invoice()` methods without needing to hold the manager

## Deviations from Plan

None — plan executed exactly as written. All 7 steps completed in order, each compiling before proceeding.

## Issues Encountered

None — all changes were straightforward Rust refactors. The `find_invoices` change required the manager borrow inside the filter to use `self.clone()` for the `InvoiceHandle` construction, which works because `RemittanceManager` is cheaply cloneable.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All PARITY-01, PARITY-03, PARITY-04, PARITY-05 gaps closed
- API surface is now parity-correct for Wave 2+ integration tests
- PARITY-02 (host_override) can now add parameters to the same methods without conflicting with these changes
- 35 tests pass (24 remittance_manager + 11 remittance_types), no regressions in wire_format/brc29/traits/module test suites

---
*Phase: 05-integrationtests-parityfixes*
*Completed: 2026-03-25*
