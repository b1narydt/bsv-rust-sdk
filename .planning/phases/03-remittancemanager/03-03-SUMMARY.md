---
phase: 03-remittancemanager
plan: 03
subsystem: payments
tags: [rust, tokio, async, notify, remittance, comms, deduplication]

# Dependency graph
requires:
  - phase: 03-02
    provides: send_invoice, pay, send_unsolicited_settlement, compose_invoice
  - phase: 02-02
    provides: ErasedRemittanceModule, AcceptSettlementErased, process_receipt_erased, process_termination_erased
  - phase: 02-01
    provides: CommsLayer, IdentityLayer traits

provides:
  - handle_inbound_message with deduplication and full dispatch pipeline
  - sync_threads (fetch and process pending messages from CommsLayer)
  - start_listening (register live message callback with CommsLayer)
  - apply_inbound_envelope dispatching all 7 RemittanceKind variants
  - wait_for_state/receipt/identity/settlement using tokio::sync::Notify
  - ThreadHandle and InvoiceHandle wait delegate methods
  - is_terminal_state helper for waiter loop exit

affects:
  - 04-persistence
  - 05-integration

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Lost-wakeup prevention: register notify.notified() future before re-checking state under lock"
    - "Inbound thread creation: role inferred from message kind (Invoice→Taker, Settlement→Maker)"
    - "Deduplication: processed_message_ids checked under lock before apply_inbound_envelope"
    - "Module lookup for Receipt/Termination: prefer settlement.module_id, fall back to first registered"
    - "start_listening callback spawns tokio::spawn for each message (Fn not async)"

key-files:
  created: []
  modified:
    - src/remittance/manager.rs
    - tests/remittance_manager.rs

key-decisions:
  - "Receipt constructed with module_id/option_id from the Settlement, payee/payer from invoice.base if available"
  - "apply_inbound_envelope extracts sender/invoice/settlement from thread before dispatch to avoid holding lock across await"
  - "Termination handler uses settlement.module_id when available, first-registered module otherwise — swallows errors"
  - "test_identity_exchange fixed to share MockComms instance between manager and observer (regression from MockComms refactor)"
  - "MockComms enhanced with queued_messages, acknowledged, live_callback, listening_flag for Plan 03 tests"

patterns-established:
  - "Notify-based waiter: register notifier entry, create notified() future, re-check state under lock, then await"
  - "Inbound pipeline: parse envelope → dedup check → apply handler → log message_id → emit event → acknowledge"

requirements-completed:
  - MGR-04
  - MGR-05
  - MGR-11
  - MGR-12
  - MGR-17

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 3 Plan 03: RemittanceManager Comms Integration Summary

**Full inbound message pipeline with tokio::sync::Notify-based waiters: sync_threads, start_listening, handle_inbound_message dispatching all 7 protocol kinds, deduplication, and non-blocking wait_for_receipt/identity/settlement on RemittanceManager and ThreadHandle**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T22:51:35Z
- **Completed:** 2026-03-24T22:57:38Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Implemented `handle_inbound_message` with full parse-dedup-dispatch-acknowledge pipeline
- Implemented `apply_inbound_envelope` covering all 7 `RemittanceKind` variants (Invoice, Settlement with auto-receipt, Receipt, Termination, all 3 identity kinds)
- Implemented `sync_threads` and `start_listening` for CommsLayer integration with spawn-based callback
- Implemented `wait_for_state/receipt/identity/settlement` using tokio::sync::Notify with lost-wakeup prevention
- Added `ThreadHandle` wait delegates and `InvoiceHandle.invoice()` and `InvoiceHandle.pay()` methods
- All 24 integration tests pass including 7 new tests for Plan 03 requirements

## Task Commits

Each task was committed atomically:

1. **Task 1: Inbound message handling, sync_threads, start_listening, Notify-based waiters** - `21e6417` (feat)
2. **Task 2: Tests for sync_threads, deduplication, start_listening, wait_for_receipt, ThreadHandle** - `c171031` (test)

**Plan metadata:** (docs commit follows)

_Note: Task 2 used TDD pattern — tests written before verification; all passed green on first run due to Task 1 completing implementation first._

## Files Created/Modified
- `src/remittance/manager.rs` — Added 802 lines: is_terminal_state, handle_inbound_message, get_or_create_thread_from_inbound, create_thread_with_id, apply_inbound_envelope (7 kinds), sync_threads, start_listening, wait_for_state, wait_for_receipt, wait_for_identity, wait_for_settlement, ThreadHandle wait methods, InvoiceHandle methods
- `tests/remittance_manager.rs` — Enhanced MockComms (queued_messages, acknowledged, live_callback, listening_flag), added MockModuleWithReceipt, 5 test helpers, 7 new tests

## Decisions Made
- Receipt constructed with module_id/option_id from the Settlement (not guessed), payee/payer from invoice.base when available
- Termination handler uses settlement.module_id when available, first-registered module as fallback — consistent with TS pattern of "best-effort notification"
- MockComms refactored from struct literals to constructor-based to support configurable queued_messages and tracking; fixed test_identity_exchange to share the same instance

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Receipt struct requires module_id, option_id, payee, payer fields**
- **Found during:** Task 1 (apply_inbound_envelope Settlement handler)
- **Issue:** Plan's Receipt construction only specified kind/thread_id/receipt_data/created_at; actual Receipt struct requires 4 additional fields
- **Fix:** Populated module_id/option_id from settlement, payee/payer from invoice.base or thread identity key
- **Files modified:** src/remittance/manager.rs
- **Verification:** cargo check --features network passes
- **Committed in:** 21e6417 (Task 1 commit)

**2. [Rule 1 - Bug] MockComms struct literal broke test_identity_exchange after refactor**
- **Found during:** Task 2 (running tests after MockComms enhancement)
- **Issue:** test_identity_exchange constructed `comms_inner = MockComms { sent: Arc::clone(&comms.sent), ... }` to share the sent arc; after refactoring MockComms to constructor-only, comms_inner was a separate instance with empty sent
- **Fix:** Changed test to use `comms.clone()` (Arc clone) as the comms_dyn, observing the same sent arc
- **Files modified:** tests/remittance_manager.rs
- **Verification:** test_identity_exchange passes
- **Committed in:** c171031 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 missing fields, 1 bug from refactor)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered
None beyond the two auto-fixed deviations above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 3 is now complete: all 22 MGR requirements implemented across Plans 01-03
- Phase 4 (persistence) can begin: RemittanceManager has save_state/load_state/persist_state and state_saver/state_loader hooks ready for integration
- Phase 5 (integration tests with TS wire format vectors) requires TS JSON test vectors to be generated first

---
*Phase: 03-remittancemanager*
*Completed: 2026-03-24*
