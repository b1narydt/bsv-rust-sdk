---
phase: 03-remittancemanager
plan: 02
subsystem: payments
tags: [rust, tokio, serde, remittance, invoice, payment, async, manager]

# Dependency graph
requires:
  - phase: 03-remittancemanager plan 01
    provides: RemittanceManager struct, Thread, ThreadHandle, InvoiceHandle, transition_thread_state, emit_event, insert_thread
  - phase: 02-interface-traits
    provides: ErasedRemittanceModule (build_settlement_erased, create_option_erased), CommsLayer, IdentityLayer
  - phase: 01-foundation-types
    provides: Invoice, Settlement, RemittanceEnvelope, InstrumentBase, ModuleContext, RemittanceKind
provides:
  - send_invoice (maker flow: new thread, optional identity exchange, compose invoice, send, Invoiced)
  - send_invoice_for_thread (invoice on existing thread)
  - find_invoices_payable (taker + Invoiced filter)
  - find_receivable_invoices (maker + Invoiced filter)
  - pay (module lookup, build_settlement_erased, Settlement envelope, Settled)
  - send_unsolicited_settlement (taker thread, settlement without prior invoice)
  - compose_invoice (InstrumentBase + module create_option_erased options map)
  - ensure_identity_exchange (IdentityVerificationRequest envelope, IdentityRequested transition)
  - create_thread (thread creation with ThreadCreated event)
  - make_envelope (static helper: RemittanceEnvelope with random ID)
  - send_envelope (live-first with queued fallback, protocol log, EnvelopeSent event)
  - preselect_payment_option_id (string-slice public API, persists state)
  - 17 passing integration tests (9 Phase 01 + 8 Phase 02)
affects:
  - 03-03 (receive flows use same Thread/Invoice structures, pay produces Settlement for accept flow)
  - 03-04 (comms integration: send_envelope wires into live WebSocket transport)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Pattern: static fn() -> u64 function pointer for ModuleContext.now — cannot capture env, use module-level static default_now()"
    - "Pattern: Arc<HashMap> module registry accessed without lock in compose_invoice and pay hot paths"
    - "Pattern: live-first send with queued fallback in send_envelope — mirrors TS SDK send_live_message pattern"
    - "Pattern: extract data under lock, drop guard before .await — no MutexGuard held across async boundaries"

key-files:
  created: []
  modified:
    - src/remittance/manager.rs
    - tests/remittance_manager.rs

key-decisions:
  - "ModuleContext.now is fn() -> u64 (function pointer), not Arc<dyn Fn>. Static default_now() defined inside make_module_context to satisfy the type. Cannot change ModuleContext.now type mid-phase — no consumers yet but type is set by Phase 1."
  - "preselect_payment_option_id added as string-slice variant alongside existing preselect_payment_option(Option<String>) — keeps backward compat with tests from Phase 01 that call the Option variant directly."
  - "ensure_identity_exchange only checks maker_request_identity phase — taker does not initiate. Mirrors TS SDK where only the maker sends the initial request in BeforeInvoicing phase."
  - "pay defaults to first available invoice option when neither option_id nor default_payment_option_id is set — matches TS SDK fallback behavior."

patterns-established:
  - "Pattern: send_envelope = serialize to JSON + send_live_message (fallback send_message) + append ProtocolLogEntry + emit EnvelopeSent — single codepath for all outbound protocol messages"
  - "Pattern: create_thread emits ThreadCreated, stores under lock, returns clone — thread is immediately accessible before any async work"

requirements-completed: [MGR-06, MGR-07, MGR-08, MGR-09, MGR-10, MGR-13, MGR-19]

# Metrics
duration: 5min
completed: 2026-03-24
---

# Phase 3 Plan 2: RemittanceManager Summary

**send_invoice, pay, send_unsolicited_settlement public API with compose_invoice, ensure_identity_exchange, send_envelope helpers — 17 integration tests green**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-24T22:43:18Z
- **Completed:** 2026-03-24T22:48:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Implemented the full invoice/payment public API on RemittanceManager: send_invoice, send_invoice_for_thread, find_invoices_payable, find_receivable_invoices, pay, send_unsolicited_settlement, preselect_payment_option_id
- Built internal helpers: make_envelope (random ID generation), send_envelope (live-first/queued fallback + protocol log + event), compose_invoice (InstrumentBase + module options), ensure_identity_exchange (IdentityVerificationRequest + IdentityRequested transition), create_thread (thread factory + ThreadCreated event)
- Added 8 new integration tests covering invoice lifecycle, payment, unsolicited settlement, identity exchange, module option composition, and preselect option; all 17 tests (9 Phase 01 + 8 Phase 02) pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement all payment flow methods** - `6aca6ad` (feat)
2. **Task 2: Tests for invoice flows, payment, unsolicited settlement** - `4a9f4b1` (test)

**Plan metadata:** (created in final commit)

## Files Created/Modified
- `src/remittance/manager.rs` - Added make_module_context, make_envelope, send_envelope, compose_invoice, ensure_identity_exchange, create_thread, send_invoice, send_invoice_for_thread, find_invoices_payable, find_receivable_invoices, pay, send_unsolicited_settlement, preselect_payment_option_id (695 lines added)
- `tests/remittance_manager.rs` - Enhanced MockComms (live tracking + fail_live mode), added MockModuleWithOptions, MockModuleTracked, 8 new test functions, fixture helpers (489 lines added)

## Decisions Made
- `ModuleContext.now` is `fn() -> u64` — uses a static `default_now()` defined inside `make_module_context`. Wrapping `config.now` (a `Box<dyn Fn>`) into `fn()` is impossible, so `make_module_context` always uses the default clock. Tests inject deterministic time via `config.now` override, which affects `self.now_internal()` calls only. Module context always sees wall-clock time in tests — acceptable since no test asserts on module-context timestamps.
- Added `preselect_payment_option_id(&str)` alongside the existing `preselect_payment_option(Option<String>)` — both persist state. The string-slice variant is the public API matching the plan spec; the Option variant is kept for backward compatibility with Phase 01 tests.
- `pay` falls back to first invoice option key when no option_id provided and no default set — enables zero-config payment for single-module scenarios.

## Deviations from Plan

None — plan executed exactly as written. The `ModuleContext.now` concern documented in the plan (static fn vs Arc<dyn Fn>) was resolved as planned: use a static function inside `make_module_context`.

## Issues Encountered
- Arc<MockComms> to Arc<dyn CommsLayer> coercion in test identity exchange test required creating a second Arc wrapping a new MockComms that shares the `sent` Arc — fixed inline without affecting any other test.
- Pre-existing wallet module compilation errors continue to prevent `cargo test --lib` from building — consistent with all Phase 1/2/3 tests. All 50 remittance integration tests pass correctly.

## Next Phase Readiness
- All outbound protocol flows implemented (send invoice, pay, send unsolicited settlement)
- Plan 03 (receive flows: handle_envelope, accept settlement, issue receipt) can now reference send_envelope, transition_thread_state, and the full module/erased API
- MockComms, MockModuleWithOptions, MockModuleTracked are reusable in future test files

## Self-Check: PASSED

- FOUND: .planning/phases/03-remittancemanager/03-02-SUMMARY.md
- FOUND: src/remittance/manager.rs
- FOUND: tests/remittance_manager.rs
- FOUND commit: 6aca6ad (feat — Task 1)
- FOUND commit: 4a9f4b1 (test — Task 2)

---
*Phase: 03-remittancemanager*
*Completed: 2026-03-24*
