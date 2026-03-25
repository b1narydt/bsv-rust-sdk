---
phase: 05-integrationtests-parityfixes
plan: "04"
subsystem: integration-tests
tags: [test, lifecycle, brc29, TEST-03, TEST-04]
dependency_graph:
  requires: [05-02]
  provides: [TEST-03, TEST-04]
  affects: [tests/remittance_manager.rs]
tech_stack:
  added: []
  patterns:
    - "Manual state-machine walk via insert_thread + transition_thread_state for pre-settlement states"
    - "Inject inbound settlement via set_queued_messages + sync_threads for real accept_settlement exercise"
key_files:
  created: []
  modified:
    - tests/remittance_manager.rs
decisions:
  - "test_full_lifecycle uses insert_thread + manual transitions for identity states (IdentityRequested through Invoiced), then injects inbound Settlement via sync_threads — avoids MockIdentity async complexity while still exercising the real accept_settlement + auto-receipt code path"
  - "TEST-04 confirmed satisfied by existing 38 BRC29 tests — MOCK_TX_BYTES (4-byte non-empty) satisfies is_atomic_beef check; CapturingMockWallet returns tx bytes via create_action; internalize_action receives the same bytes in accept_settlement"
metrics:
  duration: "3 min"
  completed_date: "2026-03-25"
  tasks: 2
  files_modified: 1
---

# Phase 5 Plan 4: Full Lifecycle and BRC29 Realism Audit Summary

Full 7-state lifecycle integration test (`New -> IdentityRequested -> IdentityResponded -> IdentityAcknowledged -> Invoiced -> Settled -> Receipted`) implemented and passing; BRC29 test realism confirmed by audit of existing 38 tests.

## Tasks Completed

### Task 1: Full 7-state lifecycle integration test (TEST-03)

Added `test_full_lifecycle_new_through_receipted` to `tests/remittance_manager.rs`.

**Approach:** Used the "simpler alternative" from the plan — manually drive the identity sub-states via `insert_thread` + `transition_thread_state`, then inject an inbound Settlement via `MockComms.set_queued_messages` + `sync_threads`. This exercises real manager behavior for the most important transitions (accept_settlement, auto-receipt) while avoiding complexity of mocking the full identity message exchange.

**Assertions verified:**
- Thread reaches `Receipted` as final state
- `thread.settlement` is `Some`
- `thread.receipt` is `Some`
- `state_log` contains entries for all 6 transitions (covering all 7 states: New is the implicit start, plus IdentityRequested, IdentityResponded, IdentityAcknowledged, Invoiced, Settled, Receipted)
- A receipt message was sent outbound via comms

**Commit:** `2c3d672`

### Task 2: BRC29 test realism audit (TEST-04)

Audited existing 38 tests in `tests/remittance_brc29.rs`. No code changes required.

**Findings:**
- `test_build_settlement_success_creates_two_nonces`: Uses `CapturingMockWallet` which returns `MOCK_TX_BYTES = &[0xEF, 0xBE, 0xAD, 0xDE]` from `create_action`. Asserts `artifact.transaction == MOCK_TX_BYTES` — proves build_settlement returns a non-empty transaction artifact.
- `test_accept_settlement_success_calls_internalize_with_correct_args`: Passes `MOCK_TX_BYTES` in the settlement artifact, asserts `internalize_action` receives `args.tx == MOCK_TX_BYTES` — proves accept_settlement processes non-empty bytes with a real wallet call.
- `is_atomic_beef` validation: `test_is_atomic_beef_empty_is_false` and `test_is_atomic_beef_nonempty_is_true` confirm the placeholder validator. Since no BEEF parser exists in this crate, 4-byte non-empty data is sufficient per research notes.

TEST-04 is satisfied. No changes needed.

## Verification Results

```
cargo test --features network --test remittance_manager --test remittance_brc29
38 BRC29 tests: ok
25 manager tests: ok (includes test_full_lifecycle_new_through_receipted)
```

## Deviations from Plan

None — plan executed exactly as written. The "simpler alternative approach" suggested in the plan task description was used for Task 1.

## Self-Check

- [x] `tests/remittance_manager.rs` modified — contains `test_full_lifecycle_new_through_receipted`
- [x] Commit `2c3d672` exists: `feat(05-04): add full 7-state lifecycle integration test (TEST-03)`
- [x] All 63 tests pass (25 manager + 38 BRC29)
