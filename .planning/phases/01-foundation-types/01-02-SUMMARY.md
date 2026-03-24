---
phase: 01-foundation-types
plan: 02
subsystem: remittance
tags: [serde, structs, wire-format, camelCase, flatten, serde_json]

# Dependency graph
requires:
  - phase: 01-foundation-types plan 01
    provides: RemittanceKind enum, RemittanceThreadState enum, LoggerLike trait, type aliases
provides:
  - Unit, Amount, LineItem structs with serde camelCase
  - InstrumentBase struct with optional field skipping
  - Invoice struct with serde(flatten) for InstrumentBase
  - IdentityRequest, IdentityCertificate sub-structs
  - IdentityVerificationRequest/Response/Acknowledgment structs
  - Settlement, Receipt, Termination structs
  - PeerMessage, RemittanceEnvelope structs
  - ModuleContext runtime-only struct (no serde)
  - sat_unit() helper function
  - 20 wire-format roundtrip integration tests
affects: [02-state-machine, 03-protocol-logic, 04-settlement-modules, 05-integration]

# Tech tracking
tech-stack:
  added: []
  patterns: [serde flatten for struct composition, serde rename for Rust keyword fields, skip_serializing_if for absent-not-null Option fields, Arc-based runtime context without serde]

key-files:
  created:
    - tests/remittance_wire_format.rs
  modified:
    - src/remittance/types.rs
    - src/remittance/mod.rs

key-decisions:
  - "Wire-format tests placed in integration test file (tests/remittance_wire_format.rs) due to pre-existing wallet module compilation errors in lib test target"
  - "ModuleContext uses Arc<dyn WalletInterface> instead of references to avoid lifetime propagation"

patterns-established:
  - "serde(flatten) for composing InstrumentBase into Invoice without nesting"
  - "serde(rename = 'type') for Rust keyword field names in wire format"
  - "skip_serializing_if = Option::is_none on every Option<T> field for TS absent-field parity"
  - "serde_json::Value for arbitrary JSON payloads (artifact, receiptData, payload)"

requirements-completed: [TYPE-03, TYPE-04, TYPE-05, TYPE-06, TYPE-07, TYPE-08, TYPE-09, TYPE-10, TYPE-11, TYPE-12, TYPE-13, TYPE-14, TYPE-17, WIRE-01, WIRE-03, WIRE-04, WIRE-05, WIRE-06]

# Metrics
duration: 6min
completed: 2026-03-24
---

# Phase 1 Plan 02: Protocol Structs Summary

**All 13 protocol structs with serde wire-format parity: Invoice with flatten, IdentityCertificate with keyword rename, arbitrary JSON payloads, and 20 roundtrip tests**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-24T19:41:11Z
- **Completed:** 2026-03-24T19:47:01Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Implemented all 13 protocol structs + 2 sub-structs with correct serde annotations
- Invoice correctly flattens InstrumentBase fields at top level via serde(flatten)
- IdentityCertificate.cert_type serializes as "type" in JSON despite being a Rust keyword
- All Option<T> fields omitted from JSON when None (not null)
- ModuleContext compiles without serde (runtime-only, uses Arc references)
- 20 wire-format roundtrip tests all passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement all protocol structs with serde annotations** - `bdd6363` (feat)
2. **Task 2: Wire-format roundtrip tests for all structs** - `60d33f2` (test)

## Files Created/Modified
- `src/remittance/types.rs` - All protocol structs with serde derives and wire-format annotations
- `src/remittance/mod.rs` - Updated re-exports for all new public types
- `tests/remittance_wire_format.rs` - 20 wire-format roundtrip integration tests

## Decisions Made
- Wire-format tests placed in integration test file rather than inline #[cfg(test)] block due to pre-existing wallet module compilation errors (consistent with Plan 01-01 approach)
- ModuleContext uses Arc<dyn WalletInterface> for runtime references to avoid lifetime propagation into trait signatures

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All foundation types complete (enums + structs + state machine)
- Phase 1 fully complete, ready for Phase 2 (interface traits)
- InstrumentBase and Invoice patterns established for trait method signatures

---
*Phase: 01-foundation-types*
*Completed: 2026-03-24*
