# Roadmap: BSV Rust SDK — Remittance Protocol

## Overview

Translate the TypeScript SDK's `src/remittance/` subsystem to Rust in strict dependency order: foundation types and wire-format serialization first, then the three pluggable-interface traits, then the RemittanceManager orchestrator, then the concrete BasicBRC29 settlement module, and finally integration and serialization tests that validate wire-format parity with TypeScript. Each phase produces a compilable, testable unit that unblocks the next. The result is a RemittanceManager that exchanges messages with a TypeScript wallet with zero translation layer.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation Types** - All protocol types, enums, state machine, and wire-format serialization (completed 2026-03-24)
- [x] **Phase 2: Interface Traits** - CommsLayer, IdentityLayer, and RemittanceModule trait definitions with erased-trait pattern (completed 2026-03-24)
- [x] **Phase 3: RemittanceManager** - Full orchestrator with state machine enforcement, message routing, and persistence (completed 2026-03-24)
- [x] **Phase 4: BasicBRC29 Module** - Concrete BRC-29 P2PKH settlement module implementing RemittanceModule (completed 2026-03-25)
- [ ] **Phase 5: Integration Tests** - Wire-format parity tests, state machine coverage, and end-to-end lifecycle tests

## Phase Details

### Phase 1: Foundation Types
**Goal**: All protocol types and enums compile with correct camelCase JSON wire format matching the TypeScript SDK
**Depends on**: Nothing (first phase)
**Requirements**: TYPE-01, TYPE-02, TYPE-03, TYPE-04, TYPE-05, TYPE-06, TYPE-07, TYPE-08, TYPE-09, TYPE-10, TYPE-11, TYPE-12, TYPE-13, TYPE-14, TYPE-15, TYPE-16, TYPE-17, TYPE-18, WIRE-01, WIRE-02, WIRE-03, WIRE-04, WIRE-05, WIRE-06
**Success Criteria** (what must be TRUE):
  1. `RemittanceThreadState` serializes all 9 variants to exact lowercase strings matching TypeScript (e.g., `"identityRequested"`, not `"identity_requested"`)
  2. `RemittanceEnvelope` roundtrips through `serde_json` with no field name differences vs. TypeScript wire format
  3. Every `Option<T>` field is absent from JSON output when `None` (not serialized as `null`)
  4. All 18 core types compile under `#[cfg(feature = "network")]` and are re-exported from `src/remittance/mod.rs`
  5. `RemittanceError` covers all error variants needed by the rest of the protocol
**Plans:** 2/2 plans complete

Plans:
- [ ] 01-01-PLAN.md — Module skeleton, enums, state transitions, error type, LoggerLike trait
- [ ] 01-02-PLAN.md — All protocol structs with serde annotations and wire-format roundtrip tests

### Phase 2: Interface Traits
**Goal**: CommsLayer, IdentityLayer, and RemittanceModule traits are object-safe, async, and Send+Sync — with the erased-trait pattern preventing any Phase 3 rewrite
**Depends on**: Phase 1
**Requirements**: TRAIT-01, TRAIT-02, TRAIT-03, TRAIT-04, TRAIT-05, TRAIT-06, TRAIT-07, TRAIT-08, TRAIT-09, TRAIT-10, TRAIT-11, TRAIT-12
**Success Criteria** (what must be TRUE):
  1. A mock `CommsLayer` impl compiles and can be stored in a `Box<dyn CommsLayer + Send + Sync>`
  2. `RemittanceModule` trait with associated types compiles alongside `ErasedRemittanceModule` object-safe blanket impl
  3. A `HashMap<String, Box<dyn ErasedRemittanceModule>>` holding multiple module types compiles without casting
  4. All three traits use `#[async_trait]` and match the method signatures from TypeScript source
**Plans:** 2/2 plans complete

Plans:
- [x] 02-01-PLAN.md — CommsLayer and IdentityLayer trait definitions with mock-based object-safety tests
- [ ] 02-02-PLAN.md — RemittanceModule + ErasedRemittanceModule traits with blanket impl, mod.rs wiring

### Phase 3: RemittanceManager
**Goal**: A fully working RemittanceManager that enforces the state machine, routes inbound messages, and exposes the complete public API for payment flows
**Depends on**: Phase 2
**Requirements**: MGR-01, MGR-02, MGR-03, MGR-04, MGR-05, MGR-06, MGR-07, MGR-08, MGR-09, MGR-10, MGR-11, MGR-12, MGR-13, MGR-14, MGR-15, MGR-16, MGR-17, MGR-18, MGR-19, MGR-20, MGR-21, MGR-22
**Success Criteria** (what must be TRUE):
  1. `RemittanceManager::send_invoice()` creates a new thread in `New` state and transitions it through the identity exchange to `Invoiced`
  2. `transition_thread_state()` returns an error for any transition not in the `allowed_transitions()` table, including the back-transitions from `Invoiced` to identity states
  3. `RemittanceManagerState` serializes to a `{ v: 1, threads: [...] }` JSON envelope that can be reloaded via `init()`
  4. `wait_for_receipt()` resolves when the thread reaches `Receipted` state without busy-polling (uses `tokio::sync::Notify`)
  5. `RemittanceEvent` listeners fire at every state change and message receipt
**Plans:** 3/3 plans complete

Plans:
- [ ] 03-01-PLAN.md — Core types, constructor, state persistence, state machine enforcement, event system, thread accessors
- [ ] 03-02-PLAN.md — Invoice and payment flow methods (send_invoice, pay, send_unsolicited_settlement, identity exchange)
- [ ] 03-03-PLAN.md — Comms integration, inbound message dispatch, Notify-based waiters, ThreadHandle/InvoiceHandle

### Phase 4: BasicBRC29 Module
**Goal**: A working BRC-29 P2PKH settlement module that builds and accepts settlements via the wallet interface, with injectable dependencies for testability
**Depends on**: Phase 2
**Requirements**: BRC29-01, BRC29-02, BRC29-03, BRC29-04, BRC29-05, BRC29-06, BRC29-07
**Success Criteria** (what must be TRUE):
  1. `Brc29RemittanceModule::build_settlement()` calls `wallet.create_action()` with a P2PKH output derived via Type-42 BRC-29 key derivation and returns a valid `Brc29SettlementArtifact`
  2. `Brc29RemittanceModule::accept_settlement()` calls `wallet.internalize_action()` with correct derivation params and returns `Brc29ReceiptData`
  3. `Brc29RemittanceModule` registers in the manager's module registry under id `"brc29.p2pkh"` and responds to `pay()` calls
  4. Mock `NonceProvider` and `LockingScriptProvider` can be injected, making the module testable without a live wallet
**Plans:** 2/2 plans complete

Plans:
- [ ] 04-01-PLAN.md — Module skeleton, types, config, injectable traits, validation helpers
- [ ] 04-02-PLAN.md — build_settlement and accept_settlement implementations with mock wallet tests

### Phase 5: Integration Tests & Parity Fixes
**Goal**: Wire-format parity with TypeScript SDK is verified by deserializing raw TypeScript-originated JSON, the full thread lifecycle runs end-to-end with a mock transport, and remaining TS SDK parity gaps are closed
**Depends on**: Phase 4
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06, PARITY-01, PARITY-02, PARITY-03, PARITY-04, PARITY-05
**Success Criteria** (what must be TRUE):
  1. Raw TypeScript-originated JSON for all 7 message kinds deserializes into Rust types without error
  2. Every `RemittanceThreadState` transition in the `allowed_transitions()` table is exercised by a passing test; every invalid transition produces an error
  3. A full `New -> identityRequested -> identityResponded -> identityAcknowledged -> invoiced -> settled -> receipted` lifecycle completes using mock CommsLayer and mock wallet
  4. `BasicBRC29` `build_settlement` and `accept_settlement` unit tests pass with a mock wallet returning realistic BEEF artifacts
  5. `wait_for_receipt()` returns `Termination` (not an error) when counterparty terminates instead of receipting
  6. `wait_for_state()` accepts optional `timeout_ms` and returns `RemittanceError::Timeout` on expiry
  7. All public methods that send messages accept optional `host_override: Option<&str>`
**Parity gaps** (from Phase 3 audit — see `.planning/phases/03-remittancemanager/PARITY-GAPS.md`):
  - BUG-03: wait_for_receipt/wait_for_settlement return error on Terminated → return enum
  - GAP-01: Auto-wait for receipt after pay based on `receiptProvided` config
  - GAP-02: Thread hostOverride through all public method signatures
  - GAP-03: Add timeout_ms to wait methods
  - GAP-04: findInvoices counterparty filter parameter
  - GAP-05: findInvoices return `Vec<InvoiceHandle>` instead of `Vec<Thread>`
  - GAP-06: Display impl for RemittanceKind
  - GAP-07: handle_inbound_message visibility to pub(crate)
  - GAP-08: sync_threads log errors via config.logger instead of swallowing
**Plans:** 2/4 plans executed

Plans:
- [ ] 05-01-PLAN.md — Parity fixes: WaitResult enums, timeout_ms, find_invoices signature, Display, visibility, logging
- [ ] 05-02-PLAN.md — host_override parameter threading on all public methods
- [ ] 05-03-PLAN.md — Exhaustive state machine tests and TS-originated JSON deserialization tests
- [ ] 05-04-PLAN.md — Full lifecycle integration test and BRC29 test realism audit

## Progress

**Execution Order:**
Phases execute in order: 1 -> 2 -> 3 -> 4 -> 5 (Phase 4 depends on Phase 2, not Phase 3 -- can be parallelized if desired, but sequential is safe)

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation Types | 2/2 | Complete   | 2026-03-24 |
| 2. Interface Traits | 2/2 | Complete   | 2026-03-24 |
| 3. RemittanceManager | 3/3 | Complete   | 2026-03-24 |
| 4. BasicBRC29 Module | 2/2 | Complete   | 2026-03-25 |
| 5. Integration Tests | 2/4 | In Progress|  |
