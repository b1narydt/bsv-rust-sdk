# Requirements: BSV Rust SDK — Remittance Protocol

**Defined:** 2026-03-24
**Core Value:** Wire-format interoperable remittance protocol in Rust, identical to TypeScript SDK

## v1 Requirements

Requirements for full parity with TypeScript SDK `src/remittance/`.

### Core Types

- [x] **TYPE-01**: RemittanceThreadState enum with 9 states matching TS (new, identityRequested, identityResponded, identityAcknowledged, invoiced, settled, receipted, terminated, errored)
- [x] **TYPE-02**: REMITTANCE_STATE_TRANSITIONS validation table with all valid transitions including back-transitions from invoiced to identity states
- [x] **TYPE-03**: Unit and Amount types for denomination-agnostic values
- [x] **TYPE-04**: LineItem struct with all fields (id, description, quantity, unitPrice, amount, metadata)
- [x] **TYPE-05**: InstrumentBase struct (threadId, payee, payer, note, lineItems, total, invoiceNumber, createdAt, arbitrary)
- [x] **TYPE-06**: Invoice struct extending InstrumentBase with expiresAt and options map
- [x] **TYPE-07**: IdentityVerificationRequest with nested request containing types map and certifiers list
- [x] **TYPE-08**: IdentityVerificationResponse with certificates array (type, certifier, subject, fields, signature, serialNumber, revocationOutpoint, keyringForVerifier)
- [x] **TYPE-09**: IdentityVerificationAcknowledgment struct
- [x] **TYPE-10**: Settlement struct (kind, threadId, moduleId, optionId, sender, createdAt, artifact, note)
- [x] **TYPE-11**: Receipt struct (kind, threadId, moduleId, optionId, payee, payer, createdAt, receiptData)
- [x] **TYPE-12**: Termination struct (code, message, details)
- [x] **TYPE-13**: PeerMessage struct (messageId, sender, recipient, messageBox, body)
- [x] **TYPE-14**: RemittanceEnvelope struct with version, id, kind, threadId, createdAt, payload
- [x] **TYPE-15**: RemittanceKind enum (invoice, identityVerificationRequest/Response/Acknowledgment, settlement, receipt, termination)
- [x] **TYPE-16**: All types derive Serialize/Deserialize with camelCase JSON field names matching TS wire format
- [x] **TYPE-17**: ModuleContext struct (wallet, originator, now, logger)
- [x] **TYPE-18**: LoggerLike trait for optional structured logging

### Interface Traits

- [x] **TRAIT-01**: CommsLayer trait with sendMessage, listMessages, acknowledgeMessage methods
- [x] **TRAIT-02**: CommsLayer optional sendLiveMessage and listenForLiveMessages methods
- [x] **TRAIT-03**: IdentityLayer trait with determineCertificatesToRequest method
- [x] **TRAIT-04**: IdentityLayer respondToRequest method returning respond or terminate
- [x] **TRAIT-05**: IdentityLayer assessReceivedCertificateSufficiency method
- [x] **TRAIT-06**: RemittanceModule trait with id, name, allowUnsolicitedSettlements properties
- [x] **TRAIT-07**: RemittanceModule createOption method (optional)
- [x] **TRAIT-08**: RemittanceModule buildSettlement method returning settle artifact or terminate
- [x] **TRAIT-09**: RemittanceModule acceptSettlement method returning accept with receipt data or terminate
- [x] **TRAIT-10**: RemittanceModule processReceipt method (optional)
- [x] **TRAIT-11**: RemittanceModule processTermination method (optional)
- [x] **TRAIT-12**: Type-erased module wrapper for heterogeneous module registry using serde_json::Value

### RemittanceManager

- [x] **MGR-01**: Constructor accepting config, wallet (Arc<dyn WalletInterface>), comms layer, and initial threads
- [x] **MGR-02**: init() method loading persisted state from stateLoader
- [x] **MGR-03**: State persistence via saveState/loadState/persistState
- [x] **MGR-04**: syncThreads() fetching and processing pending messages from CommsLayer
- [x] **MGR-05**: startListening() for live message listening via CommsLayer
- [x] **MGR-06**: sendInvoice() creating thread, optional identity exchange, composing invoice with module options
- [x] **MGR-07**: sendInvoiceForThread() sending invoice for existing thread
- [x] **MGR-08**: findInvoicesPayable() and findReceivableInvoices() query methods
- [x] **MGR-09**: pay() selecting module, building settlement, sending, optionally waiting for receipt
- [x] **MGR-10**: sendUnsolicitedSettlement() creating thread and sending settlement without prior invoice
- [x] **MGR-11**: waitForReceipt(), waitForState(), waitForIdentity(), waitForSettlement() polling methods
- [x] **MGR-12**: Inbound message handling with envelope parsing, deduplication, and dispatch by kind
- [x] **MGR-13**: Identity exchange orchestration (request, response, acknowledgment flow)
- [x] **MGR-14**: State machine enforcement via transitionThreadState with REMITTANCE_STATE_TRANSITIONS validation
- [x] **MGR-15**: Event system with RemittanceEvent enum and listener registration
- [x] **MGR-16**: Thread struct with full state (23 fields including identity, flags, stateLog, protocolLog)
- [x] **MGR-17**: ThreadHandle and InvoiceHandle ergonomic wrapper types
- [x] **MGR-18**: getThread/getThreadOrThrow/getThreadHandle accessor methods
- [x] **MGR-19**: preselectPaymentOption for default module selection
- [x] **MGR-20**: RemittanceManagerConfig and RemittanceManagerRuntimeOptions types
- [x] **MGR-21**: ComposeInvoiceInput type for invoice creation
- [x] **MGR-22**: RemittanceManagerState for serializable state snapshots

### BasicBRC29 Module

- [x] **BRC29-01**: Brc29RemittanceModule implementing RemittanceModule trait with id="brc29.p2pkh"
- [x] **BRC29-02**: buildSettlement creating BRC-29 P2PKH payment via wallet.createAction with derived keys
- [x] **BRC29-03**: acceptSettlement internalizing transaction via wallet.internalizeAction with derivation params
- [x] **BRC29-04**: Brc29OptionTerms, Brc29SettlementArtifact, Brc29ReceiptData types
- [x] **BRC29-05**: Injectable NonceProvider and LockingScriptProvider traits for testability
- [x] **BRC29-06**: Validation helpers (ensureValidOption, ensureValidSettlement, isAtomicBeef)
- [x] **BRC29-07**: Brc29RemittanceModuleConfig with all configurable options (protocolID, labels, description, fees, etc.)

### Wire Format & Serialization

- [x] **WIRE-01**: All JSON field names use camelCase matching TypeScript SDK exactly
- [x] **WIRE-02**: Enum variants serialize as lowercase strings matching TS (e.g., "new", "invoiced", "settled")
- [x] **WIRE-03**: Optional fields omitted from JSON when None (skip_serializing_if)
- [x] **WIRE-04**: RemittanceEnvelope payload uses serde_json::Value for module-opaque payloads
- [x] **WIRE-05**: Settlement.artifact and Receipt.receiptData use serde_json::Value
- [x] **WIRE-06**: Invoice.options uses HashMap<String, serde_json::Value>

### Testing

- [ ] **TEST-01**: State machine unit tests — all valid transitions pass, all invalid transitions return error
- [ ] **TEST-02**: JSON serialization roundtrip tests for every type matching TS wire format
- [ ] **TEST-03**: Full thread lifecycle integration test (new → identity → invoice → settle → receipt)
- [ ] **TEST-04**: BasicBRC29 buildSettlement and acceptSettlement unit tests with mock wallet
- [ ] **TEST-05**: RemittanceEnvelope serialization matching exact TS JSON output
- [ ] **TEST-06**: State transition back-transitions from invoiced to identity states verified

### TS SDK Parity (identified via Phase 3 audit)
- [ ] **PARITY-01**: wait_for_receipt/wait_for_settlement return Termination variant (not error) when thread terminates
- [ ] **PARITY-02**: All public methods that send messages accept optional host_override parameter
- [ ] **PARITY-03**: wait_for_state accepts optional timeout_ms, returns Timeout error on expiry
- [ ] **PARITY-04**: find_invoices_payable and find_receivable_invoices accept optional counterparty filter
- [ ] **PARITY-05**: RemittanceKind implements Display, sync_threads logs errors, handle_inbound_message is pub(crate)

## v2 Requirements

Deferred to future release.

### Extended Modules

- **MOD-01**: Additional settlement modules beyond BasicBRC29
- **MOD-02**: Concrete CommsLayer implementations (HTTP message box, WebSocket)
- **MOD-03**: Concrete IdentityLayer implementation using wallet certificates

### Cross-Language Testing

- **CROSS-01**: Generate JSON test vectors from live TS SDK for automated parity testing
- **CROSS-02**: End-to-end test with Rust wallet talking to TS wallet over mock transport

## Out of Scope

| Feature | Reason |
|---------|--------|
| CommsLayer implementations | Only the trait interface — concrete transports are application-level |
| IdentityLayer implementations | Only the trait interface — certificate logic is application-level |
| Additional settlement modules | Only BasicBRC29 ships with SDK, matching TS |
| Wallet-toolbox storage | Handled separately in another workspace |
| Push to upstream repo | Build locally, PR later |
| Go SDK remittance reference | Go SDK has no remittance package (404 confirmed) |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| TYPE-01 | Phase 1 — Foundation Types | Complete |
| TYPE-02 | Phase 1 — Foundation Types | Complete |
| TYPE-03 | Phase 1 — Foundation Types | Complete |
| TYPE-04 | Phase 1 — Foundation Types | Complete |
| TYPE-05 | Phase 1 — Foundation Types | Complete |
| TYPE-06 | Phase 1 — Foundation Types | Complete |
| TYPE-07 | Phase 1 — Foundation Types | Complete |
| TYPE-08 | Phase 1 — Foundation Types | Complete |
| TYPE-09 | Phase 1 — Foundation Types | Complete |
| TYPE-10 | Phase 1 — Foundation Types | Complete |
| TYPE-11 | Phase 1 — Foundation Types | Complete |
| TYPE-12 | Phase 1 — Foundation Types | Complete |
| TYPE-13 | Phase 1 — Foundation Types | Complete |
| TYPE-14 | Phase 1 — Foundation Types | Complete |
| TYPE-15 | Phase 1 — Foundation Types | Complete |
| TYPE-16 | Phase 1 — Foundation Types | Complete |
| TYPE-17 | Phase 1 — Foundation Types | Complete |
| TYPE-18 | Phase 1 — Foundation Types | Complete |
| WIRE-01 | Phase 1 — Foundation Types | Complete |
| WIRE-02 | Phase 1 — Foundation Types | Complete |
| WIRE-03 | Phase 1 — Foundation Types | Complete |
| WIRE-04 | Phase 1 — Foundation Types | Complete |
| WIRE-05 | Phase 1 — Foundation Types | Complete |
| WIRE-06 | Phase 1 — Foundation Types | Complete |
| TRAIT-01 | Phase 2 — Interface Traits | Complete (02-01) |
| TRAIT-02 | Phase 2 — Interface Traits | Complete (02-01) |
| TRAIT-03 | Phase 2 — Interface Traits | Complete (02-01) |
| TRAIT-04 | Phase 2 — Interface Traits | Complete (02-01) |
| TRAIT-05 | Phase 2 — Interface Traits | Complete (02-01) |
| TRAIT-06 | Phase 2 — Interface Traits | Complete |
| TRAIT-07 | Phase 2 — Interface Traits | Complete |
| TRAIT-08 | Phase 2 — Interface Traits | Complete |
| TRAIT-09 | Phase 2 — Interface Traits | Complete |
| TRAIT-10 | Phase 2 — Interface Traits | Complete |
| TRAIT-11 | Phase 2 — Interface Traits | Complete |
| TRAIT-12 | Phase 2 — Interface Traits | Complete |
| MGR-01 | Phase 3 — RemittanceManager | Complete |
| MGR-02 | Phase 3 — RemittanceManager | Complete |
| MGR-03 | Phase 3 — RemittanceManager | Complete |
| MGR-04 | Phase 3 — RemittanceManager | Complete |
| MGR-05 | Phase 3 — RemittanceManager | Complete |
| MGR-06 | Phase 3 — RemittanceManager | Complete |
| MGR-07 | Phase 3 — RemittanceManager | Complete |
| MGR-08 | Phase 3 — RemittanceManager | Complete |
| MGR-09 | Phase 3 — RemittanceManager | Complete |
| MGR-10 | Phase 3 — RemittanceManager | Complete |
| MGR-11 | Phase 3 — RemittanceManager | Complete |
| MGR-12 | Phase 3 — RemittanceManager | Complete |
| MGR-13 | Phase 3 — RemittanceManager | Complete |
| MGR-14 | Phase 3 — RemittanceManager | Complete |
| MGR-15 | Phase 3 — RemittanceManager | Complete |
| MGR-16 | Phase 3 — RemittanceManager | Complete |
| MGR-17 | Phase 3 — RemittanceManager | Complete |
| MGR-18 | Phase 3 — RemittanceManager | Complete |
| MGR-19 | Phase 3 — RemittanceManager | Complete |
| MGR-20 | Phase 3 — RemittanceManager | Complete |
| MGR-21 | Phase 3 — RemittanceManager | Complete |
| MGR-22 | Phase 3 — RemittanceManager | Complete |
| BRC29-01 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-02 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-03 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-04 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-05 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-06 | Phase 4 — BasicBRC29 Module | Complete |
| BRC29-07 | Phase 4 — BasicBRC29 Module | Complete |
| TEST-01 | Phase 5 — Integration Tests | Pending |
| TEST-02 | Phase 5 — Integration Tests | Pending |
| TEST-03 | Phase 5 — Integration Tests | Pending |
| TEST-04 | Phase 5 — Integration Tests | Pending |
| TEST-05 | Phase 5 — Integration Tests | Pending |
| TEST-06 | Phase 5 — Integration Tests | Pending |
| PARITY-01 | Phase 5 — Integration Tests & Parity | Pending |
| PARITY-02 | Phase 5 — Integration Tests & Parity | Pending |
| PARITY-03 | Phase 5 — Integration Tests & Parity | Pending |
| PARITY-04 | Phase 5 — Integration Tests & Parity | Pending |
| PARITY-05 | Phase 5 — Integration Tests & Parity | Pending |

**Coverage:**
- v1 requirements: 70 total
- Mapped to phases: 70
- Unmapped: 0

---
*Requirements defined: 2026-03-24*
*Last updated: 2026-03-24 — traceability expanded to individual requirement IDs after roadmap creation*
