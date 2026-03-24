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

- [ ] **TRAIT-01**: CommsLayer trait with sendMessage, listMessages, acknowledgeMessage methods
- [ ] **TRAIT-02**: CommsLayer optional sendLiveMessage and listenForLiveMessages methods
- [ ] **TRAIT-03**: IdentityLayer trait with determineCertificatesToRequest method
- [ ] **TRAIT-04**: IdentityLayer respondToRequest method returning respond or terminate
- [ ] **TRAIT-05**: IdentityLayer assessReceivedCertificateSufficiency method
- [ ] **TRAIT-06**: RemittanceModule trait with id, name, allowUnsolicitedSettlements properties
- [ ] **TRAIT-07**: RemittanceModule createOption method (optional)
- [ ] **TRAIT-08**: RemittanceModule buildSettlement method returning settle artifact or terminate
- [ ] **TRAIT-09**: RemittanceModule acceptSettlement method returning accept with receipt data or terminate
- [ ] **TRAIT-10**: RemittanceModule processReceipt method (optional)
- [ ] **TRAIT-11**: RemittanceModule processTermination method (optional)
- [ ] **TRAIT-12**: Type-erased module wrapper for heterogeneous module registry using serde_json::Value

### RemittanceManager

- [ ] **MGR-01**: Constructor accepting config, wallet (Arc<dyn WalletInterface>), comms layer, and initial threads
- [ ] **MGR-02**: init() method loading persisted state from stateLoader
- [ ] **MGR-03**: State persistence via saveState/loadState/persistState
- [ ] **MGR-04**: syncThreads() fetching and processing pending messages from CommsLayer
- [ ] **MGR-05**: startListening() for live message listening via CommsLayer
- [ ] **MGR-06**: sendInvoice() creating thread, optional identity exchange, composing invoice with module options
- [ ] **MGR-07**: sendInvoiceForThread() sending invoice for existing thread
- [ ] **MGR-08**: findInvoicesPayable() and findReceivableInvoices() query methods
- [ ] **MGR-09**: pay() selecting module, building settlement, sending, optionally waiting for receipt
- [ ] **MGR-10**: sendUnsolicitedSettlement() creating thread and sending settlement without prior invoice
- [ ] **MGR-11**: waitForReceipt(), waitForState(), waitForIdentity(), waitForSettlement() polling methods
- [ ] **MGR-12**: Inbound message handling with envelope parsing, deduplication, and dispatch by kind
- [ ] **MGR-13**: Identity exchange orchestration (request, response, acknowledgment flow)
- [ ] **MGR-14**: State machine enforcement via transitionThreadState with REMITTANCE_STATE_TRANSITIONS validation
- [ ] **MGR-15**: Event system with RemittanceEvent enum and listener registration
- [ ] **MGR-16**: Thread struct with full state (23 fields including identity, flags, stateLog, protocolLog)
- [ ] **MGR-17**: ThreadHandle and InvoiceHandle ergonomic wrapper types
- [ ] **MGR-18**: getThread/getThreadOrThrow/getThreadHandle accessor methods
- [ ] **MGR-19**: preselectPaymentOption for default module selection
- [ ] **MGR-20**: RemittanceManagerConfig and RemittanceManagerRuntimeOptions types
- [ ] **MGR-21**: ComposeInvoiceInput type for invoice creation
- [ ] **MGR-22**: RemittanceManagerState for serializable state snapshots

### BasicBRC29 Module

- [ ] **BRC29-01**: Brc29RemittanceModule implementing RemittanceModule trait with id="brc29.p2pkh"
- [ ] **BRC29-02**: buildSettlement creating BRC-29 P2PKH payment via wallet.createAction with derived keys
- [ ] **BRC29-03**: acceptSettlement internalizing transaction via wallet.internalizeAction with derivation params
- [ ] **BRC29-04**: Brc29OptionTerms, Brc29SettlementArtifact, Brc29ReceiptData types
- [ ] **BRC29-05**: Injectable NonceProvider and LockingScriptProvider traits for testability
- [ ] **BRC29-06**: Validation helpers (ensureValidOption, ensureValidSettlement, isAtomicBeef)
- [ ] **BRC29-07**: Brc29RemittanceModuleConfig with all configurable options (protocolID, labels, description, fees, etc.)

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
| TRAIT-01 | Phase 2 — Interface Traits | Pending |
| TRAIT-02 | Phase 2 — Interface Traits | Pending |
| TRAIT-03 | Phase 2 — Interface Traits | Pending |
| TRAIT-04 | Phase 2 — Interface Traits | Pending |
| TRAIT-05 | Phase 2 — Interface Traits | Pending |
| TRAIT-06 | Phase 2 — Interface Traits | Pending |
| TRAIT-07 | Phase 2 — Interface Traits | Pending |
| TRAIT-08 | Phase 2 — Interface Traits | Pending |
| TRAIT-09 | Phase 2 — Interface Traits | Pending |
| TRAIT-10 | Phase 2 — Interface Traits | Pending |
| TRAIT-11 | Phase 2 — Interface Traits | Pending |
| TRAIT-12 | Phase 2 — Interface Traits | Pending |
| MGR-01 | Phase 3 — RemittanceManager | Pending |
| MGR-02 | Phase 3 — RemittanceManager | Pending |
| MGR-03 | Phase 3 — RemittanceManager | Pending |
| MGR-04 | Phase 3 — RemittanceManager | Pending |
| MGR-05 | Phase 3 — RemittanceManager | Pending |
| MGR-06 | Phase 3 — RemittanceManager | Pending |
| MGR-07 | Phase 3 — RemittanceManager | Pending |
| MGR-08 | Phase 3 — RemittanceManager | Pending |
| MGR-09 | Phase 3 — RemittanceManager | Pending |
| MGR-10 | Phase 3 — RemittanceManager | Pending |
| MGR-11 | Phase 3 — RemittanceManager | Pending |
| MGR-12 | Phase 3 — RemittanceManager | Pending |
| MGR-13 | Phase 3 — RemittanceManager | Pending |
| MGR-14 | Phase 3 — RemittanceManager | Pending |
| MGR-15 | Phase 3 — RemittanceManager | Pending |
| MGR-16 | Phase 3 — RemittanceManager | Pending |
| MGR-17 | Phase 3 — RemittanceManager | Pending |
| MGR-18 | Phase 3 — RemittanceManager | Pending |
| MGR-19 | Phase 3 — RemittanceManager | Pending |
| MGR-20 | Phase 3 — RemittanceManager | Pending |
| MGR-21 | Phase 3 — RemittanceManager | Pending |
| MGR-22 | Phase 3 — RemittanceManager | Pending |
| BRC29-01 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-02 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-03 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-04 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-05 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-06 | Phase 4 — BasicBRC29 Module | Pending |
| BRC29-07 | Phase 4 — BasicBRC29 Module | Pending |
| TEST-01 | Phase 5 — Integration Tests | Pending |
| TEST-02 | Phase 5 — Integration Tests | Pending |
| TEST-03 | Phase 5 — Integration Tests | Pending |
| TEST-04 | Phase 5 — Integration Tests | Pending |
| TEST-05 | Phase 5 — Integration Tests | Pending |
| TEST-06 | Phase 5 — Integration Tests | Pending |

**Coverage:**
- v1 requirements: 65 total
- Mapped to phases: 65
- Unmapped: 0

---
*Requirements defined: 2026-03-24*
*Last updated: 2026-03-24 — traceability expanded to individual requirement IDs after roadmap creation*
