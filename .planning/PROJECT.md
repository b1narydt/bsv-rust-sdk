# BSV Rust SDK — Remittance Protocol

## What This Is

Adding the Remittance protocol subsystem to the BSV Rust SDK, translating it 1:1 from the TypeScript SDK's `src/remittance/` directory. The Rust implementation must be fully interoperable with TypeScript wallets — identical wire format, same state machine, same module interface — as if it were developed by the same team that wrote the TypeScript version.

## Core Value

A Rust wallet using RemittanceManager must seamlessly exchange remittance messages with a TypeScript wallet — same protocol, same wire format, same behavior, zero translation layer needed.

## Requirements

### Validated

- ✓ WalletInterface trait (29 BRC-compliant methods) — existing
- ✓ ProtoWallet (BRC-42 key derivation, signing) — existing
- ✓ AuthFetch (BRC-31 authenticated HTTP) — existing
- ✓ KeyDeriver / CachedKeyDeriver — existing
- ✓ Script templates (P2PKH, PushDrop, RPuzzle) — existing
- ✓ Transaction construction, BEEF/Atomic BEEF serialization — existing
- ✓ Certificate types and verification — existing

### Active

- [ ] RemittanceThreadState enum and state transition table
- [ ] Core protocol types (Invoice, LineItem, Amount, Unit, Settlement, Receipt, Termination, etc.)
- [ ] RemittanceEnvelope wire format with JSON serialization matching TS
- [ ] CommsLayer trait (message transport abstraction)
- [ ] IdentityLayer trait (certificate exchange protocol)
- [ ] RemittanceModule trait (settlement module interface)
- [ ] RemittanceManager orchestrator (thread lifecycle, state machine enforcement, message routing)
- [ ] BasicBRC29 module (BRC-29 derived key P2PKH payments)
- [ ] Wire-format interoperability with TypeScript SDK
- [ ] Unit tests for state machine transitions
- [ ] Serialization roundtrip tests matching TS JSON format
- [ ] Integration tests for full thread lifecycle

### Out of Scope

- Additional settlement modules beyond BasicBRC29 — only the default module ships with the SDK
- CommsLayer implementations (HTTP, WebSocket) — only the trait interface, not concrete transports
- IdentityLayer implementations — only the trait interface
- Wallet-toolbox storage changes — handled separately in another workspace
- Push to upstream repo — build and test locally, PR later

## Context

- **Source of truth:** `ts-sdk/src/remittance/` at https://github.com/bsv-blockchain/ts-sdk
- **Target repo:** https://github.com/b1narydt/bsv-rust-sdk (cloned locally)
- **Cross-reference:** Go SDK at https://github.com/bsv-blockchain/go-sdk has a remittance implementation
- **Rust wallet-toolbox** at `../rust-wallet-toolbox/` has `ScriptTemplateBRC29` needed by BasicBRC29
- The existing Rust SDK uses `serde` behind a `network` feature flag — remittance types must follow this pattern
- All types must derive `Serialize, Deserialize` for wire compatibility
- The `serde(rename_all = "camelCase")` convention is used throughout for JSON field names matching TS

## Constraints

- **Wire parity:** JSON serialization must produce identical output to TypeScript SDK — field names, enum values, nesting structure
- **Feature gate:** Remittance module gated behind `network` feature (requires serde, tokio, async)
- **No new external deps:** Use only dependencies already in Cargo.toml (serde, tokio, async-trait, thiserror)
- **Code style:** Match existing SDK patterns — `#[cfg_attr(feature = "network", ...)]`, `WalletError`, `async_trait`

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Remittance in SDK, not wallet-toolbox | TS SDK has remittance in src/remittance/, so Rust matches that | — Pending |
| BasicBRC29 placement follows TS structure | If TS puts it in ts-sdk, Rust puts it in bsv-rust-sdk | — Pending |
| Feature-gated behind `network` | Remittance needs async + serde, matches existing pattern | — Pending |
| serde camelCase for all types | Wire interop with TS requires matching JSON field names | — Pending |

---
*Last updated: 2026-03-24 after initialization*
