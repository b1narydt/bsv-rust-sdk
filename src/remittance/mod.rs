//! Remittance subsystem for peer-to-peer payment negotiation.
//!
//! Implements the remittance protocol from the BSV TypeScript SDK,
//! providing type-safe message exchange, state machine validation,
//! and wire-format compatibility with TypeScript wallets.

pub mod error;
pub mod types;

pub use error::RemittanceError;

// Core enums and state machine
pub use types::{
    allowed_transitions, is_valid_transition, LoggerLike, RemittanceKind,
    RemittanceOptionId, RemittanceThreadState, ThreadId, UnixMillis,
};

// Future type re-exports will be added here as plans are implemented:
// - Invoice, Settlement, Receipt, Termination (Plan 01-02)
// - PeerMessage, RemittanceEnvelope (Plan 01-03)
// - ModuleContext (Plan 01-04)
