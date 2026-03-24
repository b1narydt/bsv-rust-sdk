//! Remittance subsystem for peer-to-peer payment negotiation.
//!
//! Implements the remittance protocol from the BSV TypeScript SDK,
//! providing type-safe message exchange, state machine validation,
//! and wire-format compatibility with TypeScript wallets.

pub mod error;
pub mod types;
#[cfg(feature = "network")]
pub mod comms_layer;
#[cfg(feature = "network")]
pub mod identity_layer;

pub use error::RemittanceError;

// Core enums and state machine
pub use types::{
    allowed_transitions, is_valid_transition, LoggerLike, RemittanceKind,
    RemittanceOptionId, RemittanceThreadState, ThreadId, UnixMillis,
};

// Protocol structs
pub use types::{
    sat_unit, Amount, RemittanceCertificate, IdentityRequest,
    IdentityVerificationAcknowledgment, IdentityVerificationRequest,
    IdentityVerificationResponse, InstrumentBase, Invoice, LineItem,
    ModuleContext, PeerMessage, Receipt, RemittanceEnvelope, Settlement,
    Termination, Unit,
};
