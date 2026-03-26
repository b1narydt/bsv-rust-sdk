//! Remittance subsystem for peer-to-peer payment negotiation.
//!
//! Implements the remittance protocol from the BSV TypeScript SDK,
//! providing type-safe message exchange, state machine validation,
//! and wire-format compatibility with TypeScript wallets.

#[cfg(feature = "network")]
pub mod comms_layer;
pub mod error;
#[cfg(feature = "network")]
pub mod identity_layer;
#[cfg(feature = "network")]
pub mod manager;
#[cfg(feature = "network")]
pub mod modules;
#[cfg(feature = "network")]
pub mod remittance_module;
pub mod types;

pub use error::RemittanceError;

// Phase 2 trait re-exports
#[cfg(feature = "network")]
pub use comms_layer::CommsLayer;
#[cfg(feature = "network")]
pub use identity_layer::{AssessIdentityResult, IdentityLayer, RespondToRequestResult};
#[cfg(feature = "network")]
pub use remittance_module::{
    AcceptSettlementErased, AcceptSettlementResult, BuildSettlementErased, BuildSettlementResult,
    ErasedRemittanceModule, RemittanceModule,
};

// Phase 3 manager re-exports
#[cfg(feature = "network")]
pub use manager::{
    ComposeInvoiceInput, IdentityPhase, IdentityRuntimeOptions, InvoiceHandle, MessageDirection,
    ProtocolLogEntry, RemittanceEvent, RemittanceManager, RemittanceManagerConfig,
    RemittanceManagerRuntimeOptions, RemittanceManagerState, StateLogEntry, Thread, ThreadError,
    ThreadFlags, ThreadHandle, ThreadIdentity, ThreadRole, WaitReceiptResult, WaitSettlementResult,
};

// Phase 4 BRC-29 module re-exports
#[cfg(feature = "network")]
pub use modules::brc29::{
    Brc29OptionTerms, Brc29ReceiptData, Brc29RefundData, Brc29RemittanceModule,
    Brc29RemittanceModuleConfig, Brc29SettlementArtifact, Brc29SettlementCustomInstructions,
    LockingScriptProvider, NonceProvider,
};

// Core enums and state machine
pub use types::{
    allowed_transitions, is_valid_transition, LoggerLike, RemittanceKind, RemittanceOptionId,
    RemittanceThreadState, ThreadId, UnixMillis,
};

// Protocol structs
pub use types::{
    sat_unit, Amount, IdentityRequest, IdentityVerificationAcknowledgment,
    IdentityVerificationRequest, IdentityVerificationResponse, InstrumentBase, Invoice, LineItem,
    ModuleContext, PeerMessage, Receipt, RemittanceCertificate, RemittanceEnvelope, Settlement,
    Termination, Unit,
};
