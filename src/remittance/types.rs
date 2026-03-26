//! Core types for the remittance protocol.
//!
//! Defines enums, type aliases, state transitions, the LoggerLike trait,
//! and all protocol structs (Unit, Amount, Invoice, Settlement, etc.)
//! with serde annotations for wire-format parity with the TypeScript SDK.

use std::collections::HashMap;
use std::sync::Arc;

/// Unique identifier for a remittance thread.
pub type ThreadId = String;

/// Unique identifier for a remittance option within an invoice.
pub type RemittanceOptionId = String;

/// Unix timestamp in milliseconds.
pub type UnixMillis = u64;

/// The state of a remittance thread in the protocol state machine.
///
/// Each variant maps to the exact wire string used by the TypeScript SDK.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
pub enum RemittanceThreadState {
    #[cfg_attr(feature = "network", serde(rename = "new"))]
    New,
    #[cfg_attr(feature = "network", serde(rename = "identityRequested"))]
    IdentityRequested,
    #[cfg_attr(feature = "network", serde(rename = "identityResponded"))]
    IdentityResponded,
    #[cfg_attr(feature = "network", serde(rename = "identityAcknowledged"))]
    IdentityAcknowledged,
    #[cfg_attr(feature = "network", serde(rename = "invoiced"))]
    Invoiced,
    #[cfg_attr(feature = "network", serde(rename = "settled"))]
    Settled,
    #[cfg_attr(feature = "network", serde(rename = "receipted"))]
    Receipted,
    #[cfg_attr(feature = "network", serde(rename = "terminated"))]
    Terminated,
    #[cfg_attr(feature = "network", serde(rename = "errored"))]
    Errored,
}

impl std::fmt::Display for RemittanceThreadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::New => "new",
            Self::IdentityRequested => "identityRequested",
            Self::IdentityResponded => "identityResponded",
            Self::IdentityAcknowledged => "identityAcknowledged",
            Self::Invoiced => "invoiced",
            Self::Settled => "settled",
            Self::Receipted => "receipted",
            Self::Terminated => "terminated",
            Self::Errored => "errored",
        };
        f.write_str(s)
    }
}

/// The kind of message in the remittance protocol.
///
/// Each variant maps to the exact wire string used by the TypeScript SDK.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
pub enum RemittanceKind {
    #[cfg_attr(feature = "network", serde(rename = "invoice"))]
    Invoice,
    #[cfg_attr(feature = "network", serde(rename = "identityVerificationRequest"))]
    IdentityVerificationRequest,
    #[cfg_attr(feature = "network", serde(rename = "identityVerificationResponse"))]
    IdentityVerificationResponse,
    #[cfg_attr(
        feature = "network",
        serde(rename = "identityVerificationAcknowledgment")
    )]
    IdentityVerificationAcknowledgment,
    #[cfg_attr(feature = "network", serde(rename = "settlement"))]
    Settlement,
    #[cfg_attr(feature = "network", serde(rename = "receipt"))]
    Receipt,
    #[cfg_attr(feature = "network", serde(rename = "termination"))]
    Termination,
}

impl std::fmt::Display for RemittanceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Invoice => "invoice",
            Self::IdentityVerificationRequest => "identityVerificationRequest",
            Self::IdentityVerificationResponse => "identityVerificationResponse",
            Self::IdentityVerificationAcknowledgment => "identityVerificationAcknowledgment",
            Self::Settlement => "settlement",
            Self::Receipt => "receipt",
            Self::Termination => "termination",
        };
        f.write_str(s)
    }
}

/// Returns the valid successor states for a given remittance thread state.
///
/// The transition table matches the TypeScript SDK's `REMITTANCE_STATE_TRANSITIONS`.
/// Notably, `Invoiced` allows back-transitions to identity states.
pub fn allowed_transitions(state: &RemittanceThreadState) -> &'static [RemittanceThreadState] {
    use RemittanceThreadState::*;
    match state {
        New => &[IdentityRequested, Invoiced, Settled, Terminated, Errored],
        IdentityRequested => &[
            IdentityResponded,
            IdentityAcknowledged,
            Invoiced,
            Settled,
            Terminated,
            Errored,
        ],
        IdentityResponded => &[IdentityAcknowledged, Invoiced, Settled, Terminated, Errored],
        IdentityAcknowledged => &[Invoiced, Settled, Terminated, Errored],
        Invoiced => &[
            IdentityRequested,
            IdentityResponded,
            IdentityAcknowledged,
            Settled,
            Terminated,
            Errored,
        ],
        Settled => &[Receipted, Terminated, Errored],
        Receipted => &[Terminated, Errored],
        Terminated => &[Errored],
        Errored => &[],
    }
}

/// Returns `true` if transitioning from `from` to `to` is valid per the protocol.
pub fn is_valid_transition(from: &RemittanceThreadState, to: &RemittanceThreadState) -> bool {
    allowed_transitions(from).contains(to)
}

/// Trait for pluggable logging, matching the TypeScript SDK's `LoggerLike` interface.
///
/// Implementors must be `Send + Sync` for use in async contexts.
pub trait LoggerLike: Send + Sync {
    /// Log an informational message.
    fn log(&self, args: &[&dyn std::fmt::Debug]);
    /// Log a warning message.
    fn warn(&self, args: &[&dyn std::fmt::Debug]);
    /// Log an error message.
    fn error(&self, args: &[&dyn std::fmt::Debug]);
}

// ---------------------------------------------------------------------------
// Protocol Structs
// ---------------------------------------------------------------------------

/// A currency unit with namespace, code, and optional decimal places.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Unit {
    pub namespace: String,
    pub code: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub decimals: Option<u32>,
}

/// Returns the standard BSV satoshi unit.
pub fn sat_unit() -> Unit {
    Unit {
        namespace: "bsv".into(),
        code: "sat".into(),
        decimals: Some(0),
    }
}

/// A monetary amount as a decimal string with an associated unit.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Amount {
    pub value: String,
    pub unit: Unit,
}

/// A single line item in an invoice.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct LineItem {
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub id: Option<String>,
    pub description: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub quantity: Option<String>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub unit_price: Option<Amount>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub amount: Option<Amount>,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Common fields shared by all instrument-type messages (e.g., Invoice).
///
/// Flattened into the parent struct via `#[serde(flatten)]` so that these
/// fields appear at the top level in JSON, matching the TypeScript SDK wire format.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct InstrumentBase {
    pub thread_id: String,
    pub payee: String,
    pub payer: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub note: Option<String>,
    pub line_items: Vec<LineItem>,
    pub total: Amount,
    pub invoice_number: String,
    pub created_at: u64,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub arbitrary: Option<HashMap<String, serde_json::Value>>,
}

/// An invoice message in the remittance protocol.
///
/// The `base` field is flattened so InstrumentBase fields appear at the
/// top level in JSON, alongside `kind`, `expiresAt`, and `options`.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Invoice {
    pub kind: RemittanceKind,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub expires_at: Option<u64>,
    pub options: HashMap<String, serde_json::Value>,
    #[cfg_attr(feature = "network", serde(flatten))]
    pub base: InstrumentBase,
}

/// Sub-struct describing the identity verification request parameters.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityRequest {
    pub types: HashMap<String, Vec<String>>,
    pub certifiers: Vec<String>,
}

/// A request for identity verification from a peer.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityVerificationRequest {
    pub kind: RemittanceKind,
    pub thread_id: String,
    pub request: IdentityRequest,
}

/// A certificate proving identity in the remittance wire protocol.
///
/// Named `RemittanceCertificate` to avoid collision with
/// `crate::wallet::interfaces::IdentityCertificate` which has a different
/// structure (strongly-typed `PublicKey`, `CertificateType`, etc.).
/// This struct uses plain strings for all fields to match the TypeScript
/// SDK wire format exactly.
///
/// The `cert_type` field is renamed to `"type"` in JSON to avoid the
/// Rust reserved keyword while maintaining wire-format compatibility.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RemittanceCertificate {
    #[cfg_attr(feature = "network", serde(rename = "type"))]
    pub cert_type: String,
    pub certifier: String,
    pub subject: String,
    pub fields: HashMap<String, String>,
    pub signature: String,
    pub serial_number: String,
    pub revocation_outpoint: String,
    pub keyring_for_verifier: HashMap<String, String>,
}

/// A response containing identity certificates.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityVerificationResponse {
    pub kind: RemittanceKind,
    pub thread_id: String,
    pub certificates: Vec<RemittanceCertificate>,
}

/// Acknowledgment that identity verification was received.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct IdentityVerificationAcknowledgment {
    pub kind: RemittanceKind,
    pub thread_id: String,
}

/// A settlement message indicating payment has been made.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Settlement {
    pub kind: RemittanceKind,
    pub thread_id: String,
    pub module_id: String,
    pub option_id: String,
    pub sender: String,
    pub created_at: u64,
    pub artifact: serde_json::Value,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub note: Option<String>,
}

/// A receipt confirming payment was received and verified.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Receipt {
    pub kind: RemittanceKind,
    pub thread_id: String,
    pub module_id: String,
    pub option_id: String,
    pub payee: String,
    pub payer: String,
    pub created_at: u64,
    pub receipt_data: serde_json::Value,
}

/// A termination message ending the remittance thread.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct Termination {
    pub code: String,
    pub message: String,
    #[cfg_attr(feature = "network", serde(skip_serializing_if = "Option::is_none"))]
    pub details: Option<serde_json::Value>,
}

/// A peer-to-peer message envelope used for transport.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct PeerMessage {
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub message_box: String,
    pub body: String,
}

/// The outer envelope wrapping all remittance protocol messages.
///
/// The `v` field is a u8 (integer 1 in JSON, not a string).
/// The `payload` field accepts arbitrary JSON for flexibility.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "network", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "network", serde(rename_all = "camelCase"))]
pub struct RemittanceEnvelope {
    pub v: u8,
    pub id: String,
    pub kind: RemittanceKind,
    pub thread_id: String,
    pub created_at: u64,
    pub payload: serde_json::Value,
}

/// Runtime context passed to remittance modules during execution.
///
/// Never serialized -- holds Arc references to runtime services.
/// Does not derive serde traits.
#[derive(Clone)]
pub struct ModuleContext {
    pub wallet: Arc<dyn crate::wallet::interfaces::WalletInterface>,
    pub originator: Option<String>,
    pub now: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub logger: Option<Arc<dyn LoggerLike>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Serialization tests (require "network" feature via dev-dependencies)
    // -----------------------------------------------------------------------

    #[test]
    fn test_thread_state_serialization() {
        use RemittanceThreadState::*;
        let cases = vec![
            (New, r#""new""#),
            (IdentityRequested, r#""identityRequested""#),
            (IdentityResponded, r#""identityResponded""#),
            (IdentityAcknowledged, r#""identityAcknowledged""#),
            (Invoiced, r#""invoiced""#),
            (Settled, r#""settled""#),
            (Receipted, r#""receipted""#),
            (Terminated, r#""terminated""#),
            (Errored, r#""errored""#),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected, "serialization mismatch for {:?}", variant);
        }
    }

    #[test]
    fn test_thread_state_deserialization() {
        use RemittanceThreadState::*;
        let cases = vec![
            (r#""new""#, New),
            (r#""identityRequested""#, IdentityRequested),
            (r#""identityResponded""#, IdentityResponded),
            (r#""identityAcknowledged""#, IdentityAcknowledged),
            (r#""invoiced""#, Invoiced),
            (r#""settled""#, Settled),
            (r#""receipted""#, Receipted),
            (r#""terminated""#, Terminated),
            (r#""errored""#, Errored),
        ];
        for (json, expected) in cases {
            let parsed: RemittanceThreadState = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, expected, "deserialization mismatch for {}", json);
        }
    }

    #[test]
    fn test_kind_serialization() {
        use RemittanceKind::*;
        let cases = vec![
            (Invoice, r#""invoice""#),
            (
                IdentityVerificationRequest,
                r#""identityVerificationRequest""#,
            ),
            (
                IdentityVerificationResponse,
                r#""identityVerificationResponse""#,
            ),
            (
                IdentityVerificationAcknowledgment,
                r#""identityVerificationAcknowledgment""#,
            ),
            (Settlement, r#""settlement""#),
            (Receipt, r#""receipt""#),
            (Termination, r#""termination""#),
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected, "serialization mismatch for {:?}", variant);
        }
    }

    #[test]
    fn test_kind_deserialization() {
        use RemittanceKind::*;
        let cases = vec![
            (r#""invoice""#, Invoice),
            (
                r#""identityVerificationRequest""#,
                IdentityVerificationRequest,
            ),
            (
                r#""identityVerificationResponse""#,
                IdentityVerificationResponse,
            ),
            (
                r#""identityVerificationAcknowledgment""#,
                IdentityVerificationAcknowledgment,
            ),
            (r#""settlement""#, Settlement),
            (r#""receipt""#, Receipt),
            (r#""termination""#, Termination),
        ];
        for (json, expected) in cases {
            let parsed: RemittanceKind = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, expected, "deserialization mismatch for {}", json);
        }
    }

    // -----------------------------------------------------------------------
    // State transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_transitions() {
        use RemittanceThreadState::*;

        // New can go to several states
        assert!(is_valid_transition(&New, &IdentityRequested));
        assert!(is_valid_transition(&New, &Invoiced));
        assert!(is_valid_transition(&New, &Settled));
        assert!(is_valid_transition(&New, &Terminated));
        assert!(is_valid_transition(&New, &Errored));

        // IdentityRequested
        assert!(is_valid_transition(&IdentityRequested, &IdentityResponded));
        assert!(is_valid_transition(&IdentityRequested, &Invoiced));

        // IdentityResponded
        assert!(is_valid_transition(
            &IdentityResponded,
            &IdentityAcknowledged
        ));
        assert!(is_valid_transition(&IdentityResponded, &Invoiced));

        // IdentityAcknowledged
        assert!(is_valid_transition(&IdentityAcknowledged, &Invoiced));
        assert!(is_valid_transition(&IdentityAcknowledged, &Settled));

        // Settled
        assert!(is_valid_transition(&Settled, &Receipted));
        assert!(is_valid_transition(&Settled, &Terminated));

        // Receipted
        assert!(is_valid_transition(&Receipted, &Terminated));
        assert!(is_valid_transition(&Receipted, &Errored));

        // Terminated
        assert!(is_valid_transition(&Terminated, &Errored));
    }

    #[test]
    fn test_invalid_transitions() {
        use RemittanceThreadState::*;

        assert!(!is_valid_transition(&Receipted, &New));
        assert!(!is_valid_transition(&Errored, &New));
        assert!(!is_valid_transition(&Errored, &Settled));
        assert!(!is_valid_transition(&New, &Receipted));
        assert!(!is_valid_transition(&Settled, &Invoiced));
        assert!(!is_valid_transition(&Terminated, &Settled));
    }

    #[test]
    fn test_invoiced_back_transitions() {
        use RemittanceThreadState::*;

        // Invoiced can transition back to identity states
        assert!(is_valid_transition(&Invoiced, &IdentityRequested));
        assert!(is_valid_transition(&Invoiced, &IdentityResponded));
        assert!(is_valid_transition(&Invoiced, &IdentityAcknowledged));
    }

    #[test]
    fn test_errored_is_terminal() {
        let transitions = allowed_transitions(&RemittanceThreadState::Errored);
        assert!(
            transitions.is_empty(),
            "Errored should be a terminal state with no transitions"
        );
    }

    #[test]
    fn test_logger_like_is_object_safe() {
        struct TestLogger;

        impl LoggerLike for TestLogger {
            fn log(&self, args: &[&dyn std::fmt::Debug]) {
                let _ = args;
            }
            fn warn(&self, args: &[&dyn std::fmt::Debug]) {
                let _ = args;
            }
            fn error(&self, args: &[&dyn std::fmt::Debug]) {
                let _ = args;
            }
        }

        let logger = TestLogger;
        let dyn_logger: &dyn LoggerLike = &logger;
        dyn_logger.log(&[&"test message"]);
        dyn_logger.warn(&[&"warning"]);
        dyn_logger.error(&[&"error"]);
    }

    #[test]
    fn test_thread_state_display() {
        assert_eq!(RemittanceThreadState::New.to_string(), "new");
        assert_eq!(
            RemittanceThreadState::IdentityRequested.to_string(),
            "identityRequested"
        );
        assert_eq!(RemittanceThreadState::Invoiced.to_string(), "invoiced");
        assert_eq!(RemittanceThreadState::Errored.to_string(), "errored");
    }

    // Wire-format roundtrip tests for Plan 01-02 structs are in
    // tests/remittance_wire_format.rs (integration test file) to avoid
    // pre-existing wallet module compilation errors in lib test target.
}
