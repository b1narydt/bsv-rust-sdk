//! Core types for the remittance protocol.
//!
//! Defines enums, type aliases, state transitions, and the LoggerLike trait
//! that all other remittance types depend on.

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
    #[cfg_attr(feature = "network", serde(rename = "identityVerificationAcknowledgment"))]
    IdentityVerificationAcknowledgment,
    #[cfg_attr(feature = "network", serde(rename = "settlement"))]
    Settlement,
    #[cfg_attr(feature = "network", serde(rename = "receipt"))]
    Receipt,
    #[cfg_attr(feature = "network", serde(rename = "termination"))]
    Termination,
}

/// Returns the valid successor states for a given remittance thread state.
///
/// The transition table matches the TypeScript SDK's `REMITTANCE_STATE_TRANSITIONS`.
/// Notably, `Invoiced` allows back-transitions to identity states.
pub fn allowed_transitions(state: &RemittanceThreadState) -> &'static [RemittanceThreadState] {
    use RemittanceThreadState::*;
    match state {
        New => &[IdentityRequested, Invoiced, Settled, Terminated, Errored],
        IdentityRequested => &[IdentityResponded, IdentityAcknowledged, Invoiced, Settled, Terminated, Errored],
        IdentityResponded => &[IdentityAcknowledged, Invoiced, Settled, Terminated, Errored],
        IdentityAcknowledged => &[Invoiced, Settled, Terminated, Errored],
        Invoiced => &[IdentityRequested, IdentityResponded, IdentityAcknowledged, Settled, Terminated, Errored],
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
            (IdentityVerificationRequest, r#""identityVerificationRequest""#),
            (IdentityVerificationResponse, r#""identityVerificationResponse""#),
            (IdentityVerificationAcknowledgment, r#""identityVerificationAcknowledgment""#),
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
            (r#""identityVerificationRequest""#, IdentityVerificationRequest),
            (r#""identityVerificationResponse""#, IdentityVerificationResponse),
            (r#""identityVerificationAcknowledgment""#, IdentityVerificationAcknowledgment),
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
        assert!(is_valid_transition(&IdentityResponded, &IdentityAcknowledged));
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
        assert!(transitions.is_empty(), "Errored should be a terminal state with no transitions");
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
        assert_eq!(RemittanceThreadState::IdentityRequested.to_string(), "identityRequested");
        assert_eq!(RemittanceThreadState::Invoiced.to_string(), "invoiced");
        assert_eq!(RemittanceThreadState::Errored.to_string(), "errored");
    }
}
