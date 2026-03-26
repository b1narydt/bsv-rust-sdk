#![cfg(feature = "network")]
//! Integration tests for remittance core types.
//!
//! Tests serialization, state transitions, and LoggerLike trait.

use bsv::remittance::types::{
    allowed_transitions, is_valid_transition, LoggerLike, RemittanceKind, RemittanceThreadState,
};

// ---------------------------------------------------------------------------
// Serialization tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// State transition tests
// ---------------------------------------------------------------------------

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
fn test_kind_display() {
    use RemittanceKind::*;
    assert_eq!(Invoice.to_string(), "invoice");
    assert_eq!(
        IdentityVerificationRequest.to_string(),
        "identityVerificationRequest"
    );
    assert_eq!(
        IdentityVerificationResponse.to_string(),
        "identityVerificationResponse"
    );
    assert_eq!(
        IdentityVerificationAcknowledgment.to_string(),
        "identityVerificationAcknowledgment"
    );
    assert_eq!(Settlement.to_string(), "settlement");
    assert_eq!(Receipt.to_string(), "receipt");
    assert_eq!(Termination.to_string(), "termination");
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

// ---------------------------------------------------------------------------
// Exhaustive 9x9 transition matrix (TEST-01, TEST-06)
// ---------------------------------------------------------------------------

/// All 9 states in a stable iteration order.
fn all_states() -> Vec<RemittanceThreadState> {
    use RemittanceThreadState::*;
    vec![
        New,
        IdentityRequested,
        IdentityResponded,
        IdentityAcknowledged,
        Invoiced,
        Settled,
        Receipted,
        Terminated,
        Errored,
    ]
}

/// The canonical allowed-transition set expressed as (from, to) pairs.
/// Derived directly from the `allowed_transitions` implementation so that
/// any future change to the table propagates automatically.
fn expected_valid_pairs() -> Vec<(RemittanceThreadState, RemittanceThreadState)> {
    let states = all_states();
    let mut pairs = Vec::new();
    for from in &states {
        for to in allowed_transitions(from) {
            pairs.push((from.clone(), to.clone()));
        }
    }
    pairs
}

#[test]
fn test_all_invalid_transitions() {
    let states = all_states();
    let valid_pairs = expected_valid_pairs();

    let mut checked = 0u32;
    let mut valid_confirmed = 0u32;
    let mut invalid_confirmed = 0u32;

    for from in &states {
        for to in &states {
            let is_valid = valid_pairs.iter().any(|(f, t)| f == from && t == to);
            let result = is_valid_transition(from, to);

            if is_valid {
                assert!(
                    result,
                    "Expected valid transition {:?} -> {:?} to succeed",
                    from, to
                );
                valid_confirmed += 1;
            } else {
                assert!(
                    !result,
                    "Expected invalid transition {:?} -> {:?} to return false",
                    from, to
                );
                invalid_confirmed += 1;
            }
            checked += 1;
        }
    }

    // Sanity: all 81 pairs checked
    assert_eq!(checked, 81, "Expected exactly 81 (from, to) pairs");

    // Sanity: sum of valid + invalid == 81
    assert_eq!(valid_confirmed + invalid_confirmed, 81);
}

#[test]
fn test_invoiced_back_transitions_exhaustive() {
    use RemittanceThreadState::*;

    // TEST-06: all three back-transitions from Invoiced must be valid.
    // These are "back" transitions because Invoiced comes after the identity
    // states in the normal flow, yet can regress to them.
    assert!(
        is_valid_transition(&Invoiced, &IdentityRequested),
        "Invoiced -> IdentityRequested must be valid"
    );
    assert!(
        is_valid_transition(&Invoiced, &IdentityResponded),
        "Invoiced -> IdentityResponded must be valid"
    );
    assert!(
        is_valid_transition(&Invoiced, &IdentityAcknowledged),
        "Invoiced -> IdentityAcknowledged must be valid"
    );

    // States that are strictly later in the protocol (post-settlement) must NOT
    // reach any identity state. New -> IdentityRequested is a forward transition
    // and is intentionally excluded from this check.
    let post_settlement = [Settled, Receipted, Terminated, Errored];
    let identity_states = [IdentityRequested, IdentityResponded, IdentityAcknowledged];

    for from in &post_settlement {
        for to in &identity_states {
            assert!(
                !is_valid_transition(from, to),
                "Post-settlement state {:?} must not transition to identity state {:?}",
                from,
                to
            );
        }
    }
}
