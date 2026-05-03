//! Errors for the STAS-3 token implementation.

use crate::script::error::ScriptError;

#[derive(Debug, thiserror::Error)]
pub enum Stas3Error {
    #[error("invalid script: {0}")]
    InvalidScript(String),

    #[error("invalid token state: {0}")]
    InvalidState(String),

    #[error("missing key triple in customInstructions for outpoint {0}")]
    MissingBrc43KeyArgs(String),

    #[error("freezable flag not set on input")]
    FreezableNotSet,

    #[error("confiscatable flag not set on input")]
    ConfiscatableNotSet,

    #[error("token is frozen")]
    FrozenToken,

    #[error("amount conservation violated: inputs={inputs}, outputs={outputs}")]
    AmountMismatch { inputs: u64, outputs: u64 },

    #[error("note data too large: {0} bytes (max 65533)")]
    NoteDataTooLarge(usize),

    #[error(transparent)]
    Script(#[from] ScriptError),
    // Wallet error to be added once we wire up the wallet wrapper in Phase 9.
    // Don't add it here yet — keep this phase isolated from the wallet layer.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: each variant constructs and Display-formats without panicking.
    #[test]
    fn test_all_variants_format() {
        let cases: Vec<Stas3Error> = vec![
            Stas3Error::InvalidScript("bad header".into()),
            Stas3Error::InvalidState("frozen during transfer".into()),
            Stas3Error::MissingBrc43KeyArgs("abc:0".into()),
            Stas3Error::FreezableNotSet,
            Stas3Error::ConfiscatableNotSet,
            Stas3Error::FrozenToken,
            Stas3Error::AmountMismatch {
                inputs: 100,
                outputs: 99,
            },
            Stas3Error::NoteDataTooLarge(70_000),
            Stas3Error::Script(ScriptError::InvalidScript("oops".into())),
        ];
        for err in cases {
            // Force the Display impl to run; non-empty string asserts thiserror wired up.
            let s = format!("{}", err);
            assert!(!s.is_empty(), "Display impl produced empty string: {:?}", err);
        }
    }

    #[test]
    fn test_amount_mismatch_message_includes_values() {
        let err = Stas3Error::AmountMismatch {
            inputs: 1000,
            outputs: 900,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("1000"));
        assert!(msg.contains("900"));
    }

    #[test]
    fn test_script_error_transparent_conversion() {
        // The #[from] attribute should produce a Stas3Error from a ScriptError.
        let inner = ScriptError::InvalidScript("inner".into());
        let outer: Stas3Error = inner.into();
        match outer {
            Stas3Error::Script(_) => {}
            other => panic!("expected Stas3Error::Script, got {:?}", other),
        }
    }
}
