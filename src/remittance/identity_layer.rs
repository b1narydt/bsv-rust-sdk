//! Identity verification abstraction layer for the remittance protocol.
//!
//! Defines the `IdentityLayer` async trait that controls which certificates
//! are requested from a counterparty, how the local wallet responds to incoming
//! certificate requests, and whether a received response is considered sufficient
//! to proceed.
//!
//! Two return enums (`RespondToRequestResult`, `AssessIdentityResult`) model the
//! TS SDK union types `{ respond: … } | { terminate: … }` as proper Rust enums.

#![cfg(feature = "network")]

use async_trait::async_trait;

use crate::remittance::error::RemittanceError;
use crate::remittance::types::{
    IdentityVerificationAcknowledgment, IdentityVerificationRequest, IdentityVerificationResponse,
    ModuleContext, Termination,
};

// ---------------------------------------------------------------------------
// Return enums
// ---------------------------------------------------------------------------

/// The outcome of `IdentityLayer::respond_to_request`.
///
/// Mirrors the TypeScript SDK union `{ respond: IdentityVerificationResponse }
/// | { terminate: Termination }`.
#[derive(Debug)]
pub enum RespondToRequestResult {
    /// The local wallet can satisfy the request; includes the certificate response.
    Respond {
        response: IdentityVerificationResponse,
    },
    /// The local wallet refuses to satisfy the request; includes a termination reason.
    Terminate { termination: Termination },
}

/// The outcome of `IdentityLayer::assess_received_certificate_sufficiency`.
///
/// Mirrors the TypeScript SDK union `IdentityVerificationAcknowledgment | Termination`.
#[derive(Debug)]
pub enum AssessIdentityResult {
    /// The received certificates are sufficient; carry on with the thread.
    Acknowledge(IdentityVerificationAcknowledgment),
    /// The received certificates are insufficient; terminate the thread.
    Terminate(Termination),
}

// ---------------------------------------------------------------------------
// Trait definition
// ---------------------------------------------------------------------------

/// Pluggable identity-verification interface consumed by `RemittanceManager`.
///
/// Implementors must be `Send + Sync` so they can be stored in `Arc<dyn IdentityLayer>`.
#[async_trait]
pub trait IdentityLayer: Send + Sync {
    /// Determine which certificates and certifiers to request from `counterparty`
    /// at the start (or restart) of an identity exchange for `thread_id`.
    async fn determine_certificates_to_request(
        &self,
        counterparty: &str,
        thread_id: &str,
        ctx: &ModuleContext,
    ) -> Result<IdentityVerificationRequest, RemittanceError>;

    /// Decide how to respond to an incoming certificate request from `counterparty`.
    ///
    /// Returns either a populated `IdentityVerificationResponse` or a `Termination`
    /// explaining why the local wallet declines.
    async fn respond_to_request(
        &self,
        counterparty: &str,
        thread_id: &str,
        request: &IdentityVerificationRequest,
        ctx: &ModuleContext,
    ) -> Result<RespondToRequestResult, RemittanceError>;

    /// Assess whether the certificates received from `counterparty` are sufficient
    /// to proceed with the remittance thread.
    ///
    /// NOTE: does not receive `ctx` — per the TypeScript source this assessment
    /// relies only on the received response and the thread identifier.
    async fn assess_received_certificate_sufficiency(
        &self,
        counterparty: &str,
        received: &IdentityVerificationResponse,
        thread_id: &str,
    ) -> Result<AssessIdentityResult, RemittanceError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remittance::types::{
        IdentityRequest, IdentityVerificationAcknowledgment, IdentityVerificationResponse,
        RemittanceKind, Termination,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MockIdentity;

    #[async_trait]
    impl IdentityLayer for MockIdentity {
        async fn determine_certificates_to_request(
            &self,
            _counterparty: &str,
            thread_id: &str,
            _ctx: &ModuleContext,
        ) -> Result<IdentityVerificationRequest, RemittanceError> {
            Ok(IdentityVerificationRequest {
                kind: RemittanceKind::IdentityVerificationRequest,
                thread_id: thread_id.to_string(),
                request: IdentityRequest {
                    types: HashMap::new(),
                    certifiers: vec![],
                },
            })
        }

        async fn respond_to_request(
            &self,
            _counterparty: &str,
            thread_id: &str,
            _request: &IdentityVerificationRequest,
            _ctx: &ModuleContext,
        ) -> Result<RespondToRequestResult, RemittanceError> {
            Ok(RespondToRequestResult::Respond {
                response: IdentityVerificationResponse {
                    kind: RemittanceKind::IdentityVerificationResponse,
                    thread_id: thread_id.to_string(),
                    certificates: vec![],
                },
            })
        }

        async fn assess_received_certificate_sufficiency(
            &self,
            _counterparty: &str,
            received: &IdentityVerificationResponse,
            _thread_id: &str,
        ) -> Result<AssessIdentityResult, RemittanceError> {
            Ok(AssessIdentityResult::Acknowledge(
                IdentityVerificationAcknowledgment {
                    kind: RemittanceKind::IdentityVerificationAcknowledgment,
                    thread_id: received.thread_id.clone(),
                },
            ))
        }
    }

    #[test]
    fn identity_layer_is_object_safe() {
        // If IdentityLayer were not object-safe this line would fail to compile.
        let _: Arc<dyn IdentityLayer> = Arc::new(MockIdentity);
    }

    #[test]
    fn respond_to_request_result_variants() {
        let respond = RespondToRequestResult::Respond {
            response: IdentityVerificationResponse {
                kind: RemittanceKind::IdentityVerificationResponse,
                thread_id: "t1".into(),
                certificates: vec![],
            },
        };
        let terminate = RespondToRequestResult::Terminate {
            termination: Termination {
                code: "NO_CERTS".into(),
                message: "no certificates available".into(),
                details: None,
            },
        };

        assert!(matches!(respond, RespondToRequestResult::Respond { .. }));
        assert!(matches!(
            terminate,
            RespondToRequestResult::Terminate { .. }
        ));
    }

    #[test]
    fn assess_identity_result_variants() {
        let ack = AssessIdentityResult::Acknowledge(IdentityVerificationAcknowledgment {
            kind: RemittanceKind::IdentityVerificationAcknowledgment,
            thread_id: "t1".into(),
        });
        let terminate = AssessIdentityResult::Terminate(Termination {
            code: "INSUFFICIENT".into(),
            message: "certs do not satisfy requirements".into(),
            details: None,
        });

        assert!(matches!(ack, AssessIdentityResult::Acknowledge(_)));
        assert!(matches!(terminate, AssessIdentityResult::Terminate(_)));
    }
}
