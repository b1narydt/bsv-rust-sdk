#![cfg(feature = "network")]
//! Object-safety and behaviour tests for the CommsLayer and IdentityLayer traits.
//!
//! Kept as an integration test file (rather than inline #[cfg(test)]) because
//! pre-existing wallet module compilation errors prevent the lib test target from
//! building — matching the same pattern used for remittance_wire_format.rs.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use bsv::remittance::comms_layer::CommsLayer;
use bsv::remittance::error::RemittanceError;
use bsv::remittance::identity_layer::{
    AssessIdentityResult, IdentityLayer, RespondToRequestResult,
};
use bsv::remittance::types::{
    IdentityRequest, IdentityVerificationAcknowledgment, IdentityVerificationRequest,
    IdentityVerificationResponse, ModuleContext, PeerMessage, RemittanceKind, Termination,
};

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

struct MockComms;

#[async_trait]
impl CommsLayer for MockComms {
    async fn send_message(
        &self,
        _recipient: &str,
        _message_box: &str,
        _body: &str,
        _host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        Ok("msg-001".into())
    }

    async fn list_messages(
        &self,
        _message_box: &str,
        _host: Option<&str>,
    ) -> Result<Vec<PeerMessage>, RemittanceError> {
        Ok(vec![])
    }

    async fn acknowledge_message(&self, _message_ids: &[String]) -> Result<(), RemittanceError> {
        Ok(())
    }
}

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

// ---------------------------------------------------------------------------
// CommsLayer tests
// ---------------------------------------------------------------------------

#[test]
fn comms_layer_is_object_safe() {
    let _: Arc<dyn CommsLayer> = Arc::new(MockComms);
}

#[tokio::test]
async fn send_live_message_default_returns_error() {
    let comms = MockComms;
    let result = comms
        .send_live_message("alice", "inbox", "hello", None)
        .await;
    assert!(
        matches!(result, Err(RemittanceError::Protocol(_))),
        "expected Protocol error, got {:?}",
        result
    );
}

#[tokio::test]
async fn listen_for_live_messages_default_returns_error() {
    let comms = MockComms;
    let cb: Arc<dyn Fn(PeerMessage) + Send + Sync> = Arc::new(|_msg| {});
    let result = comms.listen_for_live_messages("inbox", None, cb).await;
    assert!(
        matches!(result, Err(RemittanceError::Protocol(_))),
        "expected Protocol error, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// IdentityLayer tests
// ---------------------------------------------------------------------------

#[test]
fn identity_layer_is_object_safe() {
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
