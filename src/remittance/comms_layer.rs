//! Transport abstraction layer for remittance message exchange.
//!
//! Defines the `CommsLayer` async trait that pluggable transports must implement.
//! Required methods cover the message-box protocol; optional live-message methods
//! return a `Protocol` error by default, allowing transports that only support
//! store-and-forward to omit the WebSocket / SSE implementation.

#![cfg(feature = "network")]

use std::sync::Arc;

use async_trait::async_trait;

use crate::remittance::error::RemittanceError;
use crate::remittance::types::PeerMessage;

/// Pluggable transport interface for the remittance protocol.
///
/// Implementors must be `Send + Sync` so they can be stored in `Arc<dyn CommsLayer>`
/// and shared across async tasks.
///
/// Three methods are required (store-and-forward messaging); two optional live-
/// message methods default to returning `RemittanceError::Protocol` so that
/// transports without WebSocket / SSE support still compile without extra boilerplate.
#[async_trait]
pub trait CommsLayer: Send + Sync {
    // ------------------------------------------------------------------
    // Required methods
    // ------------------------------------------------------------------

    /// Send an encrypted message to `recipient` in the given `message_box`.
    ///
    /// Returns the server-assigned message ID on success.
    async fn send_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        host_override: Option<&str>,
    ) -> Result<String, RemittanceError>;

    /// Retrieve all pending messages from `message_box`.
    async fn list_messages(
        &self,
        message_box: &str,
        host: Option<&str>,
    ) -> Result<Vec<PeerMessage>, RemittanceError>;

    /// Acknowledge receipt of a set of messages so the server can delete them.
    async fn acknowledge_message(&self, message_ids: &[String]) -> Result<(), RemittanceError>;

    // ------------------------------------------------------------------
    // Optional methods — default to Protocol error
    // ------------------------------------------------------------------

    /// Send a live (WebSocket / SSE) message.
    ///
    /// Defaults to `Err(RemittanceError::Protocol("live messages not supported …"))`.
    /// Transports that support live messaging should override this method.
    async fn send_live_message(
        &self,
        recipient: &str,
        message_box: &str,
        body: &str,
        host_override: Option<&str>,
    ) -> Result<String, RemittanceError> {
        let _ = (recipient, message_box, body, host_override);
        Err(RemittanceError::Protocol(
            "live messages not supported by this transport".into(),
        ))
    }

    /// Subscribe to live messages on `message_box`, invoking `on_message` for each.
    ///
    /// `on_message` is `Arc` (not `Box`) so the transport can retain the callback
    /// across reconnects without cloning the closure — matching the TypeScript SDK
    /// pattern where the listener holds a reference to the callback.
    ///
    /// Defaults to `Err(RemittanceError::Protocol("live messages not supported …"))`.
    async fn listen_for_live_messages(
        &self,
        message_box: &str,
        override_host: Option<&str>,
        on_message: Arc<dyn Fn(PeerMessage) + Send + Sync>,
    ) -> Result<(), RemittanceError> {
        let _ = (message_box, override_host, on_message);
        Err(RemittanceError::Protocol(
            "live messages not supported by this transport".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

        async fn acknowledge_message(
            &self,
            _message_ids: &[String],
        ) -> Result<(), RemittanceError> {
            Ok(())
        }
    }

    #[test]
    fn comms_layer_is_object_safe() {
        // If CommsLayer were not object-safe this line would fail to compile.
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
}
