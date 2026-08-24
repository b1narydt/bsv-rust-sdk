//! Transport abstractions for the BRC-103 authentication protocol.
//!
//! Defines the Transport trait for sending and receiving AuthMessages
//! over different communication channels (HTTP, WebSocket, etc.).
//!
//! Translated from Go SDK auth/transports/interface.go.

#[cfg(feature = "network")]
pub mod http;
#[cfg(feature = "network")]
pub mod websocket;

#[cfg(feature = "network")]
use async_trait::async_trait;
#[cfg(feature = "network")]
use tokio::sync::mpsc;

#[cfg(feature = "network")]
use super::error::AuthError;
#[cfg(feature = "network")]
use super::types::AuthMessage;

#[cfg(feature = "network")]
pub use self::http::SimplifiedHTTPTransport;
#[cfg(feature = "network")]
pub use self::websocket::{WebSocketTransport, WsOptions};

/// Transport defines the interface for communication transports used
/// in BRC-103 authentication.
///
/// Implementations handle the details of sending messages to a peer and
/// receiving messages from it. The `subscribe` method returns an mpsc
/// Receiver that delivers incoming messages (channel-based, not callbacks).
///
/// This trait is object-safe (uses async-trait) so it can be stored as
/// `Box<dyn Transport>` for runtime dispatch.
#[cfg(feature = "network")]
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send an authentication message through this transport.
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError>;

    /// Subscribe to incoming messages from this transport.
    ///
    /// Returns an mpsc Receiver that will deliver AuthMessages as they arrive.
    /// This should only be called once; subsequent calls may panic or return
    /// an empty receiver depending on the implementation.
    fn subscribe(&self) -> mpsc::Receiver<AuthMessage>;
}
