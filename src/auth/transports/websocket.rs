//! WebSocket transport for BRC-103 authentication.
//!
//! Implements WebSocketTransport using tokio-tungstenite for persistent
//! bidirectional communication with auto-reconnect and exponential backoff.
//!
//! Translated from Go SDK websocket_transport.go.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};

use super::Transport;
use crate::auth::error::AuthError;
use crate::auth::types::AuthMessage;

// ---------------------------------------------------------------------------
// WsOptions
// ---------------------------------------------------------------------------

/// Configuration options for WebSocketTransport.
#[derive(Clone, Debug)]
pub struct WsOptions {
    /// Whether to auto-reconnect on connection loss.
    pub reconnect: bool,
    /// Maximum number of reconnection attempts.
    pub max_retries: u32,
    /// Base backoff delay in milliseconds (doubles each attempt).
    pub backoff_ms: u64,
}

impl Default for WsOptions {
    fn default() -> Self {
        WsOptions {
            reconnect: true,
            max_retries: 5,
            backoff_ms: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocketTransport
// ---------------------------------------------------------------------------

/// WebSocket transport for BRC-103 authentication.
///
/// Uses tokio-tungstenite for WebSocket connectivity. Messages are sent and
/// received as JSON text frames. Supports auto-reconnect with configurable
/// exponential backoff.
///
/// Call `connect()` to establish the WebSocket connection, then use the
/// `Transport` trait methods to send/receive messages.
pub struct WebSocketTransport {
    url: String,
    options: WsOptions,
    /// Sender for outgoing messages (write task reads from this).
    outgoing_tx: mpsc::Sender<AuthMessage>,
    /// Receiver for outgoing messages (consumed by the write task).
    outgoing_rx: Arc<Mutex<Option<mpsc::Receiver<AuthMessage>>>>,
    /// Sender for incoming messages.
    incoming_tx: mpsc::Sender<AuthMessage>,
    /// Receiver for incoming messages (take-once via subscribe).
    incoming_rx: Arc<Mutex<Option<mpsc::Receiver<AuthMessage>>>>,
    /// Whether the transport is currently connected.
    connected: Arc<AtomicBool>,
}

impl WebSocketTransport {
    /// Create a new WebSocketTransport for the given WebSocket URL.
    ///
    /// Uses default WsOptions if `None` is provided.
    pub fn new(url: &str, options: Option<WsOptions>) -> Self {
        let opts = options.unwrap_or_default();
        let (outgoing_tx, outgoing_rx) = mpsc::channel(32);
        let (incoming_tx, incoming_rx) = mpsc::channel(32);

        WebSocketTransport {
            url: url.to_string(),
            options: opts,
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(Some(outgoing_rx))),
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(Some(incoming_rx))),
            connected: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Establish the WebSocket connection and spawn read/write background tasks.
    ///
    /// The read task deserializes incoming JSON text frames into AuthMessages
    /// and pushes them to the incoming channel. The write task reads from the
    /// outgoing channel and sends messages as JSON text frames.
    ///
    /// If the connection drops and `options.reconnect` is true, the read task
    /// will attempt to reconnect with exponential backoff.
    pub async fn connect(&self) -> Result<(), AuthError> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let (ws_stream, _response) = connect_async(&self.url).await.map_err(|e| {
            AuthError::TransportError(format!("WebSocket connect to {} failed: {}", self.url, e))
        })?;

        self.connected.store(true, Ordering::SeqCst);

        let (write_half, read_half) = ws_stream.split();

        // Take the outgoing receiver (only valid on first connect)
        let outgoing_rx = {
            let mut guard = self.outgoing_rx.lock().await;
            guard.take()
        };

        // Spawn write task
        if let Some(mut rx) = outgoing_rx {
            let mut write_half = write_half;
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    if let Ok(json) = serde_json::to_string(&msg) {
                        if write_half.send(WsMessage::Text(json)).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }

        // Spawn read task with auto-reconnect
        let incoming_tx = self.incoming_tx.clone();
        let connected = self.connected.clone();
        let url = self.url.clone();
        let options = self.options.clone();

        tokio::spawn(async move {
            let mut read_half = read_half;
            loop {
                // Process messages from the read half
                while let Some(result) = read_half.next().await {
                    match result {
                        Ok(WsMessage::Text(text)) => {
                            if let Ok(auth_msg) = serde_json::from_str::<AuthMessage>(&text) {
                                if incoming_tx.send(auth_msg).await.is_err() {
                                    // Receiver dropped, stop reading
                                    connected.store(false, Ordering::SeqCst);
                                    return;
                                }
                            }
                        }
                        Ok(WsMessage::Close(_)) => {
                            break;
                        }
                        Err(_) => {
                            break;
                        }
                        _ => {
                            // Ignore ping/pong/binary frames
                        }
                    }
                }

                // Connection lost
                connected.store(false, Ordering::SeqCst);

                if !options.reconnect {
                    return;
                }

                // Attempt reconnect with exponential backoff
                let mut reconnected = false;
                for attempt in 0..options.max_retries {
                    let delay = options.backoff_ms * (1u64 << attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

                    match connect_async(&url).await {
                        Ok((ws_stream, _)) => {
                            let (_new_write, new_read) = ws_stream.split();
                            read_half = new_read;
                            connected.store(true, Ordering::SeqCst);
                            // Note: write half is not reconnected here -- outgoing messages
                            // sent during disconnect will be dropped. A full reconnect would
                            // require coordination with the write task. For now we restore
                            // the read side to resume receiving.
                            reconnected = true;
                            break;
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }

                if !reconnected {
                    // Max retries exhausted
                    return;
                }
            }
        });

        Ok(())
    }

    /// Disconnect the transport.
    ///
    /// Sets connected to false. The write task will exit when the outgoing
    /// sender is dropped (or when WebSocketTransport is dropped).
    pub async fn disconnect(&self) -> Result<(), AuthError> {
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Check whether the transport is currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, message: AuthMessage) -> Result<(), AuthError> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err(AuthError::TransportNotConnected(
                "WebSocket is not connected".to_string(),
            ));
        }

        self.outgoing_tx.send(message).await.map_err(|e| {
            AuthError::TransportError(format!("failed to enqueue outgoing message: {}", e))
        })?;

        Ok(())
    }

    fn subscribe(&self) -> mpsc::Receiver<AuthMessage> {
        let mut guard = self.incoming_rx.blocking_lock();
        guard
            .take()
            // SAFETY: subscribe() is a take-once API -- callers must only invoke once per transport.
            .expect("subscribe() can only be called once per transport")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_options_default() {
        let opts = WsOptions::default();
        assert!(opts.reconnect);
        assert_eq!(opts.max_retries, 5);
        assert_eq!(opts.backoff_ms, 1000);
    }

    #[test]
    fn test_ws_options_custom() {
        let opts = WsOptions {
            reconnect: false,
            max_retries: 10,
            backoff_ms: 500,
        };
        assert!(!opts.reconnect);
        assert_eq!(opts.max_retries, 10);
        assert_eq!(opts.backoff_ms, 500);
    }

    #[test]
    fn test_websocket_transport_construction() {
        let transport = WebSocketTransport::new("ws://localhost:8080", None);
        assert_eq!(transport.url, "ws://localhost:8080");
        assert!(!transport.is_connected());
        assert!(transport.options.reconnect);
        assert_eq!(transport.options.max_retries, 5);
    }

    #[test]
    fn test_websocket_transport_custom_options() {
        let opts = WsOptions {
            reconnect: false,
            max_retries: 3,
            backoff_ms: 2000,
        };
        let transport = WebSocketTransport::new("wss://example.com/ws", Some(opts));
        assert_eq!(transport.url, "wss://example.com/ws");
        assert!(!transport.options.reconnect);
        assert_eq!(transport.options.max_retries, 3);
        assert_eq!(transport.options.backoff_ms, 2000);
    }

    #[tokio::test]
    async fn test_send_when_not_connected_returns_error() {
        let transport = WebSocketTransport::new("ws://localhost:9999", None);

        let message = AuthMessage {
            version: "0.1".to_string(),
            message_type: crate::auth::types::MessageType::InitialRequest,
            identity_key: "02abc".to_string(),
            nonce: None,
            your_nonce: None,
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        };

        let result = transport.send(message).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("not connected"),
            "Expected 'not connected' error, got: {}",
            err
        );
    }

    #[tokio::test]
    #[ignore] // Requires a real WebSocket server
    async fn test_websocket_connect_and_send() {
        let transport = WebSocketTransport::new("ws://localhost:8080/auth", None);
        transport.connect().await.unwrap();
        assert!(transport.is_connected());

        let message = AuthMessage {
            version: "0.1".to_string(),
            message_type: crate::auth::types::MessageType::InitialRequest,
            identity_key: "02abc".to_string(),
            nonce: Some("test-nonce".to_string()),
            your_nonce: None,
            initial_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        };

        transport.send(message).await.unwrap();
        transport.disconnect().await.unwrap();
        assert!(!transport.is_connected());
    }
}
