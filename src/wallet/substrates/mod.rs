//! Wallet wire transport substrates.
//!
//! Provides the wire protocol infrastructure for remote wallet access:
//! - WalletWire trait: abstraction over binary transport
//! - WalletWireCalls: enum of 28 call codes
//! - WalletWireTransceiver: client-side WalletInterface over wire
//! - WalletWireProcessor: server-side dispatch to wallet implementation
//! - WalletClient: validation layer wrapping a wire transport
//! - HTTPWalletWire: HTTP binary transport (network feature)
//! - HTTPWalletJSON: HTTP JSON transport (network feature)

pub mod wallet_client;
pub mod wallet_wire_calls;
pub mod wallet_wire_processor;
pub mod wallet_wire_transceiver;

#[cfg(feature = "network")]
pub mod http_wallet_json;
#[cfg(feature = "network")]
pub mod http_wallet_wire;

use async_trait::async_trait;

use crate::wallet::error::WalletError;

pub use wallet_client::WalletClient;
pub use wallet_wire_calls::WalletWireCall;
pub use wallet_wire_processor::WalletWireProcessor;
pub use wallet_wire_transceiver::WalletWireTransceiver;

#[cfg(feature = "network")]
pub use http_wallet_json::HttpWalletJson;
#[cfg(feature = "network")]
pub use http_wallet_wire::HttpWalletWire;

/// Abstraction over a raw transport medium where binary data can be sent
/// to and received from a wallet.
///
/// Uses `#[async_trait]` for object safety, matching WalletInterface.
/// Supports both static dispatch (`W: WalletWire`) and dynamic dispatch (`dyn WalletWire`).
#[async_trait]
pub trait WalletWire: Send + Sync {
    /// Send a binary message to the wallet and receive the response.
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, WalletError>;
}

#[cfg(test)]
mod tests;
