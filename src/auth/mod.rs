//! Authentication framework for BSV SDK.
//!
//! Implements BRC-31 Authrite mutual authentication protocol with
//! session management, certificate handling, and authenticated transports.

pub mod certificates;
#[cfg(feature = "network")]
pub mod clients;
pub mod error;
#[cfg(feature = "network")]
pub mod peer;
pub mod session_manager;
pub mod transports;
pub mod types;
pub mod utils;

pub use error::AuthError;
pub use session_manager::SessionManager;
pub use types::*;

#[cfg(feature = "network")]
pub use clients::{
    AuthFetch, AuthFetchResponse, FetchOptions, PaymentErrorLogEntry, PaymentRetryContext,
    PAYMENT_VERSION,
};
#[cfg(feature = "network")]
pub use peer::Peer;
