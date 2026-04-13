//! High-level client abstractions for authenticated communication.
//!
//! Provides AuthFetch, a simplified HTTP client that manages per-base-URL
//! peers and performs BRC-31 mutual authentication automatically.

pub mod auth_fetch;

pub use auth_fetch::{
    AuthFetch, AuthFetchResponse, FetchOptions, PaymentErrorLogEntry, PaymentRetryContext,
    PAYMENT_VERSION,
};
