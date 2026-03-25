//! Pluggable remittance module implementations.
//!
//! Each sub-module implements the `RemittanceModule` trait and provides
//! the type-safe wire format, config, and injectable dependency traits
//! needed by `RemittanceManager`.

#[cfg(feature = "network")]
pub mod brc29;
