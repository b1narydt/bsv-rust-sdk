//! Wallet module for BSV SDK.
//!
//! Provides Type-42 key derivation, wallet error types, semantic
//! type aliases, and the WalletInterface trait for the wallet layer.

pub mod cached_key_deriver;
pub mod error;
pub mod interfaces;
pub mod key_deriver;
pub mod key_deriver_api;
pub mod proto_wallet;
pub mod serializer;
pub mod substrates;
pub mod types;
pub mod validation;

pub use cached_key_deriver::CachedKeyDeriver;
pub use error::WalletError;
pub use interfaces::WalletInterface;
pub use key_deriver::KeyDeriver;
pub use key_deriver_api::KeyDeriverApi;
pub use proto_wallet::ProtoWallet;
pub use types::{anyone_private_key, anyone_pubkey, Counterparty, CounterpartyType, Protocol};
