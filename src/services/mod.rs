//! Higher-level BSV service clients.
//!
//! This module provides typed async clients for BSV overlay network services:
//! identity lookup, certificate registry, file storage, key-value store,
//! messaging (BRC-77/78), and SHIP/SLAP overlay infrastructure.

pub mod error;
pub mod messages;

#[cfg(feature = "network")]
pub mod overlay_tools;

#[cfg(any(feature = "serde", feature = "network"))]
pub mod kvstore;
#[cfg(feature = "network")]
pub mod storage;

#[cfg(feature = "network")]
pub mod identity;

#[cfg(feature = "network")]
pub mod registry;

pub use error::ServicesError;
