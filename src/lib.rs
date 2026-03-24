//! # BSV SDK
//!
//! A pure-Rust implementation of the BSV Blockchain SDK, translated from the
//! official TypeScript and Go reference implementations. The crate provides
//! everything needed to build BRC-100 compliant applications: key management,
//! transaction construction, script evaluation, wallet operations, mutual
//! authentication, and overlay-service integration.
//!
//! ## Modules
//!
//! - [`primitives`] -- Cryptographic building blocks: private/public keys,
//!   big-number arithmetic, hashing, symmetric encryption, signatures, and
//!   Shamir secret sharing.
//! - [`script`] -- Bitcoin script types (`Script`, `LockingScript`,
//!   `UnlockingScript`), opcodes, the script interpreter, address encoding,
//!   and standard templates (P2PKH, PushDrop, RPuzzle).
//! - [`transaction`] -- Transaction construction, serialization (binary, EF,
//!   BEEF/Atomic BEEF), Merkle proofs, and fee models.
//! - [`wallet`] -- The `WalletInterface` trait (29 BRC-compliant methods),
//!   `ProtoWallet` (offline key/crypto operations), `KeyDeriver` (Type-42
//!   key derivation), and wire-protocol serialization.
//! - [`auth`] -- Mutual authentication via `Peer` handshake (BRC-31),
//!   certificates, and `AuthFetch` for authenticated HTTP.
//! - [`compat`] -- Compatibility helpers: BIP-32 HD keys, BIP-39 mnemonics,
//!   BSM (Bitcoin Signed Message), and ECIES encryption.
//! - [`services`] -- Overlay network services: lookup resolution, topic
//!   broadcasting, identity management, and admin token templates.

pub mod auth;
pub mod compat;
pub mod primitives;
pub mod script;
pub mod services;
pub mod transaction;
pub mod wallet;

#[cfg(feature = "network")]
pub mod remittance;
