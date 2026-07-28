//! `KeyDeriverApi`: the BRC-42 key-derivation contract, as a trait.
//!
//! Mirrors the `KeyDeriverApi` interface declared upstream in the TypeScript
//! `@bsv/sdk` at `wallet/KeyDeriver.d.ts`, with the same seven members.
//!
//! Both [`KeyDeriver`] and [`CachedKeyDeriver`] carry these members as inherent
//! methods, so any caller holding one concrete type already has them. The trait
//! exists for callers that must hold *some* deriver without naming which: it
//! lets an identity key be decoupled from a locally-held root key, so a deriver
//! backed by a joint or threshold public key — where the private half exists
//! only as distributed shares — can stand in wherever a plain `KeyDeriver`
//! does.

use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::cached_key_deriver::CachedKeyDeriver;
use crate::wallet::error::WalletError;
use crate::wallet::key_deriver::KeyDeriver;
use crate::wallet::types::{Counterparty, Protocol};

/// Type-42 (BRC-42) key derivation, as implemented by [`KeyDeriver`] and
/// [`CachedKeyDeriver`].
///
/// Object safe: every method takes `&self`, none is generic, and none returns
/// `Self`, so callers can hold an `Arc<dyn KeyDeriverApi + Send + Sync>` and
/// swap implementations at run time.
pub trait KeyDeriverApi: Send + Sync {
    /// The root private key derivation is anchored on.
    ///
    /// Returned by reference: callers such as `ProtoWallet`'s Schnorr DLEQ
    /// proof pass it straight through to primitives that borrow it.
    fn root_key(&self) -> &PrivateKey;

    /// The public key identifying this deriver to counterparties.
    fn identity_key(&self) -> PublicKey;

    /// Derive a public key for the given protocol, key ID, and counterparty.
    ///
    /// When `for_self` is true the private child is derived first and its
    /// public key returned; otherwise derivation runs on the counterparty's
    /// public key.
    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError>;

    /// Derive a private key for the given protocol, key ID, and counterparty.
    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError>;

    /// Derive a symmetric key from the ECDH shared secret of the derived
    /// private and public keys.
    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError>;

    /// Reveal the counterparty shared secret as a public key point.
    ///
    /// Rejects counterparty=self, since that secret would reveal the root key's
    /// own linkage.
    fn reveal_counterparty_secret(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError>;

    /// Reveal the specific key-association secret for a protocol and key ID.
    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>, WalletError>;

    /// The identity key as a compressed DER hex string.
    ///
    /// A Rust-side convenience with no TS counterpart; provided here so every
    /// implementation gets it from [`Self::identity_key`].
    fn identity_key_hex(&self) -> String {
        self.identity_key().to_der_hex()
    }
}

impl KeyDeriverApi for KeyDeriver {
    fn root_key(&self) -> &PrivateKey {
        KeyDeriver::root_key(self)
    }

    fn identity_key(&self) -> PublicKey {
        KeyDeriver::identity_key(self)
    }

    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError> {
        KeyDeriver::derive_public_key(self, protocol, key_id, counterparty, for_self)
    }

    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError> {
        KeyDeriver::derive_private_key(self, protocol, key_id, counterparty)
    }

    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError> {
        KeyDeriver::derive_symmetric_key(self, protocol, key_id, counterparty)
    }

    fn reveal_counterparty_secret(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        KeyDeriver::reveal_counterparty_secret(self, counterparty)
    }

    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>, WalletError> {
        KeyDeriver::reveal_specific_secret(self, counterparty, protocol, key_id)
    }

    fn identity_key_hex(&self) -> String {
        KeyDeriver::identity_key_hex(self)
    }
}

impl KeyDeriverApi for CachedKeyDeriver {
    fn root_key(&self) -> &PrivateKey {
        CachedKeyDeriver::root_key(self)
    }

    fn identity_key(&self) -> PublicKey {
        CachedKeyDeriver::identity_key(self)
    }

    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError> {
        CachedKeyDeriver::derive_public_key(self, protocol, key_id, counterparty, for_self)
    }

    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError> {
        CachedKeyDeriver::derive_private_key(self, protocol, key_id, counterparty)
    }

    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError> {
        CachedKeyDeriver::derive_symmetric_key(self, protocol, key_id, counterparty)
    }

    fn reveal_counterparty_secret(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        CachedKeyDeriver::reveal_counterparty_secret(self, counterparty)
    }

    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>, WalletError> {
        CachedKeyDeriver::reveal_specific_secret(self, counterparty, protocol, key_id)
    }

    fn identity_key_hex(&self) -> String {
        CachedKeyDeriver::identity_key_hex(self)
    }
}
