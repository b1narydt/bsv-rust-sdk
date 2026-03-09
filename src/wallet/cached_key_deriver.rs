//! CachedKeyDeriver: Wrapper around KeyDeriver with HashMap memoization.
//!
//! Caches derived keys to improve performance for repeated derivations
//! with the same parameters. Uses interior mutability (RwLock) so that
//! derive methods take `&self`, enabling shared ownership via `Arc`
//! without external locking.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::primitives::private_key::PrivateKey;
use crate::primitives::public_key::PublicKey;
use crate::primitives::symmetric_key::SymmetricKey;
use crate::wallet::error::WalletError;
use crate::wallet::key_deriver::KeyDeriver;
use crate::wallet::types::{Counterparty, Protocol};

const DEFAULT_MAX_CACHE_SIZE: usize = 1000;

/// Cached value stored in the cache. Wraps the three possible derived types.
enum CachedValue {
    Private(PrivateKey),
    Public(PublicKey),
    Symmetric(Vec<u8>), // Store as bytes since SymmetricKey does not implement Clone
}

/// CachedKeyDeriver wraps a KeyDeriver with a HashMap cache for
/// derived key memoization. Uses interior mutability so all derive
/// methods take `&self`.
pub struct CachedKeyDeriver {
    key_deriver: KeyDeriver,
    cache: RwLock<HashMap<String, CachedValue>>,
    max_cache_size: usize,
}

impl CachedKeyDeriver {
    /// Create a new CachedKeyDeriver.
    ///
    /// `max_cache_size` defaults to 1000 if None or 0.
    pub fn new(private_key: PrivateKey, max_cache_size: Option<usize>) -> Self {
        let size = match max_cache_size {
            Some(s) if s > 0 => s,
            _ => DEFAULT_MAX_CACHE_SIZE,
        };
        CachedKeyDeriver {
            key_deriver: KeyDeriver::new(private_key),
            cache: RwLock::new(HashMap::new()),
            max_cache_size: size,
        }
    }

    /// Returns a reference to the root private key.
    ///
    /// Needed for BRC-29 key derivation and other operations that require
    /// direct access to the root key material.
    pub fn root_key(&self) -> &PrivateKey {
        self.key_deriver.root_key()
    }

    /// Returns the identity public key (delegates directly, no caching).
    pub fn identity_key(&self) -> PublicKey {
        self.key_deriver.identity_key()
    }

    /// Returns the identity key hex (delegates directly, no caching).
    pub fn identity_key_hex(&self) -> String {
        self.key_deriver.identity_key_hex()
    }

    /// Derive a private key with caching.
    pub fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError> {
        let cache_key =
            Self::make_cache_key("derivePrivateKey", protocol, key_id, counterparty, false);

        // Check cache with read lock
        {
            let cache = self.cache.read().unwrap();
            if let Some(CachedValue::Private(pk)) = cache.get(&cache_key) {
                return Ok(pk.clone());
            }
        }

        let result = self
            .key_deriver
            .derive_private_key(protocol, key_id, counterparty)?;
        self.cache_set(cache_key, CachedValue::Private(result.clone()));
        Ok(result)
    }

    /// Derive a public key with caching.
    pub fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError> {
        let cache_key =
            Self::make_cache_key("derivePublicKey", protocol, key_id, counterparty, for_self);

        // Check cache with read lock
        {
            let cache = self.cache.read().unwrap();
            if let Some(CachedValue::Public(pk)) = cache.get(&cache_key) {
                return Ok(pk.clone());
            }
        }

        let result =
            self.key_deriver
                .derive_public_key(protocol, key_id, counterparty, for_self)?;
        self.cache_set(cache_key, CachedValue::Public(result.clone()));
        Ok(result)
    }

    /// Derive a symmetric key with caching.
    pub fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError> {
        let cache_key =
            Self::make_cache_key("deriveSymmetricKey", protocol, key_id, counterparty, false);

        // Check cache with read lock
        {
            let cache = self.cache.read().unwrap();
            if let Some(CachedValue::Symmetric(bytes)) = cache.get(&cache_key) {
                return SymmetricKey::from_bytes(bytes).map_err(WalletError::from);
            }
        }

        let result = self
            .key_deriver
            .derive_symmetric_key(protocol, key_id, counterparty)?;
        let bytes = result.to_bytes();
        self.cache_set(cache_key, CachedValue::Symmetric(bytes));
        // Re-derive to return (bytes already cached)
        self.key_deriver
            .derive_symmetric_key(protocol, key_id, counterparty)
    }

    /// Returns the number of entries currently in the cache.
    #[cfg(test)]
    pub(crate) fn cache_len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Build a cache key string from the derivation parameters.
    fn make_cache_key(
        method: &str,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> String {
        let counterparty_hex = match &counterparty.public_key {
            Some(pk) => pk.to_der_hex(),
            None => format!("{:?}", counterparty.counterparty_type),
        };
        format!(
            "{}:{}:{}:{}:{}:{}",
            method, protocol.security_level, protocol.protocol, key_id, counterparty_hex, for_self
        )
    }

    /// Insert a value into the cache, clearing all entries if max size exceeded.
    fn cache_set(&self, key: String, value: CachedValue) {
        let mut cache = self.cache.write().unwrap();
        if cache.len() >= self.max_cache_size {
            cache.clear();
        }
        cache.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::types::CounterpartyType;

    #[test]
    fn test_cached_matches_uncached() {
        let priv_key = PrivateKey::from_hex("abcd").unwrap();
        let priv_key2 = PrivateKey::from_hex("abcd").unwrap();

        let kd = KeyDeriver::new(priv_key);
        let ckd = CachedKeyDeriver::new(priv_key2, None);

        let protocol = Protocol {
            security_level: 2,
            protocol: "test caching".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };

        // Private key derivation
        let pk_uncached = kd
            .derive_private_key(&protocol, "1", &counterparty)
            .unwrap();
        let pk_cached = ckd
            .derive_private_key(&protocol, "1", &counterparty)
            .unwrap();
        assert_eq!(pk_uncached.to_hex(), pk_cached.to_hex());

        // Second call should hit cache
        let pk_cached2 = ckd
            .derive_private_key(&protocol, "1", &counterparty)
            .unwrap();
        assert_eq!(pk_uncached.to_hex(), pk_cached2.to_hex());

        // Public key derivation
        let pub_uncached = kd
            .derive_public_key(&protocol, "1", &counterparty, true)
            .unwrap();
        let pub_cached = ckd
            .derive_public_key(&protocol, "1", &counterparty, true)
            .unwrap();
        assert_eq!(pub_uncached.to_der_hex(), pub_cached.to_der_hex());
    }

    #[test]
    fn test_cache_eviction() {
        let priv_key = PrivateKey::from_hex("abcd").unwrap();
        let ckd = CachedKeyDeriver::new(priv_key, Some(2));

        let protocol = Protocol {
            security_level: 0,
            protocol: "evict test".to_string(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };

        // Fill cache to max
        let _ = ckd
            .derive_private_key(&protocol, "1", &counterparty)
            .unwrap();
        let _ = ckd
            .derive_private_key(&protocol, "2", &counterparty)
            .unwrap();
        // This should trigger eviction (clear all) then insert
        let _ = ckd
            .derive_private_key(&protocol, "3", &counterparty)
            .unwrap();
        // Cache should have 1 entry now
        assert_eq!(ckd.cache_len(), 1);
    }

    #[test]
    fn test_identity_key_delegates() {
        let priv_key = PrivateKey::from_hex("ff").unwrap();
        let priv_key2 = PrivateKey::from_hex("ff").unwrap();
        let kd = KeyDeriver::new(priv_key);
        let ckd = CachedKeyDeriver::new(priv_key2, None);
        assert_eq!(kd.identity_key_hex(), ckd.identity_key_hex());
    }

    #[test]
    fn test_root_key_accessor() {
        let priv_key = PrivateKey::from_hex("abcd").unwrap();
        let expected_hex = priv_key.to_hex();
        let ckd = CachedKeyDeriver::new(priv_key, None);
        assert_eq!(ckd.root_key().to_hex(), expected_hex);
    }
}
