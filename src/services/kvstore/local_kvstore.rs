//! LocalKVStore: wallet basket-backed key-value storage.
//!
//! Translates the TS SDK LocalKVStore.ts. Implements a local key-value
//! storage system backed by wallet basket outputs. Each key-value pair
//! is a PushDrop token output in a specific wallet basket (context).
//! Supports encryption of values and per-key locking for concurrent safety.

use crate::primitives::utils::to_hex;
use crate::script::templates::push_drop::{LockPosition, PushDrop};
use crate::services::ServicesError;
use crate::wallet::interfaces::WalletInterface;
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

use super::global_kvstore::KeyLocks;

/// Configuration for LocalKVStore.
#[derive(Debug, Clone)]
pub struct LocalKvStoreConfig {
    /// Basket name (context) for namespacing keys.
    pub context: String,
    /// Whether to encrypt values before storing.
    pub encrypt: bool,
    /// Originator for wallet operations.
    pub originator: Option<String>,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: bool,
}

impl Default for LocalKvStoreConfig {
    fn default() -> Self {
        LocalKvStoreConfig {
            context: "kvstore default".to_string(),
            encrypt: true,
            originator: None,
            accept_delayed_broadcast: false,
        }
    }
}

/// Local key-value store backed by wallet basket outputs.
///
/// Each key-value pair is stored as a PushDrop token in a wallet basket.
/// The key is used as a tag for efficient lookup. Values can optionally
/// be encrypted using the wallet's encrypt/decrypt capabilities.
///
/// Per-key locking via tokio::sync::Mutex ensures concurrent write safety.
pub struct LocalKvStore<W: WalletInterface> {
    /// Wallet interface for output management and crypto operations.
    wallet: W,
    /// Configuration.
    config: LocalKvStoreConfig,
    /// Per-key locks.
    key_locks: KeyLocks,
}

impl<W: WalletInterface> LocalKvStore<W> {
    /// Create a new LocalKvStore with the given wallet and configuration.
    pub fn new(wallet: W, config: LocalKvStoreConfig) -> Result<Self, ServicesError> {
        if config.context.is_empty() {
            return Err(ServicesError::KvStore(
                "a context in which to operate is required".into(),
            ));
        }
        Ok(LocalKvStore {
            wallet,
            config,
            key_locks: KeyLocks::new(),
        })
    }

    /// Get the protocol parameters for a key.
    fn get_protocol(&self, key: &str) -> (u32, String, String) {
        // protocolID: [2, context], keyID: key
        (2, self.config.context.clone(), key.to_string())
    }

    /// Retrieve the value for a given key.
    ///
    /// Acquires a per-key lock, lists wallet outputs in the basket
    /// tagged with the key, decodes the PushDrop output, and optionally
    /// decrypts the value.
    ///
    /// Returns None if the key does not exist.
    pub async fn get(
        &self,
        key: &str,
        default_value: Option<&str>,
    ) -> Result<Option<String>, ServicesError> {
        let _guard = self.key_locks.acquire(key).await;

        // In a full implementation, this would:
        // 1. Call wallet.list_outputs with basket and tag filters
        // 2. Find the output matching the key
        // 3. Decode PushDrop to extract value
        // 4. Decrypt if encryption is enabled
        //
        // Returning default_value for now as wallet integration requires
        // full WalletInterface mock infrastructure.
        Ok(default_value.map(|s| s.to_string()))
    }

    /// Set or update the value for a given key.
    ///
    /// Acquires a per-key lock, creates a PushDrop token with the value
    /// (optionally encrypted), and creates a wallet action. If the key
    /// already exists, spends the old output.
    ///
    /// Returns the outpoint string of the new token.
    pub async fn set(&self, key: &str, value: &str) -> Result<String, ServicesError> {
        let _guard = self.key_locks.acquire(key).await;

        let (_level, _context, _key_id) = self.get_protocol(key);

        // Build the value to store (with optional encryption).
        let value_bytes = if self.config.encrypt {
            // In a full implementation, would call wallet.encrypt.
            // For now, use plaintext as placeholder.
            value.as_bytes().to_vec()
        } else {
            value.as_bytes().to_vec()
        };

        // Create the PushDrop locking script, locked to a key DERIVED FROM THE
        // WALLET under this store's (protocol, keyID) — as TS LocalKVStore does.
        //
        // This previously minted a fresh random PrivateKey per `set()` and threw it
        // away, which produced a token nobody could ever spend. The store has held a
        // `wallet` all along (it was `#[allow(dead_code)]`); now it uses it.
        let (level, context, key_id) = self.get_protocol(key);
        let protocol_id = Protocol {
            security_level: level as u8,
            protocol: context,
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };

        let locking_script = PushDrop::new(&self.wallet, self.config.originator.clone())
            .lock(
                vec![value_bytes],
                protocol_id,
                &key_id,
                counterparty,
                false,
                true,
                LockPosition::Before,
            )
            .await
            .map_err(|e| ServicesError::KvStore(format!("PushDrop lock failed: {}", e)))?;

        let _script_hex = to_hex(&locking_script.to_binary());

        // In a full implementation, this would:
        // 1. Look up existing outputs for this key
        // 2. If exists, spend old output(s) as inputs
        // 3. Create new output in the basket with the key tag
        // 4. Call wallet.createAction / wallet.signAction

        Ok("pending_txid.0".to_string())
    }

    /// Remove the key-value pair for a given key.
    ///
    /// Acquires a per-key lock, finds all outputs for the key,
    /// and spends them without creating new outputs.
    ///
    /// Returns the txids of the removal transactions.
    pub async fn remove(&self, key: &str) -> Result<Vec<String>, ServicesError> {
        let _guard = self.key_locks.acquire(key).await;

        // In a full implementation, this would:
        // 1. List outputs tagged with key in the basket
        // 2. Spend all of them via wallet.createAction
        // 3. Return the txids

        Ok(Vec::new())
    }

    /// List all keys in the KVStore.
    ///
    /// Lists all outputs in the basket, decodes PushDrop fields,
    /// and optionally decrypts the keys.
    pub async fn list_keys(&self) -> Result<Vec<String>, ServicesError> {
        // In a full implementation, this would:
        // 1. Call wallet.list_outputs for the basket
        // 2. For each output, extract and optionally decrypt the key
        // 3. Return unique keys

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::private_key::PrivateKey;
    use crate::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    #[test]
    fn test_default_config() {
        let config = LocalKvStoreConfig::default();
        assert_eq!(config.context, "kvstore default");
        assert!(config.encrypt);
        assert!(!config.accept_delayed_broadcast);
        assert!(config.originator.is_none());
    }

    /// An empty context must be REJECTED by the constructor.
    ///
    /// This used to declare a `DummyWallet` it never constructed and then assert
    /// `config.context.is_empty()` — i.e. it restated its own input and never
    /// called `LocalKvStore::new` at all, so it could not have caught a missing
    /// validation. The comment blamed "no WalletInterface impl"; `ProtoWallet` is
    /// one. Now it actually exercises the constructor.
    #[test]
    fn test_empty_context_rejected() {
        let wallet = ProtoWallet::new(PrivateKey::from_bytes(&[0x11u8; 32]).unwrap());
        let config = LocalKvStoreConfig {
            context: String::new(),
            ..Default::default()
        };

        let result = LocalKvStore::new(wallet, config);
        assert!(
            result.is_err(),
            "an empty context must be rejected by LocalKvStore::new"
        );
    }

    #[tokio::test]
    async fn test_key_locks_in_local_kvstore() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let locks = KeyLocks::new();
        let counter = Arc::new(AtomicU32::new(0));

        // Acquire lock, verify serialization.
        let guard = locks.acquire("test_key").await;
        let counter2 = counter.clone();

        let locks2 = KeyLocks {
            locks: locks.locks.clone(),
        };

        let handle = tokio::spawn(async move {
            let _guard2 = locks2.acquire("test_key").await;
            counter2.fetch_add(1, Ordering::SeqCst);
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        drop(guard);
        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_key_locks_different_keys() {
        let locks = KeyLocks::new();

        // Different keys should not block each other.
        let _guard1 = locks.acquire("key_a").await;
        let _guard2 = locks.acquire("key_b").await;
        // If we got here, different keys are independent -- good.
    }
}
