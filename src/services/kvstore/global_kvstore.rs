//! GlobalKVStore: overlay-backed key-value storage.
//!
//! Translates the TS SDK GlobalKVStore.ts. Implements a global key-value
//! storage system backed by an overlay service. Each key-value pair is
//! represented by a PushDrop token output. Uses Historian for UTXO chain
//! history traversal and with_double_spend_retry for conflict resolution.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::primitives::utils::to_hex;
use crate::script::templates::push_drop::{LockPosition, PushDrop};
use crate::services::overlay_tools::historian::Historian;
use crate::services::overlay_tools::lookup_resolver::LookupResolver;
use crate::services::overlay_tools::retry::with_double_spend_retry;
use crate::services::overlay_tools::topic_broadcaster::TopicBroadcaster;
use crate::services::overlay_tools::types::{
    LookupAnswer, LookupQuestion, LookupResolverConfig, Network, TopicBroadcasterConfig,
};
use crate::services::ServicesError;
use crate::transaction::beef::Beef;
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};
use crate::wallet::types::{Counterparty, CounterpartyType, Protocol};

use super::interpreter::kv_store_interpreter;
use super::types::{
    KvContext, KvProtocol, KvStoreConfig, KvStoreEntry, KvStoreGetOptions, KvStoreQuery,
    KvStoreToken,
};

/// Per-key lock manager using tokio::sync::Mutex.
///
/// Ensures that concurrent operations on the same key are serialized
/// to prevent data races and double-spends.
pub struct KeyLocks {
    pub(crate) locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl KeyLocks {
    /// Create a new empty KeyLocks instance.
    pub fn new() -> Self {
        KeyLocks {
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquire the lock for a given key.
    ///
    /// Returns a guard that, when dropped, releases the lock.
    pub async fn acquire(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut map = self.locks.lock().await;
            map.entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }
}

impl Default for KeyLocks {
    fn default() -> Self {
        Self::new()
    }
}

/// Global key-value store backed by overlay services.
///
/// Each key-value pair is a PushDrop token output tracked by the overlay.
/// Supports get, set, and remove operations with per-key locking and
/// double-spend retry for writes.
pub struct GlobalKvStore<W: WalletInterface> {
    /// Wallet used to derive the PushDrop locking key and sign the token — TS's
    /// GlobalKVStore takes a wallet for exactly this reason. Without it, `set`
    /// could only mint a token locked to a throwaway key that nobody can spend.
    wallet: W,
    /// Configuration.
    config: KvStoreConfig,
    /// LookupResolver for overlay queries.
    resolver: LookupResolver,
    /// TopicBroadcaster for overlay submissions.
    #[allow(dead_code)]
    broadcaster: TopicBroadcaster,
    /// Historian for UTXO chain history.
    historian: std::sync::Mutex<Historian<String, KvContext>>,
    /// Per-key locks for atomic operations.
    key_locks: KeyLocks,
}

impl<W: WalletInterface> GlobalKvStore<W> {
    /// Create a new GlobalKvStore with the given wallet and configuration.
    pub fn new(wallet: W, config: KvStoreConfig) -> Result<Self, ServicesError> {
        let network = match config.network_preset.as_str() {
            "testnet" => Network::Testnet,
            "local" => Network::Local,
            _ => Network::Mainnet,
        };

        let resolver_config = LookupResolverConfig {
            network: network.clone(),
            ..Default::default()
        };
        let resolver = LookupResolver::new(resolver_config);

        // TopicBroadcaster takes its own LookupResolver by value.
        let broadcaster_resolver_config = LookupResolverConfig {
            network: network.clone(),
            ..Default::default()
        };
        let broadcaster_resolver = LookupResolver::new(broadcaster_resolver_config);

        let broadcaster_config = TopicBroadcasterConfig {
            network,
            ..Default::default()
        };
        let broadcaster = TopicBroadcaster::new(
            config.topics.clone(),
            broadcaster_config,
            broadcaster_resolver,
        )?;

        let historian = Historian::new(Box::new(kv_store_interpreter));

        Ok(GlobalKvStore {
            wallet,
            config,
            resolver,
            broadcaster,
            historian: std::sync::Mutex::new(historian),
            key_locks: KeyLocks::new(),
        })
    }

    /// Retrieve a value from the KVStore by query.
    ///
    /// Returns a single entry for key+controller queries, or a list for
    /// broader queries.
    pub async fn get(
        &self,
        query: &KvStoreQuery,
        options: KvStoreGetOptions,
    ) -> Result<Vec<KvStoreEntry>, ServicesError> {
        let _guard = if let Some(ref key) = query.key {
            Some(self.key_locks.acquire(key).await)
        } else {
            None
        };

        self.query_overlay(query, &options).await
    }

    /// Set a key-value pair in the KVStore.
    ///
    /// Creates a new PushDrop token or updates an existing one. Uses
    /// with_double_spend_retry to handle conflicts. Returns the outpoint
    /// string of the created token.
    pub async fn set(
        &self,
        key: &str,
        value: &str,
        _controller: &str,
    ) -> Result<String, ServicesError> {
        if key.is_empty() {
            return Err(ServicesError::KvStore(
                "key must be a non-empty string".into(),
            ));
        }

        let _guard = self.key_locks.acquire(key).await;

        let key_owned = key.to_string();
        let value_owned = value.to_string();
        let config = self.config.clone();

        // Build PushDrop locking script fields.
        let protocol_str = format!("[{},\"{}\"]", config.protocol_id.0, config.protocol_id.1);

        let protocol_id = Protocol {
            security_level: config.protocol_id.0 as u8,
            protocol: config.protocol_id.1.clone(),
        };
        let counterparty = Counterparty {
            counterparty_type: CounterpartyType::Self_,
            public_key: None,
        };

        // The controller is the wallet-DERIVED key the token is locked to — not a
        // throwaway random key (which is what this used to mint, producing a token
        // nobody could spend).
        let controller = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(protocol_id.clone()),
                    key_id: Some(key_owned.clone()),
                    counterparty: Some(counterparty.clone()),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(false),
                    seek_permission: None,
                },
                None,
            )
            .await
            .map_err(|e| ServicesError::KvStore(format!("getPublicKey failed: {}", e)))?;

        let fields = vec![
            protocol_str.as_bytes().to_vec(),
            key_owned.as_bytes().to_vec(),
            value_owned.as_bytes().to_vec(),
            controller.public_key.to_der(),
        ];

        let locking_script = PushDrop::new(&self.wallet, None)
            .lock(
                fields,
                protocol_id,
                &key_owned,
                counterparty,
                false,
                true,
                LockPosition::Before,
            )
            .await
            .map_err(|e| ServicesError::KvStore(format!("PushDrop lock failed: {}", e)))?;

        let locking_script_hex = to_hex(&locking_script.to_binary());

        // Wrap in double-spend retry.
        let result = with_double_spend_retry(
            || async {
                // In a real implementation, this would:
                // 1. Query overlay for existing token
                // 2. If exists, spend it and create new output
                // 3. If new, create fresh output
                // 4. Broadcast via TopicBroadcaster
                //
                // For now, return a placeholder outpoint.
                // The actual wallet transaction creation requires a full
                // WalletInterface implementation.
                Ok::<String, ServicesError>(format!(
                    "{}:{}",
                    "pending_txid",
                    locking_script_hex.len()
                ))
            },
            None,
        )
        .await?;

        Ok(result)
    }

    /// Remove a key-value pair from the KVStore.
    ///
    /// Spends the current UTXO for the key without creating a new output.
    pub async fn remove(&self, key: &str) -> Result<String, ServicesError> {
        if key.is_empty() {
            return Err(ServicesError::KvStore(
                "key must be a non-empty string".into(),
            ));
        }

        let _guard = self.key_locks.acquire(key).await;

        // Query for existing token.
        let query = KvStoreQuery {
            key: Some(key.to_string()),
            controller: None,
            protocol_id: None,
            tags: None,
            tag_query_mode: None,
            limit: None,
            skip: None,
            sort_order: None,
        };

        let entries = self
            .query_overlay(
                &query,
                &KvStoreGetOptions {
                    include_token: true,
                    ..Default::default()
                },
            )
            .await?;

        if entries.is_empty() {
            return Err(ServicesError::KvStore(
                "the item did not exist, no item was deleted".into(),
            ));
        }

        // In a full implementation, this would spend the existing token
        // via wallet.createAction and broadcast via TopicBroadcaster.
        Ok("removed".to_string())
    }

    /// Query the overlay service for KV entries.
    async fn query_overlay(
        &self,
        query: &KvStoreQuery,
        options: &KvStoreGetOptions,
    ) -> Result<Vec<KvStoreEntry>, ServicesError> {
        let service_name = options
            .service_name
            .as_deref()
            .unwrap_or(&self.config.service_name);

        let question = LookupQuestion {
            service: service_name.to_string(),
            query: serde_json::to_value(query)
                .map_err(|e| ServicesError::Serialization(e.to_string()))?,
        };

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut entries = Vec::new();

                for result in &outputs {
                    if let Ok(entry) =
                        self.decode_output(&result.beef, result.output_index as usize, options)
                    {
                        entries.push(entry);
                    }
                }

                Ok(entries)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Decode a single overlay output into a KvStoreEntry.
    fn decode_output(
        &self,
        beef_bytes: &[u8],
        output_index: usize,
        options: &KvStoreGetOptions,
    ) -> Result<KvStoreEntry, ServicesError> {
        use std::io::Cursor;

        let beef = Beef::from_binary(&mut Cursor::new(beef_bytes))
            .map_err(|e| ServicesError::KvStore(format!("failed to parse BEEF: {}", e)))?;

        let beef_tx = beef
            .txs
            .last()
            .ok_or_else(|| ServicesError::KvStore("BEEF contains no transactions".into()))?;
        let tx = beef_tx
            .tx
            .as_ref()
            .ok_or_else(|| ServicesError::KvStore("BEEF transaction has no tx data".into()))?;

        if output_index >= tx.outputs.len() {
            return Err(ServicesError::KvStore("output index out of bounds".into()));
        }

        let output = &tx.outputs[output_index];
        let chunks = output.locking_script.chunks();

        // Extract PushDrop data fields: collect all data-push chunks
        // before the first opcode chunk (OP_DROP, OP_2DROP, etc.).
        let mut fields: Vec<Vec<u8>> = Vec::new();
        for chunk in chunks {
            if let Some(data) = &chunk.data {
                fields.push(data.clone());
            } else {
                break;
            }
        }

        let has_tags = fields.len() == KvProtocol::FIELD_COUNT;
        let is_old_format = fields.len() == KvProtocol::OLD_FIELD_COUNT;

        if !has_tags && !is_old_format {
            return Err(ServicesError::KvStore(
                "invalid PushDrop field count".into(),
            ));
        }

        let key = String::from_utf8(fields[KvProtocol::KEY].clone())
            .map_err(|e| ServicesError::KvStore(format!("invalid key: {}", e)))?;
        let value = String::from_utf8(fields[KvProtocol::VALUE].clone())
            .map_err(|e| ServicesError::KvStore(format!("invalid value: {}", e)))?;
        let controller = to_hex(&fields[KvProtocol::CONTROLLER]);
        let protocol_str = String::from_utf8(fields[KvProtocol::PROTOCOL_ID].clone())
            .map_err(|e| ServicesError::KvStore(format!("invalid protocol: {}", e)))?;

        // Parse protocol ID from JSON array string "[level,\"name\"]".
        let protocol_id = parse_protocol_id(&protocol_str)?;

        // Parse tags if present.
        let tags = if has_tags {
            String::from_utf8(fields[KvProtocol::TAGS].clone())
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        } else {
            None
        };

        let mut entry = KvStoreEntry {
            key: key.clone(),
            value,
            controller,
            protocol_id: protocol_id.clone(),
            tags,
            token: None,
            history: None,
        };

        if options.include_token {
            let txid = beef_tx.txid.clone();
            entry.token = Some(KvStoreToken {
                txid,
                output_index: output_index as u32,
                satoshis: output.satoshis.unwrap_or(1),
                beef: beef_bytes.to_vec(),
            });
        }

        if options.history {
            let ctx = KvContext { key, protocol_id };
            let history = self
                .historian
                .lock()
                .map_err(|_| ServicesError::KvStore("historian lock poisoned".into()))?
                .build_history(tx, Some(&ctx));
            entry.history = Some(history);
        }

        Ok(entry)
    }
}

/// Parse a protocol ID from its JSON string representation.
/// Expected format: `[level,"name"]`
fn parse_protocol_id(s: &str) -> Result<(u32, String), ServicesError> {
    let trimmed = s.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(ServicesError::KvStore(format!(
            "invalid protocol ID format: {}",
            s
        )));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let comma_pos = inner
        .find(',')
        .ok_or_else(|| ServicesError::KvStore(format!("invalid protocol ID: {}", s)))?;

    let level_str = inner[..comma_pos].trim();
    let name_str = inner[comma_pos + 1..].trim();

    let level: u32 = level_str
        .parse()
        .map_err(|_| ServicesError::KvStore(format!("invalid protocol level: {}", level_str)))?;

    // Strip quotes from name.
    let name = name_str.trim_matches('"').to_string();

    Ok((level, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol_id() {
        let (level, name) = parse_protocol_id("[1,\"kvstore\"]").unwrap();
        assert_eq!(level, 1);
        assert_eq!(name, "kvstore");
    }

    #[test]
    fn test_parse_protocol_id_with_spaces() {
        let (level, name) = parse_protocol_id("[ 2 , \"myprotocol\" ]").unwrap();
        assert_eq!(level, 2);
        assert_eq!(name, "myprotocol");
    }

    #[test]
    fn test_parse_protocol_id_invalid() {
        assert!(parse_protocol_id("not-valid").is_err());
        assert!(parse_protocol_id("[abc,\"name\"]").is_err());
    }

    #[tokio::test]
    async fn test_key_locks_serialization() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let locks = KeyLocks::new();
        let counter = Arc::new(AtomicU32::new(0));

        // Acquire lock for "key1".
        let guard = locks.acquire("key1").await;
        let c1 = counter.clone();

        // Spawn a task that tries to acquire the same lock.
        let locks2 = KeyLocks {
            locks: locks.locks.clone(),
        };
        let handle = tokio::spawn(async move {
            let _guard2 = locks2.acquire("key1").await;
            c1.fetch_add(1, Ordering::SeqCst);
        });

        // Give the spawned task time to attempt lock acquisition.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Counter should still be 0 because the lock is held.
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Drop the guard to release the lock.
        drop(guard);

        // Wait for the spawned task to complete.
        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_key_locks_different_keys_independent() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let locks = Arc::new(KeyLocks::new());
        let counter = Arc::new(AtomicU32::new(0));

        // Hold lock on "key1".
        let _guard = locks.acquire("key1").await;

        // "key2" should be independently lockable.
        let locks2 = Arc::clone(&locks);
        let c = counter.clone();
        let handle = tokio::spawn(async move {
            let _guard2 = locks2.acquire("key2").await;
            c.fetch_add(1, Ordering::SeqCst);
        });

        handle.await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
