//! KVStore types and constants.
//!
//! Translates the TS SDK kvstore/types.ts. Defines configuration, entry,
//! query, and protocol field index types for the key-value store modules.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Protocol field indices for PushDrop KVStore tokens.
///
/// These indices specify which PushDrop field holds each piece of data.
/// Matches the TS SDK kvProtocol constants.
pub struct KvProtocol;

impl KvProtocol {
    /// Index of the protocol ID field.
    pub const PROTOCOL_ID: usize = 0;
    /// Index of the key field.
    pub const KEY: usize = 1;
    /// Index of the value field.
    pub const VALUE: usize = 2;
    /// Index of the controller field.
    pub const CONTROLLER: usize = 3;
    /// Index of the tags field (optional, new format).
    pub const TAGS: usize = 4;
    /// Index of the signature field (position 5 when tags are present).
    pub const SIGNATURE: usize = 5;
    /// Total number of fields in the new format (with tags).
    pub const FIELD_COUNT: usize = 6;
    /// Total number of fields in the old format (without tags).
    pub const OLD_FIELD_COUNT: usize = 5;
}

/// Wallet protocol ID type: [security_level, protocol_name].
pub type WalletProtocol = (u32, String);

/// Configuration for GlobalKVStore operations.
#[derive(Debug, Clone)]
pub struct KvStoreConfig {
    /// Protocol ID for the KVStore protocol.
    pub protocol_id: WalletProtocol,
    /// Service name for overlay submission.
    pub service_name: String,
    /// Amount of satoshis for each token.
    pub token_amount: u64,
    /// Topics for overlay submission.
    pub topics: Vec<String>,
    /// Network preset for overlay services.
    pub network_preset: String,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: bool,
    /// Whether to let overlay handle broadcasting.
    pub overlay_broadcast: bool,
    /// Originator for wallet operations.
    pub originator: Option<String>,
    /// Description for token set.
    pub token_set_description: String,
    /// Description for token update.
    pub token_update_description: String,
    /// Description for token removal.
    pub token_removal_description: String,
}

impl Default for KvStoreConfig {
    fn default() -> Self {
        KvStoreConfig {
            protocol_id: (1, "kvstore".to_string()),
            service_name: "ls_kvstore".to_string(),
            token_amount: 1,
            topics: vec!["tm_kvstore".to_string()],
            network_preset: "mainnet".to_string(),
            accept_delayed_broadcast: false,
            overlay_broadcast: false,
            originator: None,
            token_set_description: String::new(),
            token_update_description: String::new(),
            token_removal_description: String::new(),
        }
    }
}

/// Query parameters for KVStore lookups from overlay services.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KvStoreQuery {
    /// Key to search for.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key: Option<String>,
    /// Controller public key (hex).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub controller: Option<String>,
    /// Protocol ID filter.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", rename = "protocolID")
    )]
    pub protocol_id: Option<WalletProtocol>,
    /// Tags to filter by.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub tags: Option<Vec<String>>,
    /// Tag query mode: "all" or "any".
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", rename = "tagQueryMode")
    )]
    pub tag_query_mode: Option<String>,
    /// Maximum number of results.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub limit: Option<u32>,
    /// Number of results to skip.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub skip: Option<u32>,
    /// Sort order: "asc" or "desc".
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Option::is_none", rename = "sortOrder")
    )]
    pub sort_order: Option<String>,
}

/// Options for KVStore get operations.
#[derive(Debug, Clone, Default)]
pub struct KvStoreGetOptions {
    /// Whether to build and include history for each entry.
    pub history: bool,
    /// Whether to include token transaction data in results.
    pub include_token: bool,
    /// Service name for overlay retrieval.
    pub service_name: Option<String>,
}

/// Options for KVStore set operations.
#[derive(Debug, Clone, Default)]
pub struct KvStoreSetOptions {
    /// Override protocol ID for this operation.
    pub protocol_id: Option<WalletProtocol>,
    /// Override description for token set.
    pub token_set_description: Option<String>,
    /// Override description for token update.
    pub token_update_description: Option<String>,
    /// Override token amount.
    pub token_amount: Option<u64>,
    /// Tags to attach.
    pub tags: Option<Vec<String>>,
}

/// Options for KVStore remove operations.
#[derive(Debug, Clone, Default)]
pub struct KvStoreRemoveOptions {
    /// Override protocol ID.
    pub protocol_id: Option<WalletProtocol>,
    /// Override description for token removal.
    pub token_removal_description: Option<String>,
}

/// A KVStore entry returned from queries.
#[derive(Debug, Clone)]
pub struct KvStoreEntry {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
    /// Controller public key (hex).
    pub controller: String,
    /// Protocol ID.
    pub protocol_id: WalletProtocol,
    /// Optional tags.
    pub tags: Option<Vec<String>>,
    /// Optional token data.
    pub token: Option<KvStoreToken>,
    /// Optional history of values.
    pub history: Option<Vec<String>>,
}

/// Token structure for a KVStore entry.
#[derive(Debug, Clone)]
pub struct KvStoreToken {
    /// Transaction ID.
    pub txid: String,
    /// Output index.
    pub output_index: u32,
    /// Satoshi amount.
    pub satoshis: u64,
    /// BEEF-encoded transaction data.
    pub beef: Vec<u8>,
}

/// Context passed to the Historian interpreter for KVStore operations.
#[derive(Debug, Clone)]
pub struct KvContext {
    /// The key to search for.
    pub key: String,
    /// The protocol ID.
    pub protocol_id: WalletProtocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KvStoreConfig::default();
        assert_eq!(config.protocol_id, (1, "kvstore".to_string()));
        assert_eq!(config.service_name, "ls_kvstore");
        assert_eq!(config.token_amount, 1);
        assert_eq!(config.topics, vec!["tm_kvstore"]);
        assert!(!config.accept_delayed_broadcast);
        assert!(!config.overlay_broadcast);
    }

    #[test]
    fn test_kv_protocol_indices() {
        assert_eq!(KvProtocol::PROTOCOL_ID, 0);
        assert_eq!(KvProtocol::KEY, 1);
        assert_eq!(KvProtocol::VALUE, 2);
        assert_eq!(KvProtocol::CONTROLLER, 3);
        assert_eq!(KvProtocol::TAGS, 4);
        assert_eq!(KvProtocol::SIGNATURE, 5);
        assert_eq!(KvProtocol::FIELD_COUNT, 6);
        assert_eq!(KvProtocol::OLD_FIELD_COUNT, 5);
    }

    #[test]
    fn test_kv_context_clone() {
        let ctx = KvContext {
            key: "mykey".to_string(),
            protocol_id: (1, "kvstore".to_string()),
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.key, "mykey");
        assert_eq!(cloned.protocol_id.0, 1);
    }

    #[test]
    fn test_kv_store_entry_clone() {
        let entry = KvStoreEntry {
            key: "k".to_string(),
            value: "v".to_string(),
            controller: "abc".to_string(),
            protocol_id: (1, "kvstore".to_string()),
            tags: Some(vec!["tag1".to_string()]),
            token: None,
            history: None,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.key, "k");
        assert_eq!(cloned.tags.unwrap()[0], "tag1");
    }
}
