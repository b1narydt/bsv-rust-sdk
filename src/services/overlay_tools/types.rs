//! Shared types for overlay tools.
//!
//! Translates the TS SDK overlay-tools types: LookupQuestion, LookupAnswer,
//! TaggedBEEF, STEAK, Network presets, and configuration structs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network presets for overlay service discovery.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Network {
    /// BSV mainnet with production SLAP trackers.
    #[default]
    Mainnet,
    /// BSV testnet with testnet SLAP trackers.
    Testnet,
    /// Local development (localhost:8080).
    Local,
    /// Custom tracker URLs.
    Custom(Vec<String>),
}

impl Network {
    /// Returns the default SLAP tracker URLs for this network preset.
    pub fn default_slap_trackers(&self) -> Vec<String> {
        match self {
            Network::Mainnet => vec![
                "https://overlay-us-1.bsvb.tech".into(),
                "https://overlay-eu-1.bsvb.tech".into(),
                "https://overlay-ap-1.bsvb.tech".into(),
                "https://users.bapp.dev".into(),
            ],
            Network::Testnet => vec!["https://testnet-users.bapp.dev".into()],
            Network::Local => vec!["http://localhost:8080".into()],
            Network::Custom(trackers) => trackers.clone(),
        }
    }
}

/// A question posed to the overlay services engine for lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupQuestion {
    /// The identifier for the lookup service to query.
    pub service: String,
    /// The query payload, whose shape depends on the lookup service.
    pub query: serde_json::Value,
}

/// An individual output entry in a lookup answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupOutputEntry {
    /// BEEF-encoded transaction bytes.
    pub beef: Vec<u8>,
    /// The output index within the transaction.
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    /// Optional context bytes associated with this output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u8>>,
}

/// Response from a lookup query.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LookupAnswer {
    /// A list of UTXO outputs matching the query.
    #[serde(rename = "output-list")]
    OutputList { outputs: Vec<LookupOutputEntry> },
    /// A freeform result from the lookup service.
    #[serde(rename = "freeform")]
    FreeformResult { result: serde_json::Value },
}

/// Tagged BEEF structure for broadcasting to overlay topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedBEEF {
    /// BEEF-encoded transaction bytes.
    pub beef: Vec<u8>,
    /// Overlay topics for this transaction.
    pub topics: Vec<String>,
    /// Optional off-chain payload appended to the request body after a
    /// `varint(beef.len())` length prefix when present, and signaled by the
    /// `x-includes-off-chain-values: true` header. Mirrors TS
    /// `TaggedBEEF.offChainValues` (`SHIPBroadcaster.ts:17-21,100-110`).
    /// `Some(vec![])` is distinct from `None`: an empty `Vec` still emits
    /// the header + length prefix (matches TS `Array.isArray` truthiness).
    #[serde(rename = "offChainValues", skip_serializing_if = "Option::is_none")]
    pub off_chain_values: Option<Vec<u8>>,
}

/// Admittance instructions from a topic manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittanceInstructions {
    /// Indices of outputs admitted into the managed topic.
    #[serde(rename = "outputsToAdmit")]
    pub outputs_to_admit: Vec<u32>,
    /// Indices of inputs whose spent outputs should be retained.
    #[serde(rename = "coinsToRetain")]
    pub coins_to_retain: Vec<u32>,
    /// Indices of inputs whose previously-admitted outputs were removed.
    #[serde(rename = "coinsRemoved", skip_serializing_if = "Option::is_none")]
    pub coins_removed: Option<Vec<u32>>,
}

/// Submitted Transaction Execution AcKnowledgment (STEAK).
///
/// Maps topic names to admittance instructions.
pub type STEAK = HashMap<String, AdmittanceInstructions>;

/// Topic-set selector for an [`AckPolicy`] field. Mirrors the TS shape
/// `'all' | 'any' | string[]` used by all three SHIPBroadcaster ack fields.
///
/// - [`AckTopics::All`] resolves to "every configured topic"; the caller's
///   `mode` (All / Any) further decides whether each evaluated host must
///   ack every topic or just one.
/// - [`AckTopics::Any`] resolves to "every configured topic" with mode
///   forced to `Any` (host needs ≥1 ack out of all).
/// - [`AckTopics::List`] resolves to the named topics with mode forced to
///   `All` — matches TS `SHIPBroadcaster.ts:264-266,302-304,334-336` which
///   never honor `'any'` semantics for an explicit list.
#[derive(Debug, Clone, PartialEq)]
pub enum AckTopics {
    /// All configured topics; mode-dependent (All or Any).
    All,
    /// All configured topics with mode = Any.
    Any,
    /// Exactly the listed topics; mode forced to All.
    List(Vec<String>),
}

/// Compound acknowledgment policy. Mirrors the three independent fields on
/// the TS `SHIPBroadcasterConfig` (`SHIPBroadcaster.ts:67-71`).
///
/// Checks are evaluated in order (AllHosts → AnyHost → SpecificHosts);
/// any failure short-circuits with that field's distinct error code.
/// All three may be set simultaneously — the most restrictive wins.
#[derive(Debug, Clone, Default)]
pub struct AckPolicy {
    /// Every responding host must ack the chosen topic set under the
    /// chosen mode. Failure surfaces as `ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED`.
    pub require_from_all_hosts: Option<AckTopics>,
    /// At least one responding host must ack the chosen topic set under
    /// the chosen mode. TS default is `Some(AckTopics::All)` — see
    /// [`AckPolicy::default_any_host_all_topics`]. Failure surfaces as
    /// `ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED`.
    pub require_from_any_host: Option<AckTopics>,
    /// Per-host requirements: each named host must ack the per-host
    /// selector — and any named host that did not respond at all is
    /// itself a failure. Empty map = check skipped. Failure surfaces as
    /// `ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED`.
    pub require_from_specific_hosts: HashMap<String, AckTopics>,
}

impl AckPolicy {
    /// All policy slots empty — caller fires-and-forgets and never inspects
    /// host acks. Equivalent to TS setting all three fields to `[]`/`{}`.
    pub fn fire_and_forget() -> Self {
        Self::default()
    }

    /// TS canonical default (`SHIPBroadcaster.ts:160-161`): "at least one
    /// host must acknowledge every configured topic." Used by
    /// [`TopicBroadcasterConfig::default`].
    pub fn default_any_host_all_topics() -> Self {
        Self {
            require_from_all_hosts: None,
            require_from_any_host: Some(AckTopics::All),
            require_from_specific_hosts: HashMap::new(),
        }
    }
}

/// Acknowledgment mode for topic broadcasting.
///
/// Retained for backwards compatibility; new code should use [`AckPolicy`]
/// directly. Convertible via `From<AcknowledgmentMode> for AckPolicy`.
#[derive(Debug, Clone, PartialEq, Default)]
#[deprecated(
    since = "0.2.83",
    note = "Use AckPolicy for full TS parity (per-topic-subset and per-host variants)."
)]
pub enum AcknowledgmentMode {
    /// All hosts must acknowledge all topics.
    RequireFromAllHosts,
    /// At least one host must acknowledge all topics.
    #[default]
    RequireFromAny,
    /// Fire-and-forget; do not check acknowledgments.
    DoNotRequire,
}

#[allow(deprecated)]
impl From<AcknowledgmentMode> for AckPolicy {
    fn from(mode: AcknowledgmentMode) -> Self {
        match mode {
            AcknowledgmentMode::DoNotRequire => AckPolicy::fire_and_forget(),
            AcknowledgmentMode::RequireFromAny => AckPolicy::default_any_host_all_topics(),
            AcknowledgmentMode::RequireFromAllHosts => AckPolicy {
                require_from_all_hosts: Some(AckTopics::All),
                require_from_any_host: None,
                require_from_specific_hosts: HashMap::new(),
            },
        }
    }
}

/// Configuration for the LookupResolver.
#[derive(Debug, Clone)]
pub struct LookupResolverConfig {
    /// Network preset to use.
    pub network: Network,
    /// Custom SLAP tracker URLs (overrides network preset if set).
    pub slap_trackers: Option<Vec<String>>,
    /// Map of service names to override host URLs.
    pub host_overrides: HashMap<String, Vec<String>>,
    /// Map of service names to additional host URLs.
    pub additional_hosts: HashMap<String, Vec<String>>,
    /// Cache TTL in milliseconds (default 5 minutes).
    pub cache_ttl_ms: u64,
    /// Maximum number of cached host entries (default 128).
    pub cache_max_entries: usize,
}

impl Default for LookupResolverConfig {
    fn default() -> Self {
        LookupResolverConfig {
            network: Network::Mainnet,
            slap_trackers: None,
            host_overrides: HashMap::new(),
            additional_hosts: HashMap::new(),
            cache_ttl_ms: 5 * 60 * 1000, // 5 minutes
            cache_max_entries: 128,
        }
    }
}

/// Configuration for the TopicBroadcaster.
///
/// `ack_policy` is the canonical TS-parity surface (three independent fields
/// each accepting all/any/list). The legacy [`AcknowledgmentMode`] enum is
/// `#[deprecated]` but convertible into [`AckPolicy`] via `.into()` for
/// callers migrating from the old shape.
#[derive(Debug, Clone)]
pub struct TopicBroadcasterConfig {
    /// Network preset to use.
    pub network: Network,
    /// Compound acknowledgment policy (canonical surface).
    pub ack_policy: AckPolicy,
    /// Cache TTL for SHIP host discovery results. Mirrors TS
    /// `SHIPBroadcaster.ts:164` (5 minutes).
    pub interested_hosts_ttl_ms: u64,
}

impl Default for TopicBroadcasterConfig {
    fn default() -> Self {
        TopicBroadcasterConfig {
            network: Network::Mainnet,
            ack_policy: AckPolicy::default_any_host_all_topics(),
            interested_hosts_ttl_ms: 5 * 60 * 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mainnet_trackers() {
        let trackers = Network::Mainnet.default_slap_trackers();
        assert_eq!(trackers.len(), 4);
        assert!(trackers[0].contains("overlay-us-1"));
        assert!(trackers[1].contains("overlay-eu-1"));
        assert!(trackers[2].contains("overlay-ap-1"));
        assert!(trackers[3].contains("users.bapp.dev"));
    }

    #[test]
    fn test_network_testnet_trackers() {
        let trackers = Network::Testnet.default_slap_trackers();
        assert_eq!(trackers.len(), 1);
        assert!(trackers[0].contains("testnet-users.bapp.dev"));
    }

    #[test]
    fn test_network_local_trackers() {
        let trackers = Network::Local.default_slap_trackers();
        assert_eq!(trackers.len(), 1);
        assert_eq!(trackers[0], "http://localhost:8080");
    }

    #[test]
    fn test_network_custom_trackers() {
        let custom = vec!["https://my-tracker.example.com".to_string()];
        let trackers = Network::Custom(custom.clone()).default_slap_trackers();
        assert_eq!(trackers, custom);
    }

    #[test]
    fn test_default_network_is_mainnet() {
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    #[allow(deprecated)]
    fn test_default_acknowledgment_mode() {
        assert_eq!(
            AcknowledgmentMode::default(),
            AcknowledgmentMode::RequireFromAny
        );
    }

    #[test]
    fn test_default_topic_broadcaster_config_matches_ts_default() {
        // TS SHIPBroadcaster.ts:160-161 default: any-host acks all topics.
        let cfg = TopicBroadcasterConfig::default();
        assert!(cfg.ack_policy.require_from_all_hosts.is_none());
        assert_eq!(cfg.ack_policy.require_from_any_host, Some(AckTopics::All));
        assert!(cfg.ack_policy.require_from_specific_hosts.is_empty());
        assert_eq!(cfg.interested_hosts_ttl_ms, 5 * 60 * 1000);
    }

    #[test]
    #[allow(deprecated)]
    fn test_acknowledgment_mode_to_ack_policy_conversion() {
        // Backwards-compat shim preserves old enum semantics.
        let any: AckPolicy = AcknowledgmentMode::RequireFromAny.into();
        assert_eq!(any.require_from_any_host, Some(AckTopics::All));
        assert!(any.require_from_all_hosts.is_none());

        let all: AckPolicy = AcknowledgmentMode::RequireFromAllHosts.into();
        assert_eq!(all.require_from_all_hosts, Some(AckTopics::All));
        assert!(all.require_from_any_host.is_none());

        let none: AckPolicy = AcknowledgmentMode::DoNotRequire.into();
        assert!(none.require_from_all_hosts.is_none());
        assert!(none.require_from_any_host.is_none());
    }
}
