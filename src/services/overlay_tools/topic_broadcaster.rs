//! TopicBroadcaster for broadcasting transactions to overlay topics via SHIP.
//!
//! Translates the TS SDK SHIPBroadcaster.ts. Discovers interested hosts for
//! a set of topics, broadcasts tagged BEEF to each, and validates
//! acknowledgments per the configured mode.

use std::collections::{HashMap, HashSet};

use super::admin_token_template::OverlayAdminTokenTemplate;
use super::lookup_resolver::LookupResolver;
use super::types::{
    AcknowledgmentMode, LookupAnswer, LookupQuestion, Network, TaggedBEEF, TopicBroadcasterConfig,
    STEAK,
};
use crate::services::ServicesError;
use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::Transaction;

use async_trait::async_trait;

/// Maximum wait time for SHIP host discovery (ms).
const MAX_SHIP_QUERY_TIMEOUT_MS: u64 = 5000;

/// Broadcasts transactions to overlay service hosts via SHIP.
///
/// Discovers hosts interested in specific topics, broadcasts BEEF to each,
/// and validates acknowledgments according to the configured mode.
pub struct TopicBroadcaster {
    /// Topics to broadcast to.
    topics: Vec<String>,
    /// HTTP client (reused).
    client: reqwest::Client,
    /// Lookup resolver for SHIP host discovery.
    resolver: LookupResolver,
    /// Acknowledgment mode.
    ack_mode: AcknowledgmentMode,
    /// Network preset.
    network: Network,
    /// Whether to allow plain HTTP.
    allow_http: bool,
}

impl TopicBroadcaster {
    /// Create a new TopicBroadcaster for the given topics and configuration.
    ///
    /// Topics must start with "tm_" per overlay protocol.
    pub fn new(
        topics: Vec<String>,
        config: TopicBroadcasterConfig,
        resolver: LookupResolver,
    ) -> Result<Self, ServicesError> {
        if topics.is_empty() {
            return Err(ServicesError::Overlay(
                "At least one topic is required for broadcast".to_string(),
            ));
        }
        if topics.iter().any(|t| !t.starts_with("tm_")) {
            return Err(ServicesError::Overlay(
                "Every topic must start with \"tm_\"".to_string(),
            ));
        }
        let allow_http = config.network == Network::Local;
        Ok(TopicBroadcaster {
            topics,
            client: reqwest::Client::new(),
            resolver,
            ack_mode: config.acknowledgment_mode,
            network: config.network,
            allow_http,
        })
    }

    /// Find hosts interested in the configured topics via SHIP lookup.
    async fn find_interested_hosts(
        &self,
    ) -> Result<HashMap<String, HashSet<String>>, ServicesError> {
        if self.network == Network::Local {
            let mut result = HashMap::new();
            result.insert(
                "http://localhost:8080".to_string(),
                self.topics.iter().cloned().collect(),
            );
            return Ok(result);
        }

        let answer = self
            .resolver
            .query(
                &LookupQuestion {
                    service: "ls_ship".to_string(),
                    query: serde_json::json!({ "topics": self.topics }),
                },
                Some(MAX_SHIP_QUERY_TIMEOUT_MS),
            )
            .await?;

        let mut results: HashMap<String, HashSet<String>> = HashMap::new();

        if let LookupAnswer::OutputList { outputs } = answer {
            for output in &outputs {
                if let Ok(parsed) = OverlayAdminTokenTemplate::decode_from_beef(
                    &output.beef,
                    output.output_index as usize,
                ) {
                    if parsed.protocol == "SHIP" && self.topics.contains(&parsed.topic_or_service) {
                        results
                            .entry(parsed.domain)
                            .or_default()
                            .insert(parsed.topic_or_service);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Send tagged BEEF to a host and return the STEAK acknowledgment.
    async fn send_to_host(
        &self,
        host: &str,
        tagged_beef: &TaggedBEEF,
    ) -> Result<STEAK, ServicesError> {
        if !self.allow_http && !host.starts_with("https:") {
            return Err(ServicesError::Http(format!(
                "HTTPS required but host URL is: {}",
                host
            )));
        }

        let url = format!("{}/submit", host);
        let topics_json = serde_json::to_string(&tagged_beef.topics).map_err(|e| {
            ServicesError::Serialization(format!("failed to serialize X-Topics: {}", e))
        })?;
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Topics", topics_json)
            .body(tagged_beef.beef.clone())
            .send()
            .await
            .map_err(|e| ServicesError::Http(e.to_string()))?;

        if response.status().is_success() {
            response
                .json::<STEAK>()
                .await
                .map_err(|e| ServicesError::Serialization(e.to_string()))
        } else {
            Err(ServicesError::Http(format!(
                "Broadcast failed: HTTP {}",
                response.status()
            )))
        }
    }

    /// Check acknowledgments against configured mode.
    fn check_acknowledgments(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<(), String> {
        match &self.ack_mode {
            AcknowledgmentMode::DoNotRequire => Ok(()),
            AcknowledgmentMode::RequireFromAny => {
                // At least one host must acknowledge all topics.
                for acked_topics in host_acks.values() {
                    if self.topics.iter().all(|t| acked_topics.contains(t)) {
                        return Ok(());
                    }
                }
                Err("No host acknowledged all required topics".to_string())
            }
            AcknowledgmentMode::RequireFromAllHosts => {
                // Every host must acknowledge all topics.
                for (host, acked_topics) in host_acks {
                    for topic in &self.topics {
                        if !acked_topics.contains(topic) {
                            return Err(format!(
                                "Host {} did not acknowledge topic {}",
                                host, topic
                            ));
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

impl TopicBroadcaster {
    /// Broadcast pre-built BEEF bytes to overlay services via SHIP.
    ///
    /// Use this when you already have valid BEEF bytes (e.g. from `create_action`
    /// or `sign_action`) and want to avoid the `Transaction → to_beef()` round-trip.
    /// The `txid` parameter is used in the success response.
    pub async fn broadcast_beef(
        &self,
        beef: Vec<u8>,
    ) -> Result<BroadcastResponse, BroadcastFailure> {
        // Parse the BEEF to extract the txid for the response.
        let beef_hex: String = beef.iter().map(|b| format!("{:02x}", b)).collect();
        let tx = Transaction::from_beef(&beef_hex).map_err(|e| BroadcastFailure {
            status: 0,
            code: "ERR_BEEF_PARSE".to_string(),
            description: format!("Failed to parse BEEF: {}", e),
        })?;
        let txid = tx.id().map_err(|e| BroadcastFailure {
            status: 0,
            code: "ERR_TXID_COMPUTE".to_string(),
            description: format!("Failed to compute txid from BEEF: {}", e),
        })?;

        self.broadcast_beef_inner(beef, txid).await
    }

    /// Shared broadcast implementation that sends BEEF bytes to interested hosts.
    async fn broadcast_beef_inner(
        &self,
        beef: Vec<u8>,
        txid: String,
    ) -> Result<BroadcastResponse, BroadcastFailure> {
        let interested_hosts =
            self.find_interested_hosts()
                .await
                .map_err(|e| BroadcastFailure {
                    status: 0,
                    code: "ERR_HOST_DISCOVERY".to_string(),
                    description: e.to_string(),
                })?;

        if interested_hosts.is_empty() {
            return Err(BroadcastFailure {
                status: 0,
                code: "ERR_NO_HOSTS_INTERESTED".to_string(),
                description: format!(
                    "No {:?} hosts are interested in receiving this transaction",
                    self.network
                ),
            });
        }

        let mut host_acks: HashMap<String, HashSet<String>> = HashMap::new();
        let mut success_count = 0u32;
        let mut host_errors: Vec<(String, String)> = Vec::new();

        for (host, topics) in &interested_hosts {
            let tagged_beef = TaggedBEEF {
                beef: beef.clone(),
                topics: topics.iter().cloned().collect(),
            };

            match self.send_to_host(host, &tagged_beef).await {
                Ok(steak) => {
                    let mut acked_topics = HashSet::new();
                    for (topic, instructions) in &steak {
                        let has_activity = !instructions.outputs_to_admit.is_empty()
                            || !instructions.coins_to_retain.is_empty()
                            || instructions
                                .coins_removed
                                .as_ref()
                                .map(|v| !v.is_empty())
                                .unwrap_or(false);
                        if has_activity {
                            acked_topics.insert(topic.clone());
                        }
                    }
                    host_acks.insert(host.clone(), acked_topics);
                    success_count += 1;
                }
                Err(e) => {
                    host_errors.push((host.clone(), e.to_string()));
                    continue;
                }
            }
        }

        if success_count == 0 {
            let details = host_errors
                .iter()
                .map(|(h, e)| format!("{}: {}", h, e))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(BroadcastFailure {
                status: 0,
                code: "ERR_ALL_HOSTS_REJECTED".to_string(),
                description: if details.is_empty() {
                    "All topical hosts have rejected the transaction".to_string()
                } else {
                    format!(
                        "All topical hosts have rejected the transaction. Details: {}",
                        details
                    )
                },
            });
        }

        // Check acknowledgments.
        if let Err(reason) = self.check_acknowledgments(&host_acks) {
            return Err(BroadcastFailure {
                status: 0,
                code: "ERR_ACKNOWLEDGMENT_FAILED".to_string(),
                description: reason,
            });
        }

        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid,
            message: format!(
                "Sent to {} Overlay Services {}",
                success_count,
                if success_count == 1 { "host" } else { "hosts" }
            ),
        })
    }
}

#[async_trait]
impl Broadcaster for TopicBroadcaster {
    /// Broadcast a transaction to overlay services via SHIP.
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let beef = tx.to_beef().map_err(|e| BroadcastFailure {
            status: 0,
            code: "ERR_BEEF_SERIALIZE".to_string(),
            description: format!("Transaction must be serializable to BEEF: {}", e),
        })?;

        let txid = tx.id().map_err(|e| BroadcastFailure {
            status: 0,
            code: "ERR_TXID_COMPUTE".to_string(),
            description: format!("Failed to compute txid: {}", e),
        })?;

        self.broadcast_beef_inner(beef, txid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topics_must_start_with_tm() {
        let resolver = LookupResolver::for_network(Network::Local);
        let result = TopicBroadcaster::new(
            vec!["invalid_topic".to_string()],
            TopicBroadcasterConfig::default(),
            resolver,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_topics_rejected() {
        let resolver = LookupResolver::for_network(Network::Local);
        let result = TopicBroadcaster::new(vec![], TopicBroadcasterConfig::default(), resolver);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_topics_accepted() {
        let resolver = LookupResolver::for_network(Network::Local);
        let result = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig::default(),
            resolver,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ack_do_not_require_always_passes() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                acknowledgment_mode: AcknowledgmentMode::DoNotRequire,
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let empty_acks = HashMap::new();
        assert!(broadcaster.check_acknowledgments(&empty_acks).is_ok());
    }

    #[test]
    fn test_ack_require_from_any_passes_with_one() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                acknowledgment_mode: AcknowledgmentMode::RequireFromAny,
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let mut acks = HashMap::new();
        let mut topics = HashSet::new();
        topics.insert("tm_test".to_string());
        acks.insert("host1".to_string(), topics);
        assert!(broadcaster.check_acknowledgments(&acks).is_ok());
    }

    #[test]
    fn test_ack_require_from_any_fails_with_none() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                acknowledgment_mode: AcknowledgmentMode::RequireFromAny,
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let acks = HashMap::new();
        assert!(broadcaster.check_acknowledgments(&acks).is_err());
    }

    #[test]
    fn test_ack_require_from_all_passes() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                acknowledgment_mode: AcknowledgmentMode::RequireFromAllHosts,
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let mut acks = HashMap::new();
        let mut topics1 = HashSet::new();
        topics1.insert("tm_test".to_string());
        let mut topics2 = HashSet::new();
        topics2.insert("tm_test".to_string());
        acks.insert("host1".to_string(), topics1);
        acks.insert("host2".to_string(), topics2);
        assert!(broadcaster.check_acknowledgments(&acks).is_ok());
    }

    #[test]
    fn test_ack_require_from_all_fails_missing_topic() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                acknowledgment_mode: AcknowledgmentMode::RequireFromAllHosts,
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let mut acks = HashMap::new();
        let topics1 = HashSet::new(); // Empty -- no ack
        acks.insert("host1".to_string(), topics1);
        assert!(broadcaster.check_acknowledgments(&acks).is_err());
    }
}
