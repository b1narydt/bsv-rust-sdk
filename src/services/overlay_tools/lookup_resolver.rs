//! LookupResolver for querying overlay services via SLAP trackers.
//!
//! Translates the TS SDK LookupResolver.ts. Discovers competent hosts for a
//! given lookup service via SLAP tracker queries, caches results with TTL,
//! and tracks host reputation for intelligent ranking.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use super::admin_token_template::OverlayAdminTokenTemplate;
use super::host_reputation::HostReputationTracker;
use super::types::{
    LookupAnswer, LookupOutputEntry, LookupQuestion, LookupResolverConfig, Network,
};
use crate::services::ServicesError;

/// Maximum wait time for SLAP tracker queries (ms).
const MAX_TRACKER_WAIT_TIME_MS: u64 = 5000;
/// Default request timeout (ms).
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Cached host list entry with expiration.
#[derive(Debug, Clone)]
struct HostsCacheEntry {
    hosts: Vec<String>,
    expires_at: Instant,
}

/// Resolves lookup questions against overlay service hosts.
///
/// Discovers competent hosts via SLAP trackers, caches results,
/// and ranks hosts by reputation for reliable queries.
pub struct LookupResolver {
    /// HTTP client (reused across requests).
    client: reqwest::Client,
    /// Network preset.
    network: Network,
    /// SLAP tracker URLs.
    slap_trackers: Vec<String>,
    /// Service-to-hosts overrides.
    host_overrides: HashMap<String, Vec<String>>,
    /// Additional hosts per service.
    additional_hosts: HashMap<String, Vec<String>>,
    /// Host reputation tracker.
    reputation: Arc<RwLock<HostReputationTracker>>,
    /// Hosts cache with TTL.
    hosts_cache: Arc<RwLock<HashMap<String, HostsCacheEntry>>>,
    /// Cache TTL duration.
    cache_ttl: std::time::Duration,
    /// Maximum cache entries.
    cache_max_entries: usize,
    /// Whether to allow plain HTTP (for local development).
    allow_http: bool,
}

impl LookupResolver {
    /// Create a new LookupResolver with the given configuration.
    pub fn new(config: LookupResolverConfig) -> Self {
        let slap_trackers = config
            .slap_trackers
            .unwrap_or_else(|| config.network.default_slap_trackers());
        let allow_http = config.network == Network::Local;

        LookupResolver {
            client: reqwest::Client::new(),
            network: config.network,
            slap_trackers,
            host_overrides: config.host_overrides,
            additional_hosts: config.additional_hosts,
            reputation: Arc::new(RwLock::new(HostReputationTracker::new())),
            hosts_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: std::time::Duration::from_millis(config.cache_ttl_ms),
            cache_max_entries: config.cache_max_entries,
            allow_http,
        }
    }

    /// Create a LookupResolver with default configuration for the given network.
    pub fn for_network(network: Network) -> Self {
        Self::new(LookupResolverConfig {
            network,
            ..Default::default()
        })
    }

    /// Query the overlay network for a lookup answer.
    ///
    /// Discovers competent hosts, queries them in reputation order,
    /// and aggregates results with deduplication.
    pub async fn query(
        &self,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer, ServicesError> {
        let timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let mut competent_hosts = self.resolve_hosts(&question.service).await?;

        // Add additional hosts.
        if let Some(extra) = self.additional_hosts.get(&question.service) {
            for h in extra {
                if !competent_hosts.contains(h) {
                    competent_hosts.push(h.clone());
                }
            }
        }

        if competent_hosts.is_empty() {
            return Err(ServicesError::Overlay(format!(
                "No competent hosts found for lookup service: {}",
                question.service
            )));
        }

        // Rank hosts by reputation and filter out those in backoff.
        let now_ms = current_time_ms();
        let available_hosts = {
            let mut rep = self.reputation.write().await;
            let ranked = rep.rank_hosts(&competent_hosts, now_ms);
            let available: Vec<String> = ranked
                .into_iter()
                .filter(|rh| rh.backoff_until <= now_ms)
                .map(|rh| rh.host)
                .collect();
            available
        };

        if available_hosts.is_empty() {
            return Err(ServicesError::Overlay(format!(
                "All hosts for {} are temporarily unavailable due to backoff",
                question.service
            )));
        }

        // Query hosts concurrently and collect results.
        let mut outputs_map: HashMap<String, LookupOutputEntry> = HashMap::new();
        let mut any_success = false;

        for host in &available_hosts {
            match self
                .lookup_host_with_tracking(host, question, timeout)
                .await
            {
                Ok(LookupAnswer::OutputList { outputs }) => {
                    any_success = true;
                    for output in outputs {
                        let key = format!("{}.{}", hex_encode(&output.beef), output.output_index);
                        outputs_map.entry(key).or_insert(output);
                    }
                }
                Ok(LookupAnswer::FreeformResult { result }) => {
                    // Return freeform immediately.
                    return Ok(LookupAnswer::FreeformResult { result });
                }
                Err(_) => {
                    // Host failed; tracked by lookup_host_with_tracking.
                    continue;
                }
            }
        }

        if !any_success && outputs_map.is_empty() {
            return Err(ServicesError::Overlay(format!(
                "All hosts failed for lookup service: {}",
                question.service
            )));
        }

        Ok(LookupAnswer::OutputList {
            outputs: outputs_map.into_values().collect(),
        })
    }

    /// Resolve competent hosts for a service.
    async fn resolve_hosts(&self, service: &str) -> Result<Vec<String>, ServicesError> {
        // SHIP and SLAP service queries go directly to the trackers: they ARE
        // the bootstrap oracles (TS `LookupResolver` resolves both against its
        // tracker set). Routing `ls_ship` through SLAP discovery instead asks
        // the network who hosts it — on mainnet that returns a single
        // third-party registration, and every SHIP host-discovery (so every
        // TopicBroadcaster submit) then lives or dies on that one stranger's
        // uptime. Observed live 2026-08-19: the sole discovered host answered
        // HTTP 500 and every broadcast failed with "All hosts failed for
        // lookup service: ls_ship" while all four trackers served `ls_ship`
        // correctly the whole time.
        if service == "ls_slap" || service == "ls_ship" {
            return Ok(if self.network == Network::Local {
                vec!["http://localhost:8080".to_string()]
            } else {
                self.slap_trackers.clone()
            });
        }

        // Check overrides.
        if let Some(overrides) = self.host_overrides.get(service) {
            return Ok(overrides.clone());
        }

        // Local mode goes directly to localhost.
        if self.network == Network::Local {
            return Ok(vec!["http://localhost:8080".to_string()]);
        }

        // Check cache.
        {
            let cache = self.hosts_cache.read().await;
            if let Some(entry) = cache.get(service) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.hosts.clone());
                }
            }
        }

        // Discover via SLAP trackers.
        let hosts = self.find_competent_hosts(service).await?;

        // Update cache.
        {
            let mut cache = self.hosts_cache.write().await;
            // Bounded cache with FIFO eviction.
            if !cache.contains_key(service) && cache.len() >= self.cache_max_entries {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(
                service.to_string(),
                HostsCacheEntry {
                    hosts: hosts.clone(),
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }

        Ok(hosts)
    }

    /// Discover competent hosts for a service via SLAP trackers.
    async fn find_competent_hosts(&self, service: &str) -> Result<Vec<String>, ServicesError> {
        let query = LookupQuestion {
            service: "ls_slap".to_string(),
            query: serde_json::json!({ "service": service }),
        };

        let mut all_hosts = Vec::new();

        for tracker in &self.slap_trackers {
            match self
                .lookup_host_with_tracking(tracker, &query, MAX_TRACKER_WAIT_TIME_MS)
                .await
            {
                Ok(answer) => {
                    let hosts = self.extract_hosts_from_answer(&answer, service);
                    for h in hosts {
                        if !all_hosts.contains(&h) {
                            all_hosts.push(h);
                        }
                    }
                    if !all_hosts.is_empty() {
                        // Resolve as soon as we have hosts from any tracker.
                        return Ok(all_hosts);
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(all_hosts)
    }

    /// Extract host domains from a SLAP tracker answer.
    fn extract_hosts_from_answer(&self, answer: &LookupAnswer, service: &str) -> Vec<String> {
        let mut hosts = Vec::new();
        if let LookupAnswer::OutputList { outputs } = answer {
            for output in outputs {
                if let Ok(parsed) = OverlayAdminTokenTemplate::decode_from_beef(
                    &output.beef,
                    output.output_index as usize,
                ) {
                    if parsed.protocol == "SLAP"
                        && parsed.topic_or_service == service
                        && !parsed.domain.is_empty()
                    {
                        hosts.push(parsed.domain);
                    }
                }
            }
        }
        hosts
    }

    /// Perform a lookup request to a single host, tracking reputation.
    async fn lookup_host_with_tracking(
        &self,
        host: &str,
        question: &LookupQuestion,
        timeout_ms: u64,
    ) -> Result<LookupAnswer, ServicesError> {
        // Validate URL scheme.
        if !self.allow_http && !host.starts_with("https:") {
            return Err(ServicesError::Http(format!(
                "HTTPS required but host URL is: {}",
                host
            )));
        }

        let url = format!("{}/lookup", host);
        let started_at = Instant::now();

        let result = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Aggregation", "yes")
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .json(&serde_json::json!({
                "service": question.service,
                "query": question.query,
            }))
            .send()
            .await;

        let latency_ms = started_at.elapsed().as_millis() as f64;

        match result {
            Ok(response) => {
                if !response.status().is_success() {
                    let mut rep = self.reputation.write().await;
                    rep.record_failure(host, Some(&format!("HTTP {}", response.status().as_u16())));
                    return Err(ServicesError::Http(format!(
                        "Lookup failed: HTTP {}",
                        response.status()
                    )));
                }

                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let answer = if content_type == "application/octet-stream" {
                    let bytes = response
                        .bytes()
                        .await
                        .map_err(|e| ServicesError::Http(e.to_string()))?;
                    self.parse_binary_response(&bytes)?
                } else {
                    response
                        .json::<LookupAnswer>()
                        .await
                        .map_err(|e| ServicesError::Serialization(e.to_string()))?
                };

                // Record success.
                let is_valid =
                    matches!(&answer, LookupAnswer::OutputList { outputs } if !outputs.is_empty());
                let mut rep = self.reputation.write().await;
                if is_valid {
                    rep.record_success(host, latency_ms);
                } else {
                    rep.record_failure(host, Some("Invalid lookup response"));
                }

                Ok(answer)
            }
            Err(e) => {
                let mut rep = self.reputation.write().await;
                rep.record_failure(host, Some(&e.to_string()));
                Err(ServicesError::Http(e.to_string()))
            }
        }
    }

    /// Parse a binary overlay response (application/octet-stream).
    ///
    /// Format: varint(count) [32-byte txid, varint(outputIndex), varint(contextLen), context...]* [BEEF]
    fn parse_binary_response(&self, data: &[u8]) -> Result<LookupAnswer, ServicesError> {
        let mut pos = 0;
        let n_outpoints = read_varint(data, &mut pos)?;

        let mut outpoints = Vec::new();
        for _ in 0..n_outpoints {
            if pos + 32 > data.len() {
                return Err(ServicesError::Serialization(
                    "binary response: truncated txid".to_string(),
                ));
            }
            let txid = hex_encode(&data[pos..pos + 32]);
            pos += 32;

            let output_index = read_varint(data, &mut pos)? as u32;
            let context_length = read_varint(data, &mut pos)?;
            let context = if context_length > 0 {
                if pos + context_length > data.len() {
                    return Err(ServicesError::Serialization(
                        "binary response: truncated context".to_string(),
                    ));
                }
                let ctx = data[pos..pos + context_length].to_vec();
                pos += context_length;
                Some(ctx)
            } else {
                None
            };

            outpoints.push((txid, output_index, context));
        }

        // Remaining data is BEEF.
        let beef = if pos < data.len() {
            data[pos..].to_vec()
        } else {
            Vec::new()
        };

        let outputs = outpoints
            .into_iter()
            .map(|(_txid, output_index, context)| LookupOutputEntry {
                beef: beef.clone(),
                output_index,
                context,
            })
            .collect();

        Ok(LookupAnswer::OutputList { outputs })
    }
}

/// Read a varint from a byte slice at the given position.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<usize, ServicesError> {
    if *pos >= data.len() {
        return Err(ServicesError::Serialization(
            "varint: unexpected end of data".to_string(),
        ));
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        0..=0xfc => Ok(first as usize),
        0xfd => {
            if *pos + 2 > data.len() {
                return Err(ServicesError::Serialization(
                    "varint: truncated u16".to_string(),
                ));
            }
            let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            Ok(val)
        }
        0xfe => {
            if *pos + 4 > data.len() {
                return Err(ServicesError::Serialization(
                    "varint: truncated u32".to_string(),
                ));
            }
            let val =
                u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                    as usize;
            *pos += 4;
            Ok(val)
        }
        0xff => {
            if *pos + 8 > data.len() {
                return Err(ServicesError::Serialization(
                    "varint: truncated u64".to_string(),
                ));
            }
            let val = u64::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]) as usize;
            *pos += 8;
            Ok(val)
        }
    }
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Get current time in milliseconds.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint_single_byte() {
        let data = [0x42];
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos).unwrap(), 0x42);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_read_varint_two_byte() {
        let data = [0xfd, 0x00, 0x01];
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos).unwrap(), 256);
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_parse_binary_response_empty() {
        let resolver = LookupResolver::for_network(Network::Local);
        let data = [0x00]; // 0 outpoints, no beef
        let answer = resolver.parse_binary_response(&data).unwrap();
        match answer {
            LookupAnswer::OutputList { outputs } => assert!(outputs.is_empty()),
            _ => panic!("expected OutputList"),
        }
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
    }

    #[test]
    fn test_default_config() {
        let config = LookupResolverConfig::default();
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.cache_ttl_ms, 300_000);
        assert_eq!(config.cache_max_entries, 128);
    }

    /// SHIP and SLAP both bootstrap at the trackers. Routing `ls_ship`
    /// through SLAP discovery makes every TopicBroadcaster submit depend on
    /// whatever single host happens to hold the network's `ls_ship`
    /// registration (observed live: one third-party host, answering 500).
    #[tokio::test]
    async fn ship_and_slap_resolve_to_the_trackers_not_slap_discovery() {
        let resolver = LookupResolver::new(LookupResolverConfig {
            network: Network::Mainnet,
            ..Default::default()
        });
        let trackers = Network::Mainnet.default_slap_trackers();
        for service in ["ls_ship", "ls_slap"] {
            let hosts = resolver.resolve_hosts(service).await.unwrap();
            assert_eq!(hosts, trackers, "{service} must resolve to the trackers");
        }
    }
}
