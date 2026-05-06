//! TopicBroadcaster for broadcasting transactions to overlay topics via SHIP.
//!
//! Translates the TS SDK SHIPBroadcaster.ts. Discovers interested hosts for
//! a set of topics, broadcasts tagged BEEF to each, and validates
//! acknowledgments per the configured policy.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex};

use super::admin_token_template::OverlayAdminTokenTemplate;
use super::lookup_resolver::LookupResolver;
use super::types::{
    AckPolicy, AckTopics, LookupAnswer, LookupQuestion, Network, TaggedBEEF,
    TopicBroadcasterConfig, STEAK,
};
use crate::services::ServicesError;
use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::broadcasters::util::{classify_reqwest_err, MAX_BODY_PREVIEW_CHARS};
use crate::transaction::transaction::write_varint_to_vec;
use crate::transaction::Transaction;

use async_trait::async_trait;

/// Maximum wait time for SHIP host discovery (ms).
const MAX_SHIP_QUERY_TIMEOUT_MS: u64 = 5000;

/// Capacity of the in-flight broadcast channel. The channel only needs to
/// fan one message out to N concurrent followers; a small bound is fine.
const IN_FLIGHT_CHANNEL_CAPACITY: usize = 16;

/// Cached result of a SHIP host-discovery query, with absolute expiry time.
#[derive(Clone)]
struct InterestedHostsCacheEntry {
    hosts: HashMap<String, HashSet<String>>,
    expires_at: Instant,
}

/// Single-slot host-discovery cache. Mirrors TS SHIPBroadcaster's
/// `interestedHostsCache` + `interestedHostsInFlight` (`SHIPBroadcaster.ts:137-139`).
/// The cache is per-broadcaster-instance, valid only for the topic set the
/// broadcaster was constructed with.
/// Payload published by the in-flight SHIP-query leader.
///
/// `Err(String)` carries the leader's error message so concurrent followers
/// receive the actual cause (timeout / lookup-server 5xx / BEEF decode
/// failure) rather than just `RecvError::Closed`. `String` is used (not
/// `ServicesError`) because `broadcast::Sender` requires `Clone` on the
/// payload and `ServicesError` is not `Clone`.
type DiscoveryResult = Result<HashMap<String, HashSet<String>>, String>;

struct InterestedHostsCache {
    cached: Option<InterestedHostsCacheEntry>,
    /// Sender side of an in-flight SHIP query. While present, concurrent
    /// callers subscribe and await the leader's broadcast rather than
    /// firing duplicate queries (`SHIPBroadcaster.ts:478-489`).
    in_flight: Option<broadcast::Sender<DiscoveryResult>>,
}

impl InterestedHostsCache {
    fn new() -> Self {
        Self {
            cached: None,
            in_flight: None,
        }
    }
}

/// Broadcasts transactions to overlay service hosts via SHIP.
///
/// Discovers hosts interested in specific topics, broadcasts BEEF to each,
/// and validates acknowledgments according to the configured policy.
pub struct TopicBroadcaster {
    /// Topics to broadcast to.
    topics: Vec<String>,
    /// HTTP client (reused).
    client: reqwest::Client,
    /// Lookup resolver for SHIP host discovery.
    resolver: LookupResolver,
    /// Compound acknowledgment policy (matches TS three-field shape).
    ack_policy: AckPolicy,
    /// Network preset.
    network: Network,
    /// Whether to allow plain HTTP.
    allow_http: bool,
    /// 5-min host-discovery cache + in-flight dedup. Wrapped in `Arc<Mutex>`
    /// so concurrent broadcasts on the same broadcaster instance share state.
    cache: Arc<Mutex<InterestedHostsCache>>,
    /// TTL applied to a successful SHIP query result (TS `5 * 60 * 1000` ms).
    interested_hosts_ttl: Duration,
    /// When set, short-circuits SHIP discovery and broadcasts directly to
    /// these hosts. Used by tests to bypass `LookupResolver`. None in
    /// production — always populated via SHIP lookup.
    manual_hosts: Option<HashMap<String, HashSet<String>>>,
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
            ack_policy: config.ack_policy,
            network: config.network,
            allow_http,
            cache: Arc::new(Mutex::new(InterestedHostsCache::new())),
            interested_hosts_ttl: Duration::from_millis(config.interested_hosts_ttl_ms),
            manual_hosts: None,
        })
    }

    /// Find hosts interested in the configured topics via SHIP lookup.
    ///
    /// Returns the host→topics map plus the count of SHIP outputs whose
    /// BEEF failed to decode. The decode-failure count lets callers
    /// distinguish "lookup returned no SHIP adverts" (legitimate empty
    /// result) from "every advert was unparseable" (silent corruption).
    ///
    /// Caches successful results for [`TopicBroadcasterConfig::interested_hosts_ttl_ms`]
    /// and dedupes concurrent in-flight queries (TS `SHIPBroadcaster.ts:461-490`):
    /// when one caller is mid-query, others await its result rather than
    /// firing duplicate SHIP queries.
    ///
    /// **Decode-failure count is not cached.** The cache stores only the
    /// successfully-derived `host→topics` map; followers receive a
    /// `decode_failures` of `0`. This matches TS behavior where the
    /// equivalent counter is computed fresh per call.
    async fn find_interested_hosts(
        &self,
    ) -> Result<(HashMap<String, HashSet<String>>, usize), ServicesError> {
        // Test override: when manual hosts are injected, skip discovery
        // entirely. This is gated to test builds via `new_with_manual_hosts`.
        if let Some(ref hosts) = self.manual_hosts {
            return Ok((hosts.clone(), 0));
        }
        // Local short-circuit (TS SHIPBroadcaster.ts:462-469): bypass cache
        // and in-flight tracking — the result is constant for this network.
        if self.network == Network::Local {
            let mut result = HashMap::new();
            result.insert(
                "http://localhost:8080".to_string(),
                self.topics.iter().cloned().collect(),
            );
            return Ok((result, 0));
        }

        // Decide our role: cache hit (return immediately), follower (await
        // leader's broadcast), or leader (fetch + publish).
        let mut follower_rx: Option<broadcast::Receiver<DiscoveryResult>> = None;
        {
            let mut guard = self.cache.lock().await;

            if let Some(entry) = &guard.cached {
                if entry.expires_at > Instant::now() {
                    return Ok((entry.hosts.clone(), 0));
                }
            }

            if let Some(tx) = &guard.in_flight {
                follower_rx = Some(tx.subscribe());
            } else {
                // We are the leader: install the in-flight slot, drop the
                // lock (so followers can subscribe), then fetch.
                let (tx, _initial_rx) = broadcast::channel(IN_FLIGHT_CHANNEL_CAPACITY);
                guard.in_flight = Some(tx);
            }
        }

        if let Some(mut rx) = follower_rx {
            // Follower path: await the leader's published Result.
            //
            // F32-20 (Quaakee): the channel now carries `Result<_, String>`
            // so the leader's actual error (timeout / lookup-server 5xx /
            // BEEF decode failure) propagates rather than collapsing to
            // `RecvError::Closed`. `Err(RecvError)` itself only fires if
            // the leader panicked before sending (channel dropped).
            return match rx.recv().await {
                Ok(Ok(hosts)) => Ok((hosts, 0)),
                Ok(Err(msg)) => Err(ServicesError::Overlay(format!(
                    "SHIP host discovery failed (leader errored): {msg}"
                ))),
                Err(e) => Err(ServicesError::Overlay(format!(
                    "SHIP host discovery channel closed unexpectedly: {e}"
                ))),
            };
        }

        // Leader path: do the SHIP query OUTSIDE the cache lock so followers
        // can subscribe in the meantime.
        let result = self.fetch_interested_hosts().await;

        // Re-acquire and publish: write the cache on success, clear the
        // in-flight slot in either case (matches TS finally-block at
        // SHIPBroadcaster.ts:487-488).
        let mut guard = self.cache.lock().await;
        let tx_opt = guard.in_flight.take();
        match &result {
            Ok((hosts, _decode_failures)) => {
                guard.cached = Some(InterestedHostsCacheEntry {
                    hosts: hosts.clone(),
                    expires_at: Instant::now() + self.interested_hosts_ttl,
                });
                if let Some(tx) = &tx_opt {
                    let _ = tx.send(Ok(hosts.clone()));
                }
            }
            Err(e) => {
                // Send the error string so followers don't await forever
                // and don't silently retry past a sustained outage.
                if let Some(tx) = &tx_opt {
                    let _ = tx.send(Err(e.to_string()));
                }
            }
        }
        drop(guard);
        drop(tx_opt);

        result
    }

    /// Inner SHIP-query implementation, factored out so
    /// [`Self::find_interested_hosts`] can wrap it in cache + dedup logic.
    ///
    /// **Panic-safety invariant:** this function must not panic. A panic
    /// would unwind past [`Self::find_interested_hosts`]'s post-await
    /// `lock().await`, leaking the `in_flight = Some(tx)` slot — followers
    /// blocked on `rx.recv()` would receive `Closed` only when the channel
    /// is dropped, but new callers would still see the stale leader marker
    /// and subscribe forever. Today the body uses only `?` propagation and
    /// `saturating_add`; preserve this discipline if you add new operations.
    async fn fetch_interested_hosts(
        &self,
    ) -> Result<(HashMap<String, HashSet<String>>, usize), ServicesError> {
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
        let mut decode_failures: usize = 0;

        if let LookupAnswer::OutputList { outputs } = answer {
            for output in &outputs {
                match OverlayAdminTokenTemplate::decode_from_beef(
                    &output.beef,
                    output.output_index as usize,
                ) {
                    Ok(parsed) => {
                        if parsed.protocol == "SHIP"
                            && self.topics.contains(&parsed.topic_or_service)
                        {
                            results
                                .entry(parsed.domain)
                                .or_default()
                                .insert(parsed.topic_or_service);
                        }
                    }
                    Err(_) => {
                        // Count rather than log: this crate has no tracing
                        // dependency, and a stderr eprintln! would break
                        // library hygiene. The count is folded into
                        // ERR_NO_HOSTS_INTERESTED so operators can see
                        // "lookup returned N adverts but all failed to
                        // decode" instead of just "no hosts".
                        decode_failures = decode_failures.saturating_add(1);
                    }
                }
            }
        }

        Ok((results, decode_failures))
    }

    /// Send tagged BEEF to a host and return the STEAK acknowledgment.
    ///
    /// When `tagged_beef.off_chain_values` is `Some`, the request body is
    /// `varint(beef.len()) || beef || off_chain_values` and the
    /// `x-includes-off-chain-values: true` header is added (matches TS
    /// `HTTPSOverlayBroadcastFacilitator` at `SHIPBroadcaster.ts:100-110`).
    /// Otherwise the body is the raw BEEF and no extra header is set.
    async fn send_to_host(
        &self,
        host: &str,
        tagged_beef: &TaggedBEEF,
    ) -> Result<STEAK, ServicesError> {
        if !self.allow_http && !host.starts_with("https:") {
            return Err(ServicesError::Http(format!(
                "HTTPS required but host URL is: {host}"
            )));
        }

        let url = format!("{host}/submit");
        let topics_json = serde_json::to_string(&tagged_beef.topics).map_err(|e| {
            ServicesError::Serialization(format!("failed to serialize X-Topics: {e}"))
        })?;

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Topics", topics_json);

        let body = if let Some(off_chain) = tagged_beef.off_chain_values.as_deref() {
            // varint(beef.len()) || beef || off_chain. The off-chain blob
            // has no internal length prefix; the receiver consumes BEEF up
            // to the varint-declared length and treats the remainder of
            // the body as the off-chain payload.
            request = request.header("x-includes-off-chain-values", "true");
            let mut framed = Vec::with_capacity(9 + tagged_beef.beef.len() + off_chain.len());
            write_varint_to_vec(&mut framed, tagged_beef.beef.len() as u64);
            framed.extend_from_slice(&tagged_beef.beef);
            framed.extend_from_slice(off_chain);
            framed
        } else {
            tagged_beef.beef.clone()
        };

        let response = request.body(body).send().await.map_err(|e| {
            // Classified network code embedded in the message string so
            // host-reputation and retry layers grepping these errors can
            // distinguish timeout / connect-refused / request-build.
            let (code, description) = classify_reqwest_err(&e);
            ServicesError::Http(format!("[{code}] {description}"))
        })?;

        if response.status().is_success() {
            response
                .json::<STEAK>()
                .await
                .map_err(|e| ServicesError::Serialization(e.to_string()))
        } else {
            // F32-14 (Quaakee): read non-2xx body for diagnostic. Overlay
            // hosts emit `{"error": ..., "code": ...}` on failure;
            // previously the body was dropped. Bounded preview keeps memory
            // safe and parity-preserves TS at the diagnostic level.
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            let preview: String = body_text.chars().take(MAX_BODY_PREVIEW_CHARS).collect();
            Err(ServicesError::Http(format!(
                "Broadcast failed: HTTP {status}: {preview}"
            )))
        }
    }

    /// Check acknowledgments against the configured policy.
    ///
    /// Evaluates the three TS `SHIPBroadcaster` ack fields in canonical
    /// order (AllHosts → AnyHost → SpecificHosts); returns the first
    /// failing field's distinct error code. All three may be set
    /// simultaneously — the most restrictive wins.
    ///
    /// Returns `(error_code, description)` on failure so callers can
    /// surface the distinct failure mode in the resulting
    /// [`BroadcastFailure`].
    fn check_acknowledgments(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<(), (&'static str, String)> {
        // 1. require_from_all_hosts (TS SHIPBroadcaster.ts:252-284)
        if let Some(sel) = &self.ack_policy.require_from_all_hosts {
            let (required, mode) = self.resolve_ack_topics(sel);
            if !required.is_empty() {
                for (host, acked) in host_acks {
                    let ok = match mode {
                        AckMode::All => required.iter().all(|t| acked.contains(t)),
                        AckMode::Any => required.iter().any(|t| acked.contains(t)),
                    };
                    if !ok {
                        return Err((
                            "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED",
                            format!(
                                "Host {host} did not acknowledge required topics ({mode:?}): {required:?}"
                            ),
                        ));
                    }
                }
            }
        }

        // 2. require_from_any_host (TS SHIPBroadcaster.ts:286-318)
        if let Some(sel) = &self.ack_policy.require_from_any_host {
            let (required, mode) = self.resolve_ack_topics(sel);
            if !required.is_empty() {
                let ok = host_acks.values().any(|acked| match mode {
                    AckMode::All => required.iter().all(|t| acked.contains(t)),
                    AckMode::Any => required.iter().any(|t| acked.contains(t)),
                });
                if !ok {
                    return Err((
                        "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED",
                        format!("No host acknowledged required topics ({mode:?}): {required:?}"),
                    ));
                }
            }
        }

        // 3. require_from_specific_hosts (TS SHIPBroadcaster.ts:320-338)
        for (host, sel) in &self.ack_policy.require_from_specific_hosts {
            let acked = match host_acks.get(host) {
                Some(a) => a,
                None => {
                    return Err((
                        "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED",
                        format!("Required host {host} did not respond"),
                    ));
                }
            };
            let (required, mode) = self.resolve_ack_topics(sel);
            if required.is_empty() {
                continue;
            }
            let ok = match mode {
                AckMode::All => required.iter().all(|t| acked.contains(t)),
                AckMode::Any => required.iter().any(|t| acked.contains(t)),
            };
            if !ok {
                return Err((
                    "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED",
                    format!(
                        "Host {host} did not acknowledge required topics ({mode:?}): {required:?}"
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Resolve an [`AckTopics`] selector against the broadcaster's topic set.
    ///
    /// Mirrors TS resolution at `SHIPBroadcaster.ts:264-266,302-304,334-336`:
    /// `'all'` and `'any'` use the full configured topic list and forward
    /// the ack mode; an explicit list forces mode = `All`.
    fn resolve_ack_topics(&self, sel: &AckTopics) -> (Vec<String>, AckMode) {
        match sel {
            AckTopics::All => (self.topics.clone(), AckMode::All),
            AckTopics::Any => (self.topics.clone(), AckMode::Any),
            AckTopics::List(v) => (v.clone(), AckMode::All),
        }
    }
}

/// Internal evaluation mode for an [`AckTopics`] selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckMode {
    All,
    Any,
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
        let txid = parse_beef_for_txid(&beef)?;
        self.broadcast_beef_inner(beef, None, txid).await
    }

    /// Like [`Self::broadcast_beef`] but also forwards an off-chain payload
    /// alongside the BEEF body. Mirrors TS
    /// `SHIPBroadcaster.ts:177` (`tx.metadata.get('OffChainValues')`) — the
    /// Rust SDK has no `Transaction` metadata facility, so callers pass
    /// the off-chain blob explicitly.
    ///
    /// `Some(vec![])` is preserved as Some: an empty vector still emits the
    /// `x-includes-off-chain-values: true` header and a `varint(0)` length
    /// prefix, matching TS `Array.isArray` truthiness semantics.
    pub async fn broadcast_beef_with_off_chain(
        &self,
        beef: Vec<u8>,
        off_chain_values: Vec<u8>,
    ) -> Result<BroadcastResponse, BroadcastFailure> {
        let txid = parse_beef_for_txid(&beef)?;
        self.broadcast_beef_inner(beef, Some(off_chain_values), txid)
            .await
    }

    /// Shared broadcast implementation that sends BEEF bytes to interested hosts.
    async fn broadcast_beef_inner(
        &self,
        beef: Vec<u8>,
        off_chain_values: Option<Vec<u8>>,
        txid: String,
    ) -> Result<BroadcastResponse, BroadcastFailure> {
        let (interested_hosts, decode_failures) =
            self.find_interested_hosts()
                .await
                .map_err(|e| BroadcastFailure {
                    status: 0,
                    code: "ERR_HOST_DISCOVERY".to_string(),
                    description: e.to_string(),
                    ..Default::default()
                })?;

        if interested_hosts.is_empty() {
            // Surface BEEF decode failures so operators can distinguish
            // "no SHIP adverts published" from "every advert failed to
            // decode" (silent corruption masquerading as no-hosts).
            let decode_suffix = if decode_failures > 0 {
                format!(
                    " ({} SHIP advert(s) failed to decode — possible BEEF corruption)",
                    decode_failures
                )
            } else {
                String::new()
            };
            return Err(BroadcastFailure {
                status: 0,
                code: "ERR_NO_HOSTS_INTERESTED".to_string(),
                description: format!(
                    "No {:?} hosts are interested in receiving this transaction{}",
                    self.network, decode_suffix
                ),
                ..Default::default()
            });
        }

        // Concurrent host fan-out (matches canonical TS SHIPBroadcaster.ts:213
        // `Promise.all(hosts.map(...))`). Each send is independent: serial
        // execution made the wall-clock cost N× the slowest host.
        let host_results =
            futures_util::future::join_all(interested_hosts.iter().map(|(host, topics)| {
                let tagged_beef = TaggedBEEF {
                    beef: beef.clone(),
                    topics: topics.iter().cloned().collect(),
                    off_chain_values: off_chain_values.clone(),
                };
                async move {
                    let result = self.send_to_host(host, &tagged_beef).await;
                    (host.clone(), result)
                }
            }))
            .await;

        let mut host_acks: HashMap<String, HashSet<String>> = HashMap::new();
        let mut success_count = 0u32;
        let mut host_errors: Vec<(String, String)> = Vec::new();

        for (host, result) in host_results {
            match result {
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
                    host_acks.insert(host, acked_topics);
                    success_count += 1;
                }
                Err(e) => {
                    host_errors.push((host, e.to_string()));
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
                ..Default::default()
            });
        }

        // Check acknowledgments. The validator returns (error_code, reason)
        // so we can surface the distinct TS-canonical failure codes
        // (ERR_REQUIRE_ACK_FROM_*_FAILED) rather than a generic literal.
        if let Err((code, reason)) = self.check_acknowledgments(&host_acks) {
            return Err(BroadcastFailure {
                status: 0,
                code: code.to_string(),
                description: reason,
                ..Default::default()
            });
        }

        // On partial success (some hosts up, some down), append the per-host
        // failure summary so operators can distinguish "9/10 succeeded" from
        // "1/10 succeeded" — both report `status: success`, but the latter
        // is a quiet degradation worth surfacing in monitoring.
        let total_hosts = success_count as usize + host_errors.len();
        let message = if host_errors.is_empty() {
            format!(
                "Sent to {} Overlay Services {}",
                success_count,
                if success_count == 1 { "host" } else { "hosts" }
            )
        } else {
            let details = host_errors
                .iter()
                .map(|(h, e)| format!("{}: {}", h, e))
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "Sent to {}/{} Overlay Services hosts; {} failed: {}",
                success_count,
                total_hosts,
                host_errors.len(),
                details
            )
        };

        Ok(BroadcastResponse {
            status: "success".to_string(),
            txid,
            message,
            ..Default::default()
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
            ..Default::default()
        })?;

        let txid = tx.id().map_err(|e| BroadcastFailure {
            status: 0,
            code: "ERR_TXID_COMPUTE".to_string(),
            description: format!("Failed to compute txid: {}", e),
            ..Default::default()
        })?;

        self.broadcast_beef_inner(beef, None, txid).await
    }
}

/// Parse BEEF bytes into a [`Transaction`] just to extract the txid for the
/// success response. Returns the same `ERR_BEEF_PARSE`/`ERR_TXID_COMPUTE`
/// failure codes that `broadcast_beef`/`broadcast_beef_with_off_chain`
/// surface to callers.
fn parse_beef_for_txid(beef: &[u8]) -> Result<String, BroadcastFailure> {
    let beef_hex: String = beef.iter().map(|b| format!("{b:02x}")).collect();
    let tx = Transaction::from_beef(&beef_hex).map_err(|e| BroadcastFailure {
        status: 0,
        code: "ERR_BEEF_PARSE".to_string(),
        description: format!("Failed to parse BEEF: {e}"),
        ..Default::default()
    })?;
    tx.id().map_err(|e| BroadcastFailure {
        status: 0,
        code: "ERR_TXID_COMPUTE".to_string(),
        description: format!("Failed to compute txid from BEEF: {e}"),
        ..Default::default()
    })
}

/// Test-only helpers that bypass `LookupResolver`-based SHIP discovery so
/// parity tests can drive `broadcast()` end-to-end against a mock server.
#[cfg(test)]
impl TopicBroadcaster {
    /// Construct a `TopicBroadcaster` whose host discovery is short-circuited
    /// to the supplied `hosts` map. Each entry maps a host base URL (e.g.
    /// `http://127.0.0.1:1234`) to the set of topics that host claims.
    ///
    /// Production code paths must use [`TopicBroadcaster::new`] (which uses
    /// `LookupResolver`); this helper exists solely to drive `broadcast()`
    /// in tests without standing up a real SHIP/lookup stack.
    pub(crate) fn new_with_manual_hosts(
        topics: Vec<String>,
        config: TopicBroadcasterConfig,
        resolver: LookupResolver,
        hosts: HashMap<String, HashSet<String>>,
    ) -> Result<Self, ServicesError> {
        let mut bc = Self::new(topics, config, resolver)?;
        bc.manual_hosts = Some(hosts);
        Ok(bc)
    }

    /// Expose `send_to_host` as `pub(crate)` for low-level wire-form tests
    /// that don't go through the full `broadcast()` flow.
    pub(crate) async fn send_to_host_wire_form_test_only(
        &self,
        host: &str,
        tagged_beef: &TaggedBEEF,
    ) -> Result<STEAK, ServicesError> {
        self.send_to_host(host, tagged_beef).await
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
                ack_policy: AckPolicy::fire_and_forget(),
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
            TopicBroadcasterConfig::default(),
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
            TopicBroadcasterConfig::default(),
            resolver,
        )
        .unwrap();
        let acks = HashMap::new();
        let err = broadcaster.check_acknowledgments(&acks).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED");
    }

    #[test]
    fn test_ack_require_from_all_passes() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: Some(AckTopics::All),
                    require_from_any_host: None,
                    require_from_specific_hosts: HashMap::new(),
                },
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
                ack_policy: AckPolicy {
                    require_from_all_hosts: Some(AckTopics::All),
                    require_from_any_host: None,
                    require_from_specific_hosts: HashMap::new(),
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();
        let mut acks = HashMap::new();
        let topics1 = HashSet::new(); // Empty -- no ack
        acks.insert("host1".to_string(), topics1);
        let err = broadcaster.check_acknowledgments(&acks).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED");
    }

    /// Wire-form parity test (low-level): asserts that the outbound HTTP
    /// request from `send_to_host` matches canonical @bsv/sdk
    /// SHIPBroadcaster.ts (lines 96-99):
    ///   POST <host>/submit
    ///   Content-Type: application/octet-stream
    ///   X-Topics: JSON-stringified topics array (e.g. `["tm_test"]`)
    ///   Body: binary BEEF bytes
    ///
    /// This test only covers the wire form of a single send, not the full
    /// `broadcast()` orchestration (host discovery, ack checking, etc.) —
    /// that is covered by `test_topic_broadcaster_end_to_end_against_mock`.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_topic_broadcaster_canonical_wire_form() {
        use wiremock::matchers::{body_bytes, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Minimal synthetic BEEF bytes for body verification.
        // BEEF magic = 0x100BEEF in little-endian: [EF, BE, 00, 01]
        let fake_beef: Vec<u8> = vec![0xEF, 0xBE, 0x00, 0x01, 0x00];

        // The canonical wire format sends X-Topics as a JSON-stringified array.
        // For topics = ["tm_test"], X-Topics must be the string: ["tm_test"]
        let expected_x_topics = r#"["tm_test"]"#;

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(header("X-Topics", expected_x_topics))
            .and(body_bytes(fake_beef.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let tagged_beef = TaggedBEEF {
            beef: fake_beef,
            topics: vec!["tm_test".to_string()],
            off_chain_values: None,
        };

        let result = broadcaster
            .send_to_host_wire_form_test_only(&mock_server.uri(), &tagged_beef)
            .await;

        // The mock verifies headers + body automatically; also assert a non-error
        // response was received.
        assert!(
            result.is_ok(),
            "send_to_host_wire_form_test_only returned an error: {:?}",
            result.err()
        );

        // Verify wiremock's expectations (the expect(1) assertion fires on drop
        // but we can also call verify explicitly for clarity).
        mock_server.verify().await;
    }

    /// End-to-end test of the full `broadcast()` flow with manual host
    /// injection (bypassing LookupResolver). Covers:
    /// - host-discovery short-circuit via `new_with_manual_hosts`
    /// - the wire-form headers + body sent to /submit
    /// - parsing the STEAK response, ack tracking, and the final
    ///   BroadcastResponse shape (txid + success message).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_topic_broadcaster_end_to_end_against_mock() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock /submit returns a STEAK that admits one output for tm_test.
        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(header("X-Topics", r#"["tm_test"]"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Inject the mock server's URL as the only interested host for
        // tm_test, bypassing LookupResolver entirely.
        let mut hosts: HashMap<String, HashSet<String>> = HashMap::new();
        let mut topics_for_host = HashSet::new();
        topics_for_host.insert("tm_test".to_string());
        hosts.insert(mock_server.uri(), topics_for_host);

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new_with_manual_hosts(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::default_any_host_all_topics(),
                ..Default::default()
            },
            resolver,
            hosts,
        )
        .unwrap();

        // Use a real V1 BEEF from test-vectors/beef_valid.json so that
        // `broadcast_beef` can parse it into a Transaction and recover the
        // txid before submitting to interested hosts.
        let vectors_json =
            std::fs::read_to_string("test-vectors/beef_valid.json").expect("read vectors");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&vectors_json).expect("parse vectors");
        let beef_hex: &str = vectors[0]["hex"].as_str().expect("hex string");
        let beef_bytes: Vec<u8> = (0..beef_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&beef_hex[i..i + 2], 16).expect("hex byte"))
            .collect();

        let result = broadcaster.broadcast_beef(beef_bytes).await;

        let resp = result.expect("end-to-end broadcast should succeed");
        assert_eq!(resp.status, "success");
        assert!(!resp.txid.is_empty(), "txid must be non-empty");
        assert!(
            resp.message.contains("Sent to 1"),
            "expected message to mention 1 host, got: {}",
            resp.message
        );

        // Confirm wiremock saw exactly one /submit POST with the matchers above.
        mock_server.verify().await;
    }

    /// `broadcast_beef` must surface a typed `ERR_BEEF_PARSE` failure when
    /// handed garbage bytes — without this, callers couldn't distinguish a
    /// malformed BEEF from a host-discovery failure.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_broadcast_beef_invalid_bytes_returns_err_beef_parse() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let err = broadcaster
            .broadcast_beef(vec![0xde, 0xad, 0xbe, 0xef])
            .await
            .expect_err("malformed BEEF must surface as failure");
        assert_eq!(err.code, "ERR_BEEF_PARSE");
        assert_eq!(err.status, 0);
    }

    /// Two manually-injected hosts: one returns a STEAK acknowledgment, one
    /// returns 500. The broadcast still succeeds (one host accepted the tx)
    /// but the success message surfaces the per-host failure so partial
    /// degradation isn't silently swept under the rug.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_topic_broadcaster_partial_success_surfaces_failures() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let ok_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .mount(&ok_server)
            .await;

        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad_server)
            .await;

        let mut hosts: HashMap<String, HashSet<String>> = HashMap::new();
        let mut topics_for_host = HashSet::new();
        topics_for_host.insert("tm_test".to_string());
        hosts.insert(ok_server.uri(), topics_for_host.clone());
        hosts.insert(bad_server.uri(), topics_for_host);

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new_with_manual_hosts(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::default_any_host_all_topics(),
                ..Default::default()
            },
            resolver,
            hosts,
        )
        .unwrap();

        let vectors_json =
            std::fs::read_to_string("test-vectors/beef_valid.json").expect("read vectors");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&vectors_json).expect("parse vectors");
        let beef_hex: &str = vectors[0]["hex"].as_str().expect("hex string");
        let beef_bytes: Vec<u8> = (0..beef_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&beef_hex[i..i + 2], 16).expect("hex byte"))
            .collect();

        let resp = broadcaster
            .broadcast_beef(beef_bytes)
            .await
            .expect("partial success path should still report success");
        assert_eq!(resp.status, "success");
        assert!(
            resp.message.contains("1/2") && resp.message.contains("1 failed"),
            "expected partial-success message with 1/2 + 1 failed, got: {}",
            resp.message
        );
        assert!(
            resp.message.contains(&bad_server.uri()),
            "expected failure detail to name the failing host, got: {}",
            resp.message
        );
    }

    /// Both manual hosts return 500 → the broadcast must fail with
    /// `ERR_ALL_HOSTS_REJECTED` and the per-host failure detail in the
    /// description.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_topic_broadcaster_all_hosts_fail_returns_err_all_hosts_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bad_a = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad_a)
            .await;
        let bad_b = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&bad_b)
            .await;

        let mut hosts: HashMap<String, HashSet<String>> = HashMap::new();
        let mut topics_for_host = HashSet::new();
        topics_for_host.insert("tm_test".to_string());
        hosts.insert(bad_a.uri(), topics_for_host.clone());
        hosts.insert(bad_b.uri(), topics_for_host);

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new_with_manual_hosts(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::default_any_host_all_topics(),
                ..Default::default()
            },
            resolver,
            hosts,
        )
        .unwrap();

        let vectors_json =
            std::fs::read_to_string("test-vectors/beef_valid.json").expect("read vectors");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&vectors_json).expect("parse vectors");
        let beef_hex: &str = vectors[0]["hex"].as_str().expect("hex string");
        let beef_bytes: Vec<u8> = (0..beef_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&beef_hex[i..i + 2], 16).expect("hex byte"))
            .collect();

        let err = broadcaster
            .broadcast_beef(beef_bytes)
            .await
            .expect_err("all-hosts-fail must surface ERR_ALL_HOSTS_REJECTED");
        assert_eq!(err.code, "ERR_ALL_HOSTS_REJECTED");
        assert!(
            err.description.contains("Details:"),
            "expected per-host details in description, got: {}",
            err.description
        );
    }

    // ===== Ack policy: AckTopics::List + per-host requirements =====

    /// `AckTopics::List(["tm_a"])` requires every host to ack `tm_a`
    /// specifically — even though the broadcaster is configured with
    /// `["tm_a", "tm_b"]`. A host that acks only `tm_b` must fail.
    /// Mirrors TS list-mode forcing `'all'` (`SHIPBroadcaster.ts:264-266`).
    #[test]
    fn test_ack_list_requires_named_topic_only() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_a".to_string(), "tm_b".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: Some(AckTopics::List(vec!["tm_a".to_string()])),
                    require_from_any_host: None,
                    require_from_specific_hosts: HashMap::new(),
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        // Host acks only tm_b → fails because list explicitly demanded tm_a.
        let mut acks_only_b = HashMap::new();
        let mut topics_b = HashSet::new();
        topics_b.insert("tm_b".to_string());
        acks_only_b.insert("host1".to_string(), topics_b);
        let err = broadcaster.check_acknowledgments(&acks_only_b).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED");

        // Host acks tm_a → passes even though tm_b was unacknowledged.
        let mut acks_with_a = HashMap::new();
        let mut topics_a = HashSet::new();
        topics_a.insert("tm_a".to_string());
        acks_with_a.insert("host1".to_string(), topics_a);
        assert!(broadcaster.check_acknowledgments(&acks_with_a).is_ok());
    }

    /// `AckTopics::Any` for the AnyHost field passes when at least one host
    /// acks at least one topic (the weakest possible policy).
    #[test]
    fn test_ack_any_host_any_topic_passes_with_partial() {
        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_a".to_string(), "tm_b".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: None,
                    require_from_any_host: Some(AckTopics::Any),
                    require_from_specific_hosts: HashMap::new(),
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let mut acks = HashMap::new();
        let mut t = HashSet::new();
        t.insert("tm_a".to_string());
        acks.insert("host1".to_string(), t);
        assert!(broadcaster.check_acknowledgments(&acks).is_ok());
    }

    /// SpecificHosts: a named host that did not respond at all fails the
    /// policy (TS `SHIPBroadcaster.ts:415` returns false on missing host).
    #[test]
    fn test_ack_specific_host_missing_response_fails() {
        let resolver = LookupResolver::for_network(Network::Local);
        let mut specific = HashMap::new();
        specific.insert("https://required.example.com".to_string(), AckTopics::All);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: None,
                    require_from_any_host: None,
                    require_from_specific_hosts: specific,
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let mut acks = HashMap::new();
        let mut topics = HashSet::new();
        topics.insert("tm_test".to_string());
        acks.insert("https://other.example.com".to_string(), topics);

        let err = broadcaster.check_acknowledgments(&acks).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED");
    }

    /// SpecificHosts: when the named host did respond and acks the right
    /// topics, the policy passes.
    #[test]
    fn test_ack_specific_host_passes_when_responding() {
        let resolver = LookupResolver::for_network(Network::Local);
        let mut specific = HashMap::new();
        specific.insert("https://required.example.com".to_string(), AckTopics::All);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: None,
                    require_from_any_host: None,
                    require_from_specific_hosts: specific,
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let mut acks = HashMap::new();
        let mut topics = HashSet::new();
        topics.insert("tm_test".to_string());
        acks.insert("https://required.example.com".to_string(), topics);
        assert!(broadcaster.check_acknowledgments(&acks).is_ok());
    }

    /// Compound policy: all three fields set, no host responded. The
    /// AllHosts branch is vacuously satisfied (no hosts means no host
    /// fails the check), so the validator falls through to AnyHost which
    /// requires at least one acking host. Verify the AnyHost code surfaces.
    /// Mirrors TS evaluation order at `SHIPBroadcaster.ts:252→286→320`.
    #[test]
    fn test_ack_compound_policy_falls_through_to_any_host_when_all_hosts_vacuous() {
        let resolver = LookupResolver::for_network(Network::Local);
        let mut specific = HashMap::new();
        specific.insert("https://required.example.com".to_string(), AckTopics::All);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_a".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: Some(AckTopics::All),
                    require_from_any_host: Some(AckTopics::All),
                    require_from_specific_hosts: specific,
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let acks = HashMap::new();
        let err = broadcaster.check_acknowledgments(&acks).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED");
    }

    /// Compound policy: AllHosts genuinely fires first. One host responded
    /// but did NOT ack the required topic — AllHosts must surface its
    /// own error code, not fall through to AnyHost or SpecificHosts.
    #[test]
    fn test_ack_compound_policy_all_hosts_short_circuits_first() {
        let resolver = LookupResolver::for_network(Network::Local);
        let mut specific = HashMap::new();
        specific.insert("https://required.example.com".to_string(), AckTopics::All);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_a".to_string()],
            TopicBroadcasterConfig {
                ack_policy: AckPolicy {
                    require_from_all_hosts: Some(AckTopics::All),
                    require_from_any_host: Some(AckTopics::All),
                    require_from_specific_hosts: specific,
                },
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        // Host responded with empty acks → AllHosts sees a host with no
        // acked topics → fails AllHosts immediately. AnyHost / SpecificHosts
        // never run.
        let mut acks = HashMap::new();
        acks.insert("https://present.example.com".to_string(), HashSet::new());
        let err = broadcaster.check_acknowledgments(&acks).unwrap_err();
        assert_eq!(err.0, "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED");
    }

    // ===== Cache + in-flight dedup =====

    /// Two consecutive `find_interested_hosts` calls inside the TTL window
    /// hit the cache on the second call. We can't easily mock the SHIP
    /// resolver without much more scaffolding, but we can verify the cache
    /// state mutates correctly: after the first call (Local short-circuit
    /// bypasses cache), and after manual_hosts is set, no SHIP query is
    /// made — the cache stays empty for those paths. So this test instead
    /// drives the cache at the API layer by mutating it directly.
    #[tokio::test]
    async fn test_cache_hit_within_ttl_skips_ship_query() {
        let resolver = LookupResolver::for_network(Network::Mainnet);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig::default(),
            resolver,
        )
        .unwrap();

        // Pre-populate the cache with a known result valid for 5 minutes.
        {
            let mut guard = broadcaster.cache.lock().await;
            let mut hosts = HashMap::new();
            let mut topics = HashSet::new();
            topics.insert("tm_test".to_string());
            hosts.insert("https://cached.example.com".to_string(), topics);
            guard.cached = Some(InterestedHostsCacheEntry {
                hosts,
                expires_at: Instant::now() + Duration::from_secs(300),
            });
        }

        // Call hits the cache; no SHIP query fires (resolver was never told
        // about a tracker, so any real query would error). Success →
        // cache hit was honored.
        let (hosts, decode_failures) = broadcaster.find_interested_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains_key("https://cached.example.com"));
        assert_eq!(decode_failures, 0);
    }

    /// An expired cache entry must NOT be returned. We populate the cache
    /// with `expires_at` already in the past; the next call should fall
    /// through to the leader path. Since the resolver isn't wired to any
    /// trackers, the leader path will error — but the *kind* of error
    /// proves the cache was bypassed (we'd see the cached value otherwise).
    #[tokio::test]
    async fn test_cache_expired_entry_is_not_returned() {
        let resolver = LookupResolver::for_network(Network::Mainnet);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig::default(),
            resolver,
        )
        .unwrap();

        {
            let mut guard = broadcaster.cache.lock().await;
            let mut hosts = HashMap::new();
            let mut topics = HashSet::new();
            topics.insert("tm_test".to_string());
            hosts.insert("https://stale.example.com".to_string(), topics);
            guard.cached = Some(InterestedHostsCacheEntry {
                hosts,
                expires_at: Instant::now() - Duration::from_secs(1), // expired
            });
        }

        // Cache is stale → leader path runs → resolver errors out (no
        // configured trackers in this minimal test setup). The point is
        // we don't get back the stale cached value.
        let result = broadcaster.find_interested_hosts().await;
        // Either Err (resolver failure) OR Ok with an empty/different map —
        // but never the stale "stale.example.com" map.
        if let Ok((hosts, _)) = result {
            assert!(
                !hosts.contains_key("https://stale.example.com"),
                "expired cache entry must not be returned"
            );
        }
    }

    /// Failed leader query must NOT poison the cache (TS finally-block at
    /// `SHIPBroadcaster.ts:487-488` clears `in_flight` only). After a
    /// failure, `cached` stays `None` so the next call retries.
    ///
    /// Drive a real leader error via `Network::Custom(["http://..."])`:
    /// `LookupResolver` rejects non-HTTPS hosts on non-Local networks
    /// (`lookup_resolver.rs::lookup_host_with_tracking`) and `query`
    /// surfaces `Err("No competent hosts found")`. No socket is opened,
    /// so this is fast and firewall-independent. If a future refactor
    /// changes the resolver to return `Ok(empty)` instead of `Err`, the
    /// `if result.is_err()` guard skips the cache assertion — the
    /// invariant (Err must not write cache) is trivially preserved on
    /// the success branch since `Ok(empty)` is itself cacheable per TS.
    #[tokio::test]
    async fn test_cache_not_poisoned_on_leader_error() {
        let resolver =
            LookupResolver::for_network(Network::Custom(vec!["http://127.0.0.1:1".to_string()]));
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Custom(vec!["http://127.0.0.1:1".to_string()]),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let result = broadcaster.find_interested_hosts().await;

        let guard = broadcaster.cache.lock().await;
        assert!(
            guard.in_flight.is_none(),
            "in_flight slot must be cleared after the leader runs (TS finally semantics)"
        );
        if result.is_err() {
            assert!(
                guard.cached.is_none(),
                "cache must not be populated after a leader error"
            );
        }
    }

    // ===== offChainValues body framing =====

    /// `Some(off_chain)` send: the body is `varint(beef.len()) || beef ||
    /// off_chain` and the request includes `x-includes-off-chain-values:
    /// true` (TS `SHIPBroadcaster.ts:100-110`).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_send_with_off_chain_values_emits_framed_body_and_header() {
        use wiremock::matchers::{body_bytes, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let beef: Vec<u8> = vec![0xEF, 0xBE, 0x00, 0x01]; // 4-byte BEEF stub
        let off_chain: Vec<u8> = vec![0xAA, 0xBB, 0xCC];

        // Expected body: varint(4) || beef || off_chain = [04, EF, BE, 00, 01, AA, BB, CC]
        let mut expected_body = vec![0x04u8];
        expected_body.extend_from_slice(&beef);
        expected_body.extend_from_slice(&off_chain);

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("Content-Type", "application/octet-stream"))
            .and(header("x-includes-off-chain-values", "true"))
            .and(body_bytes(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let tagged_beef = TaggedBEEF {
            beef,
            topics: vec!["tm_test".to_string()],
            off_chain_values: Some(off_chain),
        };

        let result = broadcaster
            .send_to_host_wire_form_test_only(&mock_server.uri(), &tagged_beef)
            .await;
        assert!(result.is_ok(), "send returned: {:?}", result.err());
        mock_server.verify().await;
    }

    /// `None` off_chain: body is the raw BEEF, no varint prefix. The
    /// `x-includes-off-chain-values` header is also omitted; verifying its
    /// absence on the wire would need a wiremock request-tap, which is out
    /// of scope. Body-bytes equality already proves we did NOT prepend a
    /// varint length (the framed body would not match `body_bytes(beef)`).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_send_without_off_chain_values_omits_header_and_prefix() {
        use wiremock::matchers::{body_bytes, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let beef: Vec<u8> = vec![0xEF, 0xBE, 0x00, 0x01, 0x00];

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(body_bytes(beef.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let tagged_beef = TaggedBEEF {
            beef,
            topics: vec!["tm_test".to_string()],
            off_chain_values: None,
        };

        let result = broadcaster
            .send_to_host_wire_form_test_only(&mock_server.uri(), &tagged_beef)
            .await;
        assert!(result.is_ok(), "send returned: {:?}", result.err());
        mock_server.verify().await;
    }

    /// Empty off-chain `Vec` (`Some(vec![])`) is preserved as Some — the
    /// request still carries the header and a `varint(beef.len())` prefix.
    /// Mirrors TS `Array.isArray([])` truthiness (non-null array is still
    /// "present").
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_send_with_empty_off_chain_still_frames_body() {
        use wiremock::matchers::{body_bytes, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let beef: Vec<u8> = vec![0xEF, 0xBE, 0x00, 0x01];
        // Expected: varint(4) || beef || (empty) = [04, EF, BE, 00, 01]
        let mut expected_body = vec![0x04u8];
        expected_body.extend_from_slice(&beef);

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("x-includes-off-chain-values", "true"))
            .and(body_bytes(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let tagged_beef = TaggedBEEF {
            beef,
            topics: vec!["tm_test".to_string()],
            off_chain_values: Some(vec![]),
        };

        let result = broadcaster
            .send_to_host_wire_form_test_only(&mock_server.uri(), &tagged_beef)
            .await;
        assert!(result.is_ok(), "send returned: {:?}", result.err());
        mock_server.verify().await;
    }

    /// Varint boundary: BEEF length 253 must produce a 3-byte varint
    /// (`0xFD || u16 LE`) in the body prefix, not the 1-byte form.
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_send_with_off_chain_varint_three_byte_boundary() {
        use wiremock::matchers::{body_bytes, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let beef: Vec<u8> = vec![0u8; 253];
        let off_chain: Vec<u8> = vec![0xAA];

        // Expected: 0xFD || u16 LE(253) || 253 zero bytes || off_chain
        let mut expected_body = vec![0xFD, 0xFD, 0x00];
        expected_body.extend_from_slice(&beef);
        expected_body.extend_from_slice(&off_chain);

        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(body_bytes(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::fire_and_forget(),
                ..Default::default()
            },
            resolver,
        )
        .unwrap();

        let tagged_beef = TaggedBEEF {
            beef,
            topics: vec!["tm_test".to_string()],
            off_chain_values: Some(off_chain),
        };

        let result = broadcaster
            .send_to_host_wire_form_test_only(&mock_server.uri(), &tagged_beef)
            .await;
        assert!(result.is_ok(), "send returned: {:?}", result.err());
        mock_server.verify().await;
    }

    /// End-to-end with off-chain payload via `broadcast_beef_with_off_chain`.
    /// Covers: (a) the public API surface, (b) the framing being applied
    /// during the full broadcast() flow (not just the wire-form helper).
    #[cfg(feature = "network")]
    #[tokio::test]
    async fn test_broadcast_beef_with_off_chain_end_to_end() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/submit"))
            .and(header("x-includes-off-chain-values", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tm_test": { "outputsToAdmit": [0], "coinsToRetain": [] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut hosts: HashMap<String, HashSet<String>> = HashMap::new();
        let mut topics_for_host = HashSet::new();
        topics_for_host.insert("tm_test".to_string());
        hosts.insert(mock_server.uri(), topics_for_host);

        let resolver = LookupResolver::for_network(Network::Local);
        let broadcaster = TopicBroadcaster::new_with_manual_hosts(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                network: Network::Local,
                ack_policy: AckPolicy::default_any_host_all_topics(),
                ..Default::default()
            },
            resolver,
            hosts,
        )
        .unwrap();

        let vectors_json =
            std::fs::read_to_string("test-vectors/beef_valid.json").expect("read vectors");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&vectors_json).expect("parse vectors");
        let beef_hex: &str = vectors[0]["hex"].as_str().expect("hex string");
        let beef_bytes: Vec<u8> = (0..beef_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&beef_hex[i..i + 2], 16).expect("hex byte"))
            .collect();

        let resp = broadcaster
            .broadcast_beef_with_off_chain(beef_bytes, vec![0x01, 0x02, 0x03])
            .await
            .expect("broadcast_beef_with_off_chain should succeed");
        assert_eq!(resp.status, "success");
        mock_server.verify().await;
    }
}
