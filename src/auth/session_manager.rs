//! Session management for the BRC-31 authentication protocol.
//!
//! SessionManager tracks authenticated sessions by both session nonce
//! (primary key) and peer identity key (secondary index), supporting
//! multiple concurrent sessions per identity key.
//!
//! Translated from TS SDK SessionManager.ts and Go SDK session_manager.go.

use std::collections::{HashMap, HashSet, VecDeque};

use super::types::PeerSession;

/// Default idle TTL for a session: 15 minutes.
///
/// A session untouched for longer than this is considered dead: lookups honor
/// it via [`SessionManager::get_active_session`] (returning `None` so the peer
/// simply re-handshakes) and [`SessionManager::reap_idle`] physically evicts it
/// and frees its replay seen-set. 15 min is *far* larger than the normal
/// sub-second idle gap between authenticated messages, so a live client never
/// trips it; a stale/captured `yourNonce` no longer resolves a session forever.
pub const DEFAULT_SESSION_IDLE_TTL_MS: u64 = 15 * 60 * 1000;

/// Default per-session cap on remembered message nonces (FIFO eviction).
///
/// Bounds memory for a long-lived busy session. Only signature-verified
/// messages ever reach the seen-set, so an attacker cannot inflate it; a real
/// peer would have to legitimately send this many messages to slide the window,
/// and the idle TTL frees the whole set on reap.
pub const DEFAULT_SEEN_NONCE_CAP: usize = 10_000;

/// Outcome of an anti-replay check-and-insert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkSeen {
    /// First time this `(session, message-nonce)` pair was seen — accept.
    Fresh,
    /// Byte-for-byte replay of an already-seen message nonce — reject.
    Replay,
    /// The session no longer exists (never added, or reaped) — reject.
    SessionGone,
}

/// Per-session anti-replay + activity bookkeeping.
///
/// Kept out of [`PeerSession`] itself so the session stays cheap to `.clone()`
/// out of the read lock on the hot verify path; this metadata is only touched
/// under the (brief, `.await`-free) write lock during the replay check.
struct SessionMeta {
    /// Wall-clock ms of the last successful activity on this session.
    last_used_ms: u64,
    /// Membership set of message nonces for O(1) replay detection.
    seen: HashSet<String>,
    /// Insertion order, so the oldest nonce can be FIFO-evicted at the cap.
    order: VecDeque<String>,
}

/// Manages authenticated peer sessions with dual-index tracking.
///
/// Sessions are indexed by:
/// - Session nonce (primary key, unique per session)
/// - Identity key (secondary index, one-to-many)
///
/// This allows lookup by either nonce or identity key, with the identity
/// key lookup returning the "best" session (preferring authenticated ones).
pub struct SessionManager {
    /// Maps session_nonce -> PeerSession (primary index).
    nonce_to_session: HashMap<String, PeerSession>,
    /// Maps identity_key -> set of session nonces (secondary index).
    identity_to_nonces: HashMap<String, HashSet<String>>,
    /// Per-session replay + activity bookkeeping, keyed by session_nonce.
    /// Created lazily on first `touch`/`mark_message_seen`; dropped whenever the
    /// session is removed or reaped, which frees its seen-set (memory bound).
    session_meta: HashMap<String, SessionMeta>,
    /// Idle TTL in ms (see [`DEFAULT_SESSION_IDLE_TTL_MS`]).
    idle_ttl_ms: u64,
    /// Per-session remembered-nonce cap (see [`DEFAULT_SEEN_NONCE_CAP`]).
    seen_nonce_cap: usize,
}

impl SessionManager {
    /// Create a new empty SessionManager with default TTL / seen-set cap.
    pub fn new() -> Self {
        Self::with_config(DEFAULT_SESSION_IDLE_TTL_MS, DEFAULT_SEEN_NONCE_CAP)
    }

    /// Create a new empty SessionManager with an explicit idle TTL and
    /// per-session replay seen-set cap. Used by tests and by callers that want
    /// a tighter reaping policy.
    pub fn with_config(idle_ttl_ms: u64, seen_nonce_cap: usize) -> Self {
        SessionManager {
            nonce_to_session: HashMap::new(),
            identity_to_nonces: HashMap::new(),
            session_meta: HashMap::new(),
            idle_ttl_ms,
            seen_nonce_cap,
        }
    }

    /// The configured idle TTL in milliseconds.
    pub fn idle_ttl_ms(&self) -> u64 {
        self.idle_ttl_ms
    }

    /// Add a session to the manager.
    ///
    /// Indexes by session_nonce (primary) and peer_identity_key (secondary).
    /// Does NOT overwrite existing sessions for the same identity key,
    /// allowing multiple concurrent sessions per peer.
    pub fn add_session(&mut self, session: PeerSession) {
        let nonce = session.session_nonce.clone();
        let identity = session.peer_identity_key.clone();

        self.nonce_to_session.insert(nonce.clone(), session);

        self.identity_to_nonces
            .entry(identity)
            .or_default()
            .insert(nonce);
    }

    /// Get a session by nonce (immutable reference).
    pub fn get_session(&self, nonce: &str) -> Option<&PeerSession> {
        self.nonce_to_session.get(nonce)
    }

    /// Get a session by nonce (mutable reference).
    pub fn get_session_mut(&mut self, nonce: &str) -> Option<&mut PeerSession> {
        self.nonce_to_session.get_mut(nonce)
    }

    /// Get all sessions for a given identity key.
    pub fn get_sessions_for_identity(&self, identity_key: &str) -> Vec<&PeerSession> {
        match self.identity_to_nonces.get(identity_key) {
            Some(nonces) => nonces
                .iter()
                .filter_map(|n| self.nonce_to_session.get(n))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get the "best" session for an identity key (prefers authenticated).
    ///
    /// Matches TS SDK SessionManager.getSession() behavior: if the identifier
    /// is a session nonce, returns that exact session. If it is an identity key,
    /// returns the best (authenticated preferred) session.
    pub fn get_session_by_identifier(&self, identifier: &str) -> Option<&PeerSession> {
        // Try as direct nonce first
        if let Some(session) = self.nonce_to_session.get(identifier) {
            return Some(session);
        }

        // Try as identity key
        let nonces = self.identity_to_nonces.get(identifier)?;
        let mut best: Option<&PeerSession> = None;
        for nonce in nonces {
            if let Some(session) = self.nonce_to_session.get(nonce) {
                match best {
                    None => best = Some(session),
                    Some(b) => {
                        // Prefer authenticated sessions
                        if session.is_authenticated && !b.is_authenticated {
                            best = Some(session);
                        }
                    }
                }
            }
        }
        best
    }

    /// Check if a session exists for a given nonce.
    pub fn has_session(&self, nonce: &str) -> bool {
        self.nonce_to_session.contains_key(nonce)
    }

    /// Check if any session exists for a given identifier (nonce or identity key).
    pub fn has_session_by_identifier(&self, identifier: &str) -> bool {
        if self.nonce_to_session.contains_key(identifier) {
            return true;
        }
        match self.identity_to_nonces.get(identifier) {
            Some(nonces) => !nonces.is_empty(),
            None => false,
        }
    }

    /// Replace a session at the given nonce.
    pub fn update_session(&mut self, nonce: &str, session: PeerSession) {
        // Remove old identity mapping if the identity key changed
        if let Some(old_session) = self.nonce_to_session.get(nonce) {
            let old_identity = old_session.peer_identity_key.clone();
            if old_identity != session.peer_identity_key {
                if let Some(nonces) = self.identity_to_nonces.get_mut(&old_identity) {
                    nonces.remove(nonce);
                    if nonces.is_empty() {
                        self.identity_to_nonces.remove(&old_identity);
                    }
                }
            }
        }

        let new_identity = session.peer_identity_key.clone();
        self.nonce_to_session.insert(nonce.to_string(), session);
        self.identity_to_nonces
            .entry(new_identity)
            .or_default()
            .insert(nonce.to_string());
    }

    /// Remove a session by nonce. Returns the removed session if found.
    ///
    /// Also drops the session's replay/activity metadata, freeing its seen-set.
    pub fn remove_session(&mut self, nonce: &str) -> Option<PeerSession> {
        // Drop replay/activity bookkeeping regardless of session presence.
        self.session_meta.remove(nonce);
        if let Some(session) = self.nonce_to_session.remove(nonce) {
            // Clean up identity index
            if let Some(nonces) = self.identity_to_nonces.get_mut(&session.peer_identity_key) {
                nonces.remove(nonce);
                if nonces.is_empty() {
                    self.identity_to_nonces.remove(&session.peer_identity_key);
                }
            }
            Some(session)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Anti-replay + idle-TTL eviction (receiver-side, wire-compatible).
    //
    // These are STRICTLY-BETTER additions over the TS reference, which tracks
    // `lastUpdate` but never reaps and has no per-message replay set. The clock
    // is injected (`now_ms`) so this module stays pure / wasm-safe — the
    // network-gated `Peer` supplies the wall clock.
    // -----------------------------------------------------------------------

    /// Record activity on an existing session, creating its metadata if absent
    /// and advancing `last_used_ms` to `now_ms`. No-op if the session is unknown.
    ///
    /// Call this right after a handshake adds/promotes a session so that idle
    /// reaping has a baseline, and on every accepted message thereafter.
    pub fn touch(&mut self, session_nonce: &str, now_ms: u64) {
        if !self.nonce_to_session.contains_key(session_nonce) {
            return;
        }
        self.session_meta
            .entry(session_nonce.to_string())
            .or_insert_with(|| SessionMeta {
                last_used_ms: now_ms,
                seen: HashSet::new(),
                order: VecDeque::new(),
            })
            .last_used_ms = now_ms;
    }

    /// True if the session has recorded activity AND has been idle longer than
    /// the configured TTL. A session with no recorded activity yet (freshly
    /// added, not touched) is treated as fresh (not expired).
    pub fn is_expired(&self, session_nonce: &str, now_ms: u64) -> bool {
        match self.session_meta.get(session_nonce) {
            Some(m) => now_ms.saturating_sub(m.last_used_ms) > self.idle_ttl_ms,
            None => false,
        }
    }

    /// Look up a session by identifier (nonce or identity key) honoring the
    /// idle TTL: returns `None` if the session is missing OR has gone idle past
    /// the TTL. The hot verify path uses this so a stale/captured `yourNonce`
    /// stops resolving a live session once the TTL lapses.
    pub fn get_active_session(&self, identifier: &str, now_ms: u64) -> Option<&PeerSession> {
        let session = self.get_session_by_identifier(identifier)?;
        if self.is_expired(&session.session_nonce, now_ms) {
            return None;
        }
        Some(session)
    }

    /// Anti-replay check-and-insert for a single per-message nonce, scoped to a
    /// session. Atomic under `&mut self` (the caller's brief write lock), so
    /// concurrent verifies of the SAME captured message resolve to exactly one
    /// [`MarkSeen::Fresh`] and the rest [`MarkSeen::Replay`].
    ///
    /// The effective replay key is `(peer_identity_key, session_nonce,
    /// message_nonce)`: `session_nonce` selects the per-session set (which is
    /// itself bound to one peer identity via the handshake), and `message_nonce`
    /// is the fresh 32-byte random nonce an honest sender mints per outbound
    /// message — so a legit sender never collides and only a byte-replay repeats.
    ///
    /// Advances `last_used_ms` and enforces the per-session FIFO cap. Only call
    /// AFTER the message signature has verified, so the set is never poisoned by
    /// unauthenticated input.
    pub fn mark_message_seen(
        &mut self,
        session_nonce: &str,
        message_nonce: &str,
        now_ms: u64,
    ) -> MarkSeen {
        if !self.nonce_to_session.contains_key(session_nonce) {
            return MarkSeen::SessionGone;
        }
        let cap = self.seen_nonce_cap;
        let meta = self
            .session_meta
            .entry(session_nonce.to_string())
            .or_insert_with(|| SessionMeta {
                last_used_ms: now_ms,
                seen: HashSet::new(),
                order: VecDeque::new(),
            });
        meta.last_used_ms = now_ms;

        if !meta.seen.insert(message_nonce.to_string()) {
            return MarkSeen::Replay;
        }
        meta.order.push_back(message_nonce.to_string());
        while meta.order.len() > cap {
            if let Some(old) = meta.order.pop_front() {
                meta.seen.remove(&old);
            }
        }
        MarkSeen::Fresh
    }

    /// Evict every session idle longer than the configured TTL, freeing each
    /// one's replay seen-set. Returns the number reaped.
    ///
    /// Intended to be called on the low-frequency handshake path (not the hot
    /// verify path), which bounds memory without serializing message verifies.
    pub fn reap_idle(&mut self, now_ms: u64) -> usize {
        let ttl = self.idle_ttl_ms;
        let expired: Vec<String> = self
            .session_meta
            .iter()
            .filter(|(_, m)| now_ms.saturating_sub(m.last_used_ms) > ttl)
            .map(|(nonce, _)| nonce.clone())
            .collect();
        let mut reaped = 0;
        for nonce in expired {
            if self.remove_session(&nonce).is_some() {
                reaped += 1;
            }
        }
        reaped
    }

    /// Test/introspection helper: number of remembered message nonces for a
    /// session (0 if the session has no metadata).
    #[doc(hidden)]
    pub fn seen_nonce_count(&self, session_nonce: &str) -> usize {
        self.session_meta
            .get(session_nonce)
            .map(|m| m.seen.len())
            .unwrap_or(0)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(nonce: &str, identity: &str, authenticated: bool) -> PeerSession {
        PeerSession {
            session_nonce: nonce.to_string(),
            peer_identity_key: identity.to_string(),
            peer_nonce: format!("peer_{}", nonce),
            is_authenticated: authenticated,
        }
    }

    #[test]
    fn test_add_and_get_session() {
        let mut mgr = SessionManager::new();
        let session = make_session("nonce1", "id_key_A", true);
        mgr.add_session(session.clone());

        let retrieved = mgr.get_session("nonce1").unwrap();
        assert_eq!(retrieved.session_nonce, "nonce1");
        assert_eq!(retrieved.peer_identity_key, "id_key_A");
        assert!(retrieved.is_authenticated);
    }

    #[test]
    fn test_has_session() {
        let mut mgr = SessionManager::new();
        assert!(!mgr.has_session("nonce1"));

        mgr.add_session(make_session("nonce1", "id_key_A", true));
        assert!(mgr.has_session("nonce1"));
        assert!(!mgr.has_session("nonce2"));
    }

    #[test]
    fn test_remove_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));

        let removed = mgr.remove_session("nonce1").unwrap();
        assert_eq!(removed.session_nonce, "nonce1");
        assert!(!mgr.has_session("nonce1"));

        // Identity index should also be cleaned up
        let sessions = mgr.get_sessions_for_identity("id_key_A");
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_get_sessions_for_identity() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));
        mgr.add_session(make_session("nonce2", "id_key_A", false));
        mgr.add_session(make_session("nonce3", "id_key_B", true));

        let a_sessions = mgr.get_sessions_for_identity("id_key_A");
        assert_eq!(a_sessions.len(), 2);

        let b_sessions = mgr.get_sessions_for_identity("id_key_B");
        assert_eq!(b_sessions.len(), 1);

        let c_sessions = mgr.get_sessions_for_identity("id_key_C");
        assert!(c_sessions.is_empty());
    }

    #[test]
    fn test_get_session_by_identifier() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));
        mgr.add_session(make_session("nonce2", "id_key_A", true));

        // Direct nonce lookup
        let s = mgr.get_session_by_identifier("nonce1").unwrap();
        assert_eq!(s.session_nonce, "nonce1");

        // Identity key lookup should prefer authenticated session
        let best = mgr.get_session_by_identifier("id_key_A").unwrap();
        assert!(best.is_authenticated);
    }

    #[test]
    fn test_has_session_by_identifier() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));

        assert!(mgr.has_session_by_identifier("nonce1"));
        assert!(mgr.has_session_by_identifier("id_key_A"));
        assert!(!mgr.has_session_by_identifier("unknown"));
    }

    #[test]
    fn test_update_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));

        // Update to authenticated
        let updated = make_session("nonce1", "id_key_A", true);
        mgr.update_session("nonce1", updated);

        let s = mgr.get_session("nonce1").unwrap();
        assert!(s.is_authenticated);
    }

    #[test]
    fn test_get_session_mut() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));

        let s = mgr.get_session_mut("nonce1").unwrap();
        s.is_authenticated = true;

        let s2 = mgr.get_session("nonce1").unwrap();
        assert!(s2.is_authenticated);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mgr = SessionManager::new();
        assert!(mgr.remove_session("nonexistent").is_none());
    }

    #[test]
    fn test_identity_cleanup_on_remove_last_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));
        mgr.add_session(make_session("nonce2", "id_key_A", true));

        mgr.remove_session("nonce1");
        // Still has one session for identity
        assert!(mgr.has_session_by_identifier("id_key_A"));

        mgr.remove_session("nonce2");
        // Now identity should be cleaned up
        assert!(!mgr.has_session_by_identifier("id_key_A"));
    }

    // -----------------------------------------------------------------------
    // Anti-replay + idle-TTL eviction tests
    // -----------------------------------------------------------------------

    /// Item 1: a replayed (same session + same message nonce) is REJECTED while
    /// a fresh per-message nonce always passes.
    #[test]
    fn test_replay_seen_set_rejects_duplicate_but_accepts_fresh() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("sess1", "id_key_A", true));
        mgr.touch("sess1", 1_000);

        // First sighting of msg nonce "m1" is fresh.
        assert_eq!(mgr.mark_message_seen("sess1", "m1", 1_000), MarkSeen::Fresh);
        // Byte-replay of the exact same message nonce is rejected.
        assert_eq!(mgr.mark_message_seen("sess1", "m1", 1_001), MarkSeen::Replay);
        // A different fresh nonce still passes on the same session.
        assert_eq!(mgr.mark_message_seen("sess1", "m2", 1_002), MarkSeen::Fresh);
        // Unknown session cannot be marked.
        assert_eq!(
            mgr.mark_message_seen("ghost", "m1", 1_003),
            MarkSeen::SessionGone
        );
    }

    /// Item 2: a session past its TTL is evicted and its seen-set freed.
    #[test]
    fn test_reap_idle_evicts_expired_and_frees_seen_set() {
        let ttl = 60_000; // 1 minute
        let mut mgr = SessionManager::with_config(ttl, DEFAULT_SEEN_NONCE_CAP);
        mgr.add_session(make_session("sess1", "id_key_A", true));
        mgr.touch("sess1", 10_000);
        mgr.mark_message_seen("sess1", "m1", 10_000);
        mgr.mark_message_seen("sess1", "m2", 10_000);
        assert_eq!(mgr.seen_nonce_count("sess1"), 2);

        // Well within TTL: still present, still remembers nonces.
        assert!(!mgr.is_expired("sess1", 10_000 + ttl));
        assert_eq!(mgr.reap_idle(10_000 + ttl), 0);
        assert!(mgr.has_session("sess1"));

        // Past TTL: expired, reaped, seen-set freed.
        assert!(mgr.is_expired("sess1", 10_000 + ttl + 1));
        assert_eq!(mgr.reap_idle(10_000 + ttl + 1), 1);
        assert!(!mgr.has_session("sess1"));
        assert_eq!(mgr.seen_nonce_count("sess1"), 0);
        // After eviction the captured nonce no longer resolves a session.
        assert!(mgr.get_active_session("sess1", 10_000 + ttl + 2).is_none());
    }

    /// Item 3: two different sessions do not cross-contaminate their seen-sets.
    #[test]
    fn test_two_sessions_do_not_cross_contaminate() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("sessA", "id_key_A", true));
        mgr.add_session(make_session("sessB", "id_key_B", true));

        // Same message nonce value on two distinct sessions: both fresh.
        assert_eq!(
            mgr.mark_message_seen("sessA", "shared", 1_000),
            MarkSeen::Fresh
        );
        assert_eq!(
            mgr.mark_message_seen("sessB", "shared", 1_000),
            MarkSeen::Fresh
        );
        // Replays are still caught per-session.
        assert_eq!(
            mgr.mark_message_seen("sessA", "shared", 1_001),
            MarkSeen::Replay
        );
        assert_eq!(
            mgr.mark_message_seen("sessB", "shared", 1_001),
            MarkSeen::Replay
        );
    }

    /// The per-session seen-set is bounded: it never exceeds the cap, and the
    /// oldest nonce is FIFO-evicted (documents the finite replay window).
    #[test]
    fn test_seen_set_is_bounded_by_cap() {
        let cap = 4;
        let mut mgr = SessionManager::with_config(DEFAULT_SESSION_IDLE_TTL_MS, cap);
        mgr.add_session(make_session("sess1", "id_key_A", true));

        for i in 0..6 {
            let n = format!("m{i}");
            assert_eq!(mgr.mark_message_seen("sess1", &n, 1_000), MarkSeen::Fresh);
        }
        // Memory is bounded to `cap`.
        assert_eq!(mgr.seen_nonce_count("sess1"), cap);
        // The most recent `cap` nonces are still remembered (replay caught).
        assert_eq!(
            mgr.mark_message_seen("sess1", "m5", 1_000),
            MarkSeen::Replay
        );
        // The oldest (m0, m1) fell out of the window (FIFO eviction).
        assert_eq!(mgr.mark_message_seen("sess1", "m0", 1_000), MarkSeen::Fresh);
    }

    /// A freshly-added session with no recorded activity is never treated as
    /// expired (avoids reaping a session before its first message).
    #[test]
    fn test_new_session_without_activity_is_not_expired() {
        let mut mgr = SessionManager::with_config(1, DEFAULT_SEEN_NONCE_CAP);
        mgr.add_session(make_session("sess1", "id_key_A", true));
        // No touch yet -> no metadata -> not expired regardless of clock.
        assert!(!mgr.is_expired("sess1", u64::MAX));
        assert!(mgr.get_active_session("sess1", u64::MAX).is_some());
        assert_eq!(mgr.reap_idle(u64::MAX), 0);
    }
}
