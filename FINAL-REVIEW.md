# Final adversarial review of `f8d82ce`

Reviewed HEAD `f8d82cee27e061e9774bbb1a76113c1a06c76a94` on
`feat/background-receive-task`, including the production diff, the full handshake/session lifecycle,
the three tests added by the commit, the four specifically refuted claims in `RECV-REVIEW2.md`, and
the requested regression seams.

## Verdict

**BLOCK 0.8.0.** The F1 security invariant is directionally correct and the F2 admission check is
genuinely atomic, but this fix round introduced two concrete defects. Most seriously, seven malformed,
unauthenticated inbound handshakes can consume the new F2 capacity for the 15-minute session TTL because
sessions are charged before fallible processing and are not removed on error. F1 also compares valid
compressed public-key strings literally, so an uppercase spelling of the correct key is rejected even
though the governed schema and both SDK key parsers accept it as the same identity.

## Ranked findings

### 1. HIGH — terminally failed handshakes retain F2 capacity and allow a seven-request admission DoS

- **Files:** `src/auth/peer.rs:1281-1363`, `src/auth/peer.rs:1395-1404`,
  `src/auth/peer.rs:1955-2075`, `src/auth/session_manager.rs:352-387`
- **Defect:** both initiator and responder paths insert the new certificate-gated session before later
  fallible work. No error path removes it. `pending_certificate_validation_count` counts only the two
  state booleans, so a failed session continues to consume one of the seven slots until successful
  validation or idle reaping. The responder path is remotely exploitable before authentication:
  `handle_initial_request` inserts at lines 1965-1975, but does not parse the peer identity until line
  2037. An invalid key returns an error with the counted session still present. Initiator failures from
  local identity lookup, transport send, the 30-second handshake timeout, signature/certificate errors,
  and the new F1 mismatch return have the same retention. The F1 regression explicitly confirms that a
  rejected replacement leaves its pending session intact.
- **Reproduction:** configure a receiver with a non-empty `certificates_to_request`. Dispatch seven
  `initialRequest` messages with a non-empty base64 `initialNonce` and `identityKey = "not-a-key"`.
  Each call inserts a gated session, then fails at `parse_public_key`. Dispatch an eighth request from
  a legitimate peer: it fails at lines 1980-1983 with `certificate-gated session capacity exhausted`
  before its identity is processed. The attacker needs no valid key or signature. The seven entries are
  not permanently leaked, but `reap_idle` cannot remove them until they have been idle for more than 15
  minutes, and it runs only on a later handshake. Repeating the seven-request burst renews the denial
  indefinitely.
- **Impact:** a cap intended to preserve dispatch availability becomes a peer-wide denial of all new
  certificate-gated sessions. The same behavior can wedge a standalone initiator after seven transient
  local/transport failures or seven F1 rejections, preventing recovery even after the remote peer is
  corrected.
- **Confidence:** high. The insertion precedes the demonstrated fallible parse, the counter directly
  includes the abandoned states, and their only production removal path is 15-minute idle reaping.
- **Provenance:** **introduced by `f8d82ce` as an admission failure.** Retaining failed sessions
  pre-existed, but those entries did not reject future handshakes until this commit made them consume a
  hard capacity.

### 2. MEDIUM — F1 rejects a valid uppercase spelling of the same compressed identity key

- **Files:** `src/auth/peer.rs:1395-1404`, `src/auth/peer.rs:1428-1431`,
  `conformance/vectors/auth/brc31-handshake.json:371-386`
- **Defect:** the new guard compares `peer_identity_key` and `response.identity_key` as raw strings,
  while the signature path immediately below parses the response as a public key. The governed
  `PubKeyHex` pattern is `^0[23][0-9a-fA-F]{64}$`, so uppercase hex is a valid spelling. An honest Rust
  responder emits canonical lowercase via `to_der_hex()` at `src/auth/peer.rs:2065`. A caller that dials
  the same key in uppercase therefore hits F1 before cryptographic equivalence can be established.
- **Reproduction:** take an honest responder identity such as
  `02ab...cd`, call `get_authenticated_session(&identity.to_uppercase())`, and let that responder return
  its ordinary lowercase, correctly signed `initialResponse`. The pending and response strings differ,
  so lines 1398-1404 return `InvalidMessage`; without the new guard, `parse_public_key` accepts both and
  the signature verifies against the same point. Executing the required `@bsv/sdk` 2.4.1 package also
  confirmed that `PublicKey.fromString(uppercase)` succeeds and canonicalizes to the same lowercase
  compressed key.
- **Impact:** valid known-identity handshakes through the public `Peer` API deterministically fail based
  only on hex casing. AuthFetch's first discovery is not affected because it passes `""`, and its
  internal learned identity is canonical; this is nevertheless a regression for public callers and
  externally stored/cased identity strings.
- **Confidence:** high. The schema explicitly accepts `A-F`, both the Rust and executed TS parsers
  normalize the spelling, and the literal inequality precedes parsing.
- **Provenance:** **introduced by `f8d82ce` (F1).**

## Attack results

### A. F1 identity guard

- **Identity discovery works end to end.** A new AuthFetch `AuthPeer` initializes `identity_key` to
  `None` (`auth_fetch.rs:921-925`), so its once-only handshake passes `""`
  (`auth_fetch.rs:381-404`). F1 permits that empty value; the response is verified against the key it
  asserts, the session is re-keyed to that authenticated identity, and AuthFetch stores the canonical
  result. The new empty-discovery regression passes.
- **Reconnect does not exercise a non-empty AuthFetch cache.** Stale recovery removes the entire
  `AuthPeer` (`auth_fetch.rs:331-335`), including its learned identity and `OnceCell`; the replacement
  again starts empty. Within one `AuthPeer`, a successful `OnceCell` prevents a second handshake. Thus
  F1 does not break AuthFetch reconnect, but AuthFetch also does not pin the old identity across that
  reconnect. That is pre-existing behavior, not a defect introduced by this commit.
- **A genuine different key should be rejected.** Redirects, key rotation, and multi-identity servers
  do not make a different key equivalent to the non-empty identity the caller selected. Callers that
  intend endpoint discovery can pass empty. The legitimate difference found here is alternate valid
  spelling of the same point (finding 2), not a different identity.
- **The empty path is TOFU, not an authentication bypass.** An empty pending identity allows any valid
  response key, but that response must still verify its handshake signature under the asserted key.
  On AuthFetch, the HTTP/TLS base URL supplies endpoint trust. A transport attacker able to replace the
  endpoint can choose the first discovered identity; this is inherent in the existing discovery API.
- **No production writer bypasses F1.** Initiator and responder creation set the initial value, and
  `complete_handshake` is the only production site that changes an existing session's
  `peer_identity_key` through `SessionManager::update_session`. Other direct mutations found by search
  are test setup.

### B. F2 capacity

- **Atomicity is correct.** At both creation sites the code acquires the session-manager write lock,
  reaps, counts, compares, inserts, and touches before releasing the guard. There is no check-then-act
  gap, and concurrent creators cannot both observe the seventh slot as free.
- **The count's predicate is correct but its lifecycle is not.** It counts every live session with
  `certificates_required && !certificates_validated`, independent of identity and authentication.
  Successful validation flips `certificates_validated` under the write lock and immediately removes
  that session from the count. Idle reaping removes it. Per-message 30-second timeouts, empty/invalid
  certificate responses, and other non-terminal gate outcomes intentionally leave the gate pending so
  a later valid response can succeed. Terminal handshake errors also leave it pending, which is finding
  1 because those attempts have no remaining handshake waiter/recovery path.
- **The 7 x 8 arithmetic holds for the stated adversarial hold.** Seven valid pending sessions can
  retain at most eight general-dispatch permits each, totaling 56 of the peer-global 64. A validated
  or legacy non-gated session can use the remaining eight, so this is not a reservation that makes
  global exhaustion impossible under mixed traffic; it guarantees that the seven pending sessions
  alone cannot consume all 64. That matches the stated purpose and is not an arithmetic defect.
- **Normal-load denial is part of the hard cap.** An eighth simultaneous certificate-gated handshake
  is rejected even when all seven predecessors are legitimate. That is the direct availability
  tradeoff of the requested cap. Finding 1 is worse: already failed, unauthenticated attempts occupy
  those slots for 15 minutes.

### C. F1/F2 interaction

An F1 mismatch returns before authentication or certificate validation and does not remove the initiating
session. When the local peer requested certificates, that rejected session remains in the F2 count. A
single rejection does not prevent retry, but seven rejected attempts make a corrected legitimate attempt
fail at capacity until reap. The empty-discovery path does not create this state because F1 deliberately
does not reject it.

## Regression re-check

- **Head-of-line deadlock remains dead.** The receive task never awaits admission, general and control
  frames use separate semaphores, and a certificate response can run while gated general tasks wait.
  The dedicated drain/progress regressions passed.
- **Replay protection remains atomic.** The signature-then-write-locked
  `SessionManager::mark_message_seen` check-and-insert is unchanged. The concurrent identical-replay and
  gated exactly-once regressions passed.
- **No map ordering or preimage fixture moved.** `f8d82ce` changed only `peer.rs`,
  `session_manager.rs`, review text, and charter/ledger text. No certificate serializer, comparator,
  ordered map type, vector, or preimage fixture changed. The ordering/serialization regressions passed.
- **The per-session dispatch quota remains eight.** Admission is still keyed by the resolved session
  nonce and uses an eight-permit semaphore below the global 64-permit lane. The concurrency-width and
  one-session fairness regressions passed.
- **F5 is accurately text-only.** The comparator was not touched. Executing real `@bsv/sdk` 2.4.1
  reproduced `aaaa, éééé, tag_A, tag-A, zzzz`, while the registered Rust divergence remains
  fail-closed.

## Tests added by `f8d82ce`

| Test | Property pinned | Revert behavior / gap | Hang assessment |
|---|---|---|---|
| `test_inbound_handshakes_cannot_exceed_gated_session_capacity` | Sequential inbound responder admission stops at seven, across fresh identities | Reverting responder admission makes the eighth call succeed, so the test fails. It does **not** exercise initiator admission, concurrent atomicity, validation/reap release, or error-path cleanup; finding 1 passes unnoticed. | Every dispatch is wrapped by the five-second `bounded` helper; the mock channel has ample capacity. It fails rather than hangs. |
| `test_initial_response_cannot_replace_dialed_identity_with_early_frame_waiting` | A non-empty pending identity cannot be replaced, including the early-gated-frame seam | It uses three wallets and explicitly asserts `early_sender_identity != response_identity`. Reverting F1 lets the valid B response complete and makes the assertion fail. It does not cover equivalent spellings of one key. | Handshake, sends, and waiter rendezvous are bounded. The rejected early dispatch remains pending internally, but runtime teardown aborts it; the test itself does not wait on it. |
| `test_initial_response_fills_empty_discovery_identity` | The empty discovery exception still authenticates and fills the session | It passes if the **entire** F1 guard is reverted, because discovery worked before F1. It correctly guards against an over-tightened version that rejects empty, but is not mutation evidence for F1 itself. It does not cover AuthFetch reconnect/caching. | All transport and handshake waits are bounded; no hang path found. |

No new test covers uppercase/lowercase equivalence or removal of capacity after a terminal handshake
failure. The cap test is sequential, so a future check-outside-lock mutation could also pass it.

## Explicit refutations retained

- **“The regression can hang” remains refuted.** Tokio's `RwLock::read().await` participates in the
  cooperative budget; the recorded mechanical timeout result is controlling evidence. None of the
  three new tests introduces that claim again.
- **AuthFetch no-ID error misattribution remains unreachable.** `ensure_peer` still creates a private
  transport and `Peer` per base URL.
- **The identity-unknown early-frame path remains unreachable over HTTP.** One POST still yields one
  frame; accepting a general frame means there is no simultaneous `initialResponse` for that request.
- **The documentation does not claim identity fairness.** It says session-fair/cross-session. F2's
  identity-agnostic cap is the right axis because identities are free to mint.

## Verification

- `git show f8d82ce` plus full production-context and lifecycle audit.
- All three tests added by `f8d82ce` passed individually.
- `cargo test --all-features` passed, including 1,181 unit tests and all integration suites (with the
  repository's existing ignored tests unchanged).
- `cargo fmt --all -- --check` passed.
- `cargo clippy --all-targets --all-features -- -D warnings` passed.
- Executed the required package copy: `@bsv/sdk` reported version `2.4.1`; its public-key parser accepted
  and canonicalized uppercase compressed keys, and its live collation retained the registered F5
  non-ASCII divergence.
