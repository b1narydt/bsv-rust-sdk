# Adversarial review 2 — background receive fixes

Reviewed `70afcbb` at HEAD on `feat/background-receive-task`, against parent `57f7d20`, the charter,
the ledger, `ROUND8-REVIEW.md`, full-file context, and executable `@bsv/sdk` 2.4.1 behavior from the
required package copy.

## Verdict

**BLOCK.** B3 is structurally correct, the narrow one-session form of B2 is fixed, and most of B1's
new ordering is sound. However, B1 can now deliver a frame after the session has been promoted to a
different identity, B2 remains bypassable by opening multiple sessions, and B4 can route an
uncorrelated background error to the sole in-flight request. The comparator is also still not
byte-exact for legal non-ASCII certificate field names. Two of the changed concurrency tests do not
meet the charter's deterministic-failure requirement.

## Ranked findings

### 1. BLOCKER — the post-gate reload does not re-bind the verified frame to the promoted session

- **Files:** `src/auth/peer.rs:1553-1582`, `src/auth/peer.rs:1378-1443`,
  `src/auth/peer.rs:2097-2108`
- **Defect:** the pending path verifies the general frame against the pre-wait session identity, waits,
  reloads by nonce, and checks only `is_authenticated`. `complete_handshake` is allowed to replace
  that nonce's `peer_identity_key` with `response.identity_key`. The reloaded session is never checked
  against `msg.identity_key`, and the signature is not checked against the reloaded binding. Replay
  state is then committed to the replacement session and the old-identity payload is delivered.
- **Concrete reproduction:** initiate a certificate-requesting handshake for identity A. Before the
  `initialResponse`, enqueue a general frame signed by A for the initiating nonce; it passes
  `resolve_general_message_session` and the pre-gate signature check. Then provide a correlated,
  correctly self-signed `initialResponse` from identity B with a valid requested certificate for B.
  `complete_handshake` promotes the same nonce to authenticated B and resolves the gate. Lines
  1563-1582 reload B, check only the boolean, mark A's message nonce in B's replay set, and deliver the
  message as A. Changing the new test at `src/auth/peer.rs:5012-5061` to use distinct early-frame and
  response wallets exercises this exact path.
- **Confidence:** high. The identity replacement and missing post-reload comparison are direct control
  flow; `git blame` confirms the authentication check moved after the gate in `70afcbb` while the
  reload does not repeat the identity invariant enforced at lines 2097-2108.
- **Provenance:** **introduced by `70afcbb`** for delivery/replay. The broader fact that a correlated
  handshake response can replace the requested identity pre-existed, but before `70afcbb` the
  unauthenticated early frame was rejected before waiting and could not cross that replacement.

### 2. HIGH — the 8-slot quota is session-fair, not identity-fair, so one identity can still own all 64 slots

- **Files:** `src/auth/peer.rs:463-524`, `src/auth/peer.rs:1902-1944`,
  `src/auth/session_manager.rs:115-130`, `docs/CONFORMANCE-AND-CONCURRENCY.md:97-98,125-130,155`,
  `REVIEW-LEDGER.md:234`
- **Defect:** admission is keyed only by the untrusted `your_nonce`; `SessionManager` explicitly allows
  unlimited sessions per identity, and every inbound `initialRequest` creates another session. There
  is no identity quota or session-count cap. The new quota therefore prevents one *session* from
  consuming 64 waits, but not one remote identity. The 16-slot control lane is likewise peer-global
  and has no identity/session sub-quota.
- **Concrete reproduction:** configure the receiver to request a non-empty certificate set. Identity A
  opens eight inbound handshakes and withholds the requested certificates. For each returned session
  nonce, A sends eight correctly signed general frames. All 64 frames verify and wait for 30 seconds,
  holding eight per-session permits and every global permit. An authenticated, validated identity B's
  next general frame then fails the global `try_acquire_owned` and is dropped. Repeating this before
  the waits expire gives A continuous starvation. The added test at `src/auth/peer.rs:2841-2900`
  creates only one gated session for A, so it cannot detect this bypass.
- **Confidence:** high. The quota key, unlimited one-to-many session index, and lack of any identity
  semaphore/cap are explicit.
- **Provenance:** **pre-existing starvation, incompletely fixed by `70afcbb`**. `57f7d20` allowed even
  one session to consume 64; `70afcbb` narrows that attack to eight sessions. The charter/ledger claim
  of cross-identity fairness was introduced/strengthened by `70afcbb` and is false.

### 3. HIGH — AuthFetch assigns an uncorrelated no-ID error to whichever request happens to be alone

- **Files:** `src/auth/clients/auth_fetch.rs:146-188`, `src/auth/peer.rs:562-575`,
  `src/auth/clients/auth_fetch.rs:1969-2045`, `docs/CONFORMANCE-AND-CONCURRENCY.md:85-88,140-145`
- **Defect:** when a `BackgroundError` is a general-frame error but has no 32-byte payload prefix,
  the new dispatcher removes and fails the sole router entry. There is no evidence that the failed
  frame belongs to that request or even to the same session. The exact same frame is ignored when two
  requests are active, making ownership depend on unrelated concurrency. This contradicts the
  charter rule that one frame's error is never returned through another call.
- **Concrete reproduction:** leave one AuthFetch request waiting in `router`, then deliver an unrelated
  general frame on the same Peer with `version = "hostile-version"` and no payload. Dispatch reports
  `{ message_type: General, request_id: None }`; lines 177-180 remove the only request and return that
  unrelated `InvalidMessage` from `fetch`. The new B4 regression always copies the real request's
  32-byte prefix at lines 2014-2018 and therefore never exercises this branch.
- **Additional correlation hole:** `background_request_id` treats the first 32 bytes of *any* payload
  of length at least 32 as an ID. `SimplifiedHTTPTransport` omits the prefix when the response's
  `x-bsv-auth-request-id` is absent or undecodable, then appends status/headers/body
  (`src/auth/transports/http.rs:272-327`). If that remaining payload is at least 32 bytes, B4 records a
  bogus ID rather than `None`, so even the sole-request fallback misses the real authentication error
  and the request returns the generic 30-second timeout.
- **Confidence:** high. Both outcomes follow directly from the new match and payload heuristic.
- **Provenance:** **introduced by `70afcbb`** for cross-frame misattribution. Missing/unusable IDs
  already timed out before this commit; the bogus-ID case shows B4 is also incomplete.

### 4. MEDIUM — B1 still rejects the normal identity-unknown initiating-session state before it can wait

- **Files:** `src/auth/clients/auth_fetch.rs:385-404`, `src/auth/peer.rs:2055-2111`,
  `src/auth/peer.rs:5012-5061`
- **Defect:** AuthFetch intentionally starts its first handshake with `cached_identity.unwrap_or_default()`,
  so the pending session's `peer_identity_key` is empty until `initialResponse` authenticates it. A
  valid early general frame carries the server's real identity. `resolve_general_message_session`
  rejects that mismatch at lines 2104-2108 before B1's gate-before-auth branch is reached. The B1 test
  starts with the server identity already known, so it excludes the production identity-discovery
  state.
- **Concrete reproduction:** in `test_general_before_initial_response_is_delivered_after_handshake_validation`,
  call `get_authenticated_session("")` rather than with `identity_b`, leaving the rest of the real
  signed frame/response sequence unchanged. The early frame produces `InvalidMessage`; the handshake
  later succeeds, but no payload is delivered.
- **Confidence:** high for the code path. The path is easiest to observe on a callback/WebSocket
  transport; the synchronous HTTP transport does not normally push a general frame during its
  handshake response.
- **Provenance:** **pre-existing in `57f7d20` / incompletely fixed by `70afcbb`**, not newly introduced.

### 5. MEDIUM — the shared comparator still diverges from real TS for legal Unicode certificate field names

- **Files:** `src/auth/certificates/certificate.rs:34-89,651-688`,
  `src/wallet/serializer/certificate_ser.rs:31-38`, `REVIEW-LEDGER.md:198`,
  `docs/CONFORMANCE-AND-CONCURRENCY.md:30-50`
- **Defect:** `field_primary_weight` puts every non-ASCII character after all ASCII and then orders it
  by code point. Real Node/ICU collation does not. Certificate field validation enforces only a 1-50
  character length, not ASCII, so this reaches certificate signing and WalletWire serialization.
  The 401 committed comparator vectors contain printable ASCII only. The comment that field names are
  ASCII identifiers is not enforced.
- **Concrete reproduction with the required real package:** `@bsv/sdk` 2.4.1
  `Certificate.toBinary(false)` and a real `WalletWireProcessor`/`WalletWireTransceiver`
  `listCertificates` round trip ordered the fields
  `aaaa, éééé, tag_A, tag-A, zzzz`. The Rust comparator necessarily orders
  `aaaa, tag_A, tag-A, zzzz, éééé`, because `é` takes the `0x1_0000 + codepoint` branch. The resulting
  binary certificate bytes and signing preimage differ cross-SDK.
- **Confidence:** high; verified by executing the required 2.4.1 package, not by reading it, and by the
  explicit Rust weight function.
- **Provenance:** **pre-existing** comparator limitation. `70afcbb` correctly replaced byte sorting at
  the three touched sites for the printable-ASCII domain, but reused the incomplete comparator and
  extended its inaccurate “TS localeCompare” claim to `certificate_ser.rs`. The changelog already
  acknowledges non-ASCII divergence, but the normative charter has no registered exception and the
  ledger still calls certificate binary ordering safe.

### 6. MEDIUM — one new race regression can hang forever; the lifetime regression uses a negative timing probe

- **Files:** `src/auth/peer.rs:5130-5168`, `src/auth/peer.rs:2903-2975`,
  `REVIEW-LEDGER.md:122`, `docs/CONFORMANCE-AND-CONCURRENCY.md:181-184`
- **Defect:** `test_validation_signal_while_gate_is_pending_cannot_spin` wraps the waiter itself in
  `tokio::time::timeout` on the default current-thread runtime. Restoring the stale-`true` loop makes
  the inner future repeatedly acquire an immediately ready read lock and continue without ever
  returning `Poll::Pending`; the timeout cannot preempt a future that never yields, so the regression
  hangs instead of failing. Separately, `test_drop_final_peer_handle_stops_receive_with_dispatch_in_flight`
  asserts only that no message arrives for 100 ms after drop. It has no rendezvous proving that the
  post-drop frame reached the reverted receive task, so scheduler delay can make a reverted build pass.
- **Concrete reproduction:** restore the parent loop in
  `wait_for_certificate_validation_with_timeout` and run the first test; after the signal becomes
  stale-true it monopolizes the current-thread executor rather than reaching the 100 ms `Elapsed`.
  For the lifetime test, restore the sender to `PeerInner` and delay receive-task polling beyond
  100 ms; the assertion passes even though admission remains live.
- **Confidence:** high for the non-yielding timeout; medium-high for the lifetime false-pass window.
- **Provenance:** **introduced by `70afcbb` as test defects**. Production stale-watch handling and the
  B3 lifetime split themselves are correct. Ledger row #33's claim that every regression fails on a
  deadline is therefore false.

## Explicit attack results and refutations

### A. B1 state enumeration

| Arrival state | Result at `70afcbb` |
|---|---|
| Not authenticated, gate pending, identity already known | Signature is verified before waiting; invalid frames do not get a 30-second wait. Promotion to the **same** identity then reloads, authenticates, marks replay exactly once, and delivers. Correct. |
| Authenticated, gate pending | Same wait/reload path; successful validation commits replay once and delivery once. Correct unless the nonce's identity is replaced while waiting (finding 1). |
| Not authenticated, no gate | Returns `NotAuthenticated` before signature/replay/delivery. Correct for the stated ordering. |
| Promoted during wait | Same-identity promotion works. Different-identity promotion is not re-bound (finding 1). Identity-unknown pending sessions never reach the wait (finding 4). |
| Reaped during wait | Reap removes the session and signals/removes the waiter. The post-registration or post-signal read returns `SessionNotFound`; the later reload also fails closed. Correct. |

Replay marking remains atomic and occurs exactly once on every accepted path: the pending path calls
only `mark_general_message_seen`; the ordinary path calls it through
`verify_general_message_with_session`; every verification/gate/auth/reap error returns before marking.
Signature verification precedes the 30-second gate wait, so an invalid/unsigned peer cannot hold a wait
slot. A correctly signed but certificate-withholding peer can hold one, which is why B2's fairness is
load-bearing.

### B. B2 semaphore mechanics

The 8-permit quota is genuinely enforced for one `your_nonce`. Both permits are owned RAII values moved
into the dispatch task, so normal return, error, panic unwind, task abort, or runtime shutdown drops them.
If global acquisition fails, the already-acquired session permit is dropped on `continue`. Both
acquisitions are non-blocking `try_acquire_owned` calls with no await between them; there is no semaphore
lock-order deadlock. Weak per-session semaphore entries are pruned and do not retain permits. The
remaining defect is scope/fairness, not a leak or deadlock (finding 2).

### C. B3 lifetime split

Refuted as a source defect. The only shutdown sender is
`Peer::_receive_task_lifetime` (`src/auth/peer.rs:289-294`), outside `PeerInner`. Application
`Peer::clone` clones that sender; the two manually constructed internal handles set it to `None`.
There is no production path that turns an internal handle back into an application handle. Dropping
the final application clone closes the watch channel; the biased receive select stops admission.
Already-spawned dispatches retain `PeerInner`, the transport, channels, and RAII permits long enough to
finish safely, then release them. Tokio runtime teardown aborts and drops those tasks without retaining
the sender. No lifetime cycle was found. Finding 6 concerns only the strength of the regression test.

### D. B4 channel behavior

Errors with an authentic 32-byte response prefix are routed correctly, and concurrent requests with
different random prefixes cannot steal those errors. The error channel is deliberately bounded at 128
and best-effort, so a dropped real error still degrades to the existing 30-second timeout; the charter
records that limitation. AuthFetch takes the one `on_error()` receiver for its private Peer, so it does
not starve another reachable AuthFetch consumer. Standalone Peer users retain the receiver themselves.
The no-ID fallback is not correlated and is a real defect (finding 3).

### E. B5 duplicate headers and printable-ASCII ordering

The duplicate rejection is properly registered at
`docs/CONFORMANCE-AND-CONCURRENCY.md:156` and has a site comment at
`src/auth/clients/auth_fetch.rs:1311-1318`. Executing real 2.4.1 produced both normalized entries in
original object order:

- `X-BSV-Foo, x-bsv-foo` -> `first, second`
- `x-bsv-foo, X-BSV-Foo` -> `second, first`

Rust cannot reproduce either order from a `HashMap`; rejection is a coherent registered divergence.
It can reject a caller/framework that constructs both spellings, but HTTP header names are
case-insensitive, so those are not two semantically distinct headers. The behavior is breaking but not
an unregistered defect.

Executing real 2.4.1 also confirmed the changed printable-ASCII cases:

- AuthFetch request headers: `x-bsv-tag_a` before `x-bsv-tag-a`.
- SimplifiedFetchTransport response headers: `authorization`, `x-bsv-tag_a`, `x-bsv-tag-a`.
- Certificate binary/WalletWire: the same underscore-before-hyphen collation.

All three sites touched by `70afcbb` call `locale_compare_field_name`, and the existing auth certificate
signing path does too. No touched call site was missed. Finding 5 is the comparator's domain mismatch,
not a forgotten call.

### F. Earlier refutations re-checked

- **Drain deadlock:** still dead. The receive task never awaits either semaphore, and certificate
  responses use the separate control lane. Saturation can deliberately drop a frame, but no gated
  general task owns the receive loop or the control permits it needs for release.
- **Concurrent replay atomicity:** unchanged `SessionManager` write-locked check-and-insert; the full
  suite's exactly-one concurrency regressions pass.
- **Map ordering:** no R8 keyring/fixture-order regression. Ordered auth maps remain `IndexMap`; no
  vector/fixture file changed in `70afcbb`.
- **#23:** the Rust proof-first producer path is unchanged, its wire-order regression passes, and the
  committed real-TS observation remains `initialRequest, general, certificateResponse`. The charter
  row remains accurate.

### G. Changed-test audit

The repaired paused-time dispatch deadline is now effective: it races the spawned dispatch against a
31-second outer bound and asserts the 30-second production error, without the former ready `yield_now`
loop. The three previously bare awaits identified by the commit are now surfaced/bounded. The B1
known-identity test, B4 prefixed-error test, quota width/fairness tests, duplicate rejection, and the
three printable-ASCII ordering tests all go red for their narrow reverted properties. The important
coverage gaps are findings 1-5; the two tests that themselves violate the deterministic-failure rule
are finding 6. Removing the duplicated background-error test did not lose the basic property because
`test_background_dispatch_isolates_one_message_failure_and_continues` still pins it.

### H. Ledger and charter sampling

Accurate rows include the branch name, R8-3 reap cleanup, future `Send` assertions, R8-5 multi-entry
discovery order, duplicate-header registration, and the deletion/supersession of the pull APIs.
Overclaims remain:

- R8-2/F2 say AuthFetch routes failures to the owning request without qualifying the no-ID
  misattribution (finding 3).
- Row #33 says every relevant regression fails on a deadline, contradicted by the non-yielding stale
  watch mutation (finding 6).
- Row #40 and the charter call admission cross-session/identity fair, contradicted by unlimited
  same-identity sessions (finding 2).
- The map audit calls certificate binary collation safe, but the real TS Unicode run differs
  (finding 5).

## Verification performed

- `git show 70afcbb` and full-file/context audit of all eight changed files.
- `cargo test --all-features` — passed: 1,175 unit tests, 3 ignored, and every integration suite.
- `cargo fmt --all -- --check` — passed.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.
- Required real `@bsv/sdk` copy identified itself as `@bsv/sdk` 2.4.1.
- Live 2.4.1 execution covered AuthFetch header inclusion/duplicates, SimplifiedFetchTransport signed
  response headers, `Certificate.toBinary(false)`, and a real WalletWire processor/transceiver
  certificate round trip. No conclusion above was derived by reading the TS package source.

## Independent verification disposition

The six findings above were challenged against the reachable transport topology, the pinned TS
package, and a mechanical Tokio 1.53.1 experiment. The corrected disposition is:

- **F1 — upheld at a different site, with narrower harm.** The defect is
  `complete_handshake` accepting an `initialResponse` identity that differs from a non-empty pending
  session identity, then letting `SessionManager::update_session` re-key the nonce. The post-gate
  reload is only the symptom and must not be patched. Replay state is not corrupted because it is
  keyed by the unchanged `session_nonce`, and `deliver_general_message` correctly attributes the
  frame with `msg.identity_key`. The residual harm is exactly one early frame from identity A being
  delivered on a certificate-requiring receiver without A's certificates having been validated.
- **F2 — upheld, but the proposed identity axis and documentation sub-finding are refuted.** Identity
  keys are free to mint, so an identity quota is bypassable. The reachable bound must apply to total
  concurrently gated sessions or handshake creation. The charter says `session-fair`, the ledger says
  `cross-session fairness`, and the admission row says one gated session cannot starve another; none
  claims implemented identity fairness. The 30-second hold exists only when the receiver configured a
  non-empty `certificates_to_request` set.
- **F3 — refuted as unreachable.** `AuthFetch::ensure_peer` constructs a private
  `SimplifiedHTTPTransport` and private `Peer` per base URL, and that transport enqueues a frame only
  as the direct result of AuthFetch's own send. With one route, the sole no-ID error therefore belongs
  to that route by construction. A bogus extracted ID removes no route and degrades to the existing
  30-second timeout, which is fail-safe rather than cross-request misattribution.
- **F4 — refuted as unreachable on the named path.** `SimplifiedHTTPTransport` yields exactly one
  response frame for the `/.well-known/auth` POST. If the server uses it for a general frame, no
  `initialResponse` exists and the handshake times out regardless of the identity check. A duplex
  WebSocket can reach the state, but rejecting a frame from an unknown-identity session is the correct
  fail-closed behavior.
- **F5 — upheld as a low-risk, fail-closed interoperability divergence.** Real `@bsv/sdk` 2.4.1 orders
  `aaaa, éééé, tag_A, tag-A, zzzz`, while Rust sorts the non-ASCII name last. Field validation permits
  Unicode, but the affected names are outside real issuance practice; the result is signature
  verification failure, not acceptance. The deterministic Rust comparator remains unchanged and the
  divergence is registered in the charter.
- **F6 — mechanically refuted.** On this repository's locked Tokio 1.53.1 current-thread runtime,
  repeated `tokio::sync::RwLock::read().await` participates in cooperative scheduling and the timeout
  preempts the restored loop (`elapsed=100.92ms`, `timed_out=true`). The lifetime test's 100 ms
  negative probe also has ample measured margin. Both tests remain unchanged.
