# Adversarial review — per-session general dispatch (`c8b5daa`, `9d758f6`)

Scope: `feat/background-receive-task` at `9d758f6`, reviewed as the 0.8.0 release lineage.
Combined diff `/private/tmp/ps-final.diff`; production files changed are `src/auth/peer.rs` and
`src/auth/session_manager.rs` only.

Build hygiene: every mutation experiment ran in `/private/tmp/ps-mut` (a `git archive` extract) with
`CARGO_TARGET_DIR=/private/tmp/ps-mut/target`. Nothing outside this worktree ever wrote to
`/Users/donot/PARAGON/PARAGON-code/bsv-sdk-recv/target`, and the worktree source was never modified.

---

## Verdict

**No — I would not block 0.8.0.**

The architecture change does what it claims. Both blockers recorded against `b11ee47` in
`RELEASE-REVIEW.md` are closed *structurally*, not patched: there is no shared general-dispatch
resource left for one gated peer to exhaust, because both semaphores were deleted rather than
re-tuned. I attacked liveness, worker lifecycle, eviction, replay marking, and ordering and found no
defect that changes an accepted/rejected decision, loses a frame that would otherwise have been
delivered, or can hang. Seven low-severity observations follow; none is release-blocking and five are
documentation or test-coverage items rather than code defects.

This is a refutation, and I am stating it plainly rather than padding it. The design got smaller and
the invariants got easier to prove, which is the honest reason there is nothing serious here.

---

## Ranked findings

Nothing at BLOCKER, HIGH, or MEDIUM. All seven items are LOW or informational.

### O1 — LOW — queued frames are discarded without an `on_error` report when a session is reaped or evicted

*Introduced by `c8b5daa`.* `src/auth/peer.rs:649-656` (worker's post-dispatch `has_session` check)
and `src/auth/peer.rs:1096-1102` (`cleanup_reaped_sessions` dropping the queue sender).

Reproduction: session `K` has one frame in flight and `N` frames queued. Another peer's handshake
triggers `reap_idle` or an LRU eviction that includes `K`. `cleanup_reaped_sessions` removes `K`'s
`GeneralDispatchWorker`, dropping the sender. The worker finishes its current dispatch, reads
`has_session(&session_key) == false`, and breaks; its `mpsc::Receiver` is then dropped with the `N`
frames still buffered. At most one of them surfaces a `SessionNotFound` through `Peer::on_error` (only
if the worker happened to be idle on `recv()` at the moment of removal, since tokio drains buffered
messages before returning `None`); the rest vanish silently.

Impact is observability only: every one of those `N` frames would have failed with `SessionNotFound`
anyway, because their session no longer exists. It is nonetheless a regression against the old
design, where each frame owned a dispatch task and reported its own error. Unreachable for
`AuthFetch`, which holds one `Peer` per base URL and therefore can never accumulate the 1024 sessions
required for its own session to become LRU-evictable. Confidence: high on mechanism, high that impact
is nil.

### O2 — LOW — narrow window where `try_send` accepts a frame no worker will consume

*Introduced by `c8b5daa`.* `src/auth/peer.rs:556-582` (`enqueue_general_message`) against
`src/auth/peer.rs:657-671` (the worker's exit block).

When the worker breaks out of its loop, its `mpsc::Receiver` stays alive until the async block ends —
which is after the map-removal block runs. In that window the sender is still registered and not
closed, so a concurrent `enqueue_general_message` gets `Ok(())` for a frame nobody will ever poll, and
then the worker removes the entry. Reaching it requires the session to be removed between the receive
task's `resolve_general_worker_session_key` and the worker's `has_session` check — i.e. the same
already-doomed frame class as O1. Same impact: silent instead of reported. No fix required; recorded
so a future reader does not rediscover it as new.

### O3 — LOW — general-frame queue routing inherits `getSession`'s identity-key fallback

*Pre-existing Layer-1 semantics, newly load-bearing.* `src/auth/peer.rs:539-554`
(`resolve_general_worker_session_key`) → `session_manager.rs:353-359` (`get_active_session`) →
`session_manager.rs:215-237` (`get_session_by_identifier`).

The routing key is the *resolved* session nonce, and resolution falls back from the nonce index to the
identity index. I confirmed this is normative rather than a Rust invention by running the reference
package rather than reading it:

```
$ node -e "... const m=new SessionManager(); m.addSession({sessionNonce:'NONCE_AAA',peerIdentityKey:'02abc',...});"
by nonce:    {"sessionNonce":"NONCE_AAA","peerIdentityKey":"02abc",...}
by identity: {"sessionNonce":"NONCE_AAA","peerIdentityKey":"02abc",...}
unknown:     undefined
```

So `@bsv/sdk` 2.4.1's `SessionManager.getSession` accepts either identifier, and dropping the fallback
at the routing stage would be a new Layer-1 acceptance divergence.

Consequence: on a hypothetical multiplexing (server) transport, remote `A` could put remote `B`'s
*public* identity key in `yourNonce` and land frames in `B`'s 64-slot queue, forcing overflow drops on
`B`'s legitimate frames. There is no authentication consequence — `resolve_general_message_session`
(`src/auth/peer.rs:2279`) rejects on identity mismatch before any delivery — and `B`'s surviving
frames keep their arrival order. It is not reachable with any transport in-tree: both
`SimplifiedHTTPTransport` (`src/auth/transports/http.rs:357`) and `WebSocketTransport`
(`src/auth/transports/websocket.rs:221`) are single-counterparty *client* transports.

It is also strictly better than what it replaced. Under the deleted design the sub-quota key was the
*lexical* `your_nonce.unwrap_or(identity_key)` string, so an attacker could mint arbitrary bucket keys
and drain the global 64-permit lane, dropping *every* session's frames — the exact blocker recorded in
`RELEASE-REVIEW.md`. The residual here is confined to one queue and is reported.

Suggestion (not a release condition): one clause in the charter noting the residual, or a
per-(session, claimed-sender-identity) sub-bound if a multiplexing server transport is ever shipped.

### O4 — LOW — canonicalization is applied to stored keys but not to lookup arguments or delivered keys

*Introduced by `c8b5daa`.* `src/auth/peer.rs:1139-1160` (`session_by_identifier`,
`sessions_for_identity`) versus `src/auth/peer.rs:1375-1379` (`get_authenticated_session`, which *does*
canonicalize its argument), and `src/auth/peer.rs:2414` (`deliver_general_message` hands the
application `msg.identity_key` — the raw wire spelling).

The session index now holds canonical DER hex. An application that receives
`(identity_key, payload)` from `on_general_message()` and calls `sessions_for_identity(identity_key)`
gets an empty result whenever the peer spelled its key uppercase or uncompressed. The new test
`test_uppercase_inbound_identity_is_stored_and_matched_canonically`
(`src/auth/peer.rs:2950-3006`) asserts exactly this asymmetry as intended behaviour.

Unreachable with `@bsv/sdk` peers, which always emit compressed lowercase hex. Cheapest fixes: parse
the argument in `session_by_identifier`/`sessions_for_identity`, or deliver the canonical key. Either
is a one-line change and neither is required for 0.8.0.

### O5 — LOW — the cap's disclosure emphasises only the abandoned-session direction

*Introduced by `c8b5daa`.* `docs/CONFORMANCE-AND-CONCURRENCY.md` divergence row (session cap) and
`src/auth/session_manager.rs:138-166`.

`MAX_SESSIONS = 1024` with LRU eviction means a peer that can drive handshakes evicts *live* sessions,
not only abandoned ones: 1025 `initialRequest` frames displace everything, including an outbound
handshake sitting in its 30-second window — `complete_handshake` then returns "session evicted during
handshake" (`src/auth/peer.rs:1604-1609`). The charter row does say "expiry or LRU eviction requires a
new handshake", so this is disclosed, but the surrounding prose only argues the "abandoned sessions
cannot refuse a legitimate handshake" direction.

I want to be explicit that the *design choice* is correct. `initialRequest` carries no signature, so
identity at admission time is unauthenticated and a per-identity cap would be spoofable — global LRU
is the right axis, and the failure mode is a bounded re-handshake rather than corruption or
unbounded memory. Suggest one clarifying clause; nothing more.

### O6 — LOW (test gap) — no regression covers teardown of an *LRU-evicted* session's peer-owned state

`test_session_reap_cleans_all_peer_owned_nonce_state` (`src/auth/peer.rs:6126`) covers only the
TTL-reap path. `test_session_cap_evicts_abandoned_lru_and_admits_new_handshake`
(`src/auth/peer.rs:3503`) asserts map membership but not that the evicted session's general worker,
handshake waiter, and certificate waiter were torn down.

The wiring is correct today — both handshake sites `.extend` the eviction list into `reaped` before
calling `cleanup_reaped_sessions` (`src/auth/peer.rs:1427-1436` and `src/auth/peer.rs:2099-2120`) —
but a refactor that dropped the `.extend` would leak a worker task, a 64-slot channel, a handshake
waiter, and a certificate waiter per eviction with no test going red.

### O7 — informational — `uses_general_worker` pins the predicate, not the call site

`src/auth/peer.rs:2491-2508`. Two theoretical gaps: the test exercises the pure function rather than
the receive loop's use of it, and its four-element array is not compile-time exhaustive over
`MessageType`. Both are covered in practice — `MessageType` has exactly five variants
(`src/auth/types.rs:37-53`), `matches!(_, MessageType::General)` routes any future variant to the
*control* lane (the safe side), and the call site is pinned behaviourally by three other tests (see
the mutation evidence below). A `match` with no wildcard in the test would close the enum gap for
free.

---

## Answers to the specific questions

### A. Liveness

**No path exists where a session worker's progress depends on work only that same worker can
perform.** The certificate gate is released by exactly three producers, none of which runs on a
session worker:

1. `process_certificate_response` → `finish_certificate_exchange` (`src/auth/peer.rs:2054-2059`),
   dispatched on the 16-slot control lane. Crucially the gate is committed **before**
   `fire_certificates_received_listeners` (`src/auth/peer.rs:2065`), so a slow or hung application
   listener — which is globally serialised through the certificate-delivery worker at
   `src/auth/peer.rs:868-946` — cannot delay the release.
2. `complete_handshake`, which runs in the caller's own task after `route_initial_response` resolves
   its nonce-keyed waiter.
3. `cleanup_reaped_sessions` → `resolve_certificate_validation` (`src/auth/peer.rs:1108-1110`), which
   signals waiters for removed sessions so they fail fast rather than hang.

**No lock is held across an await.** I read every production `session_manager.write().await` site
(`src/auth/peer.rs:1117, 1427, 1603, 1864, 2008, 2103, 2390`); each is either a single synchronous
statement or a block that closes before the next await. `cleanup_reaped_sessions` is always called
*after* the write guard's block ends. So the receive task's new
`session_manager.read().await` inside `resolve_general_worker_session_key` cannot be parked behind
long-running work.

**The receive task can never block on a full session queue.** `enqueue_general_message` uses
`try_send` exclusively (`src/auth/peer.rs:563` and `:586`); the `Full` arm calls `drop(workers)`
before reporting so it does not hold the map mutex across the error path. `deliver_general_message`
also uses `try_send` (`src/auth/peer.rs:2420`), so an absent or slow application consumer cannot park
a worker either.

**`uses_general_worker` pins what it claims** — mutation-proven, see below, subject to O7.

### B. Worker lifecycle

- **Spawned** lazily on the first general frame for a session (`src/auth/peer.rs:584-599`).
- **Stops** on shutdown-watch fire, `Weak<PeerInner>` upgrade failure, `recv()` returning `None`
  (sender dropped by `cleanup_reaped_sessions`), or the post-dispatch `has_session` check
  (`src/auth/peer.rs:618-656`).
- **Lazy-spawn race: impossible.** The check-insert-spawn sequence holds the
  `general_dispatch_workers` `StdMutex` across the whole decision, so two enqueues cannot both create.
  The `Closed` arm's `continue` drops the guard before the loop re-locks, so it cannot self-deadlock.
  The worker's self-removal is id-guarded (`src/auth/peer.rs:664-669`), so a worker can never remove a
  successor's entry.
- **Leak after removal/eviction/`Peer` drop: no.** Workers hold only `Weak<PeerInner>` between
  messages and carry `_receive_task_lifetime: None`, so they cannot keep the receive task or the peer
  alive. Both `tokio::select!` arms are biased on the same shutdown watch the receive task uses.
  Proven by `test_general_worker_exits_after_its_session_is_removed` (`:3652`) and
  `test_drop_final_peer_handle_stops_receive_with_dispatch_in_flight` (`:3565`), which now asserts the
  in-flight dispatch is actually cancelled (`probe.active` returns to 0).
- **Outlive the runtime: no.** Tokio aborts tasks at runtime shutdown; nothing detaches a thread.
- **Steady-state bound.** A worker exists only for a session resolvable by `get_active_session`, so
  the live count is bounded by `MAX_SESSIONS = 1024`, plus short-lived stragglers whose session was
  evicted mid-dispatch — those are released within a poll because `cleanup_reaped_sessions` signals
  their certificate waiter. An idle-expired session's worker parks on `recv()` until the next
  handshake reaps it; that is 1024 parked tasks worst case, which is the intended bound.
- **Queued frames on eviction:** discarded — see O1.

### C. Session cap and eviction

- **Can a peer evict a legitimate session?** Yes, with ~1025 handshakes — see O5. Disclosed,
  deliberate, and the correct axis given unsigned `initialRequest`.
- **Is LRU deterministic?** Yes. `least_recently_used_nonce` (`src/auth/session_manager.rs:168-181`)
  keys on the strictly monotonic `activity_sequence` with a `nonce.as_str()` tiebreak, so the
  `HashMap` iteration order of `nonce_to_session` cannot influence the result. Mutation-proven below.
- **Is "reap expired, then evict LRU" correct?** Yes. Both handshake sites call
  `mgr.reap_idle(now)` and only then `add_session_capped(..., MAX_SESSIONS)`
  (`src/auth/peer.rs:1427-1436`, `:2099-2120`), so an expired session is always preferred over a live
  one. `add_session_capped` cannot evict the incoming nonce (it is not yet in the map) and the `while`
  loop terminates after one eviction since `len` then drops below `max`.
- **Can eviction race an in-flight handshake or an active worker?** It can, and both races land
  safely. A pending outbound session evicted during its 30-second window makes `complete_handshake`
  return `SessionNotFound` at `src/auth/peer.rs:1604-1609` via `update_session`'s
  "do not resurrect a removed session" guard. An evicted session with a parked worker has its
  certificate waiter signalled by `cleanup_reaped_sessions`, the worker re-reads the session, gets
  `SessionNotFound`, reports it, and exits. No corruption, no hang.

### D. Replay marking

**Exactly once per frame, confirmed.** Both branches of `dispatch_general_message` converge on exactly
one `mark_general_message_seen`: the gated branch verifies the signature, waits, reloads and
re-checks the session, then marks at `src/auth/peer.rs:1751`; the ungated branch marks once inside
`verify_general_message_with_session` at `src/auth/peer.rs:2439`. Sequential per-session dispatch does
make this easier — there is at most one frame in flight per session by construction.

- **Across worker restart:** a message is consumed from the channel exactly once and never requeued.
  While the session and peer are alive the worker never exits (every break arm implies session-gone or
  peer-gone), so there is no restart to straddle.
- **Queue-overflow drops:** the dropped frame never enters `dispatch_general_message`, so it is never
  marked.
- **Eviction:** `mark_message_seen` returns `MarkSeen::SessionGone` and the frame is rejected
  (`src/auth/session_manager.rs:381-383`); `remove_session` drops the whole `SessionMeta` including
  the seen-set.
- Atomicity is unchanged: check-and-insert under one `&mut self` write lock
  (`src/auth/session_manager.rs:375-409`). `test_general_messages_are_dispatched_in_session_arrival_order`
  asserts `seen_nonce_count(&session) == MESSAGE_COUNT`.

### E. Ordering

**Same-session ordering is now guaranteed by construction**, and the guarantee is real rather than
incidental: a single-consumer FIFO `mpsc` feeds a worker that awaits each `dispatch_general_message`
to completion before the next `recv()`.

- **Under overflow:** `try_send` rejects the *newest* arrival, so survivors keep arrival order.
  `test_general_worker_queue_overflow_drops_newest_without_stalling_receive` (`:3325`) pins this
  precisely: one frame in flight and parked at the gate, exactly 64 queued, frame 66 rejected with its
  request ID asserted, all 65 accepted frames delivered in order, and `try_recv()` then empty.
- **When a gated frame parks ahead of queued frames:** later frames wait in arrival order behind it
  and drain in order on release — `test_certificate_response_bypasses_its_session_general_worker`
  (`:3220`) shows the parked frame delivered first, then the queued one.
- One caveat worth stating: the guarantee covers transport-delivered frames. `Peer::dispatch_message`
  remains `pub` for server middleware (`src/auth/peer.rs:1687-1710`) and bypasses the worker entirely,
  so a middleware that pumps frames itself gets neither ordering nor the per-session bound. That is
  the documented direct-dispatch escape hatch, not a defect.

### F. Regression re-check — all four hold

- **No map ordering or preimage fixture moved.** `git show --stat` for both commits touches only
  `CHANGELOG.md`, `REVIEW-LEDGER.md`, `docs/CONFORMANCE-AND-CONCURRENCY.md`, `src/auth/peer.rs`,
  `src/auth/session_manager.rs`. No vector, fixture, or order-bearing serialiser. The `IndexMap`
  keyring and `IndexSet` identity index are untouched; the only `SessionMeta` change is the added
  `last_used_order` field.
- **The identity guard in `complete_handshake` binds.** `src/auth/peer.rs:1535-1541` now compares
  canonical DER hex on both sides. The pending side is canonical because `initiate_handshake` is
  reachable only from `get_authenticated_session` (`src/auth/peer.rs:1399`), which parses and
  canonicalises its argument at `:1375-1379`. Pinned by the pre-existing
  `test_initial_response_cannot_replace_dialed_identity_with_early_frame_waiting` plus the new
  `test_uppercase_initial_response_matches_canonical_pending_identity` (`:3009`).
- **Replay marking is atomic.** Unchanged: one write lock, one check-and-insert.
- **The receive task exits when the last application-facing `Peer` handle drops.**
  `test_drop_final_peer_handle_stops_receive_with_dispatch_in_flight` (`:3565`) passes and now
  additionally proves worker cancellation.

Additionally, and worth recording because it is easy to lose in a routing refactor: general frames now
bypass `dispatch_message`, whose only pre-match logic was the auth-version check. `c8b5daa` correctly
re-adds the identical check at the top of `dispatch_general_message` (`src/auth/peer.rs:1719-1724`),
so no validation was dropped in the move.

**Prior blockers closed.** `RELEASE-REVIEW.md` blocked at `b11ee47` on (a) one gated identity reaching
the shared 64-permit lane and (b) inbound identity canonicalisation inconsistent with session storage.
Both are structurally closed: there is no shared general-dispatch permit left to exhaust, and
`handle_initial_request` now stores `peer_pubkey.to_der_hex()` (`src/auth/peer.rs:2109`) with a
dedicated regression. `RECV-REVIEW2.md` finding 2 ("session-fair, not identity-fair, so one identity
can own all 64 slots") is likewise moot — there are no shared slots.

### G. Test quality — per test added by these two commits

All eight use the `bounded` helper (`src/auth/peer.rs:2485-2489`), a 5-second `tokio::time::timeout`
that `expect`s. **Every busy-wait loop in the new tests is wrapped in `bounded`.** I found no test
that can hang rather than fail, which matters because `cargo test` has no per-test timeout. The
mutated run that turned four tests red completed in 7.51s, confirming they time out and fail rather
than block.

| Test | Property pinned | Would it pass reverted? | Hang risk |
|---|---|---|---|
| `test_only_general_frames_use_session_worker` (`:2492`) | Only `General` uses a session worker; all four control types bypass | No — mutating the predicate to `General \| CertificateResponse` makes it fail. Pins the predicate, not the call site (O7) | None; pure sync unit test |
| `test_gated_session_worker_does_not_block_another_session` (`:3034`) | A's second frame cannot enter verification beside A's parked frame; B dispatches three frames meanwhile | No — under the old 8-slot sub-quota A's second frame runs concurrently and the 100 ms negative probe fails | All waits `bounded`; the negative probe is an explicit 100 ms `timeout` |
| `test_general_messages_are_dispatched_in_session_arrival_order` (`:3142`) | Strict arrival order, `peak == 1`, `seen_nonce_count == 6` | No — the old design gives `peak > 1` and no order guarantee | All `bounded` |
| `test_certificate_response_bypasses_its_session_general_worker` (`:3220`) | The releasing `certificateResponse` is dispatchable while the session's worker is parked at the gate | No — mutation-proven red (below). This is the deadlock test, and it *fails* rather than hangs, which is the important property | All `bounded` |
| `test_general_worker_queue_overflow_drops_newest_without_stalling_receive` (`:3325`) | `MAX_QUEUED_GENERAL_PER_SESSION == 64`; newest-drop with the dropped request ID asserted; cross-session progress; all 65 accepted frames delivered in order and nothing extra | No — the error string and the drop semantics both differ. Dropping the oldest instead would surface the wrong request ID *and* lose an expected delivery | All `bounded`; final `try_recv` is non-blocking |
| `test_session_cap_evicts_abandoned_lru_and_admits_new_handshake` (`:3503`) | **Yes, it does what was required**: fills to `MAX_SESSIONS` with abandoned sessions, then asserts a legitimate `handle_initial_request` *succeeds*, that `abandoned-0000` (the true LRU) is gone, that the admitted nonce is present, and that `session_count` stays at the cap. Also asserts no premature eviction during the fill | No — mutation-proven red (below). Gap: fills via `add_session_capped` rather than 1024 real handshakes, and does not assert evicted-session teardown (O6) | All `bounded` |
| `test_general_worker_exits_after_its_session_is_removed` (`:3652`) | Session cleanup drops the sender and the worker task exits; `active_general_workers` returns to 0 and the map entry is gone | No — a worker that ignored session removal would spin the counter forever and fail inside `bounded` | Busy-wait is inside `bounded` |
| `test_uppercase_inbound_identity_is_stored_and_matched_canonically` (`:2950`), `test_uppercase_initial_response_matches_canonical_pending_identity` (`:3009`) | Inbound writers store canonical DER hex; the F1 guard accepts an uppercase wire spelling of the dialed key | No — reverting either writer changes the index assertion or rejects the response | All `bounded` |

---

## Mutation evidence

Run in `/private/tmp/ps-mut` with `CARGO_TARGET_DIR=/private/tmp/ps-mut/target`.

| Mutation | Result |
|---|---|
| `uses_general_worker` → `matches!(_, General \| CertificateResponse)` | **4 red in 7.51s**: `test_only_general_frames_use_session_worker`, `test_certificate_response_bypasses_its_session_general_worker`, `test_hostile_general_before_certificate_response_does_not_block_drain`, `test_certificate_request_auto_responds_with_empty_set`. All three behavioural failures panicked at `peer.rs:2488` — the `bounded` timeout — so routing control frames through the worker **fails rather than hangs**. This also closes O7's call-site concern: mutating the routing decision is caught behaviourally, independent of the predicate test |
| `least_recently_used_nonce` key `last_used_order` → `last_used_ms` (i.e. remove the monotonic tiebreak) | **1 red**: `test_session_cap_evicts_abandoned_lru_and_admits_new_handshake` panics at `peer.rs:3558`. The 1024 fill sessions share a wall-clock millisecond, so without `last_used_order` the eviction choice follows `HashMap` iteration order. The new `activity_sequence` field is genuinely load-bearing and genuinely pinned |

---

## Verification performed

- Read the full combined diff, then the surrounding production code in `src/auth/peer.rs` (receive
  loop, `enqueue_general_message`, `spawn_general_worker`, `dispatch_general_message`,
  `wait_for_certificate_validation`, `process_certificate_response`, `cleanup_reaped_sessions`,
  `deliver_general_message`, both handshake paths) and all of `src/auth/session_manager.rs`.
- Audited every production `session_manager` write-lock site for a lock held across an await.
- `cargo test --all-features`: **1185 unit tests passed, 0 failed, 3 ignored**, plus every integration
  suite (auth interop, conformance, BEEF, overlay, pushdrop, remittance) and doc-tests. Exit 0.
- `cargo test --lib --all-features auth::peer`: 72 passed, 0 failed, 3.79s.
- `cargo clippy --all-features --all-targets`: clean.
- `cargo fmt --all -- --check`: clean.
- Two mutation experiments in an isolated copy with a separate `CARGO_TARGET_DIR` (table above).
- **Executed** (did not read) `@bsv/sdk` 2.4.1 from
  `.../scratchpad/tssdk/package/dist/cjs/mod.js` to establish that `SessionManager.getSession`
  resolves by identity key as well as by session nonce — the evidence behind O3.
- Confirmed both in-tree `Transport` implementations are single-counterparty clients, bounding O3's
  reachability.
- Re-read `REVIEW-LEDGER.md`, `RECV-REVIEW2.md`, `FINAL-REVIEW.md`, and `RELEASE-REVIEW.md`; none of
  the four settled refutations (tokio non-yielding loop, AuthFetch error misattribution,
  identity-unknown early-frame path over HTTP, per-identity fairness in the docs) is reopened here.

---

## Release decision

**No, I would not block 0.8.0 at `9d758f6`.**

The two blockers from the previous round are gone by construction rather than by patch, the sequential
per-session model makes ordering and exactly-once replay marking provable instead of argued, and the
liveness argument reduces to one checkable claim — control frames never enter a general worker —
which is pinned by both a deterministic predicate test and three behavioural mutation-red tests.

O1, O2, and O4 are worth a small follow-up commit and none of them changes a protocol decision. O3,
O5, O6, and O7 are documentation and test-coverage polish. If any single item is worth doing before
tagging, it is O6 — one assertion extending the existing cap test to cover evicted-session teardown,
because that is the invariant a future refactor is most likely to break silently.
