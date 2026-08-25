# Release review — `b11ee47` simplified receive design

Reviewed branch `feat/background-receive-task` at
`b11ee47f6556bbc2b223271e13e715f28ba643a9`, 15 commits ahead of `origin/main`. The review covered
the exact simplification diff, the surrounding production paths in `peer.rs` and
`session_manager.rs`, the release-lineage regression seams, the changed tests, the recorded
refutations, and the real `@bsv/sdk` 2.4.1 package by execution only.

## Verdict

**BLOCK 0.8.0.** The three retained dispatch limits are mechanically sound, and the simplification
does remove the previous seven-handshake availability failure. However, deleting the only
gate-specific admission bound restores a deterministic way for one hostile identity to occupy all
64 general-dispatch permits for 30 seconds at a time, contrary to concurrency rule 4. Separately,
identity canonicalization is one-sided: public lookup canonicalizes, while two inbound session
writers and the session index retain raw strings. A valid uppercase inbound identity that reused an
authenticated session at `f8d82ce` now misses that session and starts another handshake.

Neither issue is speculative fairness wording or one of the refuted findings. Both follow directly
from reachable production paths.

## Ranked findings

### 1. HIGH — eight gated sessions from one identity can monopolize all 64 general slots

- **Files:** `src/auth/peer.rs:463-535`, `src/auth/peer.rs:1570-1600`,
  `src/auth/peer.rs:1919-1962`, `src/auth/session_manager.rs:115-130`,
  `docs/CONFORMANCE-AND-CONCURRENCY.md:83-106`
- **Defect:** the per-session semaphore is correctly keyed by `your_nonce` for a valid gated
  general message, but `SessionManager` deliberately allows multiple sessions for one identity.
  With the gated-session admission check gone, the same identity can create eight responder-side
  sessions and occupy eight permits on each. The arithmetic is exact: `8 sessions × 8 permits = 64`
  global general permits. Each correctly signed frame then waits inside its admitted task for the
  full 30-second certificate deadline. Later general frames from every other session are dropped at
  global admission. The separate 16-slot control lane remains usable, so this is not the old
  head-of-line deadlock; it is a repeatable denial of the complete general lane.
- **Reproduction:** configure the receiver with a non-empty `certificates_to_request`. Using one
  valid attacker key, send eight `initialRequest` messages with distinct non-empty initial nonces.
  The receiver creates eight authenticated, certificate-pending sessions for the same
  `peer_identity_key`. For each returned session, send eight correctly signed general messages and
  never send a non-empty valid `certificateResponse`. All 64 dispatches pass the per-session and
  global `try_acquire_owned` checks and wait for 30 seconds. Send one honest general frame on a ninth
  session; it is dropped with `general dispatch capacity exhausted`. Repeat after the deadlines.
- **Additional resource effect:** the 16 control permits bound only simultaneous handshake work,
  not accumulated session state. Sequential valid initial requests can create an unbounded rolling
  set of pending sessions (accepted handshake rate × the 15-minute idle TTL). Before `b11ee47`, the
  deleted count happened to cap this particular state at seven; after the deletion there is no fixed
  bound on `nonce_to_session`, the same-identity `IndexSet`, or their `SessionMeta` entries.
- **Reference comparison:** TS 2.4.1 is worse on this axis: it admits and parks gated message work
  without a dispatch bound. Rust still has a strict 64-task ceiling and therefore satisfies
  concurrency rule 1. Go has no certificate gate, so withholding a `certificateResponse` cannot
  produce this 30-second hold there. Those comparisons justify deleting the old *handshake-refusal
  mechanism*, which was a hard Layer-1 divergence and created its own seven-request DoS, but they do
  not satisfy Rust's separate rule 4: no blocking wait may consume every slot on a shared dispatch
  path.
- **Impact:** an authenticated hostile peer can deny all later general traffic in deterministic
  30-second windows while control traffic continues. The work is bounded, but there is no reserved
  general capacity for another session once eight gated sessions exist.
- **Confidence:** high. The semaphore acquisition and lifetime are explicit, a spawned task holds
  both permits across `wait_for_certificate_validation`, multiple sessions per identity are an
  intentional manager property, and the existing tests independently measure the exact 8 and 64
  limits.
- **Provenance:** **reintroduced by `b11ee47`** by deleting the total gated-session admission check.
  The multi-session capability and 30-second permit hold predate the commit; `f8d82ce` added the
  seven-session bound specifically to prevent their product from reaching 64.

### 2. MEDIUM — one-sided canonicalization makes valid inbound uppercase sessions invisible to public reuse

- **Files:** `src/auth/peer.rs:1229-1257`, `src/auth/peer.rs:1383-1449`,
  `src/auth/peer.rs:1929-1957`, `src/auth/session_manager.rs:115-180`
- **Defect:** `get_authenticated_session` now parses and canonicalizes every non-empty caller key to
  lowercase compressed DER before lookup. The session index remains raw-string keyed. Responder-side
  `handle_initial_request` parses `msg.identity_key` but stores the original string at line 1951, and
  empty-identity discovery stores the raw `initialResponse.identity_key` at line 1443. Consequently,
  a valid uppercase compressed key can be accepted and indexed uppercase, but a later call with that
  exact uppercase key is converted to lowercase before lookup and cannot find the authenticated
  session.
- **Reproduction:** send a valid `initialRequest` whose compressed identity key is uppercase. The
  parse at line 1929 succeeds and the responder inserts an authenticated session under the uppercase
  string. Then call `get_authenticated_session(uppercase_key)`, `send_message(uppercase_key, ...)`,
  or—most importantly for the documented listener workflow—
  `send_certificate_response(uppercase_key, ...)`. The public path canonicalizes to lowercase,
  misses the uppercase secondary index, and initiates a new handshake. While that lowercase session
  is pending, repeated calls do not return it because it is unauthenticated, so each call can create
  another session. At parent `f8d82ce`, the same raw uppercase lookup reused the existing session.
- **Discovery variant:** when the pending identity is empty, the F1 exception correctly permits the
  response to fill it, but a valid uppercase response is stored raw. A later non-empty lookup for the
  discovered key canonicalizes and misses in the same way.
- **Remaining raw comparisons:** F1 at lines 1386-1388 compares the canonical known-identity pending
  string with the raw response string, so an uppercase spelling of the same response key is still
  rejected before cryptographic parsing. The general-message binding at lines 2118-2122 also compares
  raw strings. These comparisons are security guards and must remain identity-binding, but the
  surrounding writers do not currently establish a single canonical string invariant for them.
- **Impact:** a valid uppercase public-key spelling accepted by both parsers can cause unnecessary
  handshakes, 30-second waits on transports without the matching response path, duplicate sessions,
  and failure of the certificate-request listener guidance to reuse the session that delivered the
  request. Normal Rust and TS peers emit canonical lowercase identities, so ordinary cross-SDK
  traffic is unaffected; externally supplied valid casing is affected.
- **Confidence:** high. Live `@bsv/sdk` 2.4.1 execution reported version 2.4.1, accepted an uppercase
  compressed key, and canonicalized it to the same lowercase key. The Rust parser does likewise. The
  raw writer, raw index, and canonical lookup are direct and there is no fallback equivalence lookup.
- **Provenance:** the **lookup/index namespace split is introduced by `b11ee47`**. Raw inbound storage
  predates it. The raw F1 rejection of an equivalently cased response was introduced by `f8d82ce` and
  remains in the 0.8.0 lineage.

## Required attack results and explicit refutations

### A. What deleting the cap did and did not reopen

- **Per-session bound confirmed.** A valid gated general frame must carry the receiver-created
  `your_nonce`; that nonce selects both the real session and the per-session semaphore. Eight permits
  can be held; the ninth frame for that session is dropped. Random fake `your_nonce` values can create
  short-lived semaphore keys before validation, but they fail nonce/session resolution and cannot
  occupy a 30-second gated wait.
- **Global bound confirmed.** The receive task uses non-blocking `try_acquire_owned` on a 64-permit
  semaphore before spawning. A task owns the permit until dispatch returns. No 65th general dispatch
  task exists. The measured-width regression reached exactly 64 and rejected the overflow.
- **Control isolation confirmed.** Non-general frames acquire only the independent 16-permit control
  semaphore. A full general lane cannot put the releasing `certificateResponse` behind a general
  permit, so the head-of-line deadlock stays dead.
- **The old cap's defects are real.** Seven well-formed pending handshakes were sufficient to make an
  eighth legitimate handshake fail, and the previous failure-state retention made that admission DoS
  especially cheap. Deleting that mechanism fixes both effects. It does not refute finding 1's
  separate 64-slot hold.
- **TS/Go do not supply the missing Rust guarantee.** TS tolerates unbounded parked gated work; Go
  omits the gate. Rust is safer than TS under rule 1 but still fails its own rule 4 once eight sessions
  are pending.

### B. Canonicalization and F1

- **Known outbound uppercase calls work.** The caller key is parsed and re-encoded before the pending
  session is created. An ordinary lowercase response therefore equals the pending identity, passes
  F1, and is indexed canonically.
- **Repeated outbound uppercase calls reuse one session.** The changed regression performs a real
  handshake and general delivery, looks the session up by lowercase, then calls
  `get_authenticated_session` again with uppercase and asserts the same nonce. That property is pinned.
- **Invalid non-empty callers now fail earlier.** They are rejected by `parse_public_key` before a
  new initiating session is created. Under the immediately preceding F1 behavior they could not
  complete as a known-identity handshake anyway, because the eventual response identity would not
  match the invalid pending string.
- **F1 still binds different identities.** A non-empty pending identity must equal the response
  identity before signature verification and session promotion. The distinct-key early-frame
  regression passed. The empty discovery identity remains fillable and its regression passed.
- **Refutation boundary:** the outbound property does not cover raw inbound or uppercase discovery
  writers. That uncovered namespace split is finding 2.

### C. Inbound parse before session creation

- An unparseable `initialRequest.identity_key` returns at line 1929, before nonce creation, session
  insertion, activity metadata, certificate observers/listeners, certificate lookup, signing, or
  transport send. No session is created for that string.
- For a valid identity, the parsed `peer_pubkey` is reused by both certificate proof generation and
  response signing. Nothing downstream depended on parsing later; moving it earlier only removes
  side effects for malformed input.
- The regression is mutation-relevant: restoring the old parse position inserts a raw invalid
  session before the parse fails, making its final zero-session assertion fail.

### D. Release-lineage regression re-check

- **Head-of-line deadlock:** refuted. General dispatch is spawned independently; admission never
  awaits; control has its own lane; certificate release can always be dispatched subject to its own
  16-slot bound. The targeted regressions and full suite passed.
- **Replay atomicity:** retained. Signature verification precedes one write-locked
  `mark_message_seen` check-and-insert. Sixteen concurrent copies still produce exactly one success
  and fifteen replay errors; the gated exactly-once regression also passed.
- **Map ordering and preimages:** unchanged by `b11ee47`. The commit touches only `peer.rs` and
  `session_manager.rs`; no ordered map type, serializer, comparator, conformance vector, or preimage
  fixture moved. Ordering, wallet-serializer, auth-conformance, and interop tests passed.
- **F1 identity binding:** retained for genuinely different keys, with the empty discovery exception.
  Finding 2 concerns equivalent string spellings and index canonicality, not removal of the binding.

### E. Changed-test quality

| Test | Assessment | Revert/mutation behavior | Hang assessment |
|---|---|---|---|
| `test_eight_concurrent_gated_handshakes_complete` | Eight futures are alive together under `join_all`; the receiver's non-empty certifier request makes every created session gate-pending, and no certificate response is sent. Eight responses are also asserted. | Restoring the exact seven-session cap makes one result return `certificate-gated session capacity exhausted`, so the result loop fails. This remains true even if scheduling happens to serialize some wallet work because the first seven pending sessions remain counted. | The entire `join_all` is inside the five-second `bounded` helper; the mock response channel has capacity 32 for eight sends. It fails rather than hangs. |
| `test_background_receive_accepts_uppercase_identity_without_caller_pump` | Exercises the public uppercase caller through a real handshake, general send/delivery, lowercase lookup, and repeated uppercase reuse. | Removing caller canonicalization restores the F1 casing failure before successful send; removing canonical reuse changes the nonce assertion. It does not cover raw uppercase inbound or discovery sessions (finding 2). | Handshake/send, receive, and repeat reuse are time-bounded. The intervening read-lock lookup is immediate under the production no-lock-across-await invariant. |
| `test_initial_request_identity_is_parsed_before_session_insert` | Preserves the existing valid empty-match response assertion, then sends an invalid identity and checks both rejection and absence from the raw identity index. | Moving the parse back below insertion leaves one invalid session, so the zero-session assertion fails. | Dispatch is bounded; the final read-lock lookup has no blocking producer and completed in the suite. |

No changed test contains an unbounded protocol receive, handshake, dispatch, or waiter rendezvous. This
does not revive the recorded Tokio hang claim; that claim remains mechanically false.

## Recorded refutations retained

- **Tokio hang claim:** not reopened. The prior cooperative-scheduling experiment remains controlling,
  and the changed tests' semantic waits are explicitly bounded.
- **AuthFetch no-ID error misattribution:** not reopened; the claimed cross-request state remains
  unreachable with AuthFetch's private peer/transport topology.
- **Identity-unknown early frame over HTTP:** not reopened; one HTTP response cannot simultaneously
  supply the early general frame and the `initialResponse` needed to complete that request.
- **Documentation identity fairness:** not reopened. The charter does not claim an implemented
  per-identity quota. Finding 1 instead applies the charter's explicit rule that a blocking wait may
  not consume every shared dispatch slot, and demonstrates the exact reachable 64-slot state.

## Verification

- `git show b11ee47` and full production-context audit of both changed files.
- `cargo test --all-features -q` passed: 1,178 unit tests passed, 3 ignored, plus every integration
  suite and doc test with zero failures.
- The focused concurrency, F1, uppercase, invalid-identity, replay, ordering, and auth-conformance
  regressions all passed within that run.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --all-targets --all-features -- -D warnings` passed.
- Executed (did not read) the supplied TypeScript package: it identified itself as
  `@bsv/sdk` 2.4.1; its public-key parser accepted an uppercase compressed key and returned the same
  canonical lowercase key.
- `git diff-tree b11ee47` confirms only `src/auth/peer.rs` and
  `src/auth/session_manager.rs` changed; no fixture or order-bearing serializer moved.

## Plain release decision

**Yes, I would block 0.8.0 at `b11ee47`.** The simplification is directionally good and most of its
intended properties are proven, but it currently trades the broken seven-handshake cap for a reachable
violation of the release's binding concurrency policy, and it leaves the new identity canonicalization
inconsistent with valid inbound session storage.
