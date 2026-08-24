# Conformance and concurrency: the design charter for the Rust port

**Status:** normative for `src/auth/**`; the principle generalises to the rest of the crate.
**Reference implementations:** `@bsv/sdk` **2.4.1** (TypeScript, normative for the wire) and
`github.com/bsv-blockchain/go-sdk` **v1.2.24** (Go, advisory for the execution model).

## Why this exists

This port has shipped three breaking releases in short order — 0.7.0 broke certificate exchange,
0.7.1 restored it, and 0.8.0 fixes a break neither caught. Every one of those was the same mistake in
a different costume: someone changed behaviour without knowing which side of the conformance boundary
they were standing on.

Two failure modes, opposite directions, equally expensive:

- **Diverging where we must conform.** A Rust-only "improvement" to a wire format, a preimage, or an
  error semantic. Invisible to every Rust↔Rust test, fatal to cross-language exchange. The keyring
  defect lived here for two releases.
- **Conforming where we should diverge.** Transliterating TypeScript's *execution model* into Rust.
  TS is single-threaded; copying its mechanisms discards the entire reason for the port, and in at
  least one case (the certificate gate) produced a deadlock TS structurally cannot have.

## The conformance boundary

> **Layer 1 — Wire and API. TypeScript is normative. Byte-exact. No divergence without a registered
> exception.**
>
> **Layer 2 — Execution model. Rust-native. Optimise freely. TypeScript's mechanism carries no
> authority here.**

**The test that assigns a change to a layer:**

> *Could a conforming TypeScript peer, using only the protocol, observe the difference?*

Yes ⇒ Layer 1: match TS exactly, and prove it with a vector.
No ⇒ Layer 2: do what is fastest and safest in Rust, and prove it with tests and benchmarks.

Applied: the bytes of a signed preimage are Layer 1. Whether we compute N of them on one thread or
`NumCPU` threads is Layer 2. The order certificates appear in a message is Layer 1. The order we
*validate* them internally is Layer 2. That a general message is not processed before certificate
validation completes is Layer 1. That we implement that by blocking a drain loop is Layer 2 — and
was wrong.

## Protocol identity

We implement **BRC-103 mutual authentication**: `AUTH_VERSION = "0.1"`, the AuthMessage envelope
(`initialRequest` / `initialResponse` / `certificateRequest` / `certificateResponse` / `general`),
protocol ID `[2, 'auth message signature']`.

**BRC-31 (Authrite) is deprecated and not implemented here.** Its discriminator is protocol ID
`[2, 'authrite message signature']`.

Decide by protocol ID, never by a file title or `brc:` tag. Both the upstream conformance corpus and
this repository's own comments mislabel BRC-103 work as BRC-31, and acting on the label leads to
wiring up vectors for a protocol we do not implement.

## Layer 1 — what is normative

Everything a peer can observe:

1. **Signed preimages.** Exact bytes. Includes key order in every serialized object, presence and
   absence of optional members, and the encoding of every scalar. `keyring` is part of the
   `certificateResponse` preimage; omitting it was the 0.7.x interop break.
2. **Map and field ordering.** Any map reaching serialization must preserve wire order — `IndexMap`,
   never `HashMap`. A randomized iteration order produces a preimage that differs *run to run*, which
   surfaces as intermittent signature failures rather than a clean red.
3. **Message shapes.** Field names, presence/absence, and the empty-versus-absent distinction
   (`certificates: []` is not the same as no `certificates` key).
4. **Protocol semantics.** Which checks run, in what order, and whether a failure rejects or is
   silently skipped. Guard conditions count: TS gating a block on `certifiers.length > 0` is
   normative, and reproducing the check without the guard is a divergence.
5. **Externally observable ordering.** What a peer can see on the wire.

**Verification is mandatory and specific:** a Layer 1 claim is established by a vector generated from
the real reference implementation, asserting byte equality in both directions. Reading the TypeScript
source and reasoning about it is how the keyring bug survived multiple readings by multiple reviewers.
It is not evidence.

## Layer 2 — the execution model

Rust may differ from both references. The obligations are stability and speed.

### Concurrency policy

0. **Isolate errors at message ownership boundaries.** Direct
   `dispatch_message` calls return their own error. Background receive/dispatch
   reports each frame's failure through `Peer::on_error`; it never stores an
   error on a session or returns one frame's failure through another call.
1. **Bound every fan-out whose width is remote-controlled.** Certificate counts arrive from a peer.
   Unbounded `join_all` over peer-supplied input is a resource-exhaustion vector. Go's cap of
   `min(len(items), NumCPU)` is the reference.
2. **Cancel siblings on first error.** Go uses `context.WithCancel`; the Rust equivalent is dropping
   the remaining futures. Do not complete work whose result is already discarded.
3. **Do not copy `Promise.all` reflexively.** In a single-threaded runtime it interleaves I/O; it is
   not a claim that parallelism is correct or worthwhile. Where Go — which has real parallelism —
   chose sequential, that judgement is better evidence than TS's.
4. **Never let one remote identity/session's work block another's.** No blocking wait may consume
   every slot on a shared dispatch path.
5. **Hold no lock across an `.await`.** Existing invariant; the `!Send` future that results breaks
   downstream `Handler` bounds in ways this crate's own tests cannot detect.
6. **Certificate-gate state is never an error-valued session latch.** The live
   state is only pending or validated. Empty/invalid responses and local waiter
   deadlines are per-message/per-waiter outcomes; they do not mutate the session
   or reject a later conforming response.
7. **Session eviction owns all nonce-indexed cleanup.** Reaping a session also
   removes its handshake response registration and wakes its certificate
   waiters; session-manager eviction must not orphan peer state.

### Reference table

| Site | TS 2.4.1 | Go v1.2.24 | Rust policy |
|---|---|---|---|
| `validate_certificates` over N certs | `Promise.all` | Worker pool, `NumCPU`-bounded, first-error-cancels | **Bounded concurrency.** Both references concurrent; sequential Rust is the outlier |
| `prove_certificate` per cert | `Promise.all` | Sequential | Sequential is acceptable — follow Go |
| Transport receive/dispatch | Background `onData` callbacks | Background goroutine | **No caller-driven pull loop on a path that can block.** The pull model is unique to this port and caused a head-of-line deadlock |
| Certificate gate on general messages | Present | **Absent entirely** | Implement (TS is normative for the *behaviour*), but never by blocking a shared drain loop |

### Background transport receive task (#40)

`Peer::new` now gives the sole transport receiver to a background task. That task routes
`initialResponse` frames directly to nonce-keyed one-shot handshake waiters and schedules every other
frame independently. Callers never pump transport progress; `process_next` and `process_pending` were
removed rather than retained as meaningless compatibility shims.

Dispatch admission is bounded, non-blocking, and session-fair. General frames have 64 global slots plus an
8-slot per-session sub-quota; control frames have a separate 16-slot lane. The lanes are separate because a
general frame may wait at the certificate gate: sharing every permit, or awaiting a permit in receive order,
could put the releasing `certificateResponse` behind the frame it must release. A frame that arrives after
either applicable limit is full is dropped and reported through the bounded `Peer::on_error` observer. The
receive task never waits for dispatch capacity and never holds a lock across an await.

Certificate-gated general messages authenticate, then wait inside their own admitted dispatch task. After
validation they atomically enter the replay set exactly once and are delivered. This makes both
`deferred_general_messages` and `pending_initial_responses` unnecessary; both stores and their expiry,
overflow, flush, and reap machinery are deleted. Session gate state remains pending-or-validated only.

The receive task owns only a weak reference to peer state. Its shutdown sender is held by application-facing
`Peer` handles, outside `PeerInner`; internal dispatch handles deliberately do not carry it. The receive task
therefore exits when the final application `Peer` handle is dropped even while a dispatch remains in flight.
Receive-channel closure, dispatch failures, and admission failures are per-frame asynchronous errors. The
bounded error observer uses non-blocking delivery so an absent or slow observer cannot become transport
backpressure; errors beyond its capacity may be dropped. `AuthFetch` additionally consumes an internal
metadata-bearing copy of this stream and routes general-frame failures by the response request ID, preserving
the concrete authentication error instead of returning a generic response timeout. No logging dependency
was added.

## Registered divergences

A Layer 1 divergence requires an entry here, a comment at the site, and a rationale. A Layer 2
divergence needs only the comment.

| Divergence | Layer | Rationale | Guard |
|---|---|---|---|
| Public middleware verification rejects a pending certificate gate immediately | 1 | TS `processGeneralMessage` waits, but Rust's direct HTTP middleware verification may not involve this peer's transport receiver. Waiting lets unsigned input occupy a handler for 30 seconds | Immediate-future forged-signature regression; site comment |
| Dispatch admission drops frames when its lane is saturated | 1 | Remote-controlled task creation must be bounded. Rust admits at most 64 general globally, 8 per session, and 16 control dispatches; later frames are dropped and surfaced locally through `Peer::on_error` so receive remains available to protocol-release frames and one gated session cannot starve another | Instrumented multi-session test measures 64 simultaneous general dispatches and observes frame 65 rejected; cross-session gated-fairness regression; separate control lane regression |
| Case-insensitive duplicate authenticated request headers are rejected | 1 | TS retains both normalized entries in original object insertion order. Rust's public input is a `HashMap`, which cannot reproduce that order; rejecting the ambiguous preimage is deterministic and safer than randomly signing either order | Live `@bsv/sdk@2.4.1` probe records both insertion orders; Rust duplicate rejection and locale-order regressions |
| Unparseable certifier or certificate type is skipped, not fatal | 1 | TS treats both as opaque strings; Rust's strongly typed wallet cannot forward malformed values, and erroring fails handshakes TS completes | Site comments and malformed-value regressions |
| Typed certificate identifiers are normalized before comparison | 1 | TS compares original strings exactly. Rust parses `PublicKey` values (case normalization and uncompressed→compressed conversion) and base64 certificate types into 32-byte values before comparing, so the original spelling cannot be recovered without raw-string shadow state | Sites in certificate validation; equivalence regressions; raise upstream |
| Certificate validation uses the session's advertised request snapshot | 1 | TS reads mutable peer state for `initialResponse` and an attacker-controlled inbound field for `certificateResponse`. Either permits TOCTOU/relabeling. Rust validates the request it actually put on the wire | Session-snapshot regression tests; raise upstream |
| Embedded certificate response precedes the first general frame (#23) | 1 | TS releases handshake waiters before answering the peer's embedded certificate request, so a client can send `general` first. Rust deliberately completes the embedded proof before releasing the initiating call: receivers see certificates first and never need to defer the first general frame | Live @bsv/sdk 2.4.1 probe observes `initialRequest, general, certificateResponse`; Rust wire-record regression observes `initialRequest, certificateResponse, general`; site comment |
| Certificate-request callbacks are fire-and-forget | 1 | TS awaits each callback; Rust's synchronous callback API spawns async work. A peer can observe `initialResponse` / `certificateResponse` wire order changes, the mirror of the preceding row | Handler-mode ordering regression; callback API comment |
| Sessions expire after 15 minutes idle | 1 | TS retains sessions indefinitely. Rust bounds session and replay-set memory and requires a new handshake after expiry | TTL/re-handshake regressions; `session_manager.rs` comment |
| Per-message replay protection and mandatory nonce | 1 | TS accepts a missing per-message nonce and has no replay set. Rust rejects missing/replayed nonces after signature verification | Missing-nonce and replay regressions |
| Handshake has a 30-second deadline | 1 | TS waits indefinitely; Rust abandons an unanswered handshake after 30 seconds | Paused-time handshake regression |
| Unsolicited/duplicate `initialResponse` is dropped | 1 | TS dispatch throws; Rust routes only a response correlated to a live nonce-keyed handshake waiter and otherwise ignores it so one frame cannot contaminate another session | Concurrent nested-handshake correlation regression |
| Full general-message observer channel drops after replay consumption | 1 | The bounded event channel uses `try_send`; at capacity a verified payload can be dropped after its nonce enters the replay set | Capacity behavior documented at the site; replace with explicit application backpressure in a future API revision |
| Certificate listener execution is capped at 30 seconds | 1 | TS awaits listeners without a deadline. Rust cancels an application callback after 30 seconds so transport progress is bounded | Paused-time listener-timeout regression |

### Conformed-to TS defects

Where TS is wrong we conform anyway and report upstream — a silent Rust-only divergence is worse than
a shared bug, because no Rust↔Rust test can detect it.

1. TS commits `certificatesValidated` before awaiting listeners, so a rejecting listener leaves
   validation committed.

## Verification requirements

| Claim | Required evidence |
|---|---|
| Layer 1 conformance | Vector generated from the real reference, byte equality asserted **both directions**, fixture committed and regenerable |
| A test pins a property | Mutation: revert the fix, show the test goes **red**. A test that passes both ways is worthless |
| Concurrency correctness | A test that fails deterministically, not via `sleep` + `is_finished()` — under load that passes on a reverted build |
| No regression hangs | Tests touching background dispatch or `dispatch_message` must be time-bounded; `cargo test` has no per-test timeout, so a regression hangs instead of failing |
| Performance claim | A benchmark, not an argument |

Generators must pin the reference version and assert it (`name === '@bsv/sdk' && version === '2.4.1'`),
so a fixture cannot be silently regenerated against a different SDK.

## Deciding a change

1. Could a TS peer observe it? → Layer 1. Match TS, add a vector. Otherwise → Layer 2.
2. Layer 2: is the fan-out width remote-controlled? Bound it.
3. Does TS's mechanism assume a single-threaded runtime or a callback transport? Then it is not
   binding — check what Go did.
4. Diverging on Layer 1? Register it above, comment the site, raise it upstream.
5. Ship no behavioural change without red-then-green evidence.
