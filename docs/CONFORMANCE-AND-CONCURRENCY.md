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

1. **Bound every fan-out whose width is remote-controlled.** Certificate counts arrive from a peer.
   Unbounded `join_all` over peer-supplied input is a resource-exhaustion vector. Go's cap of
   `min(len(items), NumCPU)` is the reference.
2. **Cancel siblings on first error.** Go uses `context.WithCancel`; the Rust equivalent is dropping
   the remaining futures. Do not complete work whose result is already discarded.
3. **Do not copy `Promise.all` reflexively.** In a single-threaded runtime it interleaves I/O; it is
   not a claim that parallelism is correct or worthwhile. Where Go — which has real parallelism —
   chose sequential, that judgement is better evidence than TS's.
4. **Never let one peer's work block another's.** No blocking wait may sit on a shared dispatch path.
5. **Hold no lock across an `.await`.** Existing invariant; the `!Send` future that results breaks
   downstream `Handler` bounds in ways this crate's own tests cannot detect.

### Reference table

| Site | TS 2.4.1 | Go v1.2.24 | Rust policy |
|---|---|---|---|
| `validate_certificates` over N certs | `Promise.all` | Worker pool, `NumCPU`-bounded, first-error-cancels | **Bounded concurrency.** Both references concurrent; sequential Rust is the outlier |
| `prove_certificate` per cert | `Promise.all` | Sequential | Sequential is acceptable — follow Go |
| Transport receive/dispatch | Background `onData` callbacks | Background goroutine | **No caller-driven pull loop on a path that can block.** The pull model is unique to this port and caused a head-of-line deadlock |
| Certificate gate on general messages | Present | **Absent entirely** | Implement (TS is normative for the *behaviour*), but never by blocking a shared drain loop |

### Transport receive-task decision analysis (#40)

The current `process_next` / `process_pending` pull model gives callers ownership of the sole transport
receiver. A background design would move that receiver into one task created with the peer, route
`initialResponse` messages to nonce-keyed handshake waiters, and dispatch other messages independently.
To avoid recreating head-of-line blocking inside the background task, dispatch would need bounded
per-message tasks (or keyed workers), with ordering retained where the protocol requires it.

That design could remove the handshake receiver mutex and the new `pending_initial_responses` safety net.
It could also remove `deferred_general_messages` **if** certificate-gated general messages are allowed to
wait in independent dispatch tasks while the receive task continues accepting the certificate response.
A single background task that still awaits dispatch inline would not remove the deadlock and therefore
would not justify deleting the deferred queue.

The compatibility cost is material. `process_next` and `process_pending` currently expose caller-driven
progress and exact processed counts; a background consumer would make those APIs meaningless or turn them
into compatibility shims. Many tests manually pump one side and inspect intermediate frames, so they would
need event/rendezvous-based replacements. Error propagation would also need a new channel because receive
and dispatch errors could no longer return through the pumping caller.

The main upside is safe concurrent per-message dispatch and elimination of listener/handshake message
stealing by construction. The risks are task lifetime and shutdown ownership, bounding peer-controlled
fan-out, preserving replay-check and wire-order invariants under concurrent dispatch, avoiding listener
backpressure accumulation, keeping all spawned futures `Send + 'static`, and defining where asynchronous
transport errors surface. This is a worthwhile architectural direction, but it is intentionally not
implemented in this round.

## Registered divergences

A Layer 1 divergence requires an entry here, a comment at the site, and a rationale. A Layer 2
divergence needs only the comment.

| Divergence | Layer | Rationale | Guard |
|---|---|---|---|
| Certificate wait defers rather than blocks | 2 | TS blocks a callback-driven transport; Rust's transport cannot block a shared consumer without deadlocking. Observable behaviour is identical | Comment at the site stating that restoring the TS mechanism reintroduces the deadlock |
| Authenticated empty `certificateResponse` terminates the wait | 1 | TS's `length > 0` guard leaves the session permanently unvalidated, stalling every subsequent message. A peer that has definitively answered must not leave the wait open | Documented here and at the site; raise upstream |
| Unparseable certifier is skipped, not fatal | 1 | TS treats certifiers as opaque strings; erroring fails handshakes TS completes | Site comment |
| Certificate validation uses the session's advertised request snapshot | 1 | TS reads mutable peer state for `initialResponse` and an attacker-controlled inbound field for `certificateResponse`. Either permits TOCTOU/relabeling. Rust validates the request it actually put on the wire | Session-snapshot regression tests; raise upstream |
| Embedded certificate response is sent before the initiating call returns | 1 | TS releases handshake waiters before answering the peer's embedded certificate request, so a general frame can race ahead. The pull architecture has no safe post-return continuation without a background receive/dispatch task; proof-first ordering is deterministic and safer | Documented here pending the #40 architecture decision |

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
| No regression hangs | Tests touching `dispatch_message`/`process_pending` must be time-bounded; `cargo test` has no per-test timeout, so a regression hangs instead of failing |
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
