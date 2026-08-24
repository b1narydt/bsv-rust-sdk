# Certificate parity work — findings ledger

Branch `fix/certificate-keyring-parity`. Every finding from four adversarial reviews, with status.
Nothing leaves this file until it is fixed, refuted, or explicitly deferred with a reason.

Reviews: R1a/R1b = TS-parity + concurrency review of the earlier `fix/certificate-response-validation`
branch. R2a/R2b = TS-parity + concurrency review of this branch at `176d079`.

Status key: **FIXED** (landed + verified) · **IN ROUND** (in the current fix round) ·
**OPEN** (not yet addressed) · **REFUTED** (investigated, not a defect) · **DECISION** (needs a human call)

---

## Critical / High

| # | Finding | Source | Status |
|---|---|---|---|
| 1 | Keyring absent from wire `Certificate` → TS↔Rust preimages differ, certificate exchange impossible in both directions | R1a | **FIXED** `039fbb2`, proven by cross-language vectors + an independent vector |
| 2 | `keyring` as `HashMap` → randomized iteration order breaks the preimage whenever >1 field is revealed | codex, during fix | **FIXED** `039fbb2` (now `IndexMap`) |
| 3 | Inbound 30s wait deadlocks the pull-based drain loop; releasing message sits behind the blocked one | R2b | **IN ROUND** (item 1 — defer, don't block) |
| 4 | Peer with no matching cert never resolves the waiter → every inbound general message stalls 30s, forever | R2b | **IN ROUND** (item 2) |
| 5 | Outbound gate self-blocks handshake in cert-request-handler mode over `SimplifiedFetchTransport` | R2b | **IN ROUND** (item 3) |
| 6 | Unparseable certifier aborts the whole message; TS treats certifiers as opaque strings → failed handshake vs. normal response | R2a | **IN ROUND** (item 6) |
| 7 | `try_send` fail-open: `certificates_validated=true` committed before delivery, drop leaves session claiming validated | R1b | **FIXED** — bounded channel removed entirely, replaced with awaited listeners |
| 8 | General messages never gated on certificate validation (`certificates_validated` was write-only) | R1b/R2a | **FIXED** in `176d079`, but see #3/#4 — the gate's *mechanism* is being redesigned |
| 9 | `get_verifiable_certificates` discarded requested certifiers | R1a | **FIXED** `176d079` (introduced #6, in round) |
| 10 | `validate_certificates` never called `decrypt_fields` — the step proving the verifier can read the fields | R2a | **FIXED** `176d079` |
| 11 | Certifier check missing from `validate_certificates` | R1a | **FIXED** `176d079` |
| 12 | Adding the certifier check made `test_validate_certificates_rejects_unrequested_type` **vacuous** (empty `certifiers` short-circuits first) | R1b | **FIXED** — verified present on this branch; deleting the type check now goes red |

## Medium

| # | Finding | Source | Status |
|---|---|---|---|
| 13 | One waiter's timeout drops the *shared* `watch::Sender`, killing co-waiters with a misleading error and no-op'ing later resolves | R2a/R2b | **IN ROUND** (item 4) |
| 14 | Waiter map leaks on future cancellation (client disconnect / `select!` loser) and on session reap; no cap | R2b | **IN ROUND** (item 5) |
| 15 | `listCertificates` `limit: 100` vs TS's default of 10 → the two SDKs reveal *different sets* for 11+ certs | R2a | **IN ROUND** (item 7) |
| 16 | Requested types with an empty field list silently dropped; TS proves them | R2a | **IN ROUND** (item 8) |
| 17 | Certifier comparison case-sensitive against a re-normalized lowercase key; TS compares the wire string verbatim | R2a | **IN ROUND** (item 9) |
| 18 | **TOCTOU**: the requested set is read from process-global `certificates_to_request` at validation time, not snapshotted per session. `set_certificates_to_request` takes `&self`. A reconfigure mid-handshake rejects a cert we ourselves requested — or accepts one we never advertised. Also means one global set serves every counterparty. | R1b | **FIXED** — `PeerSession` snapshots the exact advertised request; initial and standalone responses validate only against it. Wire bytes unchanged; reconfigure + sender-relabel regressions mutation-proven |
| 19 | Listeners run inline on the dispatch path with **no timeout**; a hung listener stalls the only transport consumer indefinitely | R2b | **FIXED** — each awaited listener is capped at 30s and its future is dropped on timeout; paused-time regression was red (`Elapsed`) before and green with `AuthError::Timeout` after |
| 20 | Listener **reentrancy / message stealing**: a listener calling `send_message` acquires `handshake` and drains the transport rx; any `InitialResponse` it dequeues is silently discarded by the `MessageType::InitialResponse => Ok(())` arm, timing out the outer handshake | R2b | **FIXED** — nested drainers retain responses for known unauthenticated session nonces; deterministic gated-transport regression timed out before and completes after |

## Low / Nits

| # | Finding | Source | Status |
|---|---|---|---|
| 21 | False code comment: "TS signs absent certificates as an empty byte string" — `JSON.stringify(undefined)` throws; TS *rejects* such a message | R2a | **IN ROUND** (item 10) |
| 22 | `initialResponse` omits `certificates` where TS emits `[]` — wire-shape difference in a message TS peers parse | R2a | **FIXED** — empty auto-match now emits `Some(vec![])`; pinned 2.4.1 generator invokes real `Peer.processInitialRequest` and records `{"certificates":[]}` |
| 23 | Frame ordering: TS releases handshake waiters *before* answering the embedded cert request, so a TS client can put a general message on the wire before its `certificateResponse`; Rust sends cert response first | R2a | **DECISION** — confirmed Layer 1 observable; current proof-first order retained as a registered divergence pending the background receive-task architecture decision (#40) |
| 24 | `requested.is_empty()` early return (keyed on `types`) has no TS counterpart; undocumented short-circuit | R2a | **FIXED** — removed; Rust now calls `list_certificates` for empty `types`, matching TS and Go. Regression red/green |
| 25 | Gate **fails open** on a reaped session: `still_waiting` re-check uses `get_session`, `None` → `false` → returns `Ok(())`. Fails closed downstream, so no security consequence, but semantics differ from TS | R2a | **REFUTED at `df0cf98`** — the alleged `still_waiting` expression no longer exists. Both the post-registration lookup and post-wakeup lookup use `ok_or_else(SessionNotFound)`, so a reaped session already failed closed before this round |
| 26 | Lost-update: `update_session` is a wholesale replace after several awaits, so it can resurrect a session `reap_idle` removed. Window lengthened by the new sequential `decrypt_fields` per certificate | R2b | **FIXED** — `update_session` only replaces an existing nonce and returns false after reap; async production callers convert that to `SessionNotFound`. Resurrection regression red/green |
| 27 | No compile-time proof the changed futures are `Send`; `_assert_peer_send_sync` asserts the *type*, not the futures. `watch::Ref` is `!Send` and survives only by scoping | R2b | **FIXED** — in-crate `is_send` assertions cover `verify_general_message`, `dispatch_message`, and `process_pending`; the first stream-based concurrency attempt demonstrably failed downstream spawn compilation and was replaced |
| 28 | Stale baseline entry `"on_certificates"` in `scripts/unwired-pub-fns.baseline.json:37` for a function that no longer exists | R2a | **FIXED** — stale entry replaced by the reviewed current external-consumer APIs; unwired-function ratchet is green |
| 29 | Sequential `decrypt_fields` loop vs TS's `Promise.all` → N serialized wallet round trips | R2a | **FIXED** with #38 — CPU-bounded validation window; paused-time measurement is 200ms for 10 certs at width 8 versus 1s on the sequential build |

## Test defects

| # | Finding | Source | Status |
|---|---|---|---|
| 30 | `test_certificate_delivery_has_no_bounded_channel_limit` is a **tautology** — awaits each of 64 deliveries before the next, so a 1-entry channel passes identically. Cannot detect the bug it names | R2b | **IN ROUND** (item 11) |
| 31 | `test_inbound_general_message_waits_for_certificate_validation` rests on `sleep(50ms)` + `!is_finished()`; under load it passes on a reverted build. Same defect as the discarded 25ms probe — 2× duration, same mechanism | R2b | **IN ROUND** (item 11) |
| 32 | Nothing tests that `verify_general_message` itself times out, nor the value of `CERTIFICATE_WAIT_TIMEOUT`. The constant could be set to 30 minutes unnoticed | R2b | **IN ROUND** (item 11) |
| 33 | Many tests call `dispatch_message`/`process_pending` untimed → a regression **hangs 30s per test** rather than failing; `cargo test` has no per-test timeout | R2b | **IN ROUND** (item 11) |

## Refuted (investigated, not defects — recorded so they are not re-raised)

- Lock held across the new await / futures non-`Send` — proved clean by scope analysis (R2b)
- Two concurrent waiters deadlocking each other — cannot; Rust is *better* than TS here, whose
  `certificateValidationPromises` map silently overwrites and orphans the first waiter (R2b)
- Lost wakeup from a late-registering waiter — the `still_waiting` re-read closes the window (R2b)
- Timeout silently proceeding — returns `Err` before signature verification and `mark_message_seen` (R2b)
- Listener registry reentrancy *deadlock* — guard dropped before awaiting (R2b). (The *message-stealing*
  hazard, #20, is a separate live finding.)
- Lock-order inversion — none introduced (R2b)
- Outbound gate blocking its own precondition at protocol level — cert messages are ungated (R2b)
- Certifier hex encoding (compressed/lowercase/66-char) — matches TS exactly (R1a/R2a)
- Error propagation divergence — R1a raised it from stale 2.0.13, then withdrew it: 2.4.1 changed the
  transport to propagate, so Rust is at parity
- `#[allow(deprecated)]` on `AcknowledgmentMode` — benign, sits on the deprecated item's own definition

## Protocol identity — BRC-103, not BRC-31

We implement **BRC-103 mutual authentication**: `AUTH_VERSION = "0.1"`, the AuthMessage envelope
(`initialRequest` / `initialResponse` / `certificateRequest` / `certificateResponse` / `general`), and
protocol ID `[2, 'auth message signature']`.

**BRC-31 (Authrite) is deprecated and we do not implement it.** Its discriminator is the protocol ID
`[2, 'authrite message signature']`. Decide by protocol ID, never by a file title or `brc:` tag — both
upstream and this repo mislabel BRC-103 as BRC-31.

| # | Finding | Status |
|---|---|---|
| 34 | ~21 code comments label the auth module "BRC-31"/"BRC-31 Authrite" (e.g. `types.rs:105`, `session_manager.rs:1`, `transports/*.rs`, `clients/*.rs`) for a BRC-103 implementation; only 3 sites say BRC-103. Actively misleads reviewers and vector-selection decisions | **FIXED** — source, API docs, README, and changelog relabelled BRC-103. Genuine upstream filenames/tags containing `brc31`/Authrite remain unchanged |
| 35 | Upstream `messaging/brc31/authrite-signature.json` (28 vectors) is **genuinely deprecated** Authrite — uses `[2,'authrite message signature']`. Must stay excluded; do NOT wire up | **RESOLVED — verified, kept unvendored**. The generated coverage ledger now records the protocol-ID reason so the similarly named BRC-103 files cannot cause it to be wired accidentally |
| 36 | Upstream `auth/brc31-handshake.json` (16) and `messaging/authsocket.json` (12) are tagged `brc: ["BRC-31"]` but their content is BRC-103 (`messageType: initialRequest`, v0.1, `x-bsv-auth-*` headers; authsocket's own text says "BRC-103 handshake"). Relevant to us and currently unvendored, unasserted | **FIXED** — both files vendored at `8b074a06`; eight real SDK properties asserted, twenty Express/AuthSocket-server vectors registered as governed component-owned skips |
| 42 | `auth.brc31-handshake.1`'s request example is stale relative to the real `@bsv/sdk` 2.4.1 `Peer`: the vector includes `nonce`, `payload: []`, and `signature: []`, while the real constructor omits them. Rust also omits them, so the runner pins this as a corpus disagreement rather than changing Rust to match stale example data | **OPEN — raise upstream**; exact named divergence is executable in `tests/conformance_auth.rs` |
| 43 | Rust's default `initialRequest` omits `requestedCertificates`, while the real TS 2.4.1 constructor always emits its default `{ certifiers: [], types: {} }`. The vendored schema vector also omits it, so this Layer-1 discrepancy is hidden rather than exposed by the corpus | **OPEN — needs a dedicated 2.4.1 byte fixture and reviewed wire fix; not changed during schema/HTTP vector wiring** |
| 44 | `auth.brc31-handshake.10` requires the Express server to wait 30 seconds for certificates and map expiry to HTTP 408. This crate has no HTTP server/status mapper; its certificate waiter and deferred-message deadline are exactly 30 seconds, while side-effect-free `verify_general_message` rejects a pending gate immediately by the registered nonblocking mechanism | **RESOLVED — Express 408 remains a governed middleware skip; crate timing is mutation-proven in `tests/conformance_auth.rs`** |
| 45 | `auth.brc31-handshake.12` and `messaging.authsocket.4` enumerate `initialRequest`, `initialResponse`, and `general`; the full BRC-103 SDK envelope also has `certificateRequest` and `certificateResponse` | **RESOLVED — assert the three listed values as real enum members, not as an exhaustive SDK enum; the vectors describe the middleware/AuthSocket subset** |

## Conformance coverage (from `conformance/COVERAGE.md`)

- **266 of 1,565** non-script upstream vectors asserted — **17.0%**, up from 258/16.5%.
  (6,681 total; 5,116 script-evaluation vectors are a deliberate scope exclusion.)
- The uncovered surface includes every certificate-wallet vector: `provecertificate` (8),
  `listcertificates` (8), `acquirecertificate` (8), `relinquishcertificate` (6) — all 0 asserted.
- **#37 — REFUTED.** The corpus was reported as pinning `@bsv/sdk@2.3.1`, but `8b074a06`
  itself contains `packages/sdk/package.json` version 2.4.1, and upstream `main` still resolves to
  that exact SHA. No newer corpus exists to adopt. The stale 2.3.1 label was in
  `conformance/README.md` and is fixed. Retain the SHA and review a future corpus bump only when
  upstream moves.

## Concurrency — where Rust should exploit real parallelism

Reference points: TS is single-threaded (`Promise.all` = interleaved I/O, not parallel). Go
(`go-sdk@v1.2.24/auth`) has real parallelism and shows where it is worth taking.

| # | Site | TS | Go | Rust today | Action |
|---|---|---|---|---|---|
| 38 | `validate_certificates` over N certs | `Promise.all` (`validateCertificates.js:17`) | **Worker pool**, `min(len(certs), NumCPU)`, first-error-cancels via `context.WithCancel` (`utils/validate_certificates.go:99-146`) | **FIXED** — `available_parallelism()`-bounded `FuturesUnordered`; first completed false/error drops siblings | Confirmed. Deterministic paused-time tests measured 1s sequential → 200ms bounded for 10 certs/8 CPUs and 7s → 0ms first-error cancellation. Single-cert behavior/order unchanged; multi-failure winner may differ, as in TS |
| 39 | `get_verifiable_certificates` → `prove_certificate` per cert | `Promise.all` (`getVerifiableCertificates.js:20`) | Sequential (`get_verifiable_certificates.go:60`) | Sequential, documented | **REFUTED as a defect** — leave sequential. Go's real-parallelism implementation made this deliberate Layer-2 choice; local wallet fan-out has no demonstrated value |
| 40 | Transport receive/dispatch | Background `onData` callbacks | **Background goroutine** `go t.receiveMessages()` (`websocket_transport.go:74`) | **Caller-driven pull loop** (`process_next`/`process_pending`) — unique to the Rust port | **DECISION — analysis written** in `docs/CONFORMANCE-AND-CONCURRENCY.md`; no implementation per task. Background receive could remove the pull mutex/pending-response net and conditionally the deferred queue, but breaks pumping APIs/tests and requires new error/lifecycle/bounding semantics |
| 41 | Certificate gate on general messages | Present (`Peer.js:114`, `:700`) | **Absent** — `PeerSession` has no `CertificatesRequired`/`CertificatesValidated` fields at all | Kept, faithfully to TS | **REFUTED as a reason to remove it** — acceptance timing is peer-observable Layer 1, so TS remains normative. Go's omission informs mechanism/load-bearing analysis only |

## Decisions outstanding

- **Version**: recommend `0.8.0`. `0.7.2` would auto-propagate a wire + API break to any repo pinned
  `^0.7`. Not yet bumped.
- **One TS bug conformed to deliberately**, documented in code, to be raised upstream:
  1. TS commits `certificatesValidated` *before* awaiting listeners, so a rejecting listener leaves
     validation committed
- **Mechanism divergence** (#3): Rust defers rather than blocks. Behaviour identical; mechanism differs
  because TS assumes a callback transport. Must stay documented or a future parity pass reintroduces
  the deadlock.
