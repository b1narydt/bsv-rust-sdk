# Certificate parity work — findings ledger

Branch `fix/certificate-keyring-parity`. Every finding from four adversarial reviews, with status.
Nothing leaves this file until it is fixed, refuted, or explicitly deferred with a reason.

Reviews: R1a/R1b = TS-parity + concurrency review of the earlier `fix/certificate-response-validation`
branch. R2a/R2b = TS-parity + concurrency review of this branch at `176d079`.

Status key: **FIXED** (landed + verified) · **IN ROUND** (in the current fix round) ·
**OPEN** (not yet addressed) · **REFUTED** (investigated, not a defect) · **DECISION** (needs a human call)

---

## Fifth adversarial review of `2127ee1`

| ID | Finding | Status |
|---|---|---|
| R8-1 | Local verifier keyrings were alphabetized from `HashMap`, diverging from TS insertion order inside the signed certificate-response preimage | **FIXED** — constructor, master-keyring producer, and `ProveCertificateResult` use `IndexMap`; live TS Auth Peer and WalletWire runs plus Rust vectors pin `zeta, alpha, middle` |
| R8-2 | Public single-frame `process_next` swallowed its consumed frame's dispatch error | **FIXED** — `process_next` propagates; only shared `process_pending` and nested handshake drains isolate per-frame errors |
| R8-3 | Session reap orphaned waiter, deferred, and pending-response entries owned by `Peer` | **FIXED** — `reap_idle` returns removed nonces and every Peer reap site cleans all three stores before continuing |
| R8-4 | Drain-sensitive test audit and ledger row #33 still missed untimed calls/receives | **FIXED** — remaining direct dispatches and new delivery receives have explicit deadlines |
| R8-5 | Discovery-map order change had only single-entry fixtures | **FIXED** — deterministic three-entry insertion-order round trip |

---

## Fourth adversarial review of `609d0b0`

The prior ledger overclaimed closure: 43 rows said fixed, but the review
verified only 36 complete fixes (6 partial, 1 unverifiable). The corrections
below supersede contradictory descriptions in older round summaries.

| ID | Finding | Corrected status |
|---|---|---|
| F1 | Public `verify_general_message` waited 30 seconds before signature verification | **FIXED** — pending gates reject immediately; forged-signature future is immediately ready |
| F2 / I1 | One frame's dispatch error aborted whoever owned the shared drain | **FIXED structurally** — direct dispatch and single-frame `process_next` report their owned frame; `process_pending` and nested handshake drains consume unrelated per-frame errors and continue |
| F3 / I2 | Empty/invalid/timeout outcomes became a sticky session-wide error and destroyed independent waiter deadlines | **FIXED structurally** — error-valued session state and all terminalization sites removed; only successful validation mutates the gate; public waiters own independent deadlines; late valid responses remain accepted |
| F4 | Empty-response charter rationale inverted TS 2.4.1 behavior | **FIXED** — real two-Peer vector proves standalone `[]` send, listener fan-out, and still-pending gate; embedded initial request includes `[]`; post-handshake and AuthFetch guards suppress `[]` |
| F5 | Certificate issue API discarded field order through `HashMap` | **FIXED** — issue/encrypt APIs accept and preserve `IndexMap`; deterministic `zeta, alpha, middle` regression; discovery `IdentityCertificate` maps audited and converted too |
| F6 | Ordering regressions could pass by randomized `HashMap` luck | **FIXED after R8 reopening** — compile-time `IndexMap` assertions plus multi-entry inbound, outbound, master-issuance, and discovery fixtures; no order-bearing auth producer accepts `HashMap` |
| Perf/API | Double nonce verification, debug ECC timeout, opposite outbound gate semantics, mutating decrypt, random session selection | **FIXED** — resolved session is threaded once; `[profile.test] opt-level = 2`; both outbound APIs reject immediately; decrypt is non-mutating; identity lookup uses max activity timestamp |
| #33 | 39 drain-sensitive test calls were untimed | **FIXED after R8 reopening** — remaining direct dispatches and delivery receives now have explicit deadlines; existing timeout-bounded `select!` calls remain explicit |
| #46 | Rust→TS cargo test asserted a generator-written boolean | **FIXED** — cargo test launches Node and real 2.4.1 verification; CI installs Node/SDK and separately regenerates + diffs the fixture |

---

## Final adversarial review of `30ad72a`

| ID | Finding | Status |
|---|---|---|
| B1 | `decrypted_fields` randomized inside signed JSON | **FIXED** — `IndexMap`; real TS three-key non-alphabetical fixture red/green |
| B2 | Deferred expiry contaminates unrelated pump caller | **FIXED after reopening** — expiry removes only the expired message; it does not terminalize session state, and shared drains isolate frame errors |
| B3 | Outbound 30-second gate only checks deadline when no work was processed | **FIXED** — unconditional top-of-loop deadline; zero-deadline remote-work regression red/green |
| B4 | Unverified general frames consume deferred capacity and deferral errors abort drains | **FIXED after reopening** — signature verified before queue lock; shared drains isolate all per-frame errors and keep draining; count remains capped at 128 |
| B5 | Validation/deferral check-then-act race strands a message | **FIXED** — after acquiring the queue lock, `try_read` rechecks session state atomically with insertion; resolved-state regression red/green |
| B6 | Empty certificate result only terminal on receive side; TS peer can still stall Rust | **PREVIOUS FIX REVERTED; FIXED BY TS PARITY** — standalone requests send `[]`, the two guarded sites suppress it, and empty input leaves the gate pending without poisoning later work |
| B7 | `handshake.1` pin accepted any key-set mismatch and hid dead checks | **FIXED** — exact expected/actual key-set evidence; checks execute before the known divergence; reverting #43 now fails the harness |
| B8 | Release hygiene | **FIXED** — version 0.8.0; changelog covers wire/API breaks and current nonblocking mechanism |
| H1 | Deferred-frame flush error fails a committed handshake | **FIXED** — flush errors are isolated after successful validation commits; malformed deferred-frame regression red/green |
| H2 | Public `verify_general_message` rejects where TS waits | **FIXED** — public middleware path uses the retained per-session waiter; dispatch remains nonblocking |
| H3 | `send_message` waits where TS rejects synchronously | **FIXED** — removed outbound pumping from `send_message`; immediate-result regression red/green |
| H4 | Charter claims deferred behavior is identical | **FIXED** — queue cap, error isolation, and drain-triggered expiry differences are explicit |
| H5 | Missing `Send` future assertions | **FIXED** — assertions now include validation wait, send, and general-message creation |
| M1 | Eviction returns before waiter/queue cleanup | **FIXED** — cleanup always runs before `SessionNotFound`; eviction regression red/green |
| M2 | Malformed requested type is fatal unlike malformed certifier | **FIXED by registered divergence** — both unrepresentable typed values are skipped; red/green regression |
| M3 | Case-insensitive certifier match differs from TS exact string match | **REGISTERED DIVERGENCE** — typed `PublicKey` parsing loses original case; no raw-string shadow state added |
| #9 | Terminal validation error can later be cleared | **SUPERSEDED** — terminal session errors were the structural defect and no longer exist; later valid responses are intentionally accepted |
| Tests | Unbounded loops, `is_finished`, hand-built AuthPeer, silent asserted-count erosion | **FIXED** — rendezvous timeouts, no `is_finished`, `ensure_peer` production-listener test, and exact eight-vector assertion |

---

## Critical / High

| # | Finding | Source | Status |
|---|---|---|---|
| 1 | Keyring absent from wire `Certificate` → TS↔Rust preimages differ, certificate exchange impossible in both directions | R1a | **FIXED** `039fbb2`, proven by cross-language vectors + an independent vector |
| 2 | `keyring` as `HashMap` → randomized iteration order breaks the preimage whenever >1 field is revealed | codex, during fix | **FIXED** `039fbb2` (now `IndexMap`) |
| 3 | Inbound 30s wait deadlocks the pull-based drain loop; releasing message sits behind the blocked one | R2b | **FIXED** — dispatch verifies then defers in a bounded per-session queue; it never waits on the sole pull receiver. Deterministic queued-general/certificate-response regression is green |
| 4 | Peer with no matching cert never resolves the waiter → every inbound general message stalls 30s, forever | R2b | **FIXED without terminal state** — dispatch verifies/defer-expires per message and middleware rejects immediately; explicit waiters time out independently, matching TS session usability |
| 5 | Outbound gate self-blocks handshake in cert-request-handler mode over `SimplifiedFetchTransport` | R2b | **FIXED** — AuthFetch's signing path pumps the certificate response before general-message creation; public `send_message` now rejects a pending gate immediately like TS. Handler-mode regression is time-bounded |
| 6 | Unparseable certifier aborts the whole message; TS treats certifiers as opaque strings → failed handshake vs. normal response | R2a | **FIXED by registered divergence** — malformed certifiers and types are skipped because the strongly typed Rust wallet cannot forward them; both paths have focused regressions |
| 7 | `try_send` fail-open: `certificates_validated=true` committed before delivery, drop leaves session claiming validated | R1b | **FIXED** — bounded channel removed entirely, replaced with awaited listeners |
| 8 | General messages never gated on certificate validation (`certificates_validated` was write-only) | R1b/R2a | **FIXED** in `176d079`, but see #3/#4 — the gate's *mechanism* is being redesigned |
| 9 | `get_verifiable_certificates` discarded requested certifiers | R1a | **FIXED** `176d079` (introduced #6, in round) |
| 10 | `validate_certificates` never called `decrypt_fields` — the step proving the verifier can read the fields | R2a | **FIXED** `176d079` |
| 11 | Certifier check missing from `validate_certificates` | R1a | **FIXED** `176d079` |
| 12 | Adding the certifier check made `test_validate_certificates_rejects_unrequested_type` **vacuous** (empty `certifiers` short-circuits first) | R1b | **FIXED** — verified present on this branch; deleting the type check now goes red |

## Medium

| # | Finding | Source | Status |
|---|---|---|---|
| 13 | One waiter's timeout drops the *shared* `watch::Sender`, killing co-waiters with a misleading error and no-op'ing later resolves | R2a/R2b | **FIXED after regression** — public waiters now share only a success signal; timeout never mutates session state, so staggered deadlines and a late valid response remain independent |
| 14 | Waiter map leaks on future cancellation (client disconnect / `select!` loser) and on session reap; no cap | R2b | **FIXED after R8 reopening** — RAII removes cancelled/last registrations; every reap site removes waiter/deferred/pending state for the returned nonces and wakes waiters |
| 15 | `listCertificates` `limit: 100` vs TS's default of 10 → the two SDKs reveal *different sets* for 11+ certs | R2a | **FIXED** — passes `limit: None`, selecting the wallet interface's TS-compatible default 10; focused argument-capture regression is green |
| 16 | Requested types with an empty field list silently dropped; TS proves them | R2a | **FIXED** — all requested type keys are forwarded regardless of field-list length; proof-call regression is green |
| 17 | Certifier comparison case-sensitive against a re-normalized lowercase key; TS compares the wire string verbatim | R2a | **RESOLVED BY REGISTERED DIVERGENCE** — typed `PublicKey` parsing loses original hex case, so Rust compares equivalent hex case-insensitively rather than adding raw-string shadow state |
| 18 | **TOCTOU**: the requested set is read from process-global `certificates_to_request` at validation time, not snapshotted per session. `set_certificates_to_request` takes `&self`. A reconfigure mid-handshake rejects a cert we ourselves requested — or accepts one we never advertised. Also means one global set serves every counterparty. | R1b | **FIXED** — `PeerSession` snapshots the exact advertised request; initial and standalone responses validate only against it. Wire bytes unchanged; reconfigure + sender-relabel regressions mutation-proven |
| 19 | Listeners run inline on the dispatch path with **no timeout**; a hung listener stalls the only transport consumer indefinitely | R2b | **FIXED** — each awaited listener is capped at 30s and its future is dropped on timeout; paused-time regression was red (`Elapsed`) before and green with `AuthError::Timeout` after |
| 20 | Listener **reentrancy / message stealing**: a listener calling `send_message` acquires `handshake` and drains the transport rx; any `InitialResponse` it dequeues is silently discarded by the `MessageType::InitialResponse => Ok(())` arm, timing out the outer handshake | R2b | **FIXED** — nested drainers retain responses for known unauthenticated session nonces; deterministic gated-transport regression timed out before and completes after |

## Low / Nits

| # | Finding | Source | Status |
|---|---|---|---|
| 21 | False code comment: "TS signs absent certificates as an empty byte string" — `JSON.stringify(undefined)` throws; TS *rejects* such a message | R2a | **FIXED** — absent `certificates` rejects explicitly before preimage construction; comment and regression now state the real TS behavior |
| 22 | `initialResponse` omits `certificates` where TS emits `[]` — wire-shape difference in a message TS peers parse | R2a | **FIXED** — empty auto-match now emits `Some(vec![])`; pinned 2.4.1 generator invokes real `Peer.processInitialRequest` and records `{"certificates":[]}` |
| 23 | Frame ordering: TS releases handshake waiters *before* answering the embedded cert request, so a TS client can put a general message on the wire before its `certificateResponse`; Rust sends cert response first | R2a | **DECISION** — confirmed Layer 1 observable; current proof-first order retained as a registered divergence pending the background receive-task architecture decision (#40) |
| 24 | `requested.is_empty()` early return (keyed on `types`) has no TS counterpart; undocumented short-circuit | R2a | **FIXED** — removed; Rust now calls `list_certificates` for empty `types`, matching TS and Go. Regression red/green |
| 25 | Gate allegedly failed open when a post-registration session lookup found a reaped session | R2a | **REFUTED at `df0cf98`** — both post-registration and post-wakeup lookups return `SessionNotFound`, so a reaped session fails closed |
| 26 | Lost-update: `update_session` is a wholesale replace after several awaits, so it can resurrect a session `reap_idle` removed. Window lengthened by the new sequential `decrypt_fields` per certificate | R2b | **FIXED** — `update_session` only replaces an existing nonce and returns false after reap; async production callers convert that to `SessionNotFound`. Resurrection regression red/green |
| 27 | No compile-time proof the changed futures are `Send`; `_assert_peer_send_sync` asserts the *type*, not the futures. `watch::Ref` is `!Send` and survives only by scoping | R2b | **FIXED** — in-crate `is_send` assertions cover `verify_general_message`, `dispatch_message`, and `process_pending`; the first stream-based concurrency attempt demonstrably failed downstream spawn compilation and was replaced |
| 28 | Stale baseline entry `"on_certificates"` in `scripts/unwired-pub-fns.baseline.json:37` for a function that no longer exists | R2a | **FIXED** — stale entry replaced by the reviewed current external-consumer APIs; unwired-function ratchet is green |
| 29 | Sequential `decrypt_fields` loop vs TS's `Promise.all` → N serialized wallet round trips | R2a | **FIXED** with #38 — CPU-bounded validation window; paused-time measurement is 200ms for 10 certs at width 8 versus 1s on the sequential build |

## Test defects

| # | Finding | Source | Status |
|---|---|---|---|
| 30 | `test_certificate_delivery_has_no_bounded_channel_limit` is a **tautology** — awaits each of 64 deliveries before the next, so a 1-entry channel passes identically. Cannot detect the bug it names | R2b | **FIXED** — blocks the first listener, concurrently accumulates 64 queued deliveries, then proves lossless ordered release; queue-fill rendezvous is time-bounded |
| 31 | `test_inbound_general_message_waits_for_certificate_validation` rests on `sleep(50ms)` + `!is_finished()`; under load it passes on a reverted build. Same defect as the discarded 25ms probe — 2× duration, same mechanism | R2b | **FIXED** — replaced with deterministic immediate-future polling/rendezvous and explicit successful-validation release; no sleep-plus-`is_finished` probe remains |
| 32 | Nothing tests that `verify_general_message` itself times out, nor the value of `CERTIFICATE_WAIT_TIMEOUT`. The constant could be set to 30 minutes unnoticed | R2b | **FIXED** — paused-time conformance test pins 29,999ms pending / 30,000ms timeout; public verifier waiting is separately exercised |
| 33 | Many tests call `dispatch_message`/`process_pending` untimed → a regression **hangs 30s per test** rather than failing; `cargo test` has no per-test timeout | R2b | **FIXED after R8 reopening** — every direct drain/dispatch call and dependent delivery receive has an explicit bound; timeout-bounded `select!` calls retain those bounds |

## Refuted (investigated, not defects — recorded so they are not re-raised)

- Lock held across the new await / futures non-`Send` — proved clean by scope analysis (R2b)
- Two concurrent waiters deadlocking each other — cannot; Rust is *better* than TS here, whose
  `certificateValidationPromises` map silently overwrites and orphans the first waiter (R2b)
- Lost wakeup from a late-registering waiter — the post-registration session re-read closes the window (R2b)
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
| 43 | Rust's default `initialRequest` omits `requestedCertificates`, while the real TS 2.4.1 constructor always emits its default `{ certifiers: [], types: {} }`. The vendored schema vector also omits it, so this Layer-1 discrepancy is hidden rather than exposed by the corpus | **FIXED** — handshake producers now normalize absent configuration to an explicit empty wire set while retaining Rust's internal no-request semantics. Real-`Peer` 2.4.1 and Rust constructor tests are mutation-proven red/green; exact envelope bytes are covered both directions |
| 44 | `auth.brc31-handshake.10` requires the Express server to wait 30 seconds for certificates and map expiry to HTTP 408. This crate has no HTTP server/status mapper; its certificate waiter and deferred-message deadline are exactly 30 seconds, and public `verify_general_message` waits on that per-session signal | **RESOLVED** — Express 408 remains a governed middleware skip; crate timing is mutation-proven in `tests/conformance_auth.rs` |
| 45 | `auth.brc31-handshake.12` and `messaging.authsocket.4` enumerate `initialRequest`, `initialResponse`, and `general`; the full BRC-103 SDK envelope also has `certificateRequest` and `certificateResponse` | **RESOLVED — assert the three listed values as real enum members, not as an exhaustive SDK enum; the vectors describe the middleware/AuthSocket subset** |
| 46 | Cross-language vectors covered the signed `certificateResponse` preimage but not complete handshake envelopes, allowing #43 and key-order drift through | **FIXED and now test-time verified** — real 2.4.1 bytes cover every envelope; `cargo test` invokes Node to verify Rust signatures/bytes instead of trusting a fixture flag; CI regenerates and diffs the fixture |
| 47 | Rust emitted `initialNonce` on `general`, while TS `Peer.toPeer` never creates that member | **FIXED** — Rust now omits it; a focused Rust-producer mutation test was red before and green after, and both-direction all-envelope vectors pin the TS shape |
| 48 | Derived Rust field order serialized `yourNonce` before `initialNonce`; TS constructs `initialNonce` first on `initialResponse`, `certificateRequest`, and `certificateResponse` | **FIXED** — `AuthMessage` declaration order now matches all five real TS constructors. Exact 2.4.1 and Rust-produced envelope vectors pin the bytes; signed payloads are unchanged |

## `skip_serializing_if = "Option::is_none"` wire audit

Scope is the complete `AuthMessage` serialization graph: `AuthMessage`, nested `Certificate` /
`VerifiableCertificate`, and `RequestedCertificateSet`. `PartialCertificate` and the other wallet
argument/result structs do not nest in an auth wire message and are outside this audit.

| Field | TS 2.4.1 behavior | Rust behavior after this round | Result / evidence |
|---|---|---|---|
| `AuthMessage.nonce` | Omitted on `initialRequest` / `initialResponse`; emitted on `certificateRequest`, `certificateResponse`, and `general` | Same producer-specific `None` / `Some` behavior | **MATCH** — real-TS and Rust all-envelope byte vectors |
| `AuthMessage.initialNonce` | Emitted on both handshake messages and both certificate messages; omitted on `general` | Same; `general` changed from `Some(session_nonce)` to `None` | **FIXED #47** — focused red/green plus all-envelope vectors |
| `AuthMessage.yourNonce` | Omitted on `initialRequest`; emitted on the other four messages | Same | **MATCH** — all-envelope vectors |
| `AuthMessage.certificates` | Emitted on `certificateResponse`; on `initialResponse`, emitted when the peer's embedded request is auto-answered (including `[]`) and otherwise omitted; omitted elsewhere | Same `Some` / `None` distinction | **MATCH** — real-`Peer` empty-array fixture plus all-envelope vectors |
| `AuthMessage.requestedCertificates` | Always emitted on `initialRequest` and `initialResponse` because the constructor defaults the local set; always emitted from `requestCertificates`; omitted on `certificateResponse` / `general` | Handshake producers now emit `Some(default)` when configuration is absent; supplied standalone requests serialize; responses/general omit | **FIXED #43** — constructor red/green plus all-envelope vectors |
| `AuthMessage.payload` | Emitted only on `general` | Same | **MATCH** — all-envelope vectors |
| `AuthMessage.signature` | Omitted only on `initialRequest`; emitted on the other four messages | Same | **MATCH** — all-envelope vectors |
| `Certificate.revocationOutpoint` | Constructor property is `undefined` when absent, so `JSON.stringify` omits it; otherwise emits | `None` omitted, `Some` emitted | **MATCH** — real 2.4.1 8-mask certificate fixture |
| `Certificate.fields` | `undefined` omitted; supplied object emitted (including its insertion order) | `None` omitted; `Some(IndexMap)` emitted in preserved order | **MATCH** — same 8-mask fixture |
| `Certificate.signature` | `undefined` omitted; supplied hex string emitted | `None` omitted; `Some` emitted as hex | **MATCH** — same 8-mask fixture, including unsigned certificates |
| `VerifiableCertificate.decryptedFields` | `undefined` omitted; explicitly supplied value emitted in insertion order. Normal `fromCertificate` production omits it | `None` omitted; `Some(IndexMap)` emitted in preserved order. Normal production begins at `None` | **MATCH** — real 2.4.1 absent plus three-key `zeta, alpha, middle` fixture |
| `VerifiableCertificate.keyring` (non-optional control) | Valid verifiable certificates emit it unconditionally | Non-optional `IndexMap`, always emitted | **MATCH** — signed certificate-response preimage vectors |
| `RequestedCertificateSet.certifiers` / `types` (non-optional controls) | Both keys emitted whenever the set is present, including `{ certifiers: [], types: {} }` | Both non-optional with empty defaults; both emitted | **MATCH** — handshake and standalone-request envelope vectors |

`certificateRequest` remains a separate signed-preimage decision: no serializer or producer change was
made to its `requestedCertificates` value. TS signs `JSON.stringify(certificatesToRequest)` and Rust
continues to verify `serde_json::to_vec(requested)` with the supplied `IndexMap` order. This round only
corrected envelope member order, which is outside that signed preimage. The existing
`certificateResponse` signed-preimage vectors remain byte-identical and cross-verified.

## Map-in-signed-preimage audit

The audit followed every `serde_json::to_vec`/`to_string` site to every
`create_signature`/`verify_signature` call and then inspected the complete serialized type graph.

| Map site | Runtime type | Can reach a reserialized signature preimage? | Verdict |
|---|---|---|---|
| `Certificate.fields` | `IndexMap<String, String>` | Yes: nested in `certificateResponse` and in the certificate's own binary signing format | **SAFE on receive and issue** — wire order is preserved; issuance now accepts ordered input and preserves it through encryption; binary signing separately applies TS field collation |
| `VerifiableCertificate.keyring` | `IndexMap<String, String>` | Yes: nested in `certificateResponse` | **SAFE** — inbound and locally produced order are preserved; the constructor requires `IndexMap` |
| `VerifiableCertificate.decrypted_fields` | `Option<IndexMap<String, String>>` | Yes when explicitly present in `certificateResponse` | **FIXED** — three-key non-alphabetical TS fixture proves `zeta, alpha, middle` survives deserialize/reserialize |
| `RequestedCertificateSet.types` | `IndexMap<String, Vec<String>>` | Yes: `certificateRequest` JSON is signed directly | **SAFE** — supplied wire order is preserved |
| `MasterCertificate.master_keyring` and `VerifiableCertificate::new` input | `IndexMap<String, String>` | Yes, through verifier-keyring creation and auth response construction | **FIXED after R8 reopening** — caller/wallet order survives into signed JSON; live TS and Rust vectors pin `zeta, alpha, middle` |
| `ProveCertificateResult.keyring_for_verifier` | `IndexMap<String, String>` | Yes: `get_verifiable_certificates` passes it into `VerifiableCertificate` | **FIXED after R8 reopening** — wallet result order is no longer destroyed before auth serialization |
| `IdentityCertificate.publicly_revealed_keyring` / `decrypted_fields` | `IndexMap<String, String>` | Wallet discovery wire uses TS `Object.entries` order | **FIXED** — both public types and serializer/deserializer preserve order |
| `Peer` waiter/deferred/pending/session indexes | `HashMap<...>` | No; internal state only, none derives `Serialize` or nests in `AuthMessage` | **SAFE / NOT WIRE DATA** |
| AuthFetch request headers | `HashMap<String, String>` | The resulting payload is signed, but the map itself is not serialized | **SAFE** — `signable_request_headers` normalizes and sorts into a vector before encoding |
| Other wallet RPC maps (`PartialCertificate`, acquire/list/discovery args/results) | `HashMap<...>` | No path into `AuthMessage`; `Certificate` and the prove-result keyring are the separate ordered wire types | **OUTSIDE AUTH PREIMAGE** — keep `HashMap` |
| Other crate JSON maps (registry/service/remittance metadata) | `HashMap<...>` | No JSON value is reserialized to reconstruct a `create_signature`/`verify_signature` preimage | **NOT THIS DEFECT CLASS** — transaction/message signatures consume the already-produced raw bytes rather than rebuilding them from a parsed map |

Result: **no remaining `HashMap` can reach an auth JSON value that a peer reserializes to construct a
signature preimage.**

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
| 38 | `validate_certificates` over N certs | `Promise.all` (`dist/cjs/src/auth/utils/validateCertificates.js:14`) | **Worker pool**, `min(len(certs), NumCPU)`, first-error-cancels via `context.WithCancel` (`utils/validate_certificates.go:99-146`) | **FIXED** — `available_parallelism()`-bounded `FuturesUnordered`; first completed false/error drops siblings | Confirmed. Deterministic paused-time tests measured 1s sequential → 200ms bounded for 10 certs/8 CPUs and 7s → 0ms first-error cancellation. Single-cert behavior/order unchanged; multi-failure winner may differ, as in TS |
| 39 | `get_verifiable_certificates` → `prove_certificate` per cert | `Promise.all` (`dist/cjs/src/auth/utils/getVerifiableCertificates.js:18`) | Sequential (`get_verifiable_certificates.go:60`) | Sequential, documented | **REFUTED as a defect** — leave sequential. Go's real-parallelism implementation made this deliberate Layer-2 choice; local wallet fan-out has no demonstrated value |
| 40 | Transport receive/dispatch | Background `onData` callbacks | **Background goroutine** `go t.receiveMessages()` (`websocket_transport.go:74`) | **Caller-driven pull loop** (`process_next`/`process_pending`) — unique to the Rust port | **DECISION — analysis written** in `docs/CONFORMANCE-AND-CONCURRENCY.md`; no implementation per task. Background receive could remove the pull mutex/pending-response net and conditionally the deferred queue, but breaks pumping APIs/tests and requires new error/lifecycle/bounding semantics |
| 41 | Certificate gate on general messages | Present (`dist/cjs/src/auth/Peer.js:102-105`, receive path later in the same file) | **Absent** — `PeerSession` has no `CertificatesRequired`/`CertificatesValidated` fields at all | Kept, with registered pull-transport divergences | **REFUTED as a reason to remove it** — acceptance timing is peer-observable Layer 1, so TS remains normative. Go's omission informs mechanism/load-bearing analysis only |

## Decisions outstanding

- **Version resolved**: bumped to `0.8.0`; `0.7.2` would have auto-propagated the wire + API break to
  consumers pinned `^0.7`.
- **One TS bug conformed to deliberately**, documented in code, to be raised upstream:
  1. TS commits `certificatesValidated` *before* awaiting listeners, so a rejecting listener leaves
     validation committed
- **Mechanism divergence** (#3): Rust defers rather than blocks because TS assumes a callback transport.
  The non-identical overflow/duplicate/expiry/error behavior is now stated explicitly in the charter.
