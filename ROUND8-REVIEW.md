# Round 8 adversarial review — structural certificate round

Reviewed branch `fix/certificate-keyring-parity` at `2127ee1` against `609d0b0`, the full branch
history, the charter, the ledger, and executable `@bsv/sdk` 2.4.1 behavior from only:

`/private/tmp/claude-501/-Users-donot-Project-Atlas/03591944-f737-4bbf-9300-4eb98375a634/scratchpad/tssdk/package`

## Verdict

**BLOCK.** Round D fixed the sticky terminal certificate state, but it introduced or retained defects
at three boundaries: locally produced verifier keyrings are deterministically reordered away from TS,
the public single-frame drain API silently discards its frame's error, and session reaping does not
clean the peer-owned state indexed by the reaped nonce. The ledger also overclaims the test and map
audits.

## Ranked findings

### 1. BLOCKER — verifier-keyring order is still discarded on the signed auth path

- **Files:** `src/auth/certificates/verifiable.rs:44-53`,
  `src/auth/certificates/master.rs:108-221`, `src/wallet/interfaces.rs:2087-2105`,
  `src/wallet/serializer/prove_certificate.rs:160-192`, `REVIEW-LEDGER.md:26-27,186-190`
- **Defect:** Round D made local keyrings deterministic by accepting `HashMap` and sorting it
  alphabetically before constructing the serializable `IndexMap`. Deterministic is not byte-exact.
  TS preserves the caller/wallet object's insertion order, and `keyring` is inside the signed
  `certificateResponse` JSON preimage. `MasterCertificate::create_keyring_for_verifier` and
  `ProveCertificateResult` also return `HashMap`, so the order has already been destroyed before the
  constructor sorts it.
- **Concrete reproduction:** executing real TS 2.4.1 with fields and keyring inserted as
  `zeta, alpha, middle` produced `Object.keys(v.keyring) == ["zeta","alpha","middle"]`. The Rust
  constructor explicitly produces `alpha, middle, zeta`. The Rust-to-TS fixture has only one keyring
  member (`middle`), so every current cross-language test remains green.
- **Confidence:** high; confirmed by real TS output and an explicit Rust sort.
- **Provenance:** the unordered public inputs pre-existed, but Round D introduced the alphabetical
  conversion and then misreported the path as fixed. Treat as **introduced by Round D** for release
  accounting.

### 2. HIGH — `process_next` no longer reports the error for the one frame its caller asked it to process

- **File:** `src/auth/peer.rs:868-903` (especially `:901`)
- **Defect:** `process_next` is a public, single-frame operation returning `Result<bool, AuthError>`.
  Before Round D, every `dispatch_message` error reached that caller. It now returns `Ok(true)` for an
  unsupported version, invalid nonce/signature, missing session, replay, failed certificate
  validation, listener failure/timeout, or transport error. This is not a shared ownership boundary:
  the caller explicitly asked for exactly one frame. With no logging dependency, the failure is
  unrecoverable and indistinguishable from successful processing except for absent side effects.
- **Concrete reproduction:** enqueue an `AuthMessage` with `version = "hostile-version"`; direct
  `dispatch_message` returns `InvalidMessage`, while `process_next` at `2127ee1` returns `Ok(true)`.
- **Confidence:** high; direct control-flow proof.
- **Provenance:** **introduced by Round D** (`self.dispatch_message(msg).await?` became `let _ = ...`).

  The same conclusion does **not** apply uniformly to the other discard sites. `process_pending` is a
  shared drain and must continue past a bad frame so it can route later replies. The nested handshake
  drain at `src/auth/peer.rs:1263` must also isolate frames unrelated to the initial response it owns;
  a matching `initialResponse` still goes through `complete_handshake` and propagates its error.
  Deferred flush at `:839` runs after validation is committed and cannot roll that commit back.

### 3. MEDIUM — session reap leaves nonce-indexed peer state orphaned

- **Files:** `src/auth/peer.rs:1173-1193,1352-1365,1840-1860`,
  `src/auth/session_manager.rs:346-365`, `REVIEW-LEDGER.md:80-81`
- **Defect:** `SessionManager::reap_idle` removes only its own session and replay metadata. `Peer` owns
  three additional nonce-indexed stores: `certificate_validation_waiters`,
  `deferred_general_messages`, and `pending_initial_responses`. None of the three reap call sites
  cleans them. A deferred queue can therefore retain up to 128 signed frames after its session is
  gone; a late response for an abandoned unauthenticated handshake can remain in
  `pending_initial_responses`; a live waiter remains until its local deadline rather than being
  notified promptly. Repeating this across reaped session nonces grows state without a live-session
  bound.
- **Concrete reproduction:** make an authenticated session certificate-pending, defer one signed
  general message, insert a correlated pending initial response/waiter, backdate the session activity,
  then process a new `initialRequest` so `reap_idle` removes the old session. `session_by_identifier`
  returns `None`, but all three peer maps still contain the old nonce.
- **Confidence:** high; the stores and all reap sites were traced end to end.
- **Provenance:** **pre-existing** (the terminalization paths covered some success/expiry cases but
  never made session reap own this cleanup). Round D's ledger nevertheless claims eviction cleanup is
  complete.

### 4. MEDIUM — Round D's “all drain-sensitive tests are bounded” claim is false

- **Files:** `src/auth/clients/auth_fetch.rs:2018`, `tests/conformance_auth.rs:165-178`,
  `src/auth/peer.rs:4513,4536`, `REVIEW-LEDGER.md:29,109-110`
- **Defect:** the Round D audit converted most direct calls to `bounded`, but at least two direct
  `dispatch_message` calls remain untimed. Two newly added peer regressions time-bound dispatch and
  drain, then await `messages.recv()` without a deadline; a regression that consumes a frame but fails
  delivery hangs the test rather than failing. The AuthFetch listener regression performs its direct
  dispatch before entering its later two-second polling timeout.
- **Concrete reproduction:** replace delivery after dispatch with a pending future (or drop the
  general-channel send). `test_dispatch_general_resolves_nonce_once` and
  `test_drain_isolates_one_message_failure_and_continues` never reach an assertion. A stalled
  `handle_initial_request` similarly prevents the AuthFetch test from reaching its timeout.
- **Confidence:** high; direct untimed awaits.
- **Provenance:** mixed: the two peer receives and AuthFetch test were **added/changed by Round D**;
  the conformance helper is pre-existing. The false ledger claim was introduced by Round D.

### 5. LOW — discovery-map ordering was changed without a multi-entry regression

- **Files:** `src/wallet/serializer/certificate_ser.rs:98-145`,
  `tests/wallet_serializer_vectors.rs:1051-1165`
- **Defect:** Round D changed identity-discovery keyring/decrypted-field serialization from sorted
  `HashMap` keys to `IndexMap` insertion order, but both affected fixtures contain only one member.
  Reintroducing `keys.sort()` while retaining the public `IndexMap` types leaves the suite green.
- **Concrete reproduction:** the current discovery vectors use only `pubField` and `name`. A
  deterministic `zeta, alpha, middle` round trip is required to distinguish insertion order from
  sorting.
- **Confidence:** high.
- **Provenance:** **introduced by Round D** as a test-coverage gap.

## Required attack traces and refutations

### A1 — the removed error state is not load-bearing for gate completion

The two-state gate itself is correct:

- **Authenticated `[]`:** nonce/signature/replay checks complete, listeners receive `[]`, the session
  remains pending, and each explicit waiter ends at its own 30-second deadline. A later non-empty,
  valid response with a fresh message nonce is accepted and validates the session.
- **Validation failure:** that response returns its own error after its nonce is marked seen; the
  session remains pending. A later valid response with a fresh nonce is accepted.
- **Silence:** each waiter times out independently and its RAII registration is removed. The session
  remains pending, so a late valid response is accepted.

No session-wide terminalization, co-waiter deadline destruction, or permanent rejection remains.
Deferred frames are signature-checked before insertion and capped at 128 per session. The refutation is
qualified by finding 3: state indexed by a reaped session is not cleaned, and drain-driven expiry is not
an autonomous lifetime bound.

### A2/A3 — state after isolated dispatch failures

The important partial updates are deliberate or already registered: certificate-response replay state
is committed before certificate validation; successful validation and deferred release are committed
before listener execution, matching TS; general-message replay state precedes the bounded observer send,
whose capacity drop is registered in the charter. `create_general_message` and `send_message` now apply
the same immediate pending-gate error. Matching handshake responses still propagate their own errors.
Only the public one-frame `process_next` caller is silently broken (finding 2).

### A4 — compile-time fixture assertion

**Refuted.** In an isolated copy, reverting only
`VerifiableCertificate.decrypted_fields` from `Option<IndexMap<...>>` to `Option<HashMap<...>>` and
running `cargo check --offline --tests --all-features` failed at
`tests/auth_certificate_interop.rs:255` with E0308 (`expected &IndexMap`, `found &HashMap`). This is a
real compile-time guard, not another randomized runtime assertion. No remaining ordering assertion was
found to be probabilistic; finding 5 is instead an entirely unpinned multi-entry property, and finding 1
is missed by the single-entry Rust outbound vector.

### A5 — ordered master issuance

**Refuted as a source defect.** Caller fields enter `issue_certificate_for_subject` as `IndexMap`, pass
by reference through `create_certificate_fields`/`encrypt_fields`, are inserted into an `IndexMap` in
caller order, and are assigned directly to `Certificate.fields`. No unordered collection remains on
that field path. The certificate's own binary signature separately applies TS `localeCompare` ordering,
while later auth JSON serialization retains the stored insertion order. `master_keyring: HashMap` is a
parallel keyring path, not the certificate-field path; it is nevertheless part of finding 1 because it
eventually feeds auth keyring construction.

### A6 — executable TS and charter/ledger accuracy

The real package identified itself as `@bsv/sdk` `2.4.1`. A linked two-Peer run observed exactly one
standalone empty response, one empty listener delivery, a still-pending gate, a registered general wait,
zero delivery before validation, and one delivery after validation. The corrected charter divergence
classification is therefore accurate. Live TS also preserved `zeta, alpha, middle` for both `fields`
and `keyring`, refuting ledger rows F6 and the “SAFE AT BOUNDARY” keyring row. Ledger rows #14 and #33
also overclaim cleanup/bounding as described in findings 3 and 4.

The live verifier accepted both committed Rust certificate-response signatures and preserved every
committed Rust auth envelope.

### A7 — baseline result

`cargo test --all-features` passed at `2127ee1` (1,167 library tests plus integration suites; one
websocket test ignored). That green baseline does not refute the findings: the outbound keyring vector
has one entry, the reap seam has no test, `process_next` has no error-propagation test, and several tests
can wait without an outer deadline.
