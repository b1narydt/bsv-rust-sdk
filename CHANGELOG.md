# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.83] - 2026-05-05

### Added

- **Arcade broadcaster** (#32, EXPERIMENTAL) — POST `/tx` (no `/v1/` prefix), `Content-Type: application/octet-stream`, no auth. Asserts `{"status":"submitted"}` on a 202 and returns the locally-computed canonical txid (`Transaction::id()`). Module doc carries an EXPERIMENTAL warning + pinned full-SHA upstream reference (no `@bsv/sdk` parity reference exists yet).
- **Full TS `SHIPBroadcaster.ts` parity for `TopicBroadcaster`** (#32):
  - **Three-field `AckPolicy`** mirroring TS lines 67-71 — `require_from_all_hosts`, `require_from_any_host`, `require_from_specific_hosts`, each accepting an `AckTopics` selector (`All` / `Any` / `List(Vec<String>)`). Compound checks evaluate in canonical order (AllHosts → AnyHost → SpecificHosts) with three distinct error codes (`ERR_REQUIRE_ACK_FROM_{ALL_HOSTS,ANY_HOST,SPECIFIC_HOSTS}_FAILED`).
  - **5-min `interestedHostsCache` + in-flight dedup** — `Arc<Mutex<InterestedHostsCache>>` with leader/follower pattern via `tokio::sync::broadcast`. Concurrent broadcasts share one SHIP query rather than firing duplicates. Cache untouched on leader error (matches TS finally-block at lines 487-488).
  - **`offChainValues` body framing** — `TaggedBEEF.off_chain_values: Option<Vec<u8>>`. When set, the request body is `varint(beef.len()) || beef || off_chain_values` and the `x-includes-off-chain-values: true` header is added (matches TS lines 100-110). New public method `broadcast_beef_with_off_chain` since the Rust SDK has no `Transaction.metadata` facility.
  - **Concurrent host fan-out** via `futures::future::join_all` (matches TS line 213 `Promise.all`); wall-clock is now max(host_latency) instead of sum.
  - **Partial-success message** appends per-host failure details so 1/10 vs 9/10 success is visible to operators.
- **Typed structured fields on `BroadcastResponse` / `BroadcastFailure`** (#32, Quaakee F32-2 review fix) — `competing_txs: Option<Vec<String>>`, `txid: Option<String>` (failure path), `more: Option<serde_json::Value>` (raw upstream JSON). Mirrors TS `Broadcaster.ts:11-34`. Programmatic callers can now recover ARC's `competingTxs`, failure-path `txid`, and RFC-7807 problem-details fields structurally rather than regex-parsing description text. Both structs derive `Default`.
- **`broadcast_beef_with_off_chain` public API** on `TopicBroadcaster` (#32) — explicit off-chain-payload submit; the SDK's `Transaction` has no `metadata` bag, so callers pass off-chain bytes directly.
- **`Transaction::to_bytes_ef`** (#32) — sibling of `to_hex_ef` returning `Vec<u8>`. Used by ARC for canonical octet-stream wire form.
- **`WhatsOnChainBroadcaster::wait_for_visibility`** (#32) — bounded exponential backoff (≈ `0, 2s, 6s, 14s, 30s, 60s`) waiting for a tx to appear via WoC GET. Bails fast on 400/401/403 (caller-side errors no amount of waiting will fix).
- **Network error classification helper `classify_reqwest_err`** (#32, Quaakee F32-13 review fix) — distinguishes `NETWORK_TIMEOUT` / `NETWORK_CONNECT` / `NETWORK_REQUEST` / `NETWORK_ERROR` via `reqwest::Error::is_*()` predicates with `source()` chaining preserved in the description. Applied at all 4 broadcaster send-error sites + WoC body-read site. Retry policies can now branch on transient (timeout/connect) vs permanent (request-build) class.

### Fixed

- **ARC: canonical octet-stream + binary EF body** (#32) — Content-Type now pairs with raw binary bytes (was hex-string body). `X-Api-Key` replaced with `Authorization: Bearer` per spec. Adds `XDeployment-ID: rust-sdk-{16-hex}` per canonical convention. Falls back to literal `rust-sdk-no-entropy` instead of panicking on `getrandom` failure (sandboxed/no-entropy environments).
- **ARC: 200 OK with error `txStatus` is a broadcast failure** (#32) — surfaces `DOUBLE_SPEND_ATTEMPTED`, `REJECTED`, `INVALID`, `MALFORMED`, `MINED_IN_STALE_BLOCK` plus any `ORPHAN` substring (case-insensitive in `txStatus` or `extraInfo`) as `BroadcastFailure`. Previously the Rust port reported these as success with txid set, which is dangerous in mint-and-merge flows where a `DOUBLE_SPEND_ATTEMPTED` would be persisted as confirmed.
- **ARC error description: prefer RFC-7807 `body.detail`** (#32, Quaakee F32-3 review fix) — canonical TS `ARC.ts:213-215` reads `body.detail`, the field real ARC servers actually emit. Rust now uses fallback chain `detail → description → title → message`.
- **ARC failure code = HTTP status** (#32, Quaakee F32-4 review fix) — canonical TS `ARC.ts:189-195` uses `response.status.toString()`. Structured `body.code` (when present) is now preserved on `more`. Cross-SDK retry policies keying on `code` now match.
- **ARC `MALFORMED_SUCCESS_BODY` extended to validate `competingTxs`** (#32, Quaakee F32-17 review fix) — must be a JSON array of strings per OpenAPI; non-array (or non-string elements) now surfaces as `MALFORMED_SUCCESS_BODY` rather than being silently coerced.
- **ARC success message includes `extraInfo`** (#32) — matches TS `ARC.ts:182` `message: \`${txStatus} ${extraInfo}\``.
- **WhatsOnChain: failure code = upstream HTTP status** (#32) — was hardcoded `"BROADCAST_FAILED"`. Matches TS `WhatsOnChainBroadcaster.ts:67-69`. Test updated.
- **WhatsOnChain: 64-char hex txid validation** (#32, Quaakee F32-18 review fix) — `trim_matches('"')` strips multiple quote layers; previously a 200 body of `"error: invalid"` would slip through as a "success" txid, poisoning STAS3's `wait_for_visibility` path. Tightens to `len() == 64 && all-ascii-hexdigit`.
- **WhatsOnChain: collapsed duplicate `Broadcaster` impls** (#32) — `WhatsOnChainBroadcaster` and `WhatsOnChainBroadcasterWithUrl` now share `broadcast_to_woc_url` so any future error-handling fix applies once.
- **WhatsOnChain: `Accept: text/plain` header** (#32) — matches canonical TS request shape.
- **`TopicBroadcaster` non-2xx response body now read** (#32, Quaakee F32-14 review fix) — overlay hosts emit `{"error": …, "code": …}` on failure; previously the body was dropped. Now read + truncated to `MAX_BODY_PREVIEW_CHARS` and embedded in the error string.
- **`TopicBroadcaster` follower path receives leader's actual error** (#32, Quaakee F32-20 review fix) — in-flight broadcast channel type changed from `HashMap<…>` to `Result<HashMap<…>, String>`. Concurrent followers now see the leader's real error (timeout / lookup-server 5xx / BEEF decode failure) rather than collapsing to `RecvError::Closed` and a generic "leader errored" string.
- **`TopicBroadcaster` BEEF decode-failure visibility** (#32) — when SHIP discovery returns adverts but every BEEF fails to decode, `ERR_NO_HOSTS_INTERESTED` description includes "(N SHIP advert(s) failed to decode — possible BEEF corruption)" so silent corruption is distinguishable from no-hosts.
- **Arcade callback headers gated on `callback_url`** (#32, Quaakee F32-11 review fix) — `X-CallbackToken` and `X-FullStatusUpdates` are now nested inside the `if let Some(callback_url)` branch. Without an URL the server has nowhere to deliver notifications.
- **`Spend::write_varint_to_vec` promoted to `pub(crate)`** (#32) — needed by `TopicBroadcaster` for off-chain body framing.

### Changed

- **`TopicBroadcasterConfig.acknowledgment_mode` → `ack_policy`** (#32) — type changed from `AcknowledgmentMode` enum to `AckPolicy` struct (three independent fields). The legacy `AcknowledgmentMode` enum is now `#[deprecated]`; convertible to `AckPolicy` via `From`/`.into()`. **Breaking** for callers using struct-literal init with the old field.
- **`serde_json` is now a non-optional dependency** — required by `BroadcastFailure.more: Option<serde_json::Value>` which is unconditionally available on the public type. Negligible binary-size cost (pure Rust, ~100KB).

### Tests

- **31 new tests across broadcasters** (#32):
  - 13 ARC tests including `MALFORMED_SUCCESS_BODY` for non-string txStatus / non-array competingTxs / non-array elements, `body.detail` (RFC-7807) preference, `body.code` routed to `more`, custom-headers passthrough, deployment-ID uniqueness per call, auth-bearer presence/absence.
  - 7 WhatsOnChain tests including hex-txid validation, network-error classification, body-read failure, `wait_for_visibility` schedule (success / 404-exhaustion / mid-budget / fast-bail-on-401 / network-error).
  - 7 Arcade tests including callback gate (assert headers absent without URL), 4xx/5xx body parsing, status-not-submitted MALFORMED.
  - 13 TopicBroadcaster tests including 6 ack-policy variants (list-named-only, any-host-any-topic, specific-host-missing, specific-host-passes, two compound-policy ordering tests), 3 cache tests (TTL hit, expired-not-returned, not-poisoned-on-leader-error), 5 off-chain framing tests (framed-body-and-header, no-framing-without, empty-vec-still-frames, varint-3-byte-boundary at BEEF len 253, end-to-end via public API), partial-success message format, all-hosts-fail surfaces `ERR_ALL_HOSTS_REJECTED`, `ERR_BEEF_PARSE` typed error.
- **2 new util tests** (#32) — `MAX_BODY_PREVIEW_CHARS` truncation lower/upper bounds.

## [0.2.82] - 2026-04-15

### Added

- **`Transaction::to_beef()`** (#28) — serializes a transaction and its source chain to BEEF V1 format by delegating to the existing `Beef` struct, so BUMP deduplication, topological sorting, and wire serialization go through one code path instead of an inline reimplementation. Matches TS SDK `Transaction.toBEEF()`.
- **`TopicBroadcaster::broadcast_beef(Vec<u8>)`** (#28) — broadcasts pre-built BEEF bytes directly. Lets callers that already hold BEEF (e.g. from `create_action` / `sign_action` results) skip the `Transaction → to_beef()` round-trip. `broadcast()` is refactored to share the HTTP/error-collection path via a shared `broadcast_beef_inner()`.

### Fixed

- **`TopicBroadcaster` sent raw tx bytes instead of BEEF** (#28, redo of reverted #26/#27) — overlay SHIP hosts parse bodies with `Transaction.fromBEEF`, so every Rust-SDK submission was rejected with `ERR_ALL_HOSTS_REJECTED`. `broadcast()` now calls `tx.to_beef()` and posts the BEEF body. Returns a clear error when an input lacks `source_transaction` (required to build BEEF) and validates that the assembled BEEF contains at least one BUMP before submitting.
- **`Beef::into_transaction()` dropped merkle paths on reconstruction** (#28) — proven txs carry their proof via `bump_index` into `self.bumps`, but `into_transaction()` wasn't copying the referenced `MerklePath` onto the subject tx or any source tx in the chain. Result: `from_beef → to_beef` round-trips lost proofs and re-serialized output differed from input. Now attaches `merkle_path` from the bump index on both the subject and any linked source transactions. Also returns an error on out-of-bounds `bump_index` instead of silently skipping, so corrupt BEEF surfaces immediately rather than producing a half-populated `Transaction`.
- **Silent failures in `TopicBroadcaster` error paths** (#28) — `unwrap_or_default()` on `tx.id()` produced an empty txid string on failure, and `unwrap_or_default()` on the `X-Topics` header silently dropped serialization errors. Both now propagate real errors. Per-host broadcast failures are collected and included in the `ERR_ALL_HOSTS_REJECTED` message instead of being swallowed, so operators can see which hosts rejected and why. The misleading "broadcast succeeded but..." wording on the final error has been corrected.

### Tests

- Added 5 tests covering the BEEF round-trip and broadcaster error paths: `to_beef` round-trip across all `beef_valid.json` vectors, byte-equal re-serialization, multi-tx source chain with topological ordering, missing-merkle-proofs error, missing-source-transaction error. Plus `into_transaction` coverage for merkle-path attachment on the subject (vector 0) and on a 2-tx source chain (vector 1).

## [0.2.81] - 2026-04-14

### Fixed

- **BRC-100 JSON wire-format parity with TS SDK** (#24) — two classes of drift in `HttpWalletJson` substrate types (`src/wallet/interfaces.rs`). Binary serializers under `src/wallet/serializer/` were already correct and are unchanged.
  - **`reference` field encoding**: `SignActionArgs.reference`, `AbortActionArgs.reference`, and `SignableTransaction.reference` now use `serde_helpers::bytes_as_base64` instead of `bytes_as_array`, matching the TS `Base64String` type. Previously, deserializing TS-produced JSON failed outright (`invalid type: string "dGVzdA==", expected a sequence`). `SignableTransaction.tx` correctly stays on `bytes_as_array` (TS type is `AtomicBEEF = Byte[]`).
  - **Default-valued field omission**: TS uses `JSON.stringify(args)` which omits `undefined` properties. Rust was emitting `"forSelf": null`, `"identityKey": false`, `"seekPermission": true`, etc. for fields the caller never set. Resolution: `BooleanDefaultTrue` / `BooleanDefaultFalse` newtypes gain a `none()` constructor returning `Self(None)`; all 22 `BooleanDefault*` field annotations now use `default = "BooleanDefault*::none"` + `skip_serializing_if = "BooleanDefault*::is_none"` so missing JSON deserializes to `None` (omitted on re-serialize) while explicit `true`/`false` round-trips intact. `Default::default()` still returns `Self(Some(default))` for runtime convenience, so no caller breaks. Also added `skip_serializing_if = "Option::is_none"` to 9 `Option<bool>` fields (`VerifySignatureArgs.for_self` + 8 `seek_permission` occurrences) and an `is_false` skip on `GetPublicKeyArgs.identity_key`. Verified against `rust-wallet-toolbox/tests/brc100_vectors.rs` reproducer: 49 pass / 8 fail → 57 pass / 0 fail.

## [0.2.8] - 2026-04-13

### Fixed

- **`write_send_with_results` empty-array encoding** (#23) — writer now emits the `NEGATIVE_ONE` varint sentinel (9 bytes of `0xFF`) for empty `sendWithResults`, matching BRC-100 canonical universal test vectors and the Go SDK wire format. Previously wrote `varint(0)`. Reader accepts both `0` and `NEGATIVE_ONE` as empty for backward compatibility. Affects both `serialize_create_action_result` and `serialize_sign_action_result` (shared helper in `src/wallet/serializer/create_action.rs`).

### Tests

- Added 8 BRC-100 universal test vectors, bringing wire-format coverage from 54 to 62 (all canonical vectors now covered): `getNetwork-simple-args`, `getVersion-simple-args`, `createAction-1-out-result`, `createAction-no-signAndProcess-{args,result}`, `signAction-simple-result`, `acquireCertificate-issuance-result`, `listCertificates-full-args`. All vector files are byte-identical copies from `universal-test-vectors/generated/brc100/`.

## [0.2.7] - 2026-04-13

### Added

- **`AuthFetch` HTTP 402 Payment Required auto-retry** (#21) — ports TS SDK `AuthFetch.handlePaymentAndRetry`. When a paid endpoint returns 402, `AuthFetch::fetch` now automatically reads `x-bsv-payment-version`, `x-bsv-payment-satoshis-required`, and `x-bsv-payment-derivation-prefix` from the response, derives a BRC-29 payee key (`Protocol { security_level: 2, protocol: "3241645161d8" }`, `keyID = "{prefix} {suffix}"`, `counterparty = serverIdentityKey`), builds a P2PKH locking script, calls `wallet.create_action`, and re-sends the request with an `x-bsv-payment` header carrying `{derivationPrefix, derivationSuffix, transaction}` camelCase JSON. Wire-compatible with TS AuthFetch.
- **`AuthFetch::fetch_with_options`** public API — accepts a `FetchOptions { payment_retry_attempts: Option<u32> }` for configurable retry limits. Default is 3 attempts, clamped to minimum 1.
- **Public types**: `FetchOptions`, `PaymentErrorLogEntry`, `PaymentRetryContext`, `PAYMENT_VERSION` constant. Re-exported from `bsv::auth::clients` and `bsv::auth`.
- **New `AuthError` variants**: `Payment(String)` for per-attempt failures (missing/invalid headers, no tx bytes from wallet), `PaymentFailed { attempts, max_attempts, message }` for retry exhaustion.

### Changed

- **Retry transaction regeneration** — intentional divergence from TS SDK: the Rust implementation regenerates the payment transaction on every retry attempt, rather than reusing a cached transaction when server parameters haven't changed. The TS cache (`isPaymentContextCompatible`) risks double-spend rejection if the server rebroadcasts the same tx on a second 402. Rust always creates a fresh `PaymentRetryContext` per attempt — safer, with identical wire behavior per attempt.
- Retry backoff is linear: `250ms × min(attempt, 5)`, matching TS `getPaymentRetryDelay` exactly.

## [0.2.6] - 2026-04-12

### Added

- **`Peer::listen_for_certificates_requested` / `stop_listening_for_certificates_requested`** (#19) — new public API mirroring TS SDK `Peer.listenForCertificatesRequested` / `stopListeningForCertificatesRequested`. Registered callbacks override the default auto-response so consumers can supply their own certificate-resolution logic. Observer channel exposed via `on_certificate_request()` continues to fire regardless of listener registration.
- **`OnCertificateRequestReceived`** public type alias (`dyn Fn(String, RequestedCertificateSet) + Send + Sync + 'static`) for the listener callback.

### Fixed

- **`Peer::dispatch_message` auto-responds to inbound `CertificateRequest`** (#19) — previously the `CertificateRequest` arm forwarded the message to the `certificate_request_tx` observer channel and returned `Ok(())` without invoking `send_certificate_response`. Downstream middleware (e.g. `bsv-auth-axum-middleware` 0.1.1) had to re-implement the auto-response round trip with a 500ms timeout workaround. Now ports the full TS `Peer.processCertificateRequest` flow: nonce verification, signature verification over `JSON.stringify(requestedCertificates)`, then listener-registered callbacks OR wallet-driven auto-response via `get_verifiable_certificates` + `send_certificate_response`. Same branching added to `handle_initial_request` (single-round-trip embed in `initialResponse.certificates`) and `complete_handshake` (separate follow-up `CertificateResponse`).
- **`Peer::send_certificate_response` signs outgoing messages** (#19) — the Rust port previously shipped `CertificateResponse` AuthMessages with `signature: None`, causing any receiver performing TS-parity signature verification to reject them. Now signs `JSON.stringify(certificates)` inline at the Peer level with `keyID = "{requestNonce} {peerNonce}"` and `counterparty = peerIdentityKey`, matching TS `Peer.sendCertificateResponse` exactly.
- **`AuthFetch` cert-exchange serialization matches TS `pendingCertificateRequests` semantics** (#19) — replaced the inline channel-drain (`process_certificate_requests`) with a registered cert-request listener. `fetch()` now polls an `Arc<Mutex<Vec<bool>>>` queue (30s timeout, 100ms interval — `CERTIFICATE_WAIT_TIMEOUT` / `CERTIFICATE_WAIT_POLL_INTERVAL`) before emitting its general message, and the listener sleeps `CERTIFICATE_POST_SEND_GRACE` (500ms) after sending the `CertificateResponse` before shifting the queue. Mirrors TS `AuthFetch.ts:131-264`.
- **`Peer` observer channel is non-blocking** — the three sites that push to `certificate_request_tx` now use `try_send` instead of awaiting `send`. A full buffer with no consumer can no longer stall `dispatch_message`.

## [0.2.5] - 2026-04-12

### Added

- **PushDrop `lock_position` support** — aligns with TS SDK parity for lock positioning in PushDrop script construction.

### Fixed

- **`AuthFetch` session reuse** (#18) — `AuthFetch::fetch()` now passes the cached `auth_peer.identity_key` to `get_authenticated_session()` after the first handshake, eliminating a redundant handshake on every subsequent request. Matches TS SDK behavior where `peers[baseURL].identityKey` is learned from the server's initial response and reused.
- **BRC-100 arg structs accept omitted optional fields** (#11/#12) — added `#[serde(default)]` to boolean, `BooleanDefaultTrue`, `BooleanDefaultFalse`, and `Counterparty` fields across 16 arg structs so TS SDK clients can omit optional fields without triggering 422 errors.
- **`Counterparty::default()` now returns `Uninitialized`** (#12) — preserves `ProtoWallet::default_counterparty()` per-op dispatch so `createSignature` with an omitted `counterparty` correctly defaults to `Anyone` (matching TS `ProtoWallet.ts:259`) instead of silently deriving against `Self_`. Fixes cross-SDK signature divergence.
- **`Counterparty::deserialize` accepts explicit JSON `null`** (#12) — both omitted and `null` `counterparty` now map to `Uninitialized`, matching TS `??` nullish-coalesce semantics.
- **`list_certificates` keyring three-state serialization** (#12) — serializer preserves `None` / `Some(empty)` / `Some(populated)` distinction on the wire per Go SDK `list_certificates.go:101-119`. Previously `Some(empty)` was folded into the same flag byte as `None`.
- **Overlay `PushDrop` field extraction for SHIP/SLAP tokens** (#15) — corrected field extraction logic.
- **`OverlayAdminTokenTemplate::decode_from_beef` parses BEEF format** (#14) — previously failed on BEEF-encoded inputs.

## [0.2.4] - 2026-04-06

### Fixed

- **`GetPublicKeyArgs` optional field serialization** — Added `skip_serializing_if = "Option::is_none"` to `for_self` and `seek_permission` fields, preventing `null` values from appearing on the wire when unset.

## [0.2.3] - 2026-03-30

### Added

- **`ReviewActionResult` and `ReviewActionResultStatus` types** — New types for undelayed broadcast result handling.

## [0.2.2] - 2026-03-30

### Fixed

- **`InternalizeOutput` enum serde field rename** — Added explicit
  `#[serde(rename = "outputIndex")]` to `output_index` fields in both
  `WalletPayment` and `BasketInsertion` variants. The enum-level
  `rename_all = "camelCase"` does not cascade into internally-tagged
  enum variant fields, causing `output_index` to appear on the wire
  instead of `outputIndex`. Required for TS wallet-toolbox wire parity.

## [0.2.1] - 2026-03-30

### Fixed

- **JSON serde annotations for HttpWalletJson interop** — Corrected three
  `serde(with)` mismatches in `wallet/interfaces.rs` that caused
  `HttpWalletJson` to fail when communicating with BSV Desktop wallet:
  - `CreateSignatureResult.signature`: `bytes_as_hex` → `bytes_as_array`
    (TS SDK returns `Byte[]`, Go SDK uses `BytesList` — both are number arrays)
  - `VerifySignatureArgs.signature`: `bytes_as_hex` → `bytes_as_array`
    (same mismatch)
  - `Payment.derivation_prefix/suffix`: `bytes_as_array` → `bytes_as_base64`
    (TS SDK uses `Base64String`, Go's default `json.Marshal` for `[]byte` is base64)

### Added

- **`bytes_as_base64` serde helper** — Serialize/deserialize `Vec<u8>` as
  base64 strings, matching Go SDK and TS SDK `Base64String` wire format.
  Used for `Payment.derivation_prefix` and `Payment.derivation_suffix`.

## [0.2.0] - 2026-03-26

### Added

- **Complete remittance protocol module** — Full port of the TypeScript SDK's
  remittance system with wire-format parity, gated behind the `network` feature.

- **RemittanceManager** — 20+ public async methods covering the full payment
  lifecycle: `send_invoice`, `pay`, `sync_threads`, `start_listening`,
  `wait_for_receipt`, `wait_for_state`, `wait_for_identity`,
  `wait_for_settlement`, `send_unsolicited_settlement`, with event system
  (subscribe + unsubscribe), state persistence, and message deduplication.

- **BRC-29 module** (`Brc29RemittanceModule`) — P2PKH settlement module with
  `build_settlement` (nonce generation, derived keys, wallet.createAction) and
  `accept_settlement` (wallet.internalizeAction with WalletPayment and
  BasketInsertion support). Configurable via `Brc29RemittanceModuleConfig`
  with 9 fields matching TS SDK defaults.

- **Trait interfaces** — `CommsLayer` (message transport), `IdentityLayer`
  (certificate exchange), `RemittanceModule` (typed) with `ErasedRemittanceModule`
  (type-erased via blanket impl for heterogeneous module registry).

- **9-state thread machine** — New, IdentityRequested, IdentityResponded,
  IdentityAcknowledged, Invoiced, Settled, Receipted, Terminated, Errored
  with validated transitions matching TypeScript SDK exactly.

- **Identity exchange** — Identity-before-settlement and identity-before-invoicing
  guards, phase-aware role inference for identity messages on new threads,
  full request/response/acknowledgment flow.

- **Wire format parity** — All protocol types serialize to identical JSON as
  the TypeScript SDK (camelCase fields, protocolID casing, optional field
  omission). Verified with TS-originated JSON deserialization test vectors.

- **ThreadHandle and InvoiceHandle** — Ergonomic wrappers with `wait_for_state`,
  `wait_for_receipt`, `wait_for_identity`, `wait_for_settlement`, and
  `InvoiceHandle.pay()`.

- **InternalizeProtocol enum** — `WalletPayment` and `BasketInsertion` variants
  with serde support, wired into `accept_settlement` dispatch.

- **Validation helpers** — `ensure_valid_option` (amount, payee, protocolID,
  labels, description), `ensure_valid_settlement` (transaction, derivation,
  amount), `is_atomic_beef`.

### Fixed

- **Pre-existing wallet compilation errors** — Wrapped `None` values in
  `BooleanDefaultTrue`/`BooleanDefaultFalse` newtypes in `substrates/tests.rs`
  and `token_lifecycle` example. Fixed `std::sync::Mutex` lock call in
  `auth/transports/http.rs` that was incorrectly awaited as async. Unblocks
  `cargo test --features network` for the full test suite.

- **`receipt_provided` default** — Changed from `false` to `true` to match
  TypeScript SDK.

- **`identity_poll_interval_ms` default** — Changed from `1000` to `500` to
  match TypeScript SDK.

### Tests

- 96 new remittance tests (52 BRC-29, 36 manager, 7 module, 6 trait) plus
  29 wire format and 13 type/state transition tests.
- Full end-to-end narrative test (invoice → settlement → receipt).
- Identity-before-invoicing integration test.
- Module-refuses-settlement termination flow test.
- Event listener subscribe/unsubscribe test.
- TS-originated JSON deserialization vectors for all 7 message types.
- Exhaustive 9x9 state transition matrix test.
- Total suite: 1,196 tests pass, 0 fail.

## [0.1.75] - 2026-03-19

### Fixed

- **`CertificateType::from_string` now decodes base64 and hex** -- Previously
  only accepted raw byte strings <=32 chars, rejecting base64-encoded types
  (44 chars) which caused certificate lookups to silently fall back to all-zeros.

### Added

- **`partial` field on `ListCertificatesArgs`** -- Optional `PartialCertificate`
  filter for exact certificate matching by type, serialNumber, certifier, and
  subject. Required by `proveCertificate` which calls `listCertificates` with
  a partial filter to find the unique matching certificate.

## [0.1.74] - 2026-03-19

### Fixed

- **`Peer::dispatch_message` is now public** -- Allows middleware to verify
  individual auth messages directly without draining the entire transport
  channel via `process_pending`, preventing request serialization bottlenecks.

- **`handle_general_message` uses non-blocking channel send** -- Changed
  `general_message_tx.send().await` to `try_send()` to prevent deadlock when
  the general message channel fills up (buffer=32) and nobody consumes from it.
  Previously, after 32 authenticated requests the Peer Mutex would deadlock.

## [0.1.73] - 2026-03-15

### Changed
- **`ProveCertificateArgs.certificate`** -- now uses `PartialCertificate` (all fields optional) instead of `Certificate`, matching TS SDK's `Partial<WalletCertificate>`
- **`ProveCertificateResult`** -- added optional `certificate` and `verifier` fields

## [0.1.72] - 2026-03-10

### Fixed
- **Auth payload deserialization overflow** -- `deserialize_request_payload` now correctly handles varint(-1) sentinel (two's complement `u64::MAX`) as "absent/empty" for query string, body, and header count fields. Previously caused `attempt to add with overflow` panic when parsing payloads serialized with the corrected varint(-1) encoding.

## [0.1.71] - 2026-03-10

### Fixed
- **`ProveCertificateArgs.certificate` type mismatch** -- added `.into()` conversion from `Certificate` to `PartialCertificate` in identity client, fixing compilation with `network` feature enabled

## [0.1.7] - 2026-03-10

### Fixed
- **BRC-100 compliance** -- merged PR #5 (sirdeggen): align wallet interface with TS SDK and BRC-100 spec
- **`verify_signature_sync` now properly handles `hash_to_directly_verify`** -- previously ignored the parameter and only used `data`
- **`verify_signature` accepts `Option<&[u8]>` for both `data` and `hash_to_directly_verify`** -- callers must provide at least one
- **`prove_certificate` serialization** -- updated to match TS SDK wire format
- **`list_actions` serialization** -- added missing fields
- **`create_signature` / `verify_signature` serialization** -- aligned with BRC-100 spec

## [0.1.6] - 2026-03-09

### Added
- **`PushDrop::decode()`** -- decodes a PushDrop script back into its component fields and locking key, with 4 unit tests
- **`Transaction::from_beef()`** -- constructs a Transaction from BEEF binary data, resolving source transactions from the BEEF structure
- **`Beef::into_transaction()`** -- extracts the subject transaction from a BEEF container as a fully-resolved Transaction
- **`Beef::sort_txs()`** -- topologically sorts BEEF transactions so dependencies appear before dependents, with 4 unit tests
- **`SerialNumber::from_string()`** -- parses a serial number from its string representation, with 5 unit tests
- **`BeefParty::new()` iterator API** -- accepts any `IntoIterator<Item = Beef>` instead of requiring a pre-built `Vec`, with 3 unit tests

### Changed
- **`BooleanDefaultTrue` / `BooleanDefaultFalse` converted from type aliases to newtypes** -- now proper structs with `Default` (returning `true`/`false` respectively), `Deref<Target = bool>`, `From<bool>`, and serde support. Enables correct default semantics in wallet option types.
- **`InternalizeOutput` converted from struct to enum** -- now `InternalizeOutput::Change` and `InternalizeOutput::NoChange` variants matching TypeScript SDK semantics
- **`ProtoWallet` inherent methods renamed with `_sync` suffix** -- `get_public_key` -> `get_public_key_sync`, `encrypt` -> `encrypt_sync`, etc. (9 methods total). Eliminates name collision between inherent methods and `WalletInterface` trait methods, enabling correct trait dispatch.
- **`WalletInterface` generic bounds relaxed with `?Sized`** -- added to certificate operations, identity client, contacts manager, and registry client generics, enabling `dyn WalletInterface` usage in more contexts
- **`Default` derives added to `CreateActionOptions` and `SignActionOptions`** -- enables `..Default::default()` builder pattern
- **`WalletError` now implements `From<String>`** -- enables `?` operator with string error sources

## [0.1.5] - 2026-03-09

### Added
- **`CachedKeyDeriver::root_key()` accessor** -- exposes a `&PrivateKey` reference to the root key, eliminating the need to store root key material separately for BRC-29 key derivation
- **`KeyDeriver::root_key()` accessor** -- same root key accessor on the underlying deriver
- **`Transaction::sign_all_inputs()` bulk signing** -- signs all unsigned inputs in one call by resolving source satoshis and locking scripts from each input's `source_transaction`, reducing the verbose per-input signing loop

### Changed
- **`CachedKeyDeriver` now uses interior mutability** -- internal cache changed from `HashMap` to `RwLock<HashMap>`, so all `derive_*` methods now take `&self` instead of `&mut self`. This allows `Arc<CachedKeyDeriver>` to be shared directly without wrapping in `Arc<Mutex<CachedKeyDeriver>>`

## [0.1.4] - 2026-03-09

### Added
- **BEEF merge and atomic serialization methods** matching TypeScript SDK:
  - `Beef::merge_beef()` -- merge another Beef (bumps deduplicated by block height + root, transactions by txid)
  - `Beef::merge_raw_tx()` -- merge a raw serialized transaction with optional bump index
  - `Beef::to_binary_atomic()` -- serialize as Atomic BEEF (BRC-95) targeting a specific txid
  - `Beef::merge_beef_from_binary()` -- convenience method to merge from raw bytes
  - `Beef::merge_bump()` -- merge a MerklePath with deduplication and transaction bump assignment
  - `Beef::find_txid()` -- look up a BeefTx by txid
- 9 new unit tests for BEEF merge and atomic serialization

### Fixed
- Removed stale "Stub for Task 1" comment from beef.rs module documentation

## [0.1.3] - 2026-03-08

### Fixed
- **Critical: prevent unsigned overflow panic in `truncate_to_n`** -- use `saturating_sub` for `msg.byte_length() * 8 - n_bit_length` in ECDSA signature truncation. SHA-256 hashes with leading zero bytes (byte_length < 32) would cause a subtract-with-overflow panic. Matches TypeScript SDK behavior where negative delta harmlessly skips the shift.

## [0.1.2] - 2026-03-08

### Added
- Certificate exchange support in AuthFetch and Peer -- enables authenticated certificate acquisition and proving over HTTP transport

### Fixed
- Normalize `content-type` header in AuthFetch request serialization to prevent case-sensitivity mismatches
- Use `std::sync::Mutex` instead of `tokio::sync::Mutex` for `subscribe()` in HTTP transport, fixing potential deadlocks in sync contexts
- Add `process_pending` call in AuthFetch to flush queued messages before sending requests

## [0.1.1] - 2026-03-08

### Changed
- **WalletInterface and WalletWire traits migrated to `#[async_trait]`** for object safety -- `dyn WalletInterface` and `dyn WalletWire` now compile and work with `Box`, `Arc`, and trait objects (Phase 10)
- All 10 `impl WalletInterface` / `impl WalletWire` blocks annotated with `#[async_trait::async_trait]`
- 4 internal macros (`stub_method!`, `impl_json_method!`, `impl_wire_method!`, `impl_validated_method!`) desugared to produce async-trait compatible `Pin<Box<dyn Future>>` signatures

### Added
- `async-trait` as a required dependency
- Dispatch overhead benchmark (`benches/dispatch_bench.rs`) comparing RPITIT vs async-trait (~10ns delta, negligible)
- Technical report: `docs/wallet-interface-object-safety.md` with Send audit, benchmark data, and cross-SDK comparison

### Fixed
- Production hardening: removed all `unwrap()`/`panic!()` from library code (Phase 9)
- Clippy clean with zero warnings
- Visibility audit: only public API items are `pub`

## [0.1.0] - 2026-03-07

### Added
- Pure Rust cryptographic primitives: BigNumber, SHA-256, SHA-512, RIPEMD-160, HMAC, AES-CBC, AES-GCM, ECDSA, Schnorr
- secp256k1 elliptic curve with Jacobian coordinates, wNAF multiplication, Shamir's trick
- PrivateKey/PublicKey with WIF, DER, and address derivation
- Script engine with full opcode support, stack machine interpreter, and script templates (P2PKH, R-Puzzle, RPuzzle)
- Transaction builder with BEEF serialization, Merkle path validation, and fee models
- BIP-32 HD key derivation and BIP-39 mnemonic support
- BRC-42/43 key derivation, BRC-77 signed messages, BRC-78 encrypted messages
- WalletInterface trait (BRC-100) with 28 wallet operations
- Wallet substrates: ProtoWallet, WalletWireProcessor, WalletWireTransceiver, WalletClient, HttpWalletJson
- Auth module: Peer (BRC-31 handshake), SessionManager, transport layer (HTTP, WebSocket)
- Certificate system: CertificateManager, MasterCertificate, CompoundMerkleTree
- Services: IdentityClient, ContactsManager, Storage (UHRP), KVStore, OverlayTools
- Benchmark infrastructure with Criterion (primitives, crypto, script, transactions, BEEF)
- Performance optimizations: Montgomery CIOS, Karatsuba multiplication, cached neg tables
- 12 offline examples covering keys, signing, encryption, transactions, certificates, and wallet operations
- Comprehensive rustdoc on all public API items
