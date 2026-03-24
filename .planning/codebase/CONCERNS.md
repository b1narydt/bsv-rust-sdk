# Codebase Concerns

**Analysis Date:** 2026-03-24

## Tech Debt

**Incomplete TransactionSignature Methods:**
- Issue: Three methods (`format()`, `formatOTDA()`, `formatBip143()`) are absent from `TransactionSignature`. They are marked Phase 3 TODOs requiring cross-module types (`Script`, `Transaction`, `TransactionInput`/`TransactionOutput`) that now exist.
- Files: `src/primitives/transaction_signature.rs` lines 106-108
- Impact: Consumers cannot produce the formatted signature representations required by standard BSV tooling (e.g., building P2PKH unlock scripts from signatures within the SDK).
- Fix approach: Implement the three methods now that `Script` and `Transaction` are available. Remove the phase annotations.

**Duplicated Base64 Implementation:**
- Issue: A standalone `base64_encode` / `base64_decode` pair is hand-rolled inside `src/auth/peer.rs` (lines 29-101). The same encoding logic exists independently in `src/auth/utils/nonce.rs` and `src/auth/certificates/master.rs` (15 files use their own copy according to `grep`).
- Files: `src/auth/peer.rs`, `src/auth/utils/nonce.rs`, `src/auth/utils/certificates.rs`, `src/auth/certificates/master.rs`, `src/auth/certificates/verifiable.rs`, `src/auth/certificates/certificate.rs`, `src/auth/transports/http.rs`
- Impact: Bug fixes or edge-case corrections must be applied in multiple places. The custom decoder has a subtle iteration step of 4 that may mishandle strings whose length is not a multiple of 4.
- Fix approach: Extract a single `base64` utility module under `src/primitives/` (or `src/auth/utils/`) and re-export it. Replace all inline copies.

**`GlobalKvStore` Holds `std::sync::Mutex` Around Async `Historian`:**
- Issue: `Historian` is wrapped in `std::sync::Mutex` inside `GlobalKvStore` (`src/services/kvstore/global_kvstore.rs` line 83). The build history traversal is synchronous but the surrounding store methods are `async`. Holding a `std::sync::Mutex` guard across `.await` points would deadlock; the current code avoids this only by careful manual scoping.
- Files: `src/services/kvstore/global_kvstore.rs`
- Impact: Fragile — any future refactor that holds the guard across an `.await` will deadlock in the tokio runtime with no compile-time warning.
- Fix approach: Replace with `tokio::sync::Mutex` for the `Historian` field, or make `build_history` truly async-safe.

**Reconnect Write-Half Not Restored on WebSocket Reconnect:**
- Issue: On reconnection after disconnect, `WebSocketTransport` restores the read half but deliberately discards the new write half, leaving the outgoing channel pointing at a dead task.
- Files: `src/auth/transports/websocket.rs` lines 179-186, comment: "write half is not reconnected here -- outgoing messages sent during disconnect will be dropped."
- Impact: After a reconnect, all outgoing `send()` calls silently succeed (channel buffering) but messages are never actually transmitted until the connection is re-established manually.
- Fix approach: Pass a shared write-half handle (e.g., `Arc<Mutex<SplitSink>>`) to both the initial write task and the reconnect path so the write task can be restarted or given the new write half.

**`broadcaster` Field Always Dead Code in `GlobalKvStore`:**
- Issue: `TopicBroadcaster broadcaster` field in `GlobalKvStore` is annotated `#[allow(dead_code)]` (line 80-81). The broadcaster is constructed but never called.
- Files: `src/services/kvstore/global_kvstore.rs`
- Impact: KV store writes are not broadcast to the overlay network, silently making `set` operations local-only. This is a functional incompleteness.
- Fix approach: Wire the broadcaster into the `set()` / `delete()` operation paths.

**`IdentityClient.options` Field Always Dead Code:**
- Issue: `options: IdentityClientOptions` is stored on `IdentityClient` but annotated `#[allow(dead_code)]` (line 32-33). Configuration values (e.g., custom resolver URLs) are ignored.
- Files: `src/services/identity/identity_client.rs`
- Impact: Identity resolution cannot be customized via the public API even though the type signature advertises configurability.
- Fix approach: Apply `options` fields (resolver URL, etc.) when constructing the inner `ContactsManager` and during resolution calls.

**`sub_at` Helper Function Unused:**
- Issue: `sub_at` in `src/primitives/big_number.rs` line 1747 is silently dead (`#[allow(dead_code)]`). It was written as part of the big-number arithmetic but is never called.
- Files: `src/primitives/big_number.rs`
- Impact: Dead code bloat in a performance-critical module. It may indicate a missing use-site (e.g., modular subtraction path not yet exercised).
- Fix approach: Either wire it into the arithmetic path where it is needed, or delete it if the logic was superseded.

**`varint_size` Helper Unused:**
- Issue: `varint_size` in `src/transaction/mod.rs` line 106 is annotated `#[allow(dead_code)]`. Varint sizes are computed inline in several serialization paths rather than using this utility.
- Files: `src/transaction/mod.rs`
- Impact: Minor dead code; the function exists but all callers re-implement the same logic.
- Fix approach: Either apply `varint_size` in serialization paths or delete it.

---

## Known Bugs

**Historian Depth-First Traversal Can Stack-Overflow on Deep Ancestry:**
- Symptoms: `build_history` in `Historian` is recursive (calls itself on each `source_transaction` input). A deeply-chained transaction graph triggers unbounded recursion.
- Files: `src/services/overlay_tools/historian.rs`
- Trigger: Any transaction with a source chain exceeding the thread stack depth (~10k-80k frames depending on platform).
- Workaround: None in current code.

**Double-Spend Retry Has No Backoff:**
- Symptoms: `with_double_spend_retry` retries in a tight loop with no delay between attempts. On a genuine double-spend the retries hammer the network endpoint immediately.
- Files: `src/services/overlay_tools/retry.rs` line 39, comment: "Retry without backoff."
- Trigger: Any scenario where the overlay service needs time to resolve the conflict.
- Workaround: None; intentionally matches TS SDK behavior, but the TS SDK note is itself a known limitation.

---

## Security Considerations

**`allow_http` Bypasses HTTPS Enforcement on `Network::Local`:**
- Risk: When `config.network == Network::Local`, `allow_http` is set to `true` in both `LookupResolver` and `TopicBroadcaster`. This flag disables TLS enforcement for all hosts, not just localhost. A misconfigured `network_preset` of `"local"` in a staging/production deploy silently strips HTTPS requirements.
- Files: `src/services/overlay_tools/lookup_resolver.rs` line 64, `src/services/overlay_tools/topic_broadcaster.rs` line 62
- Current mitigation: Flag only activates for the `Local` enum variant; production deployments using `"mainnet"` / `"testnet"` are safe.
- Recommendations: Validate that `allow_http` only allows `localhost` / `127.0.0.1` hostnames even on `Local` network; or document the risk clearly at the constructor level.

**`PrivateKey::from_hex("1")` in Tests Leaks Weak Key Pattern:**
- Risk: Multiple test helpers construct private keys from the scalar `"1"` (`src/services/kvstore/interpreter.rs` line 81). This pattern is fine for unit tests, but if copy-pasted into production code it produces a trivially-breakable key.
- Files: `src/services/kvstore/interpreter.rs`, `src/primitives/private_key.rs` tests
- Current mitigation: These are `#[cfg(test)]`-scoped; not reachable in production builds.
- Recommendations: No action required; awareness is sufficient.

**`String::from_utf8(...).unwrap()` on Untrusted Overlay Data:**
- Risk: `registry_client.rs` lines 565 and 569 call `.unwrap()` on `String::from_utf8` for data fields read from overlay responses. Non-UTF-8 bytes in a malicious response will panic the calling thread.
- Files: `src/services/registry/registry_client.rs` lines 565, 569, 616
- Current mitigation: Only reached during registry resolution, which is gated behind network calls; crash is recoverable if the thread is isolated.
- Recommendations: Replace `.unwrap()` with `.map_err(...)` and propagate as a `ServicesError`.

---

## Performance Bottlenecks

**`BigNumber` (2810 lines) is the Core Arithmetic Engine — Heap-Allocating on Large Values:**
- Problem: All values exceeding 256 bits fall through to `SmallLimbs::Heap(Vec<u64>)`. In the ECC scalar operations this occurs in the Montgomery multiplication path and Karatsuba recursion. Each intermediate result allocates a new `Vec`.
- Files: `src/primitives/big_number.rs`
- Cause: `SmallLimbs::from_limbs` always allocates a new `Vec` on the heap for values with more than 4 limbs; there is no in-place mutation path.
- Improvement path: Add in-place arithmetic methods (`add_assign`, `mul_assign`) that reuse the existing allocation before cloning.

**Historian Cache is Keyed by `tx.id().unwrap_or_default()`:**
- Problem: `id()` serializes and double-SHA256-hashes the transaction on every cache lookup miss (`src/services/overlay_tools/historian.rs` line 53). For a chain of 100 transactions this adds 100 hash computations per `build_history` call.
- Files: `src/services/overlay_tools/historian.rs`
- Cause: `Transaction` has no pre-computed `txid` field; `id()` is always re-computed.
- Improvement path: Cache the computed txid on the `Transaction` struct after first computation (e.g., `OnceLock<String>`).

**`CachedKeyDeriver` Eviction is O(n):**
- Problem: When the cache exceeds `max_cache_size`, all entries are cleared (`cache.clear()`), causing a cold-cache thundering-herd on the next burst of requests.
- Files: `src/wallet/cached_key_deriver.rs`
- Cause: Simple threshold eviction with no LRU policy.
- Improvement path: Replace full clear with LRU eviction (e.g., an `IndexMap` or `linked_hash_map` crate) or at least evict the oldest half.

---

## Fragile Areas

**`Peer` Event Receivers Are Take-Once `Option<Receiver>`:**
- Files: `src/auth/peer.rs` lines 132-137
- Why fragile: `on_general_message()`, `on_certificate()`, and `on_certificate_request()` each `take()` an `Option<Receiver>`. Calling any of these methods twice returns `None` silently, causing callers to miss all subsequent events with no error.
- Safe modification: Add an assertion or return a `Result<Receiver, AuthError>` to signal double-take. Never call these methods more than once per `Peer` instance.
- Test coverage: Tests in `src/auth/peer.rs` cover the happy path; no test for double-take.

**`WebSocketTransport` `subscribe()` is Take-Once:**
- Files: `src/auth/transports/websocket.rs`
- Why fragile: Mirrors the `Peer` take-once problem — `incoming_rx` is wrapped in `Option<Mutex<...>>` and taken on first `subscribe()`. Second `subscribe()` panics or returns an error silently.
- Safe modification: Document clearly and add a defensive check with a useful error message.

**`process()` on `WalletWireProcessor` Silently Swallows All Errors Into Wire Frames:**
- Files: `src/wallet/substrates/wallet_wire_processor.rs` lines 40-44
- Why fragile: `process()` catches every `Err` and encodes it into a result frame. If the frame parser itself panics (e.g., OOM on a huge malformed message), the panic propagates uncaught. Additionally, logging is absent — errors from wallet dispatch are invisible without a debugger.
- Safe modification: Add structured logging (`tracing` or `log` crate) before encoding error frames to make failures observable.
- Test coverage: Unit tests confirm encoding, but no tests for malformed oversized frames.

---

## Scaling Limits

**In-Memory `SessionManager` in `Peer`:**
- Current capacity: Single-process in-memory `HashMap` keyed by identity key.
- Limit: Cannot be shared across multiple instances of `Peer` or across processes; no persistence.
- Scaling path: `SessionManager` interface is not yet abstracted as a trait, making it impossible to swap in a distributed session store. Extract a `SessionStore` trait first.

**`KeyLocks` (GlobalKvStore) Grow Unboundedly:**
- Current capacity: `Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>` — one entry per unique key ever seen.
- Limit: Entries are never removed; a high-cardinality key space grows the map without bound.
- Scaling path: Add a TTL or reference-count cleanup pass after a lock is released.

---

## Dependencies at Risk

**`getrandom = "0.2"` — WASM Compatibility Risk:**
- Risk: `getrandom 0.2` requires explicit feature flags for WASM targets (`js` feature). The `Cargo.toml` does not specify this feature. A future WASM build target would fail to compile or silently use a non-random fallback.
- Files: `Cargo.toml` line 18
- Impact: Only affects WASM targets; native builds are unaffected.
- Migration plan: Add `getrandom = { version = "0.2", features = ["js"] }` under a WASM conditional, or migrate to `getrandom 0.3` (which handles WASM differently).

**`async-trait = "0.1"` — Pending Stabilization:**
- Risk: Rust is progressively stabilizing async-in-traits natively (RPITIT). `async-trait` macro generates verbose desugared code with `Box<dyn Future>` allocations per call and is needed for every `WalletInterface` dispatch.
- Files: `Cargo.toml` line 20; used across `src/wallet/interfaces.rs`, `src/auth/peer.rs`, etc.
- Impact: Each `WalletInterface` method call allocates a `Box<dyn Future>`. This is a hot path for wallet operations.
- Migration plan: Track Rust 1.75+ `async fn` in trait stabilization; migration is non-trivial because `dyn WalletInterface` object safety requires `async-trait` until the ecosystem fully adopts the new approach.

---

## Test Coverage Gaps

**No Integration Tests for `auth` Module Against Real HTTP:**
- What's not tested: The `SimplifiedHTTPTransport` → `Peer` → `AuthFetch` flow against a live or mock HTTP server with actual BSV auth headers.
- Files: `src/auth/transports/http.rs`, `src/auth/clients/auth_fetch.rs`
- Risk: Header-parsing and round-trip handshake bugs would only surface in production.
- Priority: High

**WebSocket Integration Test is `#[ignore]`:**
- What's not tested: `test_websocket_connect_and_send` requires a real WebSocket server and is permanently ignored.
- Files: `src/auth/transports/websocket.rs` line 323-324
- Risk: Reconnect logic, write-half loss on reconnect, and message framing are untested.
- Priority: High

**No Tests for `StorageUploader` / `StorageDownloader` Network Paths:**
- What's not tested: The `upload_file()` presigned URL flow and `download_file()` expiry checks are only exercised by end-to-end calls to `https://storage.bsvb.tech`.
- Files: `src/services/storage/storage_uploader.rs`, `src/services/storage/storage_downloader.rs`
- Risk: Silent regressions in the HTTP POST/PUT flow or UHRP URL derivation.
- Priority: Medium

**No Tests for `GlobalKvStore.set()` / `get()` Network Paths:**
- What's not tested: End-to-end set/get via the overlay broadcaster and lookup resolver. Only the `interpreter` and `types` modules have unit tests.
- Files: `src/services/kvstore/global_kvstore.rs`
- Risk: The broadcaster dead-code issue (above) would not be caught by tests.
- Priority: High

**`TransactionSignature::format()` Methods Cannot Be Tested (Not Yet Implemented):**
- What's not tested: The three Phase 3 TODO methods.
- Files: `src/primitives/transaction_signature.rs`
- Risk: P2PKH script template generation within the SDK produces incomplete unlock scripts without these methods.
- Priority: High

---

*Concerns audit: 2026-03-24*
