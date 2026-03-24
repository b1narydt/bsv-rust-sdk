# External Integrations

**Analysis Date:** 2026-03-24

## APIs & External Services

**Transaction Broadcasting:**
- ARC (Bitcoin SV Transaction Processor) — broadcast signed transactions
  - SDK/Client: `reqwest::Client` (HTTP POST `/v1/tx`)
  - Auth: optional `X-Api-Key` header, passed as constructor arg to `ARC::new(url, api_key)`
  - Implementation: `src/transaction/broadcasters/arc.rs`
  - Format: EF hex in `application/octet-stream` body; JSON response with `txid`

**Chain Verification:**
- WhatsOnChain API — Merkle root verification and current block height
  - SDK/Client: `reqwest::Client` (HTTP GET)
  - Auth: None (public API)
  - Implementation: `src/transaction/chaintrackers/whats_on_chain.rs`
  - Endpoints used: `GET /v1/bsv/{network}/block/{height}/header`, `GET /v1/bsv/{network}/chain/info`
  - Base URL: `https://api.whatsonchain.com`
  - Network: `"main"` or `"test"` passed at construction

**Overlay Network (SLAP/SHIP):**
- BSV Overlay Services — distributed lookup and topic broadcast
  - SDK/Client: `reqwest::Client` (HTTP POST to discovered hosts)
  - Auth: None for basic queries; admin token templates for privileged operations
  - Implementation:
    - Lookup (SLAP): `src/services/overlay_tools/lookup_resolver.rs`
    - Broadcast (SHIP): `src/services/overlay_tools/topic_broadcaster.rs`
  - Mainnet SLAP trackers (hardcoded defaults in `src/services/overlay_tools/types.rs`):
    - `https://overlay-us-1.bsvb.tech`
    - `https://overlay-eu-1.bsvb.tech`
    - `https://overlay-ap-1.bsvb.tech`
    - `https://users.bapp.dev`
  - Testnet SLAP tracker: `https://testnet-users.bapp.dev`
  - Local dev: `http://localhost:8080`
  - Custom: `Network::Custom(Vec<String>)` variant

**File Storage (UHRP):**
- BSV Storage Server — authenticated file upload/download via UHRP protocol
  - SDK/Client: `AuthFetch` (authenticated POST) + plain `reqwest` (PUT to presigned URL)
  - Auth: BRC-31 mutual authentication via `AuthFetch`
  - Implementation: `src/services/storage/storage_uploader.rs`, `src/services/storage/storage_downloader.rs`
  - Default base URL: `https://storage.bsvb.tech`
  - Upload flow: POST to negotiate → PUT to presigned URL → compute UHRP URL from SHA-256

**Registry Service:**
- On-chain Registry — basket, protocol, and certificate definitions stored as PushDrop tokens
  - SDK/Client: `LookupResolver` (read) + `TopicBroadcaster` (write)
  - Auth: Wallet-signed transactions
  - Implementation: `src/services/registry/registry_client.rs`
  - Backed by overlay network; no dedicated external URL

**Identity Resolution:**
- Overlay Identity Service — resolve displayable identities by key or attributes
  - SDK/Client: `WalletInterface::discover_by_identity_key` / `discover_by_attributes`
  - Auth: Wallet-based
  - Implementation: `src/services/identity/identity_client.rs`
  - Uses `ContactsManager` for local cache override

## Data Storage

**Databases:**
- None — no traditional database; no SQL, no embedded DB

**On-chain Storage:**
- BSV blockchain UTXOs — GlobalKVStore stores key-value pairs as PushDrop token outputs
  - Implementation: `src/services/kvstore/global_kvstore.rs`
  - Uses overlay topics `tm_*` for data routing
  - `LocalKVStore` (`src/services/kvstore/local_kvstore.rs`) provides in-memory fallback

**File Storage:**
- UHRP protocol via `https://storage.bsvb.tech` (see above)

**Caching:**
- In-memory only:
  - `LookupResolver` hosts cache with configurable TTL (`src/services/overlay_tools/lookup_resolver.rs`)
  - `HostReputationTracker` (`src/services/overlay_tools/host_reputation.rs`)
  - `ContactsManager` in-memory contact cache (`src/services/identity/contacts_manager.rs`)
  - `GlobalKVStore` per-key `tokio::sync::Mutex` lock manager

## Authentication & Identity

**Auth Provider:**
- BRC-31 Mutual Authentication — custom BSV protocol (no OAuth/JWT/session cookies)
  - Implementation: `src/auth/peer.rs`, `src/auth/session_manager.rs`
  - Transport layer: HTTP (`src/auth/transports/http.rs`) or WebSocket (`src/auth/transports/websocket.rs`)
  - Custom HTTP headers: `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-nonce`, `x-bsv-auth-your-nonce`, `x-bsv-auth-signature`, `x-bsv-auth-certificates`, `x-bsv-auth-message-type`, `x-bsv-auth-request-id`
  - `AuthFetch` (`src/auth/clients/auth_fetch.rs`) wraps `reqwest` with automatic BRC-31 handshake

**Certificates:**
- Custom BSV certificate types (BRC-52 compatible)
  - Implementation: `src/auth/certificates/`
  - Operations: acquire, prove, relinquish, list

**Key Derivation:**
- Type-42 key derivation — BSV-specific protocol
  - Implementation: `src/wallet/key_deriver.rs`, `src/wallet/cached_key_deriver.rs`
- BIP-32 HD keys — compatibility layer
  - Implementation: `src/compat/bip32.rs`
- BIP-39 mnemonics — compatibility layer
  - Implementation: `src/compat/bip39.rs`

## Monitoring & Observability

**Error Tracking:**
- None — no external error tracking service integrated

**Logs:**
- None — no logging framework integrated; errors propagate via `Result<T, E>` using `thiserror`

## CI/CD & Deployment

**Hosting:**
- Library crate published to crates.io as `bsv-sdk` 0.1.75

**CI Pipeline:**
- GitHub Actions (`.github/workflows/ci.yml`) — 4 jobs on push/PR to `main`:
  - `check` — `cargo check --verbose`
  - `test` — `cargo test --verbose`
  - `clippy` — `cargo clippy -- -D warnings`
  - `fmt` — `cargo fmt -- --check`
- Runner: `ubuntu-latest` with `dtolnay/rust-toolchain@stable`

## Environment Configuration

**Required env vars:**
- None — the crate has no required environment variables
- Network URLs and API keys are passed as constructor arguments at runtime

**Secrets location:**
- No secrets storage pattern — callers supply API keys (e.g., ARC `api_key`) and wallet keys at runtime

## Webhooks & Callbacks

**Incoming:**
- None — this is a client library, not a server

**Outgoing:**
- Not applicable — the library makes outbound HTTP/WebSocket calls; it does not register webhooks

---

*Integration audit: 2026-03-24*
