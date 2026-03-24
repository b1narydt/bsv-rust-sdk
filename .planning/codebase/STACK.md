# Technology Stack

**Analysis Date:** 2026-03-24

## Languages

**Primary:**
- Rust 2021 edition (MSRV 1.87) - all library and test code

## Runtime

**Environment:**
- Native binary (no runtime VM); async via Tokio
- No runtime version manager file detected

**Package Manager:**
- Cargo (Rust toolchain)
- Lockfile: `Cargo.lock` present (standard for binaries/libraries)

## Frameworks

**Core:**
- No web framework — this is a pure library crate (`[lib]` in `Cargo.toml`)

**Async Runtime (optional):**
- `tokio` 1.x (`rt-multi-thread`, `macros`, `time` features) — gated behind `network` feature flag

**Testing:**
- Built-in `cargo test` — all tests use `#[cfg(test)]` modules and integration test files
- `criterion` 0.5 with `html_reports` — benchmarking framework (13 bench targets defined)
- `wiremock` 0.6 — HTTP mock server used in tests for ARC broadcaster and WhatsOnChain tracker

**Build/Dev:**
- `cargo clippy` — linting (CI enforces `-D warnings`)
- `cargo fmt` — formatting (CI enforces `--check`)
- GitHub Actions CI (`.github/workflows/ci.yml`) — check, test, clippy, fmt jobs

## Key Dependencies

**Critical (always compiled):**
- `getrandom` 0.2 — OS-level random number generation for key material
- `thiserror` 2.0 — derive macros for error types across all modules
- `async-trait` 0.1 — `#[async_trait]` on `Broadcaster`, `ChainTracker`, `WalletInterface`, `Transport`

**Network feature (opt-in via `features = ["network"]`):**
- `tokio` 1.x — async runtime; required for all network operations
- `reqwest` 0.12 with `json` feature — HTTP client used by ARC broadcaster, WhatsOnChain tracker, LookupResolver, TopicBroadcaster, HttpWalletJson, StorageUploader, AuthFetch
- `tokio-tungstenite` 0.24 — WebSocket client used by `WebSocketTransport` for BRC-31 auth
- `futures-util` 0.3 — stream utilities for WebSocket message handling
- `serde` 1.x with `derive` — serialization framework for all wire types
- `serde_json` 1.x — JSON encoding/decoding for API responses and wallet wire protocol

**Dev-only:**
- `serde` / `serde_json` 1.x — always available in tests (not gated)
- `hex` 0.4 — hex encode/decode in test assertions
- `wiremock` 0.6 — mock HTTP server for integration tests
- `tokio` 1.x — async test execution
- `criterion` 0.5 — benchmark harness

## Configuration

**Feature Flags (`Cargo.toml`):**
- `default = []` — no features enabled by default; the crate compiles as a pure offline library
- `network` — enables all async/HTTP/WebSocket capabilities: `tokio`, `reqwest`, `tokio-tungstenite`, `futures-util`, `serde`, `serde_json`

**Build:**
- `Cargo.toml` — single workspace member, no workspace file detected
- `.github/workflows/ci.yml` — CI pipeline for check/test/clippy/fmt

**Environment:**
- No `.env` files present
- No runtime environment variables required for offline operation
- Network integrations accept URLs and API keys as constructor arguments (not env vars)

## Platform Requirements

**Development:**
- Rust toolchain stable (MSRV 1.87)
- `cargo` for build, test, bench

**Production:**
- Embeds as a library crate; no standalone deployment target
- Published to crates.io as `bsv-sdk` (docs at `https://docs.rs/bsv-sdk`)
- Repository: `https://github.com/b1narydt/bsv-rust-sdk`

---

*Stack analysis: 2026-03-24*
