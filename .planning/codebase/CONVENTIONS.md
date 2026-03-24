# Coding Conventions

**Analysis Date:** 2026-03-24

## Naming Patterns

**Files:**
- `snake_case.rs` for all source files (e.g., `big_number.rs`, `private_key.rs`, `transaction_input.rs`)
- `mod.rs` for module root files
- `error.rs` for per-module error types (every major module has one)
- Test files in `tests/` directory named `wallet_client.rs`, `wallet_key_deriver.rs` (noun-focused, not `test_wallet_client.rs`)

**Functions:**
- `snake_case` for all functions and methods
- Constructor pattern: `new()` for default construction, `from_*()` for conversion constructors (e.g., `from_hex()`, `from_bytes()`, `from_wif()`, `from_binary()`)
- Serialization pair: `to_bytes()` / `from_bytes()`, `to_hex()` / `from_hex()`, `to_binary()` / `from_binary()`
- In-place mutation variants suffix with `i` prefix: `iadd()`, `isub()`, `imul()`
- Small-number variants suffix with `n`: `addn()`, `subn()`

**Variables:**
- `snake_case` for all variables and struct fields
- Underscore-prefixed `_args`, `_originator` for intentionally unused parameters (common in mock/stub implementations)

**Types:**
- `PascalCase` for structs, enums, and traits
- Error enums named `{ModuleName}Error` (e.g., `PrimitivesError`, `TransactionError`, `ScriptError`, `WalletError`, `ServicesError`, `AuthError`)
- Semantic newtypes in `wallet/types.rs` use descriptive names: `DescriptionString5to50Bytes`, `BasketStringUnder300Bytes`, `TXIDHexString`

**Constants:**
- `SCREAMING_SNAKE_CASE` for constants (e.g., `SIGHASH_ALL`, `EF_MARKER`, `SHA256_IV`, `K256`)

**Modules:**
- `pub(crate)` for internal-only modules (e.g., `jacobian_point`, `k256`, `montgomery`, `spend_ops`, `spend_stack`)
- `pub` for API-facing modules

## Code Style

**Formatting:**
- Tool: `rustfmt` (enforced in CI with `cargo fmt -- --check`)
- Standard Rust formatting conventions; no `rustfmt.toml` customizations detected

**Linting:**
- Tool: `cargo clippy`
- CI enforces: `cargo clippy -- -D warnings` (warnings are hard errors)
- `#[allow(clippy::module_inception)]` used in `src/script/mod.rs` and `src/transaction/mod.rs` where module name matches file name
- `#[allow(dead_code)]` used on test-only struct fields in `#[cfg(test)]` blocks

## Import Organization

**Order (observed pattern):**
1. Standard library imports (`use std::...`)
2. External crate imports
3. Internal crate imports (`use crate::...`)

**Example from `src/transaction/transaction.rs`:**
```rust
use std::io::{Cursor, Read, Write};

use crate::primitives::hash::hash256;
use crate::primitives::transaction_signature::{...};
use crate::script::locking_script::LockingScript;
use crate::transaction::error::TransactionError;
```

**Path Aliases:**
- No path aliases (`use` renames) observed in production code
- Module re-exports via `pub use` in `mod.rs` files provide a clean public API surface

## Error Handling

**Pattern:** Per-module error enums using `thiserror`

**Every major module has a dedicated error file:**
- `src/primitives/error.rs` → `PrimitivesError`
- `src/transaction/error.rs` → `TransactionError`
- `src/script/error.rs` → `ScriptError`
- `src/wallet/error.rs` → `WalletError`
- `src/services/error.rs` → `ServicesError`
- `src/compat/error.rs` → compat error type

**Error propagation:** `#[from]` conversions for cross-layer bubbling:
```rust
// TransactionError wraps lower-level errors:
#[error("script error: {0}")]
Script(#[from] crate::script::error::ScriptError),

#[error("primitives error: {0}")]
Primitives(#[from] crate::primitives::error::PrimitivesError),
```

**`impl From<X> for Y`** used explicitly in `src/wallet/error.rs` when `#[from]` is not used:
```rust
impl From<crate::primitives::PrimitivesError> for WalletError {
    fn from(e: crate::primitives::PrimitivesError) -> Self {
        WalletError::Internal(e.to_string())
    }
}
```

**Result type:** All fallible operations return `Result<T, ModuleError>`; no panics in production code paths.

**Error messages:** Lowercase, context-first strings in `#[error("...")]` attributes (e.g., `"invalid format: {0}"`, `"signing failed: {0}"`).

## Logging

**Framework:** None detected — no `log`, `tracing`, or `env_logger` dependencies.

**Patterns:**
- No logging in production code; errors are propagated, not logged
- Callers are responsible for handling and displaying errors

## Comments

**Module-level docs:** Every file begins with a `//!` module doc comment explaining purpose and scope:
```rust
//! Bitcoin transaction type with wire format and EF format serialization.
//! ...
```

**Function-level docs:** `///` doc comments on all public functions; brief single-line summary followed by extended explanation for complex behavior:
```rust
/// Compute the SHA-256 hash of the input data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
```

**Inline comments:** Used for WHY, not WHAT — algorithm steps, protocol constants, edge cases:
```rust
// Extremely unlikely (probability 2^-256), but loop to be safe

// Pad and process remaining data

// Check if we need one or two blocks for padding
```

**Section separators:** `// ---------------------------------------------------------------------------` divider comments used in large files and test files to delineate sections.

**TS SDK references:** Comments frequently note the corresponding TypeScript SDK class/file (e.g., `"Translates the TS SDK Transaction.ts"`, `"Mirrors the TS SDK PrivateKey.ts API"`).

## Function Design

**Size:** Functions are kept focused; complex algorithms split into private helpers (e.g., `sha256_process_block`, `sub_unsigned`, `mul_magnitudes`).

**Parameters:** Take references (`&T`) for inputs; owned types for constructors. Mutable references (`&mut impl Write`, `&mut impl Read`) for I/O streaming.

**Return Values:**
- Infallible: return `T` directly
- Fallible: return `Result<T, ModuleError>`
- Constructors: return `Result<Self, ModuleError>`
- Methods that cannot fail (e.g., serialization to `Vec<u8>`): sometimes return `Result` for consistency, sometimes return directly

## Module Design

**Exports:**
- Each module's `mod.rs` re-exports the public API with `pub use`:
```rust
// src/transaction/mod.rs
pub use transaction::Transaction;
pub use transaction_input::TransactionInput;
pub use error::TransactionError;
```

**Barrel Files:** `mod.rs` files serve as barrel exports. Importing code uses the module path directly (e.g., `use crate::transaction::Transaction`) rather than deep paths.

**Visibility:**
- `pub` for all user-facing types and functions
- `pub(crate)` for internal implementation modules
- Private helpers are bare `fn` (no `pub`) within their module

## Feature Flags

**`network` feature** gates all async HTTP/WebSocket and serde dependencies:
```rust
#[cfg(feature = "network")]
pub(crate) mod serde_helpers { ... }
```
Core cryptographic primitives have no feature requirements. Network-dependent code (broadcasters, chain trackers, wallet substrates) requires `--features network`.

---

*Convention analysis: 2026-03-24*
