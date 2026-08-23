# Cross-implementation conformance vectors

Vendored copies of the official BSV conformance corpus maintained in
[`bsv-blockchain/ts-stack`](https://github.com/bsv-blockchain/ts-stack) under
`conformance/vectors/`, pinned by [`SOURCE`](SOURCE). The TypeScript reference
is `@bsv/sdk@2.3.1`; its dispatcher defines the assertion semantics mirrored by
the Rust runners.

The crate's existing `test-vectors/` fixtures remain independent regression
coverage. These official vectors are embedded with `include_str!`, so tests
are deterministic, hermetic, and do not depend on a sibling checkout.

## Runners

| Vectors | Runner |
|---|---|
| `vectors/sdk/crypto/*.json` (124) | `tests/conformance_crypto.rs` |
| `vectors/sdk/keys/*.json` (59) | `tests/conformance_keys.rs` |
| `vectors/sdk/transactions/*.json` (31) | `tests/conformance_transactions.rs` |
| `vectors/sdk/compat/bsm.json` (9) | `tests/conformance_compat.rs` |
| `vectors/regressions/*.json` (36) | `tests/conformance_regressions.rs` |

Every runner checks its exact corpus size and names each vector in failures.
Assertions intentionally match `runner/ts/dispatchers/sdk.ts`,
`sdkHelpers.ts`, and `regressions.ts`: dispatcher no-ops remain no-ops, and an
assertion is not strengthened merely because Rust exposes more functionality.
Known disagreements execute and are pinned by vector ID; they are never
removed from the run or made weaker. See [`DIVERGENCES.md`](DIVERGENCES.md).

`sdk.crypto.ecies.17` is the corpus's one metadata-governed skip in this scope.
The Rust ledger preserves its upstream reason and does not dispatch it, exactly
as `runner/ts/runner.test.ts` does for `v.skip === true`.

Runner ownership and governed skips are machine-readable in
[`RUST_RUNNERS.json`](RUST_RUNNERS.json). The coverage generator validates that
each vendored file is embedded by its declared runner.

## Refreshing

The tracked-file manifest is the single source of truth for refresh and
coverage generation:

```sh
./conformance/scripts/refresh-vectors.sh           # current upstream main
./conformance/scripts/refresh-vectors.sh <sha>     # explicit immutable pin
```

The refresh resolves the ref to a full SHA, copies upstream bytes without
reformatting them, rewrites `SOURCE`, and regenerates `COVERAGE.md`. To rebuild
only the ledger from a local upstream checkout:

```sh
./conformance/scripts/generate-coverage.py \
  --upstream-dir /path/to/ts-stack/conformance
```

After a refresh, run all five conformance runners and the full crate checks.
If a new vector disagrees, fix the implementation or pin and report the exact
vector finding; never edit a vendored vector or weaken its assertion.
