# Conformance divergences

This ledger records every selected official vector that the Rust SDK does not
satisfy under the TypeScript dispatcher's exact assertion semantics. The
runners pin each finding by vector ID and fail if a finding appears, disappears,
or changes unexpectedly.

The upstream TypeScript evidence is from
`conformance/runner/reports/report.json` at the SHA in [`SOURCE`](SOURCE).
Every vector below is recorded there with `pass: true`. The disputed operations
were also replayed against the installed `@bsv/sdk@2.4.1` reference; those
results are included below. Therefore these are Rust findings, not corpus
defects.

`TYPE_SHAPE` is reserved for a legal reference input or output the Rust public
API cannot represent. All other verdicts are `RUST_DEFECT`.

| Vector | Rust evidence | TypeScript 2.4.1 evidence | Verdict |
|---|---|---|---|

## Governed skip (not a divergence)

`sdk.crypto.ecies.17` is marked `skip: true` upstream with this reason:
the TypeScript dispatcher’s decrypt-only shape does not check throws; the
wrong-key error is instead covered by `sdk.crypto.ecies.16`. The upstream
runner registers it as a governed Jest skip before dispatch. Rust does the
same, accounts for it as the one unasserted vendored vector, and does not list
it as an implementation disagreement.
