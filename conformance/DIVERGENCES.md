# Conformance divergences

This ledger records every selected official vector that the Rust SDK does not
satisfy under the TypeScript dispatcher's exact assertion semantics. The
runners pin each finding by vector ID and fail if a finding appears, disappears,
or changes unexpectedly.

The upstream TypeScript evidence is from
`conformance/runner/reports/report.json` at the SHA in [`SOURCE`](SOURCE).
Every vector below is recorded there with `pass: true`. The disputed operations
were also replayed against the installed `@bsv/sdk@2.3.1` reference; those
results are included below. Therefore these are Rust findings, not corpus
defects.

`TYPE_SHAPE` is reserved for a legal reference input or output the Rust public
API cannot represent. All other verdicts are `RUST_DEFECT`.

| Vector | Rust evidence | TypeScript 2.3.1 evidence | Verdict |
|---|---|---|---|
| `sdk.crypto.ecies.3` | `ECIES::electrum_encrypt` has no `noKey` argument; its closest legal call embeds the sender key and the two ECDH-direction ciphertexts differ. | `electrumEncrypt(..., noKey=true)` produces equal ciphertexts and decrypts to “this is my ECDH test message”. | `TYPE_SHAPE` — legal `noKey=true` cannot be represented. |
| `sdk.crypto.ecies.18` | Same missing `noKey` input shape and asymmetric closest-call ciphertexts. | Produces equal ciphertexts and decrypts to “ECDH symmetric test”. | `TYPE_SHAPE` — legal `noKey=true` cannot be represented. |
| `mp-compound-001` | `MerklePath::from_hex` rejects the official BUMP with “Mismatched roots”. | `MerklePath.fromHex` parses it, round-trips byte-exactly, and computes the expected root for all four txids. | `RUST_DEFECT` — compound-BUMP parsing/root computation differs. |
| `tx-007` | `Transaction::add_input(TransactionInput::default())` accepts a missing source reference. | `Transaction.addInput({})` throws “A reference to an an input transaction is required…”. | `RUST_DEFECT` — missing input-source validation. |
| `tx-009` | `Transaction::add_output(TransactionOutput::default())` accepts neither satoshis nor `change=true`. | `Transaction.addOutput({ lockingScript })` throws “either satoshis must be defined or change must be set to true”. | `RUST_DEFECT` — missing output-value validation. |
| `tx-014` | `SatoshisPerKilobyte::compute_fee` succeeds for an input with no source value. | `Transaction.getFee()` throws “Source transactions or sourceSatoshis are required…”. | `RUST_DEFECT` — fee calculation does not require source value. |
| `regression.privatekey.modular-reduction.0002` | `PrivateKey::from_hex(n + 12)` rejects the scalar as greater than or equal to `n`. | Reduces to scalar 12 and returns the expected WIF `KwDi…B1G`. | `RUST_DEFECT` — private-key modular-reduction semantics differ. |
| `regression.script.writebin-empty.0001` | The OP_0 script serializes correctly as `00` but `Script::to_asm()` renders `0`. | `new Script().writeBin([]).toASM()` returns `OP_0`. | `RUST_DEFECT` — ASM rendering differs. |

## Governed skip (not a divergence)

`sdk.crypto.ecies.17` is marked `skip: true` upstream with this reason:
the TypeScript dispatcher’s decrypt-only shape does not check throws; the
wrong-key error is instead covered by `sdk.crypto.ecies.16`. The upstream
runner registers it as a governed Jest skip before dispatch. Rust does the
same, accounts for it as the one unasserted vendored vector, and does not list
it as an implementation disagreement.
