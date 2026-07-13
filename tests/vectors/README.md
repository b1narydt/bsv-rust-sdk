# Conformance vectors

The PushDrop / overlay-advertisement parity tests
(`tests/pushdrop_ts_parity_probe.rs`, `tests/overlay_ad_parity.rs`) assert against
hex vectors produced by the **real** `@bsv/sdk`. The vectors are hard-coded in
those tests, so the Rust suite has no Node dependency and runs offline.

These scripts regenerate them, and are the audit trail for where those constants
came from. Run them only when re-deriving vectors against a new `@bsv/sdk`:

```bash
npm i @bsv/sdk        # or run from any dir that already has it
node gen_pushdrop_vectors.mjs      # PushDrop lock/decode, minimal encoding
node gen_op16_vector.mjs           # the OP_16 round-trip bug (ts-stack#277)
node gen_overlay_ad_vectors.mjs    # SHIP/SLAP advertisements
```

Generated against `@bsv/sdk` **2.0.13**; cross-checked against `go-sdk` v1.2.24.

Note `gen_op16_vector.mjs` documents a bug we did NOT adopt: `@bsv/sdk` encodes a
`[16]` field as `OP_16` but its decoder cannot read it back (see
https://github.com/bsv-blockchain/ts-stack/issues/277). We follow go-sdk, which
round-trips it. Do not "fix" our decoder to match TS here.
