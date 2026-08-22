#!/usr/bin/env node
// The Rust-built -> TS-verified half of the cross-language BEEF golden
// (the R6b residual): feed any BEEF hex this stack emits (an overlay advert
// submission, a spend proof, an action result) and the NORMATIVE TS
// implementation renders a rule-by-rule verdict. Structure-only — no
// ChainTracker — so it answers "is this well-formed BEEF whose graph chains
// to its BUMPs", not "is it mined".
//
// Usage: node rust_advert_verify.mjs <beef-hex>
//        (or pipe the hex on stdin)
// Exit 0 = TS accepts; exit 1 = TS rejects (verdict JSON on stdout either way).
// Resolve the normative SDK: plain specifier when run from a directory whose
// node_modules carries @bsv/sdk; else point BSV_SDK at an installed copy,
// e.g. BSV_SDK=/path/to/app/node_modules/@bsv/sdk/dist/esm/mod.js
const { Beef } = await import(process.env.BSV_SDK ?? "@bsv/sdk");

const hex = (process.argv[2] ?? (await import("node:fs")).readFileSync(0, "utf8")).trim();
const verdict = { sdk: "@bsv/sdk (normative)", bytes: hex.length / 2 };
try {
  const beef = Beef.fromString(hex, "hex");
  verdict.version = beef.version;
  verdict.atomicTxid = beef.atomicTxid ?? null;
  verdict.txs = beef.txs.length;
  verdict.bumps = beef.bumps.length;
  const v = beef.verifyValid(false);
  verdict.structurallyValid = v.valid;
  verdict.roots = v.roots ?? null;
  if (beef.atomicTxid) {
    verdict.isAtomic = beef.isAtomic ? beef.isAtomic(true) : null;
  }
  console.log(JSON.stringify(verdict, null, 2));
  process.exit(v.valid ? 0 : 1);
} catch (e) {
  verdict.parseError = String(e?.message ?? e);
  console.log(JSON.stringify(verdict, null, 2));
  process.exit(1);
}
