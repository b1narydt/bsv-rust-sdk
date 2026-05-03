# STAS-3 Mainnet Smoke Test — Handover

**Status:** blocked on broadcast propagation. The local SDK + wallet wrapper appear correct; the issue is at the ARC/network layer. **No STAS-3 operations are actually on chain yet** despite many sessions reporting "✅ broadcast OK." Read this entire document before resuming.

**Branch:** `stas3-wave-2a` (PR [#31](https://github.com/b1narydt/bsv-rust-sdk/pull/31))
**Companion PR:** [#30](https://github.com/b1narydt/bsv-rust-sdk/pull/30) — script-interpreter prerequisites (OP_RETURN + BIP-143)
**Smoke example:** `examples/stas3_mainnet_smoke.rs`

---

## TL;DR — what the next agent needs to do

1. **Don't trust prior "broadcast OK" logs.** Verify every claimed-on-chain txid via WhatsOnChain (`https://api.whatsonchain.com/v1/bsv/main/tx/{txid}`). Only the wallet's `createAction`-driven topup txs landed for real this session.
2. **Find a working broadcaster.** GorillaPool's free-tier ARC silently swallows our txs into its orphan mempool (the txid appears in their response with `txStatus: SEEN_IN_ORPHAN_MEMPOOL`, but never propagates to the BSV network). WhatsOnChain's `/v1/bsv/main/tx/raw` endpoint returns "Missing inputs" — possibly an mAPI propagation lag, possibly a real issue.
3. **Fix the broadcast layer first**, then re-run the smoke phases. The BUILD path (factory → engine-verify → atomic BEEF construction) is solid and well-tested. Only the "actually get bytes onto miner mempools" step is broken.

---

## What's actually on chain

The user verified these txids on WhatsOnChain — these are the only confirmed on-chain operations from this session:

| Tx kind | Txid | Notes |
|---|---|---|
| Topup #1 | `ceb123c612da55575426817adc2478c24a0eea639cea1e3c2634dec4c3f0e783` | Wallet `createAction`, mined |
| Topup #2 | `a622de34a458195db3c250a41f473a1cda75e1450d98167864fa8a2f08e44f03` | Wallet `createAction`, mined |
| Topup #3 | `a07cb36f8b3e2f4bda479eaba7272ca40366d1d357c797e5e690d27255a7ad16` | Wallet `createAction`, mined (block 947534, 19 confirms at last check) |

**Every other txid the smoke output called "✅ broadcast OK" is NOT on chain.** Specifically:
- All contract_tx, issue_tx, transfer_tx, split_tx, freeze_tx, unfreeze_tx, confiscate_tx, redeem_tx, merge_tx claims this session.
- Including the supposedly-working `mint-and-merge` end-to-end run (`merge_tx 79e92316...`).

The smoke's "verify in basket" step DID see them in the basket immediately after broadcast — but that's the wallet's local view, not chain reality.

---

## The chain of bugs we surfaced (in order)

These are real and have been fixed in the branch. Don't redo them.

### 1. SDK helper bug: `make_p2pkh_with_op_return` had spurious `OP_FALSE`
**Where:** `src/script/templates/stas3/factory/common.rs:67-88`
**Symptom:** Engine-verify of issue_tx's supply spend returned `Ok(false)` because the lock pushed `OP_FALSE` before `OP_RETURN`, leaving FALSE on stack at termination.
**Fix:** dropped the `0x00` push to match the dxs reference. Commit `890b3ce`.

### 2. SDK ARC broadcaster sends wrong content-type
**Where:** `src/transaction/broadcasters/arc.rs` — sends EF hex with `Content-Type: application/octet-stream`. ARC expects `text/plain` for hex strings.
**Workaround:** smoke has its own `arc_broadcast` helper. SDK fix is a separate PR.

### 3. NullData output missing when `note` slot set
**Where:** `factory/{transfer,split,merge}.rs`. Engine reconstructs an OP_FALSE+OP_RETURN+note output and folds it into hashOutputs. We had the witness slot 15 carrying the note but never emitted the matching tx output.
**Fix:** new `factory::common::make_op_return_note_output` helper, called in transfer/split/merge when `note.is_some()`. Commit `51e88dc`.

### 4. Smoke didn't sign the fuel input on transfer
**Where:** `examples/stas3_mainnet_smoke.rs` transfer phase
**Symptom:** ARC rejects with "inputs must have an unlocking script" — factory leaves funding inputs unsigned per convention.
**Fix:** smoke-local `sign_p2pkh_input_in_smoke` helper called before broadcast. Commit `03e42b6`.

### 5. Stale txid used for atomic BEEF
**Where:** smoke caches `transfer_tx.id()` BEFORE signing the fuel input. Signing changes bytes → changes txid. The stale txid then doesn't match what's in the BEEF.
**Fix:** recompute `final_txid = transfer_tx.id()` after signing. Commit `03e42b6`.

### 6. `internalize_stas_outputs` ignored `accepted` flag
**Where:** `src/script/templates/stas3/wallet/mod.rs:243`
**Note:** `result.accepted` is set to `true` in the wallet's constructor and **never set to false anywhere** (per `internalizeAction.ts:113`). It's a useless success indicator. Wrapper now checks it but should be replaced by checking `notDelayedResults`/`sendWithResults` once the SDK type is extended.

### 7. Smoke broadcast pattern racing the wallet's internal broadcast
**Where:** every phase that called both `arc_broadcast` AND `internalize_action`.
**Symptom:** wallet's internalize tries to re-broadcast the tx, ARC says "duplicate," wallet hits early `return` (line 425-435 of `internalizeAction.ts`), basket insertion is skipped silently. We get back `accepted: true` (meaningless) and assume success.
**Partial fix (commit `a4b3822`):** for single-tx ops, stop broadcasting via ARC; let wallet broadcast via internalize. For 2-tx mint, WE broadcast contract_tx (via ARC) and let wallet broadcast issue_tx (via internalize).
**Status:** the pattern is correct, but we discovered after committing that BOTH our ARC broadcast AND the wallet's broadcast end up in orphan mempool — see "current blocker" below.

---

## The current blocker — broadcast doesn't propagate

Multiple broadcasters tested, all failing in different ways:

### GorillaPool ARC (`https://arc.gorillapool.io/v1/tx`)
- Returns HTTP 200 with txid in body
- Body's `txStatus` is `SEEN_IN_ORPHAN_MEMPOOL`
- Tx never propagates to chain
- **Why:** GorillaPool's ARC node doesn't see our parent fuel UTXO (`a07cb36f`) in its mempool/chain index, even though it's deeply confirmed on chain. Their `/v1/tx/{txid}` endpoint returns 404 for `a07cb36f`. Free-tier limitation.
- **Initial smoke bug:** `arc_broadcast` only checked HTTP status, not `txStatus` field. Now patched (commit pending push) to reject on non-success `txStatus`. **Pre-fix sessions reported false success.**

### WhatsOnChain (`https://api.whatsonchain.com/v1/bsv/main/tx/raw`)
- Returns HTTP 400 with body `"unexpected response code 500: Missing inputs"`
- Despite the input UTXO being verifiably unspent on WoC's own indexer
- Likely cause: WoC's broadcast endpoint forwards to mAPI providers that have similar visibility issues, OR there's an actual conflict (e.g., a previous orphan tx from GorillaPool somehow got partially propagated)

### Wallet's internal broadcast (via `internalize_action`)
- Returns success
- But subsequent WhatsOnChain check: 404 for the txid the wallet supposedly broadcast
- **Hypothesis:** wallet uses delayed broadcast queue OR uses GorillaPool ARC under the hood and inherits the same orphan issue
- **Wallet's `createAction` path WORKS** — top_up_fuel txs all landed. Different code path, possibly different broadcaster config. Worth investigating which.

---

## Specific things for the next agent to investigate

### 1. What ARC does the wallet actually use?

The wallet at `localhost:3321` is the canonical TS p2ppsr UserWallet. Find its config:
- Check `/Users/donot/Misc/metanet-projects/wallet-toolbox/src/storage/methods/processAction.ts` and the `shareReqsWithWorld` function
- Look for what `getServices().getChainTracker()` returns
- Find the broadcaster used when wallet broadcasts via `createAction` vs `internalize_action`

If they're DIFFERENT, that explains why createAction works but internalize doesn't. The fix would be to ensure internalize uses the same (working) broadcaster.

### 2. Get a TAAL API key

TAAL ARC at `https://arc.taal.com/v1/tx` is the canonical reliable endpoint. Free tier requires registration but is generous. Request key from user.

Once you have a key, smoke usage:
```bash
SMOKE_ARC_URL=https://arc.taal.com SMOKE_ARC_API_KEY=<key> SMOKE_PHASE=mint-broadcast SMOKE_BROADCAST=1 cargo run --example stas3_mainnet_smoke --features network
```

### 3. Verify the smoke's `arc_broadcast` `txStatus` check

Pending in working tree (uncommitted as of handover). The check rejects anything that isn't in `[ANNOUNCED_TO_NETWORK, REQUESTED_BY_NETWORK, SENT_TO_NETWORK, ACCEPTED_BY_NETWORK, SEEN_ON_NETWORK, MINED]`. Confirm this list is complete per current ARC spec. Get the patch committed.

### 4. Decide on hybrid vs full-wallet broadcast

If TAAL works:
- Keep "WE broadcast contract_tx via TAAL, wallet broadcasts issue_tx via internalize" pattern
- Single-tx ops: wallet does it all

If only the wallet's broadcast works:
- Need to internalize contract_tx with one of its outputs as a basket entry to satisfy the wallet's "non-empty outputs" rule
- The contract_tx has 2 outputs: vout 0 (P2PKH+OP_RETURN supply) and vout 1 (P2PKH change to issuer). Vout 1 is the easier candidate (no OP_RETURN trailer)
- Smoke previously tried this — wallet returned success but txid still 404. Need to determine WHY.

---

## Code map

### Smoke example: `examples/stas3_mainnet_smoke.rs`

The single integrated runnable. ~3000 lines. Phases dispatched by `SMOKE_PHASE` env var.

**Phase functions:**
- `connect`, `topup`, `pickfuel` — read-only / simple createAction
- `mint`, `mint-broadcast` — inline in main() around line 320–890
- `transfer` — inline in main() ~line 890–1170
- `mint-and-merge` — `run_mint_and_merge_phase` ~line 1522
- `redeem` — `run_redeem_phase` ~line 2098
- `split` — `run_split_phase` ~line 2233
- `freeze` / `unfreeze` — `run_freeze_or_unfreeze_phase` ~line 2421
- `confiscate` — `run_confiscate_phase` ~line 2648
- `merge` — `run_merge_phase` ~line 2820 (basket-driven; needs same-collection tokens)

**Helpers:**
- `arc_broadcast(url, api_key, tx)` — ARC POST as text/plain hex. **Uncommitted txStatus check needs to land.**
- `woc_broadcast(tx)` — WhatsOnChain POST as JSON `{"txhex":"..."}`. Currently failing with "Missing inputs."
- `sign_p2pkh_input_in_smoke(...)` — manual P2PKH input signing (factory leaves funding unsigned per convention)
- `push_data_minimal_smoke(...)` — minimal push encoder
- `list_basket(...)` — wrapper over `list_outputs` for one basket

**Env vars (full list in file header):**
- `WALLET_URL` (default `http://localhost:3321`)
- `ORIGINATOR` (default `stas3-smoke`)
- `SMOKE_PHASE`
- `SMOKE_BROADCAST` (1 to actually broadcast)
- `SMOKE_FUEL_SATS`, `SMOKE_FUEL_COUNT`, `SMOKE_FUEL_BASKET`
- `SMOKE_ARC_URL` (default `https://arc.gorillapool.io` — change this)
- `SMOKE_ARC_API_KEY`
- `SMOKE_TRANSFER_DEST_KEYID`
- `SMOKE_MINT_SATS`, `SMOKE_MINT_FLAGS`, `SMOKE_MINT_TO_ISSUER`, `SMOKE_MINT_ISSUER_KEYID`, `SMOKE_MINT_DEST_KEYID`
- `SMOKE_EAC_FIXED` (use constant timestamps so two mints can produce same-collection tokens)

### Wallet wrapper: `src/script/templates/stas3/wallet/mod.rs`

- `Stas3Wallet::pick_fuel(min_satoshis)` — list_outputs against fuel basket, pick smallest sufficient
- `Stas3Wallet::find_token(outpoint)` — list_outputs against token basket, find by outpoint, derive signing_key from customInstructions
- `Stas3Wallet::internalize_stas_outputs(beef, [(idx, triple, schema)], description)` — register one or more STAS outputs in token basket. **Now checks `accepted: true` but per the wallet source that flag is ALWAYS true; needs deeper check on `sendWithResults`/`notDelayedResults` — but those aren't exposed in the SDK type.**
- `Stas3Wallet::top_up_fuel(satoshis_per_utxo, count)` — wraps `wallet.create_action` with a P2PKH output per fuel UTXO

### Factory: `src/script/templates/stas3/factory/`

- `common.rs` — `make_p2pkh_lock`, `make_p2pkh_with_op_return` (the dxs supply-output shape, `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG OP_RETURN <data>` — NO leading OP_FALSE), `make_op_return_note_output` (the NullData output for note slot), `sign_p2pkh_input` (private to issue), various util fns
- `issue.rs` — `build_issue` 2-tx contract+issue flow. **Funder vs issuer keys are independent (Fix B from earlier session).**
- `transfer.rs`, `split.rs`, `merge.rs`, `merge_chain.rs`, `freeze.rs`, `unfreeze.rs`, `confiscate.rs`, `redeem.rs`, `swap_*.rs` — single-spend factories
- All factories now emit the OP_FALSE+OP_RETURN note output when `note: Some(...)` (commit `51e88dc`)

### TS wallet-toolbox source (read-only reference)

`/Users/donot/Misc/metanet-projects/wallet-toolbox/src/storage/methods/internalizeAction.ts`

**Critical lines to know:**
- Line 113: `r.accepted = true` initialized — never set to false anywhere
- Lines 425-435: early return if wallet's broadcast fails — basket insertion is then SKIPPED silently
- Lines 437-446: basket insertion loop (only runs if broadcast succeeded)
- Line 272-294: `validateAtomicBeef` — calls `ab.verify(chainTracker, false)`
- Lines 425-429: `shareReqsWithWorld` is the broadcast call

---

## How to verify a tx is REALLY on chain

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://api.whatsonchain.com/v1/bsv/main/tx/<txid>"
# 200 = on chain ✓
# 404 = NOT on chain (regardless of what the smoke or wallet said)
```

Always run this after any "broadcast OK" claim in this codebase.

---

## What to commit before testing further

There are uncommitted changes in the working tree from this session. Inspect with `git status` and `git diff`. The relevant ones:

- `examples/stas3_mainnet_smoke.rs` — `arc_broadcast` now checks `txStatus`, has `woc_broadcast` helper, mint-broadcast uses WoC for contract_tx, redeem uses ARC. Some changes were exploratory; review before committing.

The latest committed state is `a4b3822` (push to origin/stas3-wave-2a). Commit anything you want as a follow-up commit; don't amend `a4b3822`.

---

## Recommended next session sequence

1. **Read this whole document.**
2. **Pick a broadcaster.** Get a TAAL key from the user OR investigate the wallet's internal broadcaster and figure out how to drive everything through it.
3. **Update `DEFAULT_ARC_URL`** in the smoke and confirm via WoC that a single test broadcast actually lands.
4. **Re-run mint-broadcast** with the working broadcaster. Verify the issue_txid lands on WoC. If yes:
5. **Re-run all phases** (transfer, split, freeze, unfreeze, confiscate, redeem, merge, mint-and-merge) and verify each on WoC.
6. **Update the PR description on #31** with the real verified txids.
7. **Don't claim "✅ MAINNET" without WoC verification.** The smoke's logs are not authoritative.

---

## Open questions for the user

- **TAAL API key?** They mentioned the wallet works in production for them — they may have one already.
- **Is the wallet's broadcast intentionally delayed?** If so, we need to either wait/poll OR use a different broadcast path for the smoke.
- **Should the smoke use the wallet's broadcaster exclusively** (avoiding any direct ARC config)?
- **Does the user want to debug GorillaPool's orphan-mempool behavior** (file an issue) or just switch?

---

## Architectural framing the user provided (preserve in any rewrite)

From the user's own words (paraphrased):
- Self-issuance: every output we produce belongs to our wallet → MUST be internalized into a basket.
- Cross-wallet issuance: out of scope here — handled via message box / overlay distribution. The recipient internalizes their own BEEF.
- The wallet IS the source of truth. It owns ARC config, broadcast, persistence, SPV proofs.
- Application layer should hand the wallet signed bytes (BEEF) and ask it to internalize. Don't race its broadcast.
- Token "collections" are defined by the issuance event. Two separate mints with the same issuer key still produce different collections. Merging cross-collection requires swap, not merge.

---

**End of handover.** Good luck. Verify everything on WoC.
