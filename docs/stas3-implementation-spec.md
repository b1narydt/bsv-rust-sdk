# STAS 3.0 Implementation Specification

**Repo:** `b1narydt/bsv-rust-sdk` (this fork)
**Status:** Draft for review — implementation has not started.
**Authoritative sources of truth (in priority order):**

1. **`stassso/STAS-3-script-templates`** — official ASM template (`Template STAS 3.0`). Compiles to a 2,899-byte engine body. This is the authoritative on-chain definition. Local clone: `.ref/STAS-3-script-templates/`.
2. **STAS 3.0 Protocol Specification v0.2** (PDF/DOCX) — authoritative semantic spec for var2 sub-formats (§6), unlocking script slot order (§7), spend/tx types (§8), operation semantics (§9), authorization schemes (§10), trailing note (§11), and protocol constants (§12).
3. **`dxs-bsv-token-sdk`** — production TypeScript implementation, marked production on stastech docs. Reference for locking script construction, unlocking script ordering, factory function shapes, and conformance vectors. Local copy: `~/METAWATT/METAWATT-code/dxs-bsv-token-sdk/`.

**Patterns-only reference (NOT for byte-level logic):**

- **`Bittoku/bsv-sdk-rust`** — beta Rust implementation, marked beta on stastech docs. Useful as a model for how to organize a Rust implementation: workspace layout, `SwapDescriptor` type with recursive `next`, `SigningKey`/`OwnerAddress` enums, factory function shapes. **Bittoku's `STAS3_BASE_TEMPLATE_HEX` is 2,812 bytes (beta variant) and must NOT be used for the engine body.** The engine bytes come from compiling the official ASM (or the verified `stas3_body.bin` already in this fork). Local clone: `.ref/bsv-sdk-rust/`.

---

## 1. Scope and Goals

Build a STAS 3.0 token implementation native to `b1narydt/bsv-rust-sdk` (single-crate `bsv-sdk`, lib name `bsv`), tracking the canonical 2,899-byte engine, customized for MetaWatt's EAC use case and clean Runar interop.

### Goals

- Native to b1narydt's type universe (`bsv::primitives`, `bsv::script`, `bsv::transaction`).
- **Byte-for-byte parity with the canonical engine.** Tokens minted by this crate must be readable, transferable, and swappable by any production STAS-3 implementation (dxs, future canonical ports).
- Full operation coverage per spec v0.2: issue, transfer/split, merge (2..=7 pieces), redeem, freeze/unfreeze, confiscate, swap (mark, execute, cancel) — including recursive swap chains via the `next` field.
- Atomic mint pattern usable from Runar contracts. The canonical engine bytes are exposed as a `pub const` that Runar can embed in its covenant verification logic to require a STAS-3 EAC output as a parallel emission.
- Raw-TX flow that bypasses BRC-100 `createAction` for any STAS-input-spending operation, using `wallet.createSignature` for signing and `wallet.internalizeAction` for output registration. This is the only viable path; `createAction`'s output-injection behavior is fundamentally incompatible with the canonical engine's output constraints.
- High-level wallet wrapper that integrates with `bsv-sdk`'s `WalletInterface`.

### Non-Goals

- STAS v1/v2 (legacy) compatibility.
- Bittoku's 2,812-byte beta engine.
- Lineage analytics (`lineage.rs` in Bittoku) — out of scope; provenance is tracked by MetaWatt overlay.
- Raw-private-key handling. **All key material is derived via BRC-42 (Type-42) from the wallet root** — see §1A.

---

## 1A. Key Derivation Policy (BRC-42 / Type-42, Mandatory)

**Every key material in this implementation is derived via BRC-42 (Type-42) hierarchical derivation through `WalletInterface`.** No raw private keys, no ad-hoc Hash160 of bare keys, no off-wallet seed expansion. This is non-negotiable for production use and tightly enforced throughout the API surface.

### 1A.1 Why

- BRC-42 derives a unique key per `(protocolID, keyID, counterparty)` triple. Reusing keys across protocols or counterparties is impossible by construction — privacy and isolation are enforced by the derivation, not by convention.
- All signing flows through `wallet.create_signature(...)`. The wallet never exports private keys. Compromise blast-radius is bounded by what the wallet decides to expose.
- BRC-42 keys are deterministically re-derivable by any wallet that knows the same root + triple. Counterparty-aware derivation (`forSelf=true/false`) supports both wallet-internal usage and counterparty key sharing for swaps.
- BRC-100 wallet integration is uniform — every operation in this crate that needs a key calls `wallet.get_public_key({ protocolID, keyID, counterparty })` or `wallet.create_signature({ protocolID, keyID, counterparty, hashToDirectlySign })`.

### 1A.2 What this means concretely

For any 20-byte HASH160 that ends up in a STAS-3 locking script:

```rust
// CORRECT — Type-42 derived
let pk = wallet.get_public_key(GetPublicKeyArgs {
    protocol_id: protocol_id.clone(),
    key_id: key_id.clone(),
    counterparty: counterparty.clone(),
    for_self: Some(true),
    ..Default::default()
}, originator).await?;
let pkh = hash160(&pk.public_key.to_compressed());

// WRONG — raw-key derivation, must NOT appear anywhere in this crate's public API
let pkh = hash160(&priv_key.pub_key().to_compressed());
```

This applies to:

| Slot | Type-42 source |
|---|---|
| STAS-3 owner field (locking script byte 1..21) | wallet-derived PKH or MPKH |
| protoID / redemption address (after-OP_RETURN slot 1) | wallet-derived PKH or MPKH (the issuer's identity key) |
| Freeze authority service field | wallet-derived PKH or MPKH (per the freeze authority's wallet) |
| Confiscation authority service field | wallet-derived PKH or MPKH (per the confiscation authority's wallet) |
| Swap descriptor `receive_addr` | wallet-derived PKH or MPKH (per the swap maker's wallet) |
| Funding input owner (P2PKH change destination) | wallet-derived PKH (per the funder's fuel basket triple) |
| Change output destination | same as funding input owner |
| Trailing OP_RETURN note signers (if any) | n/a — note is unsigned data |

The only HASH160 that's NOT a wallet-derived key is `EMPTY_HASH160` = `b472a266d0bd89c13706a4132ccfb16f7c3b9fcb`, the spec-defined sentinel for signature suppression (§2.3).

### 1A.3 The triple

Every operation that touches a key takes a `KeyTriple`:

```rust
pub struct KeyTriple {
    pub protocol_id: WalletProtocol,        // (security_level, protocol_string)
    pub key_id: String,                     // KeyIDStringUnder800Bytes
    pub counterparty: WalletCounterparty,   // "self" | "anyone" | hex pubkey
}
```

The triple is the unit of identity for any key material in the API. Functions that produce or consume keys take the triple, not raw bytes. The wallet wrapper resolves the triple to a public key (for owner/auth slots) or to a signature (for unlocking).

### 1A.4 customInstructions JSON shape

Every UTXO that this crate creates or consumes (STAS-3 outputs in `stas3-tokens` basket, funding outputs in `stas3-fuel` basket) carries a `customInstructions` JSON value with the wallet-relevant key triple:

```json
{
  "template": "stas3",
  "protocolID": [2, "stas3-token"],
  "keyID": "1",
  "counterparty": "self",
  "forSelf": true,
  "schema": "EAC1"
}
```

`internalize_action` populates this on output registration. Subsequent `list_outputs` returns it; the wrapper parses it to re-derive the signing key for the next spend. **Without these instructions a STAS-3 UTXO is effectively unspendable by this crate** — the triple is not recoverable from the locking script alone.

### 1A.5 Test fixtures and ProtoWallet

Tests use `ProtoWallet` (which is itself a BRC-42-compliant wallet over a single root key). Owner and authority PKHs in tests are derived via `wallet.get_public_key`, NOT via `Hash.hash160(privKey.publicKey)`. This is the same gotcha that bit the stas3-sdk integration tests earlier — raw-key derivation produces a PKH that does NOT match the wallet-derived PKH from the same root, breaking the covenant's owner-equality check on spend. Test driver utilities expose `walletPkh()` (Type-42) and explicitly NOT `pkhFromKey()`.

### 1A.6 No raw-private-key public API

The crate's public API exposes:
- `&dyn WalletInterface` for any operation that needs to sign or derive
- `KeyTriple` for any operation that needs to identify a key
- `[u8; 20]` PKH / MPKH only as opaque address material, never as something a caller can "make up"

Constructors that would otherwise take a `PrivateKey` (e.g. `Stas3::new_with_key(PrivateKey)`) do NOT exist. If someone needs raw-key behavior for a specialized scenario, they wrap their key in a `ProtoWallet` and pass that — the wrapping forces them through the BRC-42 derivation path even for trivial cases.

---

## 2. On-Chain Format (Canonical, Spec v0.2 §5)

### 2.1 Locking Script Layout

```
[0x14] [owner:20]              # 21 bytes — bare PUSH20 of owner PKH or MPKH (spec §5.1.1)
[var2 push]                    # variable — see §3 below (spec §5.1.2)
[engine:2899]                  # the canonical engine bytes (spec §5.1.3 + ASM)
                               # starts with 0x6d (OP_2DROP), ends with 0x6a (OP_RETURN)
[0x14 protoID:20]              # PUSH20 of redemption-address / protocol-ID (spec §5.2.1)
[flags push: 1+ bytes]         # PUSH1 of flag bits, never as OP_N (spec §5.2.2)
[svc fields...]                # 0+ pushes per flag bits set (spec §5.2.3)
[optional data...]             # 0+ pushes — issuer-defined (spec §5.2.4)
```

The `0x14 owner` push and `var2` push are the only two fields permitted to change across spends. The engine itself enforces this invariant via sighash-preimage inspection.

### 2.2 Engine Body

The 2,899-byte engine compiled from the official ASM (`stassso/STAS-3-script-templates/Template STAS 3.0`) is shipped as `src/script/templates/stas3_body.bin` (already present in this fork; verified byte-identical to the dxs production body). This file is the source of truth at runtime. The compile-from-ASM path is preserved as a build-time check (see §10.5).

### 2.3 Owner Field

20-byte HASH160. Three forms (spec §5.1.1):

- HASH160(pubkey) → P2PKH ownership; standard ECDSA spend.
- HASH160(P2MPKH redeem script) → P2MPKH ownership; m-of-n multisig spend (§5).
- `EMPTY_HASH160` = `b472a266d0bd89c13706a4132ccfb16f7c3b9fcb` (= HASH160("")) → signature-suppression sentinel; engine accepts `OP_FALSE` in place of all auth params (§4.4). Used for arbitrator-free swap legs and similar.

---

## 3. var2 Sub-Formats (Spec v0.2 §6)

The first byte of the var2 push (after the push header) is an action selector. Three sub-formats:

### 3.1 Passive / Data-Only (action `0x00` or empty)

```
[0x00] [arbitrary owner notes...]   # or empty push
```

Untouched by the engine; tag-along data for higher-level use.

### 3.2 Frozen Marker (action `0x02`)

Produced by `freeze`. Construction rules per spec §6.2:

| Original var2 | Frozen var2 |
|---|---|
| empty push (`OP_0`) | `OP_2` (single byte `0x52`) |
| pushdata bytes | prepend `0x02` to the bytes |
| `OP_1`, `OP_3..OP_16`, `OP_1NEGATE` | convert to pushdata, then prepend `0x02` |

Unfreeze strictly reverses.

### 3.3 Swap Descriptor (action `0x01`)

Fixed 61-byte minimum (spec §6.3):

```
[0x01]                         # action
[requested_script_hash:32]     # SHA-256 of the full counterparty locking script
[receive_addr:20]              # HASH160 — where counter-asset is delivered (also identifies maker for cancel)
[rate_numerator:4]             # u32 LE — numerator of exchange rate
[rate_denominator:4]           # u32 LE — denominator
[next?]                        # optional — see §3.4
```

If `rate_numerator == 0`, the engine skips rate verification.

Exchange rate semantics: `A' = A × (rate_numerator / rate_denominator)`. Multiplication is performed before division to preserve precision (8-byte values throughout). Rounding mode is unspecified in spec v0.2 — flagged as TBD in spec §6.3. **Implementation decision: floor (truncation), matching dxs production behavior.** This must be confirmed against the engine.

### 3.4 Swap Descriptor `next` Field

The `next` field holds whatever var2 value should be installed on the maker's remainder UTXO after the swap consumes them (or on the next swap leg in a chain). Spec §6.3:

| Leading byte | Form | Meaning |
|---|---|---|
| `0x00` | `Passive(rest)` | rest = arbitrary owner data (or empty) |
| `0x02` (single byte) | `Frozen` | frozen marker — no extra bytes allowed |
| anything else | `Swap(inner)` | inner descriptor, encoded WITHOUT its leading `0x01` (the action byte is implied) |

This is what enables chained atomic swaps in a single tx — the `next` of one descriptor is itself another descriptor, etc.

---

## 4. Unlocking Script (Spec v0.2 §7)

Parameters pushed in this order:

| # | Parameter | Type | Notes |
|---|---|---|---|
| 1 | out1_amount | u64 LE (≤8 B) or empty | STAS output 1 satoshi value |
| 2 | out1_addr | 20 B or empty | STAS output 1 owner |
| 3 | out1_var2 | variable push | STAS output 1 var2 |
| 4–6 | out2_* | optional triplet | (omit entirely if no out2) |
| 7–9 | out3_* | optional triplet | (omit entirely if no out3) |
| 10–12 | out4_* | optional triplet | max 4 STAS outputs per spend |
| 13 | change_amount | u64 LE or empty | optional non-STAS change |
| 14 | change_addr | 20 B or empty | P2PKH address for change |
| 15 | noteData | ≤65,533 B or `OP_FALSE` | trailing OP_RETURN note payload |
| 16 | fundIdx | 4 B LE or `OP_FALSE` | funding tx vOut |
| 17 | fundTxid | 32 B or `OP_FALSE` | funding txid |
| 18 | txType | 1 B | tx type (§4.1) |
| 19 | sighashPreimage | variable | BIP-143 preimage of this input |
| 20 | spendType | 1 B | spend type (§4.2) |
| 21+ | authz | variable | per §4.3 |

Optional outputs 2..4: their absence is signaled by *omitting the triplet entirely*, NOT by passing `OP_FALSE` in their slots.
Optional fields 13–17: their absence is signaled by `OP_FALSE` in the slot.

### 4.1 TX Types (Spec v0.2 §8.1)

| Value | Meaning | Trailing params after authz |
|---|---|---|
| 0 | Regular spend / split | none |
| 1 | Atomic swap | counterparty locking script, piece count, piece array |
| 2..7 | Merge with N pieces | piece count (2..7), piece array |

Piece arrays are space-delimited.

### 4.2 Spend Types (Spec v0.2 §8.2)

| Value | Meaning |
|---|---|
| 0 | Reserved — DO NOT USE |
| 1 | Regular owner spend (transfer, split, merge, swap) |
| 2 | Freeze / unfreeze (requires freeze authority) |
| 3 | Confiscation (requires confiscation authority) |
| 4 | Swap cancellation (requires swap maker authorization) |

### 4.3 Authorization (Spec v0.2 §10)

Three structural variants:

- **P2PKH:** `<sig> <pubkey>`
- **P2MPKH:** `<OP_0 multisig dummy> <sig_1> ... <sig_m> <redemption_script>`
  - redemption script: `m <0x21 pubkey_1> ... <0x21 pubkey_n> n`
  - n ≤ 5 in current spec
  - single-key spend path: pubkey is exactly 33 bytes (size 0x21) → routes through `OP_CHECKSIG`, indistinguishable from P2PKH on-chain
- **Suppress:** single `OP_FALSE` push (when owner is `EMPTY_HASH160`)

### 4.4 Sighash Coverage

The engine reconstructs the BIP-143 preimage and uses the "ECDSA trick" (synthesized signature with `r = G_x`) to verify sighash inclusion. Spec §12 protocol constants:

- `HALF_N` = `414136d08c5ed2bf3ba048afe6dcaebafe` (17 bytes) — half of secp256k1 group order
- `SIG_PREFIX_DER` = `3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220` — DER prefix
- `PUBKEY_A` = `038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218`
- `PUBKEY_B` = `023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc48`

These are embedded in the engine bytes; expose as named constants for tooling.

---

## 5. Operation Semantics (Spec v0.2 §9)

### 5.1 Regular Spend / Split (§9.1)
- `txType=0`, `spendType=1`
- 1..4 STAS outputs
- Each STAS output copies engine + protoID + flags + svc + optional data byte-for-byte
- Sum of STAS output amounts = sum of STAS input amounts
- P2PKH or P2MPKH unlock under input owner

### 5.2 Freeze / Unfreeze (§9.2)
- `spendType=2`
- Exactly one STAS output
- Owner + all data fields byte-identical to input; only `var2` changes per §3.2
- Freeze auth must validate; FREEZABLE flag must be set in the input frame

### 5.3 Confiscation (§9.3)
- `spendType=3`
- **No restriction on number of outputs, owner, or var2** — most permissive operation
- Confiscation auth must validate; CONFISCATABLE flag must be set
- Highest precedence

### 5.4 Swap Cancellation (§9.4)
- `spendType=4`
- Single output whose owner = input's `var2.receiveAddr`
- Authorization validates under `receiveAddr`
- Input var2 must be a swap descriptor

### 5.5 Atomic Swap (§9.5)
- `txType=1`, `spendType=1` on both STAS inputs
- Counterparty script + piece count + reverse-ordered piece array supplied as trailing params
- Output index assignment: requested asset → output matching initiator's input index; given asset → opposite
- Remainder/split outputs inherit source UTXO's owner and var2
- Owner = `EMPTY_HASH160` → no signature required from that leg (arbitrator-free)

### 5.6 Precedence (§9.6)

```
Confiscation > Freeze/unfreeze > Swap > Regular
```

Burn semantics: freeze and confiscate MUST NOT burn tokens. Only the issuer can redeem (= burn) by spending tokens received at `protoID` to any other address.

---

## 6. P2MPKH Locking Script (Spec v0.2 §10.2, §12)

Used for issuance/redemption outputs and as the embedded template inside the engine. Fixed 70-byte template:

```
[0x76 0xa9 0x14] [mpkh:20] [47-byte suffix]
```

47-byte suffix (verbatim from spec §12 / engine bytes):
```
0x88 0x82 0x01 0x21 0x87 0x63 0xac 0x67    # EQUALVERIFY SIZE PUSH(33) EQUAL IF CHECKSIG ELSE
0x51 0x7f 0x51 0x7f 0x73 0x63 0x7c 0x7f 0x68    # iter 1 (9 bytes)
[0x51 0x7f 0x73 0x63 0x7c 0x7f 0x68] × 4         # iters 2-5 (7 bytes each = 28 bytes)
0xae 0x68                                         # CHECKMULTISIG ENDIF
```

**Note:** the canonical layout for the post-`OP_ELSE` block is "iteration 1 has TWO `OP_1 OP_SPLIT` pairs, iterations 2-5 have ONE `OP_1 OP_SPLIT` each." This is what the bug-fix in `stas3-sdk` (made earlier in this collab) corrected — the prior code had 5 × 9-byte iterations producing a 78-byte script; canonical is 9 + 4×7 + 2 = 39 bytes after `OP_ELSE`, total 70 bytes.

---

## 7. Module Layout

All code lives inside the existing `bsv-sdk` crate (no new workspace member).

```
src/
  script/templates/
    stas3_body.bin                  # KEEP — canonical 2,899-byte engine, already verified
    stas3/
      mod.rs                        # public re-exports
      constants.rs                  # body bytes, P2MPKH template, EMPTY_HASH160, ECDSA-trick keys, etc.
      flags.rs                      # FREEZABLE, CONFISCATABLE bit constants + helpers
      action_data.rs                # ActionData enum, SwapDescriptor, NextVar2 — encode/decode
      lock.rs                       # build_locking_script(...)
      unlock.rs                     # per-spend-type unlocking-script builders
      decode.rs                     # parse a STAS-3 locking script back to fields
      p2mpkh.rs                     # 70-byte P2MPKH builder + recognizer + extractor
      spend_type.rs                 # Stas3SpendType, Stas3TxType enums
      sighash.rs                    # BIP-143 preimage construction matching engine's reconstruction
      error.rs                      # Stas3Error
  tokens/
    mod.rs
    stas3/
      mod.rs
      types.rs                      # Payment, Destination, OwnerAddress, SigningKey
      factory/
        issue.rs                    # 2-tx contract+issue (manual issuance path)
        transfer.rs
        split.rs
        merge.rs
        redeem.rs
        freeze.rs                   # also unfreeze
        confiscate.rs
        swap_mark.rs
        swap_execute.rs
        swap_cancel.rs
      eac.rs                        # MetaWatt EAC field schema + builders
      eac_template.rs               # EAC byte-template layout (slot offsets for covenant authors)
      wallet.rs                     # Stas3Wallet<W: WalletInterface> high-level wrapper
      verify.rs                     # engine-verify helpers (script interpreter wiring)
```

Re-export public surface from `src/lib.rs` under `bsv::tokens::stas3`.

---

## 8. Funding & BRC-100 Integration

### 8.1 Why raw-TX flow

The canonical engine permits at most one inline non-STAS change output (slots 13–14 in the unlocking script). BRC-100 wallets — particularly those using hosted storage like babbage.systems — unconditionally inject:

- A storage commission output (≥1 P2PKH, hard-coded server-side)
- 0–8 wallet-managed change outputs (controlled by `numberOfDesiredUTXOs`)

There is no `createAction` configuration that *guarantees* zero extra outputs. Any code path that depends on the wallet not adding outputs is fragile and breaks on every wallet-toolbox revision.

The canonical solution — used by dxs production code and by Bittoku — is to bypass `createAction` for any STAS-input-spending operation. The wallet remains involved as a:

- **Signing oracle** via `wallet.createSignature({ hashToDirectlySign, protocolID, keyID, counterparty })`
- **UTXO source** via `wallet.list_outputs({ basket })`
- **Output tracker** via `wallet.internalize_action({ tx, outputs: [...] })` after broadcast

This is BRC-100-compliant in the sense that signatures are produced by BRC-100 key derivation. It just doesn't use the `createAction` TX-construction abstraction.

### 8.2 Fuel Basket Pattern

Caller pre-creates funding UTXOs in a wallet basket they control. **All keys involved are Type-42 derived from the wallet root** (per §1A):

- Basket name: `stas3-fuel` (configurable)
- Each UTXO is a P2PKH output to a wallet-derived key. PKH = `Hash160(wallet.get_public_key({ protocolID, keyID, counterparty }))` — *never* a raw private key's PKH.
- `customInstructions` JSON includes the full Type-42 triple so the wrapper can re-derive the signing key on spend:

  ```json
  {
    "template": "stas3-fuel",
    "protocolID": [2, "stas3-fuel"],
    "keyID": "<unique per UTXO or per-batch>",
    "counterparty": "self",
    "forSelf": true
  }
  ```

- Suggested UTXO size: 250–500 sats per spend (covers fee + dust margin)

Bootstrap: a single `createAction` call seeds N fuel UTXOs at once, each with its own `keyID` so they're independently spendable. That seed tx pays commission + change one time; from then on, every STAS spend uses the fuel basket directly via raw flow with zero commission overhead.

### 8.3 Tx Construction, Signing, Broadcast

For any spend operation. **All signing flows through `wallet.create_signature` with the Type-42 triple from `customInstructions` — no raw private keys touch this path:**

1. `wallet.list_outputs({ basket: token_basket })` → find the STAS-3 UTXO matching params
2. `wallet.list_outputs({ basket: fuel_basket })` → greedy-pick funding UTXO ≥ estimated need
3. Parse `customInstructions` from each UTXO to extract its `KeyTriple` (protocolID, keyID, counterparty)
4. Build raw TX using the operation factory in `factory/`
5. For each STAS-3 input: assemble unlocking script per §4 of this spec; compute BIP-143 preimage; ask wallet to sign:
   ```rust
   let sig = wallet.create_signature(CreateSignatureArgs {
       hash_to_directly_sign: Some(hash256(&preimage)),
       protocol_id: triple.protocol_id,
       key_id: triple.key_id,
       counterparty: triple.counterparty,
       ..Default::default()
   }, originator).await?;
   ```
6. For funding input: same flow with the funding UTXO's triple; assemble P2PKH unlock with `[sig, pubkey]` where `pubkey` comes from `wallet.get_public_key` for the same triple
7. Broadcast via `wallet.broadcast_beef` (if exposed) or external ARC client
8. `wallet.internalize_action({ tx, outputs: [{ basket: token_basket, customInstructions: {...full triple + schema...} }] })` to register new STAS-3 output(s) — the registered customInstructions MUST include the Type-42 triple of whoever owns the new output, otherwise the next spend won't be able to sign

If at step 3 a UTXO is found whose customInstructions are missing or don't contain a valid triple, the wrapper fails fast with `Error::MissingKeyTriple(outpoint)`. Such UTXOs are unspendable by this crate — they were created outside the conventions of this implementation.

### 8.4 Issue Flow (Manual)

Spec §13 states issuance/redemption outputs are P2MPKH. The 2-tx issue flow from dxs:

- Tx 1 (contract): consumes funder P2PKH → outputs `[contract_lock_to_protoID, change]`
- Tx 2 (issue): consumes contract output → outputs `[stas_output_1..N, change]`

This path uses `createAction` for tx 1 (no STAS input being spent, no engine constraint), then raw flow for tx 2 (the contract output uses a special placeholder owner that's just a P2MPKH; the engine doesn't run on tx 2 either since the contract output isn't a STAS-3 covenant — it's just a P2MPKH).

### 8.5 Atomic Mint via Runar (Production Path for MetaWatt)

A Runar VPPA settlement contract emits a STAS-3 EAC as a parallel output:

```
TX inputs:  [previous_VPPA_state_input, funding_input]
TX outputs:
  output[0] = next_VPPA_state              # Runar covenant
  output[1..N] = EAC tokens                # STAS-3 lock scripts (one per beneficiary)
  output[N+1] = change                     # P2PKH
```

The Runar VPPA covenant validates:
- Its own state transition (oracle verification, delta math, running total update)
- That `output[1..N]` have the exact STAS-3 EAC locking-script structure with correct fields:
  - quantity_wh, intervals, source, etc. (from settlement)
  - owner = **beneficiary's Type-42 derived PKH** (from the beneficiary's wallet, triple supplied in the settlement event)
  - protoID = **issuer's Type-42 derived PKH** (the VPPA contract's deployed identity, derived under a known issuer triple)

The STAS-3 engine does NOT run because no STAS-3 input is being spent. The new EAC is a real STAS-3 token — subsequent transfers/swaps go through this crate's STAS-3 factory.

**This is the only place where `createAction` is acceptable for STAS-3.** Because the STAS engine doesn't run on this tx, BRC-100's auto-injected outputs (commission, change) are harmless — Runar's covenant doesn't reject them, and STAS engine doesn't run.

**Type-42 enforcement on the Runar path:** the beneficiary PKH and protoID PKH are both derived via BRC-42 by their respective wallets *before* the settlement event reaches Runar. The event payload carries the resolved 20-byte hashes; the contract embeds them. The Runar contract itself does not perform key derivation — it operates on already-derived PKHs supplied as event arguments. The atomic-mint helper (§8.6) takes these PKHs as inputs and assumes they are wallet-derived; the wallet wrapper (§8.7) is responsible for performing the derivation before constructing the event.

### 8.6 Runar-Side Helper API

All `[u8; 20]` parameters here are **assumed to be Type-42 derived** by the caller (the wallet wrapper, before constructing the Runar event). The helper performs no derivation and exposes no raw-key API.

```rust
// In bsv::tokens::stas3::eac_template
pub const STAS3_ENGINE_BYTES: &[u8; 2899] = include_bytes!("../../script/templates/stas3_body.bin");

pub struct Stas3LockingTemplate {
    pub static_prefix:   Vec<u8>,   // 0x14 + owner_slot + var2_slot bytes (constant)
    pub engine:          &'static [u8],  // STAS3_ENGINE_BYTES
    pub static_suffix:   Vec<u8>,   // protoID push + flags push + svc fields + (constant) optional data prefix
    pub eac_field_slots: Vec<EacFieldSlot>, // per-field per-tx slots (Runar fills)
}

pub struct EacFieldSlot {
    pub field_name: &'static str,    // "quantity_wh", "interval_start", ...
    pub byte_offset: usize,           // offset within the locking script
    pub byte_length: usize,
    pub validator: FieldValidator,    // e.g. "must equal settlement.delta_wh"
}

/// Build the verification template a Runar contract uses to assert
/// `output[i] is a valid EAC with these fields`.
///
/// # Inputs
/// All 20-byte hashes here MUST be Type-42 (BRC-42) derived public-key hashes
/// produced by `wallet.get_public_key(...)` and HASH160'd. The helper does not
/// validate this (it can't — they look like any other 20-byte value), but
/// usage outside this contract violates §1A.
///
/// # Returns
/// A template the Runar contract embeds in its covenant logic to enforce
/// `output[i]` matches a valid EAC.
pub fn build_eac_template(
    proto_id: [u8; 20],            // Type-42 PKH of the issuer
    flags: u8,
    freeze_auth: [u8; 20],          // Type-42 PKH/MPKH of freeze authority
    confiscation_auth: [u8; 20],    // Type-42 PKH/MPKH of confiscation authority
) -> Stas3LockingTemplate;
```

### 8.7 `Stas3Wallet` API Surface

The wallet wrapper is the only place callers interact with Type-42 derivation explicitly. Every operation takes one or more `KeyTriple`s; the wrapper resolves them via `WalletInterface` and constructs the appropriate raw TX.

```rust
pub struct Stas3Wallet<W: WalletInterface> {
    wallet: Arc<W>,
    fuel_basket: String,            // default: "stas3-fuel"
    token_basket: String,           // default: "stas3-tokens"
    fee_rate_sats_per_kb: u64,      // default: 500 (= 0.5 sat/byte)
    originator: Option<String>,
}

pub struct KeyTriple {
    pub protocol_id: WalletProtocol,
    pub key_id: String,
    pub counterparty: WalletCounterparty,
}

impl<W: WalletInterface> Stas3Wallet<W> {
    // ---- Setup ----
    pub async fn seed_fuel(&self, count: usize, sats_per_utxo: u64) -> Result<TxHex, Error>;

    // ---- Issue (manual 2-tx path; Runar atomic-mint is a separate flow) ----
    pub async fn mint_eac(&self, params: MintEacParams) -> Result<TxHex, Error>;

    // ---- Owner ops ----
    pub async fn transfer(&self, input: TokenSelector, dest: KeyTriple, var2: Option<ActionData>) -> Result<TxHex, Error>;
    pub async fn split(&self, input: TokenSelector, dests: Vec<(KeyTriple, u64)>) -> Result<TxHex, Error>;  // up to 4 dests
    pub async fn merge(&self, inputs: Vec<TokenSelector>, dest: KeyTriple) -> Result<TxHex, Error>;          // 2..=7 inputs
    pub async fn redeem(&self, input: TokenSelector) -> Result<TxHex, Error>;

    // ---- Authority ops ----
    pub async fn freeze(&self, input: TokenSelector, freeze_auth_triple: KeyTriple) -> Result<TxHex, Error>;
    pub async fn unfreeze(&self, input: TokenSelector, freeze_auth_triple: KeyTriple) -> Result<TxHex, Error>;
    pub async fn confiscate(&self, input: TokenSelector, dest: KeyTriple, confiscate_auth_triple: KeyTriple) -> Result<TxHex, Error>;

    // ---- Swap ops ----
    pub async fn swap_offer(&self, input: TokenSelector, descriptor: SwapDescriptor) -> Result<TxHex, Error>;
    pub async fn swap_match(&self, my_input: TokenSelector, marked_input: TokenSelector) -> Result<TxHex, Error>;
    pub async fn swap_cancel(&self, marked_input: TokenSelector) -> Result<TxHex, Error>;

    // ---- Discovery ----
    pub async fn list_tokens(&self) -> Result<Vec<TokenUtxo>, Error>;
    pub async fn list_swap_offers(&self) -> Result<Vec<SwapOffer>, Error>;

    // ---- Internal: derive PKH from a triple via BRC-42, used pervasively ----
    async fn pkh_for(&self, triple: &KeyTriple) -> Result<[u8; 20], Error>;
}

pub struct TokenSelector {
    pub outpoint: OutPoint,
    pub triple: KeyTriple,           // signing triple from customInstructions
}

pub struct MintEacParams {
    pub destinations: Vec<(KeyTriple, EacFields)>,  // beneficiary triple + EAC fields
    pub issuer_triple: KeyTriple,                   // for protoID derivation
    pub freeze_auth_triple: KeyTriple,              // for service field derivation
    pub confiscation_auth_triple: KeyTriple,        // for service field derivation
    pub flags: u8,
}
```

Anywhere a `[u8; 20]` PKH would otherwise be a parameter, the API takes a `KeyTriple` instead and the wrapper resolves it via `pkh_for`. This makes it impossible to call the high-level API with a non-Type-42 key — the only way to get a PKH into a script is via the wrapper, which always derives.

The Runar contract uses this to construct a sequence of byte-comparison + per-field validators inside its covenant logic.

---

## 9. MetaWatt EAC Extension

### 9.1 EAC `optional_data` Layout

```
optional_data[0]  = "EAC1"                       # 4-byte schema tag (versioning)
optional_data[1]  = quantity_wh        (8 B u64 LE)
optional_data[2]  = interval_start_ts  (8 B i64 LE Unix seconds)
optional_data[3]  = interval_end_ts    (8 B i64 LE)
optional_data[4]  = energy_source      (16 B ASCII fixed, NUL-padded)   # "WIND", "SOLAR", "HYDRO", etc.
optional_data[5]  = country_code       (2 B ISO 3166-1 alpha-2)
optional_data[6]  = device_id          (32 B application-defined hash)
optional_data[7]  = id_range_start     (8 B u64 LE)
optional_data[8]  = id_range_end       (8 B u64 LE)
optional_data[9]  = issue_date_ts      (8 B i64 LE)
optional_data[10] = storage_tag        (8 B u64 LE — 0 if not storage-derived)
optional_data[11..] = reserved
```

### 9.2 Versioning

Schema tag `"EAC1"` allows future revisions. Decoder routes on tag:
- `"EAC1"` → current schema above
- `"EAC2"` → future
- unknown tag → return as opaque `optional_data` for higher-level handling

### 9.3 EAC Builder API

```rust
pub struct EacFields {
    pub quantity_wh: u64,
    pub interval_start: i64,
    pub interval_end: i64,
    pub energy_source: EnergySource,
    pub country: [u8; 2],
    pub device_id: [u8; 32],
    pub id_range: (u64, u64),
    pub issue_date: i64,
    pub storage_tag: u64,
}

impl EacFields {
    pub fn to_optional_data(&self) -> Vec<Vec<u8>>;
    pub fn from_optional_data(data: &[Vec<u8>]) -> Result<Self, EacError>;
}

pub enum EnergySource {
    Wind, Solar, Hydro, Geothermal, Biomass, Nuclear, Storage, Other(String),
}
```

Op-level wrappers (`mint_eac`, `transfer_eac`, `retire_eac`, `swap_offer_eac`, etc.) constrain scheme to EAC and surface MetaWatt-friendly types instead of raw STAS fields.

---

## 10. Validation Strategy

### 10.1 Conformance Vectors

Port all 12 conformance vectors from `stas3-sdk/tests/fixtures/dstas-conformance-vectors.json` to Rust as `tests/conformance_vectors.rs`. These target the canonical 2,899-byte body and are the strongest protocol-level correctness gate. Coverage: transfer, freeze, confiscate, redeem (valid + reject paths), swap-cancel.

### 10.2 ASM Compile Check

Build script (`build.rs`) compiles `.ref/STAS-3-script-templates/Template STAS 3.0` from ASM and asserts byte-equality with `src/script/templates/stas3_body.bin`. If the official template is updated (e.g., a future spec rev), the build fails until we sync.

### 10.3 Round-Trip Tests

For every operation, build a tx with known inputs/outputs, decode the produced locking scripts back to fields, assert all fields match. Catches encoding bugs immediately.

### 10.4 Engine-Verify

Run produced txs through `bsv::script` interpreter (b1narydt's). Mirrors Bittoku's `stas3/engine_verify.rs` pattern. This is the strongest correctness signal short of on-chain broadcast — it's the same interpreter Bitcoin nodes use.

### 10.5 Cross-SDK Byte-Parity (Optional)

For a representative tx (transfer with 1 P2PKH change), build it via this crate AND via `dxs-bsv-token-sdk` (TypeScript, executed via subprocess from Rust test). Diff the bytes. **Strongest end-to-end correctness signal.** Enabled via `cargo test --features dxs-parity`.

### 10.6 Type-42 Compliance Tests

Beyond the protocol-level conformance vectors, a dedicated test pass verifies the Type-42 policy from §1A holds across the API surface:

- **No raw-key public API** — a build-time check (or trybuild test) verifies no public function in `tokens::stas3` accepts `PrivateKey`. Only `KeyTriple` + `&dyn WalletInterface`.
- **Wallet-derived owner round-trip** — using `ProtoWallet`, derive a Type-42 PKH for a triple, mint a token to that triple, transfer it to a new triple, verify the owner field changes correctly and the new owner is again wallet-derivable.
- **Mismatched-triple negative test** — attempting to spend a STAS-3 UTXO with a triple whose derived PKH does not match the script's owner field MUST fail at signing (covenant rejects the wrong signer).
- **`customInstructions` round-trip** — every UTXO this crate creates carries the triple in its customInstructions JSON; `internalize_action` reads it back and the next spend re-derives via the wallet.

This catches the class of bug that broke stas3-sdk's integration tests (raw `Hash160(pubkey)` ≠ wallet-derived PKH) at compile/test time.

### 10.7 Phase Gates

| Phase | Gate |
|---|---|
| 1. Body + constants | `stas3_body.bin` matches official ASM compile (build.rs check) |
| 2. Types (flags, spend types, action data, swap descriptor incl. `next`, `KeyTriple`) | Round-trip on all canonical encodings |
| 3. Lock + decode | Round-trip a known token; owner field is Type-42 in test fixtures |
| 4. Unlock (transfer) | Engine-verify a transfer tx; signer derived via `wallet.create_signature` |
| 5. Factory: transfer, split, merge, redeem, freeze/unfreeze, confiscate | All engine-verify; all signers Type-42 |
| 6. Conformance vectors | 12/12 pass |
| 7. Swap (mark, cancel, execute incl. recursive `next`) | Engine-verify all paths; receive_addr is Type-42 |
| 8. EAC layer | Round-trip + integration; protoID and authorities are Type-42 |
| 9. Wallet wrapper | End-to-end with `ProtoWallet` fixture; §10.6 Type-42 compliance suite passes |
| 10. Runar template export | Bytewise template matches a manually-constructed reference; PKH inputs documented as Type-42-required |

Each step gates the next — no advancing on red.

---

## 11. Type Translation (b1narydt mappings)

Patterns we'll borrow from Bittoku, retyped to b1narydt's universe:

| Bittoku | b1narydt equivalent | Notes |
|---|---|---|
| `bsv_primitives::ec::PrivateKey` | `crate::primitives::private_key::PrivateKey` | **Internal use only**; never in `tokens::stas3` public API |
| `bsv_primitives::hash::hash160` | `crate::primitives::hash::hash160` | Used only on wallet-derived public keys |
| `bsv_primitives::ec::PublicKey` | `crate::primitives::public_key::PublicKey` | Comes from `wallet.get_public_key`, not raw construction |
| `bsv_script::Script` | `crate::script::Script` | Verify `from_bytes` ergonomics |
| `bsv_script::Address` | `crate::primitives::address::Address` | Verify path |
| `bsv_transaction::Transaction` | `crate::transaction::Transaction` | Direct |
| `bsv_transaction::template::p2mpkh::MultisigScript` | NEW — port minimal version from Bittoku | Used by P2MPKH paths; pubkeys still come from wallet derivation per-key |
| `bsv_primitives::chainhash::Hash` | `crate::primitives::Hash` (TBD) | Verify |
| `SwapDescriptor`, `NextVar2`, `ActionData` | NEW types in `script::templates::stas3::action_data` | Port from Bittoku — type-only port, no dependency |
| `SigningKey`, `OwnerAddress`, `Payment`, `Destination` | NEW types in `tokens::stas3::types` | Port from Bittoku, **adapted to use `KeyTriple` instead of raw `PrivateKey`** |
| `KeyTriple` | NEW in `tokens::stas3::types` | Required wrapper for any key reference per §1A |

**Important deviation from Bittoku:** Bittoku's `SigningKey::Single(PrivateKey)` and `SigningKey::Multi { private_keys, multisig }` accept raw private keys. **Our port replaces these with triple-based equivalents** that go through `WalletInterface::create_signature`:

```rust
pub enum SigningKey {
    /// Single-key signing via Type-42 derivation.
    Single { triple: KeyTriple },
    /// M-of-N multisig signing — each leg has its own triple.
    Multi { triples: Vec<KeyTriple>, multisig: MultisigScript },
}
```

The `MultisigScript` itself still describes the on-chain template (m, n, ordered pubkeys); the pubkeys come from `wallet.get_public_key(triple)` for each leg. This preserves Bittoku's clean type structure while enforcing Type-42.

Phase 1 of implementation verifies these mappings against actual b1narydt API and notes any gaps.

---

## 12. Implementation Order

1. **Phase 0** — this spec, accepted
2. **Phase 1** — body bytes verified + ASM compile check; constants module (engine bytes, P2MPKH template, EMPTY_HASH160, ECDSA-trick consts)
3. **Phase 2** — types (flags, spend/tx types, ActionData + SwapDescriptor + NextVar2 with full encode/decode + round-trip tests on canonical vectors)
4. **Phase 3** — `lock.rs` (build_locking_script) + `decode.rs` (parse STAS-3 lock back to fields) + round-trip gate
5. **Phase 4** — `unlock.rs` for transfer; `sighash.rs` BIP-143 preimage; engine-verify of a transfer tx
6. **Phase 5** — factory: transfer, split, merge, redeem, freeze/unfreeze, confiscate. One at a time, gated by engine-verify.
7. **Phase 6** — port the 12 conformance vectors, gate the rest of work on 12/12 passing
8. **Phase 7** — swap descriptor encode/decode (including recursive `next`); swap-mark, swap-cancel, swap-execute (with remainder)
9. **Phase 8** — EAC layer (`EacFields`, schema tag handling, op wrappers)
10. **Phase 9** — `Stas3Wallet<W: WalletInterface>` wrapper with raw-TX flow + `createSignature` + `internalizeAction`
11. **Phase 10** — Runar template export helpers (the bridge for atomic mint)

Each phase ends with tests passing.

---

## 13. Out of Scope

- Runar VPPA contract logic — lives in `metawatt-edge`, not this fork
- MetaWatt overlay schemas — lives in `metawatt-overlay`
- BRC-100 wallet workarounds — this crate uses raw flow; `createAction`-based STAS spending is architecturally infeasible and not pursued
- STAS v1/v2 backward compatibility
- Bittoku 2,812-byte beta engine support
- Lineage analytics

---

## 14. Open Decisions for Confirmation

These are spec-level choices that benefit from explicit sign-off before code is written:

1. ~~Rounding mode~~ → **LOCKED: floor (truncation)**, matching dxs production behavior.
2. **`stas3fuel` basket name and bootstrap behavior**. 250–500 sat fuel UTXOs, batched bootstrap, distinct `keyID` per UTXO. Basket name `stas3fuel` (no hyphens, matching protocol ID convention).
3. **EAC schema fields list** (§9.1). 11 fields proposed; subject to MetaWatt domain review.
4. **Cross-SDK byte-parity test** enabled by default? §10.5 — gated behind `--features dxs-parity` (off by default) to keep test setup simple.
5. **Runar template export — slot validators format.** §8.6 sketches `Stas3LockingTemplate { eac_field_slots: Vec<EacFieldSlot> }`. Phase 10 starts with confirming this against Runar's actual API.
6. ~~MetaWatt protocolID conventions~~ → **LOCKED: no hyphens, format `stas3<function>`**:
   - Token ownership: `[2, "stas3owner"]`
   - Issuer identity (protoID): `[2, "stas3mint"]`
   - Freeze authority: `[2, "stas3freeze"]`
   - Confiscation authority: `[2, "stas3confiscate"]`
   - Swap maker (receive_addr derivation): `[2, "stas3swap"]`
   - Funding / fuel basket: `[2, "stas3fuel"]`

   These strings appear in `customInstructions` JSON and as basket names where applicable.

---

## 15. Sources Reference

| Source | Local path | Role |
|---|---|---|
| `stassso/STAS-3-script-templates` | `.ref/STAS-3-script-templates/` | Authoritative ASM (compiles to 2,899 bytes) |
| STAS 3.0 Spec v0.2 (DOCX) | `~/Downloads/STAS 3 spec v0.2.docx` | Authoritative semantic spec |
| `dxs-bsv-token-sdk` | `~/METAWATT/METAWATT-code/dxs-bsv-token-sdk/` | Production TypeScript reference |
| `Bittoku/bsv-sdk-rust` | `.ref/bsv-sdk-rust/` | Rust patterns reference (NOT body bytes) |
| `stas3-sdk` | `~/METAWATT/METAWATT-code/stas3-sdk/` | Has canonical conformance vectors at `tests/fixtures/dstas-conformance-vectors.json` |
