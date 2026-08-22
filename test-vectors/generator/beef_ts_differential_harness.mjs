// Differential harness: run the normative @bsv/sdk (2.3.1) through the call
// sequences tests/beef_ts_differential.rs replays, and emit JSON keyed by
// scenario. The committed output is test-vectors/beef_ts_differential.json.
//
// Run from the repo root with a checkout of @bsv/sdk resolvable from `SDK`:
//   SDK=/path/to/node_modules/@bsv/sdk node test-vectors/generator/beef_ts_differential_harness.mjs
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const SDK = process.env.SDK ?? '@bsv/sdk'
const { Beef, BeefParty, MerklePath } = await import(SDK.startsWith('/') ? join(SDK, 'dist/esm/mod.js') : SDK)

const VEC = 'test-vectors/'
const sort = JSON.parse(readFileSync(VEC + 'beef_sort_order.json', 'utf8')).vectors
const out = {}
const hex = (b) => Buffer.from(b.toBinary()).toString('hex')
const order = (b) => b.txs.map(t => t.txid.slice(0, 8) + (t.isTxidOnly ? '(txidonly)' : '') + (t.bumpIndex === undefined ? '' : `[b${t.bumpIndex}]`))
const tryRun = (f) => { try { return f() } catch (e) { return 'THROW: ' + (e.message ?? String(e)) } }

const s1 = sort[0] // already sorted chain: 92af(proven), 529a, 8df6
const s2 = sort[1] // reversed chain
const s4 = sort[3] // txid-only entry
const s5 = sort[4] // interleaved proven families
const T8 = s1.sort_result.valid[2]
const T5 = s1.sort_result.valid[1]

// A: needsSort after mergeBump once the beef is already sorted.
for (const [label, txid] of [['A1_bump_8df6', T8], ['A2_bump_529a', T5]]) {
  const mp = new MerklePath(800002, [[{ offset: 0, hash: txid, txid: true }]])
  out[label + '_bump_hex'] = mp.toHex()
  const b = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  b.sortTxs()
  b.mergeBump(mp)
  out[label + '_order'] = order(b)
  out[label + '_hex'] = hex(b)
  // same but WITHOUT the explicit sort first (the conformance test's shape)
  const c = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  c.mergeBump(mp)
  out[label + '_nosort_hex'] = hex(c)
}

// B: verifyValid / isValid / getValidTxids side-effect sort on a parsed reversed chain.
{
  const b = Beef.fromBinary(Buffer.from(s2.input_beef_hex, 'hex'))
  out.B_parsed_order = order(b)
  b.verifyValid()
  out.B_after_verify_order = order(b)
  out.B_after_verify_hex = hex(b)
  const c = Beef.fromBinary(Buffer.from(s2.input_beef_hex, 'hex'))
  c.getValidTxids()
  out.B_after_getValidTxids_hex = hex(c)
  const d = Beef.fromBinary(Buffer.from(s2.input_beef_hex, 'hex'))
  out.B_untouched_hex = hex(d)
}

// C: BeefParty.mergeBeefFromParty sorts `other` first (getValidTxids) — does it change bytes?
for (const [label, v] of [['C_s2', s2], ['C_s5', s5], ['C_s4', s4]]) {
  const bp = new BeefParty(['a'])
  bp.mergeBeefFromParty('a', Beef.fromBinary(Buffer.from(v.input_beef_hex, 'hex')))
  out[label + '_party_order'] = order(bp)
  out[label + '_party_hex'] = hex(bp)
  out[label + '_party_known'] = bp.getKnownTxidsForParty('a').map(t => t.slice(0, 8))
  const plain = new Beef()
  plain.mergeBeef(Beef.fromBinary(Buffer.from(v.input_beef_hex, 'hex')))
  out[label + '_plain_order'] = order(plain)
  out[label + '_plain_hex'] = hex(plain)
}

// D: mergeBeef on a beef whose entries carry `_tx` graphs (mergeTransaction-built),
// after a public removal — does the _tx branch resurrect the removed tx?
{
  const src = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  const tx = src.findAtomicTransaction(T8)
  const other = new Beef()
  other.mergeTransaction(tx)
  out.D_other_order = order(other)
  other.removeExistingTxid(T5)
  out.D_other_after_remove = order(other)
  const self = new Beef()
  self.mergeBeef(other)
  out.D_self_order_after_remove = order(self)
  out.D_self_hex_after_remove = hex(self)
  out.D_self_valid_after_remove = self.verifyValid().valid

  const other2 = new Beef()
  other2.mergeTransaction(src.findAtomicTransaction(T8))
  other2.makeTxidOnly(T5)
  out.D2_other_after_txidonly = order(other2)
  const self2 = new Beef()
  self2.mergeBeef(other2)
  out.D2_self_order = order(self2)
  out.D2_self_hex = hex(self2)
}

// E: zero-height bump (tree height byte 0) — hostile input.
{
  const zero = '0200beef' + '01' + '01' + '00' + '00'
  out.E_parse = tryRun(() => { const b = Beef.fromBinary(Buffer.from(zero, 'hex')); return { bumps: b.bumps.length, levels: b.bumps[0].path.length } })
  out.E_verifyValid = tryRun(() => Beef.fromBinary(Buffer.from(zero, 'hex')).verifyValid())
  out.E_mergeBeef = tryRun(() => { const s = new Beef(); s.mergeBeef(Beef.fromBinary(Buffer.from(zero, 'hex'))); return order(s) })
  out.E_toBinary = tryRun(() => hex(Beef.fromBinary(Buffer.from(zero, 'hex'))))
  // zero-height bump plus one proven-claiming tx
  const withTx = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  const raw = withTx.txs[0].rawTx
  out.E_mergeRawTx_bump0 = tryRun(() => { const b2 = Beef.fromBinary(Buffer.from(zero, 'hex')); b2.mergeRawTx(raw, 0); return hex(b2) })
}

// F: txid-only subject that still has a bumpIndex.
{
  const b = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  const P = s1.sort_result.valid[0]
  b.makeTxidOnly(P)
  out.F_order = order(b)
  out.F_atomic_hex = tryRun(() => Buffer.from(b.toBinaryAtomic(P)).toString('hex'))
  out.F_hex = hex(b)
  out.F_verify_false = b.verifyValid(false).valid
  out.F_verify_true = b.verifyValid(true).valid
  out.F_sort = b.sortTxs()
}

// H: sortTxs twice on the txid-only vector — memoized `valid` order.
{
  const b = Beef.fromBinary(Buffer.from(s4.input_beef_hex, 'hex'))
  out.H_first_valid = b.sortTxs().valid.map(t => t.slice(0, 8))
  out.H_second_valid = b.sortTxs().valid.map(t => t.slice(0, 8))
}

// I: parse → mergeTxidOnly(new) → toBinary
{
  const b = Beef.fromBinary(Buffer.from(s1.input_beef_hex, 'hex'))
  b.mergeTxidOnly('11'.repeat(32))
  out.I_hex = hex(b)
  // parse → mergeRawTx(existing raw, no bump) → toBinary (replace in place, then sort)
  const c = Beef.fromBinary(Buffer.from(s2.input_beef_hex, 'hex'))
  c.mergeRawTx(c.txs[0].rawTx)
  out.I2_hex = hex(c)
}

// J: trimKnownTxids prunes bumps; getTrimmedBeefForParty shares BeefTx objects (TS aliasing).
{
  const bp = new BeefParty(['a'])
  bp.mergeBeef(Beef.fromBinary(Buffer.from(s5.input_beef_hex, 'hex')))
  const P0 = s5.sort_result.valid[0]
  bp.makeTxidOnly(P0)
  bp.addKnownTxidsForParty('a', [P0])
  out.J_before = order(bp)
  const trimmed = bp.getTrimmedBeefForParty('a')
  out.J_trimmed = order(trimmed)
  out.J_trimmed_hex = hex(trimmed)
  out.J_original_after_trim = order(bp)
  out.J_original_hex_after_trim = tryRun(() => hex(bp))
  out.J_original_valid_after_trim = tryRun(() => bp.verifyValid(true).valid)
}

writeFileSync(VEC + 'beef_ts_differential.json', JSON.stringify(out, null, 1))
console.log(Object.keys(out).length + ' scenario keys written to ' + VEC + 'beef_ts_differential.json')
