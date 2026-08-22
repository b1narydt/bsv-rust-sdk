// Shared deterministic builders for the cross-language BEEF golden-vector corpus.
// Normative reference: TS @bsv/sdk (BRC-62 BEEF, BRC-74 BUMP, BRC-95 Atomic, BRC-96 V2).
// Determinism: fixed private keys, fixed lock heights, fixed sequences, no Date/random.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

export const SDK_PATH = '/Users/donot/PARAGON/PARAGON-code/atlas-certifier/backend/node_modules/@bsv/sdk';
const sdk = require(SDK_PATH);
export const {
  Beef, BeefTx, MerklePath, Transaction, PrivateKey, P2PKH,
  Script, LockingScript, UnlockingScript, Utils, Hash,
  BEEF_V1, BEEF_V2, ATOMIC_BEEF
} = sdk;

export const SDK_VERSION = require(`${SDK_PATH}/package.json`).version;

export const toHex = (bytes) => Utils.toHex(bytes);

// ---------------------------------------------------------------------------
// Deterministic key material
// ---------------------------------------------------------------------------
export function key(n) {
  // Small fixed scalars; valid non-zero private keys.
  return new PrivateKey(n);
}

export function p2pkhLock(n) {
  return new P2PKH().lock(key(n).toPublicKey().toAddress());
}

export function opReturnLock(asciiData) {
  // OP_FALSE OP_RETURN <push data>
  const dataHex = Buffer.from(asciiData, 'ascii').toString('hex');
  const pushLen = (dataHex.length / 2).toString(16).padStart(2, '0');
  return Script.fromHex('006a' + pushLen + dataHex);
}

// ---------------------------------------------------------------------------
// Deterministic transactions (no signatures: fixed pushdata unlocking scripts,
// so byte-exactness never depends on nonce generation)
// ---------------------------------------------------------------------------
const FAKE_GENESIS_TXID_BASE = '00000000000000000000000000000000000000000000000000000000000000';

/** A "root" transaction: spends a fabricated outpoint; proven via fabricated BUMP. */
export function rootTx(n, { sats = 1000, keyIndex = n, extraOpReturn = null } = {}) {
  const tx = new Transaction();
  tx.version = 1;
  tx.lockTime = 0;
  tx.addInput({
    sourceTXID: FAKE_GENESIS_TXID_BASE + n.toString(16).padStart(2, '0'),
    sourceOutputIndex: 0,
    unlockingScript: Script.fromHex('51'), // OP_TRUE placeholder; never executed
    sequence: 0xffffffff
  });
  if (extraOpReturn != null) tx.addOutput({ satoshis: 0, lockingScript: opReturnLock(extraOpReturn) });
  tx.addOutput({ satoshis: sats, lockingScript: p2pkhLock(keyIndex) });
  return tx;
}

/** A spend of `parentTx` output `vout`; deterministic fixed unlocking script. */
export function spendTx(parentTx, { vout = 0, sats = 900, keyIndex = 9, extraParents = [] } = {}) {
  const tx = new Transaction();
  tx.version = 1;
  tx.lockTime = 0;
  tx.addInput({
    sourceTXID: parentTx.id('hex'),
    sourceOutputIndex: vout,
    // Fixed fake "signature-shaped" pushdata (deterministic, not a real sig).
    unlockingScript: Script.fromHex('483045022100' + 'aa'.repeat(31) + '0220' + 'bb'.repeat(32) + '01'),
    sequence: 0xffffffff
  });
  for (const [p, pv] of extraParents) {
    tx.addInput({
      sourceTXID: p.id('hex'),
      sourceOutputIndex: pv,
      unlockingScript: Script.fromHex('483045022100' + 'cc'.repeat(31) + '0220' + 'dd'.repeat(32) + '01'),
      sequence: 0xffffffff
    });
  }
  tx.addOutput({ satoshis: sats, lockingScript: p2pkhLock(keyIndex) });
  return tx;
}

// ---------------------------------------------------------------------------
// Fabricated-but-internally-consistent BUMPs (BRC-74)
// ---------------------------------------------------------------------------
export function fabricatedSibling(seed) {
  // Deterministic 32-byte hash as txid-style hex from a fixed ascii seed.
  return toHex(Hash.sha256(Array.from(Buffer.from(seed, 'ascii'))));
}

/** Two-leaf block: our txid at offset 0, a fabricated sibling at offset 1. */
export function bumpFor(txid, height, seed) {
  const path = [[
    { offset: 0, hash: txid, txid: true },
    { offset: 1, hash: fabricatedSibling(seed) }
  ]];
  return new MerklePath(height, path);
}

/** Two-leaf block proving BOTH txids (offset 0 = txidA, offset 1 = txidB). */
export function bumpForPair(txidA, txidB, height, { markA = true, markB = true } = {}) {
  const leaves = [
    { offset: 0, hash: txidA, ...(markA ? { txid: true } : {}) },
    { offset: 1, hash: txidB, ...(markB ? { txid: true } : {}) }
  ];
  return new MerklePath(height, [leaves]);
}

// ---------------------------------------------------------------------------
// Manual BEEF serializer — for inputs the TS Beef class refuses to produce
// (unsorted order, duplicate txids, bad bump indexes, V1 splices, trailing
// garbage). Mirrors Beef.toWriter/BeefTx.toWriter byte-for-byte.
// ---------------------------------------------------------------------------
export function buildRawBeefHex({ version = BEEF_V2, bumps = [], txs = [], atomicTxid = null, trailing = '' }) {
  const w = new Utils.Writer();
  if (atomicTxid != null) {
    w.writeUInt32LE(ATOMIC_BEEF);
    w.writeReverse(Utils.toArray(atomicTxid, 'hex'));
  }
  w.writeUInt32LE(version);
  w.writeVarIntNum(bumps.length);
  for (const b of bumps) w.write(b.toBinary());
  w.writeVarIntNum(txs.length);
  for (const t of txs) {
    if (version === BEEF_V2) {
      if (t.txidOnly != null) {
        w.writeUInt8(2); // TXID_ONLY
        w.writeReverse(Utils.toArray(t.txidOnly, 'hex'));
      } else if (t.bumpIndex !== undefined && t.bumpIndex !== null) {
        w.writeUInt8(1); // RAWTX_AND_BUMP_INDEX
        w.writeVarIntNum(t.bumpIndex);
        w.write(t.tx.toBinary());
      } else {
        w.writeUInt8(0); // RAWTX
        w.write(t.tx.toBinary());
      }
    } else {
      // V1: rawTx, then hasBump byte, then optional varint bump index
      if (t.txidOnly != null) throw new Error('txid-only is not expressible in well-formed V1; hand-splice instead');
      w.write(t.tx.toBinary());
      if (t.bumpIndex !== undefined && t.bumpIndex !== null) {
        w.writeUInt8(1);
        w.writeVarIntNum(t.bumpIndex);
      } else {
        w.writeUInt8(0);
      }
    }
  }
  return toHex(w.toArray()) + trailing;
}

// ---------------------------------------------------------------------------
// Verdict capture: run TS structural verification on a hex, recording truth.
// ---------------------------------------------------------------------------
export function tsVerdict(hex, { allowTxidOnly = false } = {}) {
  let beef;
  try {
    beef = Beef.fromString(hex);
  } catch (e) {
    return { parses: false, parse_error: String(e.message ?? e) };
  }
  let vv;
  try {
    vv = beef.verifyValid(allowTxidOnly);
  } catch (e) {
    return { parses: true, verify_error: String(e.message ?? e) };
  }
  const out = {
    parses: true,
    valid: vv.valid,
    roots: vv.roots
  };
  if (beef.atomicTxid != null) {
    out.atomic_txid = beef.atomicTxid;
    out.is_atomic = beef.isAtomic(beef.atomicTxid);
  }
  return out;
}

/** Round-trip assertion: parse expected hex with TS and re-serialize byte-exact. */
export function assertRoundTrip(hex, { atomicSubject = null } = {}) {
  const beef = Beef.fromString(hex);
  const re = atomicSubject != null
    ? toHex(beef.toUint8ArrayAtomic(atomicSubject))
    : beef.toHex();
  if (re !== hex) {
    throw new Error(`round-trip mismatch:\n  expected ${hex}\n  got      ${re}`);
  }
}

export function sortResultOf(hex) {
  const beef = Beef.fromString(hex);
  const sr = beef.sortTxs();
  return { beef, sr };
}
