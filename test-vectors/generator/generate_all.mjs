// Cross-language BEEF golden-vector generator.
// TS @bsv/sdk is the NORMATIVE reference (BRC-62 BEEF, BRC-74 BUMP, BRC-95 Atomic,
// BRC-96 V2 txid-only). Every expected hex below is TS output, captured byte-exact
// and round-trip re-verified through TS before being written.
//
// Determinism: fixed private keys (scalars 1..10), fixed heights (800000..800002),
// fixed sequences (0xffffffff), fixed lockTime 0, fabricated sibling hashes from
// fixed ascii seeds. No Date.now, no Math.random, no ECDSA.
import fs from 'node:fs';
import path from 'node:path';
import {
  Beef, MerklePath, Utils, BEEF_V1, BEEF_V2, ATOMIC_BEEF,
  SDK_VERSION, toHex,
  rootTx, spendTx, bumpFor, bumpForPair, fabricatedSibling,
  buildRawBeefHex, tsVerdict, assertRoundTrip
} from './lib.mjs';

const H1 = 800000, H2 = 800001, H3 = 800002;
const BRC_REFS = ['BRC-62', 'BRC-74', 'BRC-95', 'BRC-96'];
const GENERATOR = 'conformance/vectors/beef/generator/generate_all.mjs (session scratchpad beef-vectors/, vendored alongside the vectors)';

const surprises = [];
function surprise(s) { surprises.push(s); console.log('SURPRISE:', s); }

// ---------------------------------------------------------------------------
// Deterministic universe
// ---------------------------------------------------------------------------
const A = rootTx(1);                       // proven at H1
const B = rootTx(2);                       // proven at H2
const U = rootTx(3);                       // unrelated, proven at H3
const C  = spendTx(A, { vout: 0, sats: 900, keyIndex: 9 });   // spends A
const C2 = spendTx(A, { vout: 0, sats: 800, keyIndex: 10 });  // second child of A
const D  = spendTx(C, { vout: 0, sats: 850, keyIndex: 9 });   // spends C
const E  = spendTx(C, { vout: 0, sats: 700, keyIndex: 9, extraParents: [[C2, 0]] }); // diamond: spends C and C2

const txidA = A.id('hex'), txidB = B.id('hex'), txidU = U.id('hex');
const txidC = C.id('hex'), txidC2 = C2.id('hex'), txidD = D.id('hex'), txidE = E.id('hex');

const bumpA = () => bumpFor(txidA, H1, 'sib-A');
const bumpB = () => bumpFor(txidB, H2, 'sib-B');
const bumpU = () => bumpFor(txidU, H3, 'sib-U');

function beefOf(parts) {
  // parts: list of ['bump', mp] | ['raw', tx] | ['txidOnly', txid], applied in order.
  const beef = new Beef();
  for (const [kind, v] of parts) {
    if (kind === 'bump') beef.mergeBump(v);
    else if (kind === 'raw') beef.mergeRawTx(v.toBinary());
    else if (kind === 'txidOnly') beef.mergeTxidOnly(v);
    else throw new Error(kind);
  }
  return beef;
}

// ===========================================================================
// 1. beef_atomic_closure.json
// ===========================================================================
function genAtomicClosure() {
  const cases = [];

  function atomicCase(name, inputHex, subject, notes, { allowTxidOnlySubject = false } = {}) {
    const beef = Beef.fromString(inputHex);
    let expected, error;
    try {
      expected = toHex(beef.toUint8ArrayAtomic(subject));
    } catch (e) {
      error = String(e.message ?? e);
    }
    const c = { name, input_beef_hex: inputHex, subject_txid: subject, notes };
    if (expected != null) {
      assertRoundTrip(expected, { atomicSubject: subject });
      c.expected_atomic_hex = expected;
      const inner = Beef.fromString(expected);
      c.expected_verdict = {
        is_atomic: inner.isAtomic(subject),
        verify_valid: inner.verifyValid(allowTxidOnlySubject).valid,
        bump_count: inner.bumps.length,
        tx_count: inner.txs.length
      };
    } else {
      c.expected_error = error;
    }
    cases.push(c);
    return c;
  }

  // 1: single tx with bump
  atomicCase('single tx with bump',
    beefOf([['bump', bumpA()], ['raw', A]]).toHex(), txidA,
    'Minimal atomic BEEF: subject is directly proven; expected output = ATOMIC prefix + subject txid (reversed on wire) + V2 beef with 1 bump, 1 tx.');

  // 2: two-tx chain, canonical order
  atomicCase('two-tx chain canonical order',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C]]).toHex(), txidC,
    'Subject C spends proven ancestor A; closure = {A, C}. Ancestor serialized before dependent.');

  // 3: unsorted input — ancestor after subject (hand-built bytes; Beef.toBinary always sorts, so raw serializer required to make this input)
  {
    const unsortedHex = buildRawBeefHex({
      version: BEEF_V2,
      bumps: [bumpA()],
      txs: [{ tx: C }, { tx: A, bumpIndex: 0 }]
    });
    const c = atomicCase('unsorted input ancestor after subject', unsortedHex, txidC,
      'Input bytes deliberately place the dependent C before its ancestor A. TS derives the closure from txids (not array position) and re-sorts before serializing, so the expected atomic output is byte-identical to the canonical-order case.');
    const canonical = cases[1];
    if (c.expected_atomic_hex !== canonical.expected_atomic_hex) {
      surprise('atomic closure of unsorted input differs from canonical-order input');
    }
  }

  // 4: unrelated transactions dropped
  atomicCase('unrelated transactions dropped',
    beefOf([['bump', bumpA()], ['bump', bumpB()], ['raw', A], ['raw', C], ['raw', B]]).toHex(), txidC,
    'Input carries unrelated proven tx B and its bump. BRC-95 closure for subject C = {A, C}; B and its bump must not appear in the atomic output.');

  // 5: two bumps, only index 1 referenced — prune + reindex
  {
    const inputHex = beefOf([['bump', bumpU()], ['bump', bumpA()], ['raw', U], ['raw', A], ['raw', C]]).toHex();
    const c = atomicCase('bump prune and reindex', inputHex, txidC,
      'Input bumps: [bumpU (index 0, unreferenced by closure), bumpA (index 1)]. TS prunes the unreferenced bump and re-derives indexes: in the atomic output A references bump index 0.');
    const inner = Beef.fromString(c.expected_atomic_hex);
    if (inner.bumps.length !== 1) surprise(`bump prune case kept ${inner.bumps.length} bumps`);
  }

  // 6: subject is txid-only
  {
    const inputHex = beefOf([['bump', bumpA()], ['raw', A], ['txidOnly', txidB]]).toHex();
    const c = atomicCase('subject is txid-only', inputHex, txidB,
      'TS behavior (captured as truth): a txid-only subject IS serializable as atomic. Closure = just the txid-only entry (dependency walk stops at txid-only); output = ATOMIC prefix + txid + V2 beef with 0 bumps and 1 TXID_ONLY tx. isAtomic()=true but verifyValid(false)=false (txid-only not allowed); verifyValid(true)=true.',
      { allowTxidOnlySubject: false });
    const inner = Beef.fromString(c.expected_atomic_hex);
    c.expected_verdict.verify_valid_allow_txid_only = inner.verifyValid(true).valid;
  }

  // 7: three-deep chain
  atomicCase('three-deep chain',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C], ['raw', D]]).toHex(), txidD,
    'Subject D -> C -> A(proven). Closure = all three, topologically sorted ancestors-first.');

  // 8: diamond dependency
  atomicCase('diamond dependency',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C], ['raw', C2], ['raw', E]]).toHex(), txidE,
    'E spends both C and C2, which both spend A. Closure = {A, C, C2, E}; shared ancestor A appears exactly once.');

  return cases;
}

// ===========================================================================
// 2. beef_sort_order.json
// ===========================================================================
function genSortOrder() {
  const cases = [];

  function sortCase(name, inputHex, notes) {
    const beef = Beef.fromString(inputHex);
    const sr = beef.sortTxs();
    const afterHex = beef.toHex();
    assertRoundTrip(afterHex);
    cases.push({
      name,
      input_beef_hex: inputHex,
      expected_serialized_hex_after_sort: afterHex,
      sort_result: {
        missingInputs: sr.missingInputs,
        notValid: sr.notValid,
        txidOnly: sr.txidOnly,
        valid: sr.valid,
        withMissingInputs: sr.withMissingInputs
      },
      notes
    });
  }

  // 1: already sorted
  sortCase('already sorted chain',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C], ['raw', D]]).toHex(),
    'Input already in dependency order; sort is a no-op on the byte level.');

  // 2: reversed chain
  sortCase('reversed chain',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: D }, { tx: C }, { tx: A, bumpIndex: 0 }] }),
    'Input in exactly reversed dependency order (D, C, A). Sorted output places proven A first, then C, then D.');

  // 3: missing input
  sortCase('missing input',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: A, bumpIndex: 0 }, { tx: C }, { tx: spendTx(B, { vout: 0, sats: 500, keyIndex: 7 }) }] }),
    'Third tx spends absent parent B. sort_result.missingInputs names the absent parent txid; withMissingInputs names the orphan tx. TS serializes unsortable txs FIRST, then sorted valid txs.');

  // 4: txid-only entry
  sortCase('txid-only entry',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: A, bumpIndex: 0 }, { txidOnly: txidB }, { tx: C }] }),
    'BRC-96 txid-only entry sorts into the txidOnly partition (after unsortable, before proven/sorted). txid-only with no inputs is treated as valid for ordering purposes.');

  // 5: interleaved families
  sortCase('interleaved proven families',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA(), bumpB()], txs: [{ tx: C }, { tx: B, bumpIndex: 1 }, { tx: D }, { tx: A, bumpIndex: 0 }] }),
    'Two independent proven roots (A, B) with a dependent chain on A, interleaved. Pins the exact deterministic order TS emits after sort.');

  return cases;
}

// ===========================================================================
// 3. beef_invalid.json  (negative corpus — TS verdict is truth)
// ===========================================================================
function genInvalid() {
  const cases = [];

  function invalidCase(name, hex, rule, notes, extra = {}) {
    const verdict = tsVerdict(hex);
    const c = { name, beef_hex: hex, expect_reject_rule: rule, ts_verdict: verdict, notes, ...extra };
    cases.push(c);
    if (verdict.parses === true && verdict.valid === true) {
      surprise(`invalid corpus case "${name}" is ACCEPTED by TS verifyValid — recorded as truth`);
      c.ts_accepts = true;
    }
    return c;
  }

  // 1: missing ancestor — input tx absent, no bump
  invalidCase('missing ancestor',
    buildRawBeefHex({ version: BEEF_V2, bumps: [], txs: [{ tx: C }] }),
    'missing-input',
    'C spends A but A is absent and there is no bump. verifyValid must be false (sortTxs reports the missing input).');

  // 2: bump index names non-leaf
  invalidCase('bump index names non-leaf',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: B, bumpIndex: 0 }] }),
    'bump-leaf-mismatch',
    'B claims bumpIndex 0 but bump 0 has no level-0 leaf with B\'s txid. TS rejects in verifyBumpIndexLeaves. Note the tx still parses and even sorts as "proven" — the rejection happens at verification, not parse.');

  // 3: duplicate txid
  invalidCase('duplicate txid',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: A, bumpIndex: 0 }, { tx: A, bumpIndex: 0 }] }),
    'duplicate-txid',
    'Same transaction serialized twice. Unreachable through the TS merge API (mergeRawTx replaces by txid) — hand-built bytes. verifyValid must be false.');

  // 4: txid-only spliced into V1 bytes
  {
    // V1 has no TXID_ONLY format. Hand-splice: V1 header, 0 bumps, 1 "tx" whose
    // bytes are just a 32-byte txid. The V1 reader tries to parse it as a raw
    // transaction; TS behavior captured as truth.
    const w = new Utils.Writer();
    w.writeUInt32LE(BEEF_V1);
    w.writeVarIntNum(0);
    w.writeVarIntNum(1);
    w.writeReverse(Utils.toArray(txidB, 'hex'));
    invalidCase('txid-only spliced into V1',
      toHex(w.toArray()),
      'v1-cannot-express-txid-only',
      'BRC-62 V1 has no txid-only format (that is the BRC-96 V2 extension). These bytes put a bare 32-byte txid where V1 expects a raw transaction. TS verdict (parse error or misparse) recorded as truth.');
  }

  // 5: mismatched per-height roots
  {
    const conflicting = bumpFor(txidB, H1, 'sib-B-conflicting'); // same height as bumpA, different root
    invalidCase('mismatched per-height roots',
      buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA(), conflicting], txs: [{ tx: A, bumpIndex: 0 }, { tx: B, bumpIndex: 1 }] }),
      'conflicting-roots-same-height',
      'Two bumps at the same block height compute different merkle roots. TS accepts the first root seen for a height and rejects any bump whose root disagrees (confirmComputedRoot).');
  }

  // 6: trailing garbage bytes
  {
    const goodHex = beefOf([['bump', bumpA()], ['raw', A]]).toHex();
    const hex = goodHex + 'deadbeef';
    let viewError = null;
    try {
      Beef.fromBinaryView(Uint8Array.from(Buffer.from(hex, 'hex')));
    } catch (e) {
      viewError = String(e.message ?? e);
    }
    const c = invalidCase('trailing garbage bytes', hex,
      'trailing-data',
      'TS has TWO parsers with different verdicts, both recorded: Beef.fromBinary/fromString is a prefix parser and silently IGNORES trailing bytes (parses + verifies valid); Beef.fromBinaryView enforces exact framing and throws. Rust implementers should match the strict (fromBinaryView) behavior for wire acceptance and note the lenient path exists in TS.',
      {});
    c.ts_from_binary_view_error = viewError;
    if (viewError == null) surprise('fromBinaryView accepted trailing garbage');
  }

  // 7: atomic prefix, subject absent from inner beef
  invalidCase('atomic subject absent',
    buildRawBeefHex({ version: BEEF_V2, bumps: [bumpA()], txs: [{ tx: A, bumpIndex: 0 }], atomicTxid: txidB }),
    'atomic-subject-missing',
    'ATOMIC_BEEF prefix names subject B but the inner beef only contains A. Parses fine; verifyValid must be false (isAtomic check on atomicTxid fails before structural checks).');

  return cases;
}

// ===========================================================================
// 4. beef_merge.json
// ===========================================================================
function genMerge() {
  const cases = [];

  function mergeCase(name, beefA, beefB, notes, check) {
    const aHex = beefA.toHex();
    const bHex = beefB.toHex();
    const merged = Beef.fromString(aHex);
    merged.mergeBeef(Beef.fromString(bHex));
    const mergedHex = merged.toHex();
    assertRoundTrip(mergedHex);
    const c = {
      name,
      beef_a_hex: aHex,
      beef_b_hex: bHex,
      expected_merged_hex: mergedHex,
      merged_verdict: {
        verify_valid: Beef.fromString(mergedHex).verifyValid(true).valid,
        bump_count: Beef.fromString(mergedHex).bumps.length,
        tx_count: Beef.fromString(mergedHex).txs.length
      },
      notes
    };
    if (check != null) check(Beef.fromString(mergedHex), c);
    cases.push(c);
  }

  // 1: full tx replaces txid-only
  mergeCase('full tx replaces txid-only',
    beefOf([['bump', bumpA()], ['raw', A], ['txidOnly', txidC]]),
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C]]),
    'beef_a knows C only by txid; beef_b carries the full tx. Merged result holds the FULL C (full data upgrades txid-only).',
    (m) => {
      const t = m.findTxid(txidC);
      if (t == null || t.isTxidOnly) surprise('merge did not upgrade txid-only C to full tx');
    });

  // 2: txid-only does NOT downgrade full tx
  mergeCase('txid-only does not replace full tx',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C]]),
    beefOf([['txidOnly', txidC]]),
    'beef_b brings only a txid-only reference for C, which beef_a already holds in full. Merge must keep the full transaction (never the reverse of case 1).',
    (m) => {
      const t = m.findTxid(txidC);
      if (t == null || t.isTxidOnly) surprise('merge downgraded full C to txid-only');
    });

  // 3: bump dedup by (height, root) with leaf combine
  {
    const pairAB_markA = bumpForPair(txidA, txidB, H1, { markA: true, markB: false });
    const pairAB_markB = bumpForPair(txidA, txidB, H1, { markA: false, markB: true });
    mergeCase('bump dedup by height and root',
      beefOf([['bump', pairAB_markA], ['raw', A]]),
      beefOf([['bump', pairAB_markB], ['raw', B]]),
      'Both beefs carry a bump for the same 2-leaf block (same height, same computed root), each proving a different leaf. Merge must dedupe to ONE bump (combined leaves) and re-derive both txs\' bump indexes to it.',
      (m, c) => {
        if (m.bumps.length !== 1) surprise(`bump dedup produced ${m.bumps.length} bumps`);
        c.merged_verdict.bump_leaf_txids = m.bumps[0].path[0].filter(l => l.txid === true).map(l => l.hash);
      });
  }

  // 4: overlapping txs
  mergeCase('overlapping transaction graphs',
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C]]),
    beefOf([['bump', bumpA()], ['raw', A], ['raw', C2]]),
    'Both beefs share proven ancestor A (same bump). Merged beef holds one copy of A + one bump + both children, serialized in sorted order.');

  return cases;
}

// ===========================================================================
// 5. beef_spend_closure.json — the #352 regression shape
// ===========================================================================
function genSpendClosure() {
  const cases = [];

  // Parent simulates a minted PushDrop token: OP_RETURN data output + P2PKH output.
  const P = rootTx(5, { sats: 1200, keyIndex: 5, extraOpReturn: 'paragon-token-mint' });
  const txidP = P.id('hex');
  const bumpP = bumpFor(txidP, H1, 'sib-P');

  function record(name, buildInput, subjectTx, notes, { graphRoute = null } = {}) {
    const inputBeef = buildInput();
    const inputHex = inputBeef.toHex();
    const subject = subjectTx.id('hex');
    let expected, error;
    try {
      expected = toHex(Beef.fromString(inputHex).toUint8ArrayAtomic(subject));
    } catch (e) {
      error = String(e.message ?? e);
    }
    const c = { name, input_beef_hex: inputHex, subject_txid: subject, notes };
    if (expected != null) {
      assertRoundTrip(expected, { atomicSubject: subject });
      c.expected_atomic_hex = expected;
      const inner = Beef.fromString(expected);
      c.expected_verdict = {
        is_atomic: inner.isAtomic(subject),
        verify_valid: inner.verifyValid(false).valid,
        bump_count: inner.bumps.length,
        tx_count: inner.txs.length
      };
    } else {
      c.expected_error = error;
    }
    // Cross-check the Transaction-graph route (mergeTransaction of a Transaction
    // whose inputs carry sourceTransaction/merklePath), the exact #352 call shape.
    if (graphRoute != null) {
      let graphHex = null, graphError = null;
      try {
        const gb = new Beef();
        gb.mergeTransaction(graphRoute());
        graphHex = toHex(gb.toUint8ArrayAtomic(subject));
      } catch (e) {
        graphError = String(e.message ?? e);
      }
      c.graph_route = graphError != null
        ? { error: graphError }
        : { matches_expected: graphHex === c.expected_atomic_hex, ...(graphHex === c.expected_atomic_hex ? {} : { atomic_hex: graphHex }) };
      if (graphError == null && graphHex !== c.expected_atomic_hex) {
        surprise(`spend-closure "${name}": mergeTransactionGraph route produced different bytes than merge-raw route`);
      }
    }
    cases.push(c);
    return c;
  }

  // 1: parent proven
  {
    const child = spendTx(P, { vout: 1, sats: 1100, keyIndex: 6 });
    record('parent proven with bump',
      () => beefOf([['bump', bumpP], ['raw', P], ['raw', child]]),
      child,
      'Parent is a minted-token-shaped tx (OP_RETURN + P2PKH outputs) with a BUMP; child spends parent P2PKH output (vout 1). Expected Atomic BEEF for the child = {parent, child} closure. graph_route replays the same expectation through Transaction.sourceTransaction/merklePath + mergeTransaction (the #352 call shape).',
      {
        graphRoute: () => {
          const p = rootTx(5, { sats: 1200, keyIndex: 5, extraOpReturn: 'paragon-token-mint' });
          p.merklePath = bumpFor(p.id('hex'), H1, 'sib-P');
          const ch = spendTx(p, { vout: 1, sats: 1100, keyIndex: 6 });
          ch.inputs[0].sourceTransaction = p;
          return ch;
        }
      });
  }

  // 2: parent unproven, grandparent proven (3-deep)
  {
    const G = rootTx(6, { sats: 2000, keyIndex: 6 });
    const bumpG = bumpFor(G.id('hex'), H2, 'sib-G');
    const P2 = spendTx(G, { vout: 0, sats: 1500, keyIndex: 5 });
    const child2 = spendTx(P2, { vout: 0, sats: 1400, keyIndex: 6 });
    record('parent unproven grandparent proven',
      () => beefOf([['bump', bumpG], ['raw', G], ['raw', P2], ['raw', child2]]),
      child2,
      '3-deep chain: grandparent proven by BUMP, parent unproven, child spends parent. Closure must include all three transactions and the single bump.',
      {
        graphRoute: () => {
          const g = rootTx(6, { sats: 2000, keyIndex: 6 });
          g.merklePath = bumpFor(g.id('hex'), H2, 'sib-G');
          const p2 = spendTx(g, { vout: 0, sats: 1500, keyIndex: 5 });
          p2.inputs[0].sourceTransaction = g;
          const ch = spendTx(p2, { vout: 0, sats: 1400, keyIndex: 6 });
          ch.inputs[0].sourceTransaction = p2;
          return ch;
        }
      });
  }

  // 3: parent missing entirely
  {
    const child = spendTx(P, { vout: 1, sats: 1100, keyIndex: 6 });
    const c = record('parent missing',
      () => beefOf([['raw', child]]),
      child,
      'TS behavior captured as truth: toBinaryAtomic does NOT error when the subject\'s parent is absent — it emits an atomic BEEF containing only the child (the dependency walk simply finds nothing to include). The result claims atomicity (isAtomic=true: every contained tx is in the subject\'s graph) but verifyValid=false (missing input, no proof). Rust must not treat toBinaryAtomic success as proof of a complete closure. graph_route: mergeTransaction of a child with no sourceTransaction likewise merges only the child.',
      {
        graphRoute: () => {
          const p = rootTx(5, { sats: 1200, keyIndex: 5, extraOpReturn: 'paragon-token-mint' });
          const ch = spendTx(p, { vout: 1, sats: 1100, keyIndex: 6 });
          return ch; // no sourceTransaction, no merklePath
        }
      });
    if (c.expected_error != null) {
      surprise(`parent-missing atomic serialization errored: ${c.expected_error}`);
    }
  }

  return cases;
}

// ===========================================================================
// Emission
// ===========================================================================
const corpora = [
  {
    file: 'beef_atomic_closure.json',
    id: 'transaction.beef.atomic_closure',
    name: 'BRC-95 Atomic BEEF dependency-closure serialization',
    description: 'Golden vectors for Beef.toBinaryAtomic(subject): closure derivation, unrelated-tx dropping, bump pruning/reindexing, unsorted inputs, txid-only subjects.',
    cases: genAtomicClosure()
  },
  {
    file: 'beef_sort_order.json',
    id: 'transaction.beef.sort_order',
    name: 'BEEF sortTxs ordering and partition results',
    description: 'Golden vectors for Beef.sortTxs(): post-sort serialization bytes plus the exact partition result (missingInputs/notValid/txidOnly/valid/withMissingInputs).',
    cases: genSortOrder()
  },
  {
    file: 'beef_invalid.json',
    id: 'transaction.beef.invalid',
    name: 'BEEF negative corpus (structural rejection)',
    description: 'Hand-built invalid BEEF bytes with the TS verdict recorded as truth (parse error vs parse-but-invalid vs accepted). expect_reject_rule names the rule a conforming implementation should enforce.',
    cases: genInvalid()
  },
  {
    file: 'beef_merge.json',
    id: 'transaction.beef.merge',
    name: 'BEEF merge semantics',
    description: 'Golden vectors for Beef.mergeBeef: full-tx-vs-txid-only precedence, bump dedup by (height, root) with leaf combining and index re-derivation, overlapping graphs.',
    cases: genMerge()
  },
  {
    file: 'beef_spend_closure.json',
    id: 'transaction.beef.spend_closure',
    name: 'Spend closure (rust-mpc#352 regression shape)',
    description: 'Minted-token-shaped parent + child spend: expected Atomic BEEF for the child across proven / chain-to-proven / missing-parent cases, with the Transaction-graph merge route cross-checked.',
    cases: genSpendClosure()
  }
];

// --- validate counts & determinism guard: regenerate expected data is pure ---
for (const c of corpora) {
  console.log(`${c.file}: ${c.cases.length} cases`);
}

const RUST_SDK_DIR = '/Users/donot/PARAGON/PARAGON-code/bsv-rust-sdk/test-vectors';
const TOOLBOX_DIR = '/Users/donot/PARAGON/PARAGON-code/rust-wallet-toolbox/conformance/vectors/beef';
fs.mkdirSync(TOOLBOX_DIR, { recursive: true });

const meta = {
  generator: GENERATOR,
  sdk_version: SDK_VERSION,
  generated_from: 'TS @bsv/sdk (normative)',
  brc_refs: BRC_REFS
};

for (const corpus of corpora) {
  // bsv-rust-sdk house shape: keep it flat-ish; metadata header + cases array.
  const rustSdkShape = {
    description: corpus.description,
    ...meta,
    cases: corpus.cases
  };
  fs.writeFileSync(path.join(RUST_SDK_DIR, corpus.file), JSON.stringify(rustSdkShape, null, 2) + '\n');

  // toolbox conformance house shape (id / name / brc / reference_impl / vectors with per-vector ids)
  const toolboxShape = {
    id: corpus.id,
    name: corpus.name,
    brc: BRC_REFS,
    version: '1.0.0',
    reference_impl: `@bsv/sdk@${SDK_VERSION}`,
    parity_class: 'required',
    ...meta,
    vectors: corpus.cases.map((c, i) => ({ id: `${corpus.id}.${i + 1}`, ...c }))
  };
  fs.writeFileSync(path.join(TOOLBOX_DIR, corpus.file), JSON.stringify(toolboxShape, null, 2) + '\n');
}

fs.writeFileSync(path.join(TOOLBOX_DIR, 'SURPRISES.json'), JSON.stringify({ ...meta, surprises }, null, 2) + '\n');
console.log('\nAll corpora written.');
console.log('Surprises:', surprises.length === 0 ? '(none)' : '');
for (const s of surprises) console.log(' -', s);
