// TS-SDK side of the PushDrop parity check (@bsv/sdk 2.0.13).
// Emits the canonical locking scripts + decoded fields so the Rust port can be
// diffed byte-for-byte against them.
import { PushDrop, ProtoWallet, PrivateKey, LockingScript, Utils } from '@bsv/sdk'

const key = new PrivateKey('55'.repeat(32), 16)
const wallet = new ProtoWallet(key)
const pd = new PushDrop(wallet)

const PROTOCOL = [2, 'did revocation']
const KEY_ID = 'serial-1'
const CPTY = 'self'

// Field set deliberately includes the minimal-encoding trigger cases:
//   [0x05]  -> TS emits OP_5   (0x55)
//   [0x00]  -> TS emits OP_0   (0x00)
//   [0x81]  -> TS emits OP_1NEGATE (0x4f)
//   []      -> TS emits OP_0
// plus an ordinary multi-byte field.
const fields = [
  Utils.toArray('did:revocation', 'utf8'),
  [0x05],
  [0x81],
  Utils.toArray('abc', 'utf8'),
]

const show = (label, v) => console.log(`${label}: ${v}`)

// 1. Default lock (includeSignature = true, as TS defaults).
const withSig = await pd.lock(fields.map(f => [...f]), PROTOCOL, KEY_ID, CPTY)
show('TS_LOCK_WITH_SIG', withSig.toHex())

// 2. lock with includeSignature = false — the closest analogue of what the Rust
//    port actually builds (no appended signature field).
const noSig = await pd.lock(fields.map(f => [...f]), PROTOCOL, KEY_ID, CPTY, false, false)
show('TS_LOCK_NO_SIG', noSig.toHex())

// 3. The derived locking pubkey TS uses (BRC-42 child key, NOT the raw key).
const { publicKey } = await wallet.getPublicKey({ protocolID: PROTOCOL, keyID: KEY_ID, counterparty: CPTY })
show('TS_DERIVED_PUBKEY', publicKey)
show('TS_RAW_PUBKEY', key.toPublicKey().toString())

// 4. TS decode of its own no-sig script — the field list Rust must reproduce.
const dec = PushDrop.decode(LockingScript.fromHex(noSig.toHex()))
show('TS_DECODE_FIELD_COUNT', dec.fields.length)
dec.fields.forEach((f, i) => show(`TS_DECODE_FIELD_${i}`, Utils.toHex(f)))
