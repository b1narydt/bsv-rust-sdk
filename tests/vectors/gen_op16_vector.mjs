import { PushDrop, ProtoWallet, PrivateKey, LockingScript, Utils } from '@bsv/sdk'
const wallet = new ProtoWallet(new PrivateKey('55'.repeat(32), 16))
const pd = new PushDrop(wallet)
// [16] encodes to OP_16 (0x60). Does TS's own decoder read it back?
const s = await pd.lock([[16], [15]], [2, 'did revocation'], 'k', 'self', false, false)
console.log('TS_SCRIPT      :', s.toHex())
const d = PushDrop.decode(LockingScript.fromHex(s.toHex()))
console.log('TS_ROUNDTRIP   :', JSON.stringify(d.fields.map(f => Utils.toHex(f))))
console.log('EXPECTED       : ["10","0f"]   (i.e. [16],[15])')
