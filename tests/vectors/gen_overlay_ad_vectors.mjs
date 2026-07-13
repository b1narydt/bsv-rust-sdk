import { OverlayAdminTokenTemplate, ProtoWallet, PrivateKey, LockingScript, PushDrop, Utils } from '@bsv/sdk'
const key = new PrivateKey('77'.repeat(32), 16)
const wallet = new ProtoWallet(key)
const tmpl = new OverlayAdminTokenTemplate(wallet)

for (const proto of ['SLAP', 'SHIP']) {
  const s = await tmpl.lock(proto, 'https://overlay.example.com', 'ls_test_service')
  console.log(`${proto}_SCRIPT: ${s.toHex()}`)
  const d = OverlayAdminTokenTemplate.decode(LockingScript.fromHex(s.toHex()))
  console.log(`${proto}_TS_DECODE: ${JSON.stringify(d)}`)
  const raw = PushDrop.decode(LockingScript.fromHex(s.toHex()))
  console.log(`${proto}_FIELD_COUNT: ${raw.fields.length}`)
  console.log(`${proto}_FIELDS: ${JSON.stringify(raw.fields.map(f => Utils.toHex(f)))}`)
}
const { publicKey } = await wallet.getPublicKey({ identityKey: true })
console.log('IDENTITY_KEY:', publicKey)
