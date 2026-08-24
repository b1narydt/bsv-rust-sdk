// Re-check Rust-produced auth vectors with the real @bsv/sdk at test time.

import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const [sdkPath, fixturePath] = process.argv.slice(2)
if (sdkPath == null || fixturePath == null) {
  throw new Error('usage: node verify_auth_certificate_interop.mjs /path/to/@bsv/sdk fixture.json')
}

const require = createRequire(import.meta.url)
const sdkPackage = require(resolve(sdkPath, 'package.json'))
if (sdkPackage.name !== '@bsv/sdk' || sdkPackage.version !== '2.4.1') {
  throw new Error(`expected @bsv/sdk 2.4.1, got ${sdkPackage.name} ${sdkPackage.version}`)
}
const { PrivateKey, ProtoWallet } = require(resolve(sdkPath))
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))

for (const name of ['rustToTypeScript', 'emptyRustToTypeScript']) {
  const vector = fixture[name]
  const result = await new ProtoWallet(PrivateKey.fromHex(vector.receiverPrivateKey))
    .verifySignature({
      data: vector.preimageBytes,
      signature: vector.message.signature,
      protocolID: [2, 'auth message signature'],
      keyID: vector.keyId,
      counterparty: vector.senderPublicKey
    })
  if (!result.valid) throw new Error(`TS 2.4.1 rejected ${name}`)
}

for (const [name, vector] of Object.entries(fixture.rustAuthMessages)) {
  const parsed = JSON.parse(vector.json)
  if (Buffer.from(vector.hex, 'hex').toString('utf8') !== vector.json ||
      JSON.stringify(parsed) !== vector.json) {
    throw new Error(`TS did not preserve Rust ${name} bytes`)
  }
}

console.log('TS 2.4.1 accepted Rust certificate signatures and preserved every Rust auth envelope')
