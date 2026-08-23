// Generates the auth-certificate cross-language golden vectors with the exact
// @bsv/sdk 2.4.1 implementation supplied as argv[2]. The committed JSON is all
// Rust tests need; Node is only required when intentionally regenerating it.

import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { writeFileSync } from 'node:fs'

const sdkPath = process.argv[2]
if (sdkPath == null) {
  throw new Error('usage: node tests/vectors/gen_auth_certificate_interop.mjs /path/to/@bsv/sdk/package')
}

const require = createRequire(import.meta.url)
const sdkPackage = require(resolve(sdkPath, 'package.json'))
if (sdkPackage.name !== '@bsv/sdk' || sdkPackage.version !== '2.4.1') {
  throw new Error(`expected @bsv/sdk 2.4.1, got ${sdkPackage.name} ${sdkPackage.version}`)
}
const { Certificate, PrivateKey, ProtoWallet, VerifiableCertificate, Utils } = require(resolve(sdkPath))

const privateKey = value => PrivateKey.fromHex(value.toString(16).padStart(64, '0'))
const identityKey = async wallet => (await wallet.getPublicKey({ identityKey: true })).publicKey
const utf8Bytes = text => Array.from(Buffer.from(text, 'utf8'))

const senderPrivateKey = privateKey(1)
const receiverPrivateKey = privateKey(2)
const certifierPrivateKey = privateKey(3)
const senderWallet = new ProtoWallet(senderPrivateKey)
const receiverWallet = new ProtoWallet(receiverPrivateKey)
const certifierWallet = new ProtoWallet(certifierPrivateKey)
const senderPublicKey = await identityKey(senderWallet)
const receiverPublicKey = await identityKey(receiverWallet)
const certifierPublicKey = await identityKey(certifierWallet)

const type = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64')
const serialNumber = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32)).toString('base64')
const fields = {
  zeta: Buffer.from('ts-zeta').toString('base64'),
  alpha: Buffer.from('ts-alpha').toString('base64'),
  middle: Buffer.from('ts-middle').toString('base64')
}
const revocationOutpoint = `${'cd'.repeat(32)}.7`
const certificate = new Certificate(
  type,
  serialNumber,
  senderPublicKey,
  certifierPublicKey,
  revocationOutpoint,
  fields
)
await certificate.sign(certifierWallet)
const verifiable = VerifiableCertificate.fromCertificate(certificate, {
  zeta: Buffer.from('ts-keyring-zeta').toString('base64'),
  alpha: Buffer.from('ts-keyring-alpha').toString('base64'),
  middle: Buffer.from('ts-keyring-middle').toString('base64')
})
const certificates = [verifiable]
const preimageUtf8 = JSON.stringify(certificates)
const preimageBytes = utf8Bytes(preimageUtf8)
const nonce = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo='
const sessionNonce = 'dHMtc2Vzc2lvbi1ub25jZS0wMDAwMDAwMDA='
const keyId = `${nonce} ${sessionNonce}`
const { signature } = await senderWallet.createSignature({
  data: preimageBytes,
  protocolID: [2, 'auth message signature'],
  keyID: keyId,
  counterparty: receiverPublicKey
})
const tsMessage = {
  version: '0.1',
  messageType: 'certificateResponse',
  identityKey: senderPublicKey,
  nonce,
  yourNonce: sessionNonce,
  initialNonce: 'dHMtaW5pdGlhbC1ub25jZS0wMDAwMDAwMA==',
  certificates,
  signature
}
const tsSignatureCheck = await receiverWallet.verifySignature({
  data: preimageBytes,
  signature,
  protocolID: [2, 'auth message signature'],
  keyID: keyId,
  counterparty: senderPublicKey
})
if (!tsSignatureCheck.valid) throw new Error('TS failed to verify its generated signature')

const emptyPreimageUtf8 = JSON.stringify([])
const emptyPreimageBytes = utf8Bytes(emptyPreimageUtf8)
const emptyNonce = 'RU1QVFlDRVJUSUZJQ0FURVJFU1BPTlNFISE='
const emptyKeyId = `${emptyNonce} ${sessionNonce}`
const { signature: emptySignature } = await senderWallet.createSignature({
  data: emptyPreimageBytes,
  protocolID: [2, 'auth message signature'],
  keyID: emptyKeyId,
  counterparty: receiverPublicKey
})
const emptyTsMessage = {
  version: '0.1',
  messageType: 'certificateResponse',
  identityKey: senderPublicKey,
  nonce: emptyNonce,
  yourNonce: sessionNonce,
  initialNonce: 'dHMtaW5pdGlhbC1ub25jZS0wMDAwMDAwMA==',
  certificates: [],
  signature: emptySignature
}
const emptyTsSignatureCheck = await receiverWallet.verifySignature({
  data: emptyPreimageBytes,
  signature: emptySignature,
  protocolID: [2, 'auth message signature'],
  keyID: emptyKeyId,
  counterparty: senderPublicKey
})
if (!emptyTsSignatureCheck.valid) throw new Error('TS failed to verify its empty response signature')

// Cover every omission combination for the three optional Certificate members.
const optionalFieldSerializations = []
for (let mask = 0; mask < 8; mask++) {
  const candidate = new VerifiableCertificate(
    type,
    serialNumber,
    senderPublicKey,
    certifierPublicKey,
    (mask & 1) === 0 ? undefined : revocationOutpoint,
    (mask & 2) === 0 ? undefined : fields,
    { middle: Buffer.from('ts-keyring').toString('base64') },
    (mask & 4) === 0 ? undefined : certificate.signature
  )
  optionalFieldSerializations.push({ mask, json: JSON.stringify(candidate) })
}

const scriptDir = dirname(fileURLToPath(import.meta.url))
const repositoryRoot = resolve(scriptDir, '..', '..')
const rustVector = async empty => {
  const args = ['run', '--quiet', '--example', 'generate_auth_certificate_rust_vector', '--features', 'serde']
  if (empty) args.push('--', '--empty')
  const rust = spawnSync('cargo', args, { cwd: repositoryRoot, encoding: 'utf8' })
  if (rust.status !== 0) {
    throw new Error(`Rust vector generator failed:\n${rust.stderr}`)
  }
  const vector = JSON.parse(rust.stdout.trim())
  const signatureCheck = await new ProtoWallet(PrivateKey.fromHex(vector.receiverPrivateKey))
    .verifySignature({
      data: vector.preimageBytes,
      signature: vector.message.signature,
      protocolID: [2, 'auth message signature'],
      keyID: vector.keyId,
      counterparty: vector.senderPublicKey
    })
  if (!signatureCheck.valid) throw new Error('TS 2.4.1 rejected the Rust-produced signature')
  vector.verifiedByTypeScript = true
  return vector
}
const rustToTypeScript = await rustVector(false)
const emptyRustToTypeScript = await rustVector(true)

const fixture = {
  sdk: { name: sdkPackage.name, version: sdkPackage.version },
  typeScriptToRust: {
    producer: '@bsv/sdk 2.4.1',
    senderPrivateKey: senderPrivateKey.toHex(),
    senderPublicKey,
    receiverPrivateKey: receiverPrivateKey.toHex(),
    receiverPublicKey,
    keyId,
    preimageBytes,
    preimageHex: Buffer.from(preimageBytes).toString('hex'),
    preimageUtf8,
    message: tsMessage
  },
  emptyTypeScriptToRust: {
    producer: '@bsv/sdk 2.4.1',
    senderPrivateKey: senderPrivateKey.toHex(),
    senderPublicKey,
    receiverPrivateKey: receiverPrivateKey.toHex(),
    receiverPublicKey,
    keyId: emptyKeyId,
    preimageBytes: emptyPreimageBytes,
    preimageHex: Buffer.from(emptyPreimageBytes).toString('hex'),
    preimageUtf8: emptyPreimageUtf8,
    message: emptyTsMessage
  },
  rustToTypeScript,
  emptyRustToTypeScript,
  optionalFieldSerializations
}

const fixturePath = resolve(scriptDir, 'auth_certificate_interop.json')
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`)
console.log(`wrote ${fixturePath}; nonempty and empty TS<->Rust signatures valid`)
