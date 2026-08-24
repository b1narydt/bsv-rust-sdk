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
const { Certificate, Peer, PrivateKey, ProtoWallet, VerifiableCertificate, Utils } = require(resolve(sdkPath))

// Keep the real Peer constructors while making their nonce bytes reproducible.
// The SDK's auth helpers retain this CommonJS export object, so replacing its
// default function here affects only the fixture process, not production code.
const randomModule = require(resolve(sdkPath, 'dist/cjs/src/primitives/Random.js'))
let deterministicRandomCall = 0
randomModule.default = length => {
  const start = deterministicRandomCall++ * 32
  return Array.from({ length }, (_, index) => (start + index) & 0xff)
}

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

// Exercise Peer.processInitialRequest itself, not a hand-built object. When a
// real embedded certificate request has no wallet matches, TS assigns the []
// result to `certificatesToInclude`, so JSON serialization retains the member.
const sentDuringInitialRequest = []
const emptyListWallet = new Proxy(receiverWallet, {
  get (target, property, receiver) {
    if (property === 'listCertificates') {
      return async () => ({ totalCertificates: 0, certificates: [] })
    }
    const value = Reflect.get(target, property, receiver)
    return typeof value === 'function' ? value.bind(target) : value
  }
})
const captureTransport = {
  onData: async () => {},
  send: async message => { sentDuringInitialRequest.push(message) }
}

// Exercise Peer.initiateHandshake itself with constructor defaults. The
// transport deliberately rejects after capturing the request so the private
// handshake waiter cannot keep the fixture generator alive.
const sentDuringHandshakeInitiation = []
const stopAfterInitialRequest = new Error('fixture captured initialRequest')
const initialRequestTransport = {
  onData: async () => {},
  send: async message => {
    sentDuringHandshakeInitiation.push(message)
    throw stopAfterInitialRequest
  }
}
const initialRequestPeer = new Peer(senderWallet, initialRequestTransport)
try {
  await initialRequestPeer.initiateHandshake(receiverPublicKey)
  throw new Error('TS initiateHandshake unexpectedly completed')
} catch (error) {
  if (error !== stopAfterInitialRequest) throw error
}
const defaultInitialRequest = sentDuringHandshakeInitiation[0]
if (defaultInitialRequest?.messageType !== 'initialRequest') {
  throw new Error('TS did not emit the expected initialRequest')
}

const shapePeer = new Peer(emptyListWallet, captureTransport)
await shapePeer.processInitialRequest({
  version: '0.1',
  messageType: 'initialRequest',
  identityKey: senderPublicKey,
  initialNonce: sessionNonce,
  requestedCertificates: {
    certifiers: [certifierPublicKey],
    types: { [type]: ['name'] }
  }
})
const emptyInitialResponse = sentDuringInitialRequest[0]
if (emptyInitialResponse?.messageType !== 'initialResponse') {
  throw new Error('TS did not emit the expected initialResponse')
}
const emptyInitialResponseShape = {
  hasCertificatesMember: Object.hasOwn(emptyInitialResponse, 'certificates'),
  serializedMember: JSON.stringify({ certificates: emptyInitialResponse.certificates })
}
const sentDuringDefaultInitialRequest = []
const defaultResponseTransport = {
  onData: async () => {},
  send: async message => { sentDuringDefaultInitialRequest.push(message) }
}
const defaultResponsePeer = new Peer(receiverWallet, defaultResponseTransport)
await defaultResponsePeer.processInitialRequest(defaultInitialRequest)
const defaultInitialResponse = sentDuringDefaultInitialRequest[0]
if (defaultInitialResponse?.messageType !== 'initialResponse') {
  throw new Error('TS did not emit the expected default initialResponse')
}
const exactWireMessage = message => {
  const json = JSON.stringify(message)
  return {
    json,
    hex: Buffer.from(json, 'utf8').toString('hex'),
    keys: Object.keys(JSON.parse(json))
  }
}

// Capture the remaining three envelopes from real Peer methods against a
// pre-authenticated session. This records actual member presence and order,
// including the fact that `general` has no `initialNonce`.
const sentAfterAuthentication = []
const authenticatedCaptureTransport = {
  onData: async () => {},
  send: async message => { sentAfterAuthentication.push(message) }
}
const authenticatedPeer = new Peer(senderWallet, authenticatedCaptureTransport)
authenticatedPeer.sessionManager.addSession({
  isAuthenticated: true,
  sessionNonce,
  peerNonce: nonce,
  peerIdentityKey: receiverPublicKey,
  lastUpdate: Date.now(),
  certificatesRequired: false,
  certificatesValidated: true
})
const standaloneRequest = {
  certifiers: [certifierPublicKey],
  types: { [type]: [] }
}
await authenticatedPeer.toPeer([9, 8, 7], receiverPublicKey)
await authenticatedPeer.requestCertificates(standaloneRequest, receiverPublicKey)
await authenticatedPeer.sendCertificateResponse(receiverPublicKey, certificates)
const [generalMessage, certificateRequestMessage, certificateResponseMessage] = sentAfterAuthentication
if (generalMessage?.messageType !== 'general' ||
    certificateRequestMessage?.messageType !== 'certificateRequest' ||
    certificateResponseMessage?.messageType !== 'certificateResponse') {
  throw new Error('TS did not emit the expected authenticated message sequence')
}
const typeScriptAuthMessages = {
  initialRequest: exactWireMessage(defaultInitialRequest),
  initialResponse: exactWireMessage(defaultInitialResponse),
  initialResponseWithEmptyCertificates: exactWireMessage(emptyInitialResponse),
  certificateRequest: exactWireMessage(certificateRequestMessage),
  certificateResponse: exactWireMessage(certificateResponseMessage),
  general: exactWireMessage(generalMessage)
}
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

const decryptedFieldSerializations = [undefined, {
  zeta: 'ts-zeta',
  alpha: 'ts-alpha',
  middle: 'ts-middle'
}].map(decryptedFields => {
  const candidate = new VerifiableCertificate(
    type,
    serialNumber,
    senderPublicKey,
    certifierPublicKey,
    revocationOutpoint,
    fields,
    { middle: Buffer.from('ts-keyring').toString('base64') },
    certificate.signature,
    decryptedFields
  )
  return JSON.stringify(candidate)
})

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

// Real two-Peer behavioral observation for the certificate gate. This is a
// Layer-1 vector: a conforming peer can observe both the standalone [] frame
// and whether a general payload is delivered before validation succeeds.
class LinkedTransport {
  constructor () {
    this.sent = []
  }

  async onData (callback) { this.callback = callback }
  async send (message) {
    this.sent.push(message)
    await this.peer.callback(message)
  }
}
const transportA = new LinkedTransport()
const transportB = new LinkedTransport()
transportA.peer = transportB
transportB.peer = transportA
const emptyReceiverWallet = new Proxy(receiverWallet, {
  get (target, property, receiver) {
    if (property === 'listCertificates') {
      return async () => ({ totalCertificates: 0, certificates: [] })
    }
    const value = Reflect.get(target, property, receiver)
    return typeof value === 'function' ? value.bind(target) : value
  }
})
const behaviorPeerA = new Peer(senderWallet, transportA)
const behaviorPeerB = new Peer(emptyReceiverWallet, transportB)
await Promise.all([behaviorPeerA.ready, behaviorPeerB.ready])
await behaviorPeerA.initiateHandshake(receiverPublicKey)
const behaviorSession = await behaviorPeerA.sessionManager.getSession(receiverPublicKey)
behaviorSession.certificatesRequired = true
behaviorSession.certificatesValidated = false
await behaviorPeerA.sessionManager.updateSession(behaviorSession)
const receivedEmptySets = []
behaviorPeerA.listenForCertificatesReceived(async (_identity, received) => {
  receivedEmptySets.push(received)
})
await behaviorPeerA.requestCertificates(standaloneRequest, receiverPublicKey)
const standaloneEmptyResponses = transportB.sent
  .filter(message => message.messageType === 'certificateResponse' && message.certificates?.length === 0)
const emptyResponseLeftGatePending = behaviorSession.certificatesValidated !== true

let generalDeliveries = 0
behaviorPeerA.listenForGeneralMessages(async () => { generalDeliveries++ })
const blockedGeneral = behaviorPeerB.toPeer([4, 5, 6], senderPublicKey)
let waitRegistered = false
for (let attempt = 0; attempt < 100; attempt++) {
  if (behaviorPeerA.certificateValidationPromises.has(behaviorSession.sessionNonce)) {
    waitRegistered = true
    break
  }
  await Promise.resolve()
}
if (!waitRegistered || generalDeliveries !== 0) {
  throw new Error('TS certificate gate did not retain the general message before validation')
}
behaviorSession.certificatesValidated = true
await behaviorPeerA.sessionManager.updateSession(behaviorSession)
behaviorPeerA.resolveCertificateValidation(behaviorSession.sessionNonce)
await blockedGeneral
const certificateGateBehavior = {
  standaloneEmptyResponseSent: standaloneEmptyResponses.length === 1,
  emptyResponseListenerFired: receivedEmptySets.length === 1 && receivedEmptySets[0].length === 0,
  emptyResponseLeftGatePending,
  generalWaitRegistered: waitRegistered,
  generalDeliveredBeforeValidation: false,
  generalDeliveredAfterValidation: generalDeliveries === 1
}

const rustHandshakeProcess = spawnSync(
  'cargo',
  ['run', '--quiet', '--example', 'generate_auth_certificate_rust_vector', '--features', 'serde', '--', '--handshake'],
  { cwd: repositoryRoot, encoding: 'utf8' }
)
if (rustHandshakeProcess.status !== 0) {
  throw new Error(`Rust handshake vector generator failed:\n${rustHandshakeProcess.stderr}`)
}
const rustAuthMessages = JSON.parse(rustHandshakeProcess.stdout.trim())
const expectedAuthMessageKeys = {
  initialRequest: ['version', 'messageType', 'identityKey', 'initialNonce', 'requestedCertificates'],
  initialResponse: [
    'version',
    'messageType',
    'identityKey',
    'initialNonce',
    'yourNonce',
    'requestedCertificates',
    'signature'
  ],
  initialResponseWithEmptyCertificates: [
    'version',
    'messageType',
    'identityKey',
    'initialNonce',
    'yourNonce',
    'certificates',
    'requestedCertificates',
    'signature'
  ],
  certificateRequest: [
    'version',
    'messageType',
    'identityKey',
    'nonce',
    'initialNonce',
    'yourNonce',
    'requestedCertificates',
    'signature'
  ],
  certificateResponse: [
    'version',
    'messageType',
    'identityKey',
    'nonce',
    'initialNonce',
    'yourNonce',
    'certificates',
    'signature'
  ],
  general: ['version', 'messageType', 'identityKey', 'nonce', 'yourNonce', 'payload', 'signature']
}
for (const [name, vector] of Object.entries(rustAuthMessages)) {
  const parsed = JSON.parse(vector.json)
  const bytesAsJson = Buffer.from(vector.hex, 'hex').toString('utf8')
  if (bytesAsJson !== vector.json || JSON.stringify(parsed) !== vector.json) {
    throw new Error(`TS did not preserve Rust ${name} bytes`)
  }
  const expectedKeys = expectedAuthMessageKeys[name]
  if (JSON.stringify(Object.keys(parsed)) !== JSON.stringify(expectedKeys)) {
    throw new Error(`Rust ${name} key order does not match TS ${parsed.messageType}`)
  }
  if ((parsed.messageType === 'initialRequest' || parsed.messageType === 'initialResponse') &&
      JSON.stringify(parsed.requestedCertificates) !== '{"certifiers":[],"types":{}}') {
    throw new Error(`Rust ${name} omitted the TS default requestedCertificates set`)
  }
  vector.keys = Object.keys(parsed)
  vector.verifiedByTypeScript = true
}

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
  typeScriptAuthMessages,
  rustAuthMessages,
  certificateGateBehavior,
  emptyInitialResponseShape,
  optionalFieldSerializations,
  decryptedFieldSerializations
}

const fixturePath = resolve(scriptDir, 'auth_certificate_interop.json')
writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`)
console.log(`wrote ${fixturePath}; nonempty and empty TS<->Rust signatures valid`)
