#!/usr/bin/env node

import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const EXPECTED_PACKAGE = '@bsv/sdk'
const EXPECTED_VERSION = '2.4.1'
const sdkRoot = resolve(process.env.BSV_TS_SDK_ROOT ?? '/private/tmp/tscheck2/package')
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const outputDir = join(repoRoot, 'testdata', 'wallet')

const packageJson = JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8'))
assert.equal(packageJson.name, EXPECTED_PACKAGE, `expected ${EXPECTED_PACKAGE}`)
assert.equal(packageJson.version, EXPECTED_VERSION, `expected ${EXPECTED_VERSION}`)

const substratesDir = join(sdkRoot, 'dist', 'esm', 'src', 'wallet', 'substrates')
const { default: WalletWireTransceiver } = await import(
  pathToFileURL(join(substratesDir, 'WalletWireTransceiver.js'))
)
const { default: WalletWireProcessor } = await import(
  pathToFileURL(join(substratesDir, 'WalletWireProcessor.js'))
)

const TYPE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0ZXN0LXR5cGU='
const SERIAL = 'AAAAAAAAAAAAAAAAAAB0ZXN0LXNlcmlhbC1udW1iZXI='
const SUBJECT = '025ad43a22ac38d0bc1f8bacaabb323b5d634703b7a774c4268f6a09e4ddf79097'
const CERTIFIER = '0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1'
const VERIFIER = '03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee'
const OUTPOINT = 'aec245f27b7640c8b1865045107731bfb848115c573f7da38166074b1c9e475d.0'
const SIGNATURE =
  '3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a'

function hex(bytes) {
  return Buffer.from(bytes).toString('hex')
}

async function writeVector(name, json, wire) {
  const payload = { json, wire: hex(wire) }
  await writeFile(join(outputDir, `${name}.json`), `${JSON.stringify(payload, null, 2)}\n`)
}

async function captureRequest(method, args) {
  let request
  const rejectingWire = {
    async transmitToWalletUint8Array(frame) {
      request = Uint8Array.from(frame)
      // A valid empty WalletError frame. The request has already been captured.
      return Uint8Array.from([1, 0, 0])
    }
  }
  const transceiver = new WalletWireTransceiver(rejectingWire)
  await assert.rejects(transceiver[method](args))
  assert.ok(request, `${method} did not transmit a request`)
  return request
}

const acquireFields = {
  type: TYPE,
  certifier: CERTIFIER,
  acquisitionProtocol: 'issuance',
  fields: { zeta: 'last', Alpha: 'first', middle: 'center' },
  certifierUrl: 'https://certifier.example.com',
  privileged: false
}
await writeVector(
  'acquireCertificate-fields-wire-order-args',
  acquireFields,
  await captureRequest('acquireCertificate', acquireFields)
)

const acquireKeyring = {
  type: TYPE,
  certifier: CERTIFIER,
  acquisitionProtocol: 'direct',
  fields: { only: 'field' },
  serialNumber: SERIAL,
  revocationOutpoint: OUTPOINT,
  signature: SIGNATURE,
  keyringRevealer: 'certifier',
  keyringForSubject: { zeta: 'eg==', Alpha: 'YQ==', middle: 'bQ==' },
  privileged: false
}
await writeVector(
  'acquireCertificate-keyring-wire-order-args',
  acquireKeyring,
  await captureRequest('acquireCertificate', acquireKeyring)
)

const discover = {
  attributes: { zeta: 'last', Alpha: 'first', middle: 'center' },
  limit: 5,
  offset: 0,
  seekPermission: false
}
await writeVector(
  'discoverByAttributes-wire-order-args',
  discover,
  await captureRequest('discoverByAttributes', discover)
)

const prove = {
  certificate: {
    type: TYPE,
    subject: SUBJECT,
    serialNumber: SERIAL,
    certifier: CERTIFIER,
    revocationOutpoint: OUTPOINT,
    signature: SIGNATURE,
    fields: { zeta: 'last', Alpha: 'first', middle: 'center' }
  },
  fieldsToReveal: ['zeta'],
  verifier: VERIFIER,
  privileged: false
}
await writeVector(
  'proveCertificate-fields-wire-order-args',
  prove,
  await captureRequest('proveCertificate', prove)
)

const signAction = {
  spends: {
    10: { unlockingScript: '51', sequenceNumber: 10 },
    2: { unlockingScript: '52', sequenceNumber: 2 }
  },
  reference: 'dGVzdA=='
}
await writeVector(
  'signAction-numeric-spend-order-args',
  signAction,
  await captureRequest('signAction', signAction)
)

const listResult = {
  totalCertificates: 1,
  certificates: [
    {
      type: TYPE,
      serialNumber: SERIAL,
      subject: SUBJECT,
      certifier: CERTIFIER,
      revocationOutpoint: OUTPOINT,
      fields: {},
      signature: SIGNATURE,
      keyring: { zeta: 'eg==', Alpha: 'YQ==', middle: 'bQ==' },
      verifier: ''
    }
  ]
}
let listWire
const processor = new WalletWireProcessor({
  async listCertificates() {
    return listResult
  }
})
const recordingProcessor = {
  async transmitToWalletUint8Array(frame) {
    const response = await processor.transmitToWalletUint8Array(frame)
    listWire = Uint8Array.from(response)
    return response
  }
}
const listTransceiver = new WalletWireTransceiver(recordingProcessor)
await listTransceiver.listCertificates({ certifiers: [], types: [] })
assert.ok(listWire, 'listCertificates did not return a response')
await writeVector('listCertificates-keyring-wire-order-result', listResult, listWire)

console.log(
  `Generated 6 wallet wire-order vectors from ${packageJson.name}@${packageJson.version} at ${sdkRoot}`
)
