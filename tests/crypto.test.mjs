// Run with: npm test  (Node >= 22)
// Checks the browser crypto helpers, the Node reference client and the mock server against each other.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { after, before, test } from 'node:test'

import * as lib from '../src/lib/iam-smart-crypto.js'
import { IamSmartClient, decryptContent, encryptContent } from '../examples/node/iam-smart-client.mjs'

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'pem' })
const pkcs1 = privateKey.export({ type: 'pkcs1', format: 'pem' })
const cek = crypto.randomBytes(32)
const cekB64 = cek.toString('base64')

test('browser and Node AES-GCM formats are interchangeable', async () => {
  const fromBrowser = await lib.encryptContent('{"a":"申智能"}', cekB64)
  assert.equal(decryptContent(fromBrowser, cek), '{"a":"申智能"}')
  const fromNode = encryptContent('{"b":1}', cek)
  assert.equal(await lib.decryptContent(fromNode, cekB64), '{"b":1}')
  const raw = Buffer.from(fromNode, 'base64')
  assert.equal(raw.readInt32BE(0), 12)
})

test('signature matches an independent HMAC computation', async () => {
  const body = '{"content":"abc"}'
  const s = await lib.signRequest({ clientId: 'c1', clientSecret: 's3cret', timestamp: 1557048906183, nonce: 'n1', body })
  const expected = crypto.createHmac('sha256', 's3cret').update(`c1HmacSHA2561557048906183n1${body}`).digest('base64')
  assert.equal(s.signature, expected)
  assert.equal(s.signatureUrlEncoded, encodeURIComponent(expected))
})

test('CEK unwrap supports PKCS#1 v1.5 and OAEP with PKCS#8 and PKCS#1 keys', async () => {
  const wrapped = {
    pkcs1: crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, cek).toString('base64'),
    'oaep-sha1': crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, cek).toString('base64'),
    'oaep-sha256': crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek).toString('base64'),
  }
  for (const [padding, value] of Object.entries(wrapped)) {
    const r = await lib.unwrapCek(pkcs8, value)
    assert.equal(r.cekBase64, cekB64)
    assert.equal(r.padding, padding)
  }
  assert.equal((await lib.unwrapCek(pkcs1, wrapped.pkcs1, 'pkcs1')).cekBase64, cekB64)
})

test('HKICHash strips the check digit', async () => {
  const expected = crypto.createHash('sha256').update('A123456').digest('base64')
  for (const input of ['A123456(7)', 'a123456 (7)', 'A1234567', 'A123456']) {
    assert.equal((await lib.hkicHash(input)).base64, expected)
  }
})

// ---- end to end against the mock server -------------------------------------------
const port = 18787 + Math.floor(Math.random() * 1000)
let mock
let dir

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iamsmart-'))
  fs.writeFileSync(path.join(dir, 'kek-public.pem'), publicKey.export({ type: 'spki', format: 'pem' }))
  mock = spawn(process.execPath, ['examples/mock-server/mock-iam-smart.mjs'], {
    env: { ...process.env, PORT: String(port), CLIENT_ID: 'demo-client', CLIENT_SECRET: 'demo-secret', KEK_PUBLIC_KEY: path.join(dir, 'kek-public.pem') },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  await new Promise((resolve) => mock.stdout.once('data', resolve))
})

after(() => {
  mock?.kill()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('reference client completes a login against the mock', async () => {
  const base = `http://localhost:${port}`
  const client = new IamSmartClient({ baseUrl: base, clientId: 'demo-client', clientSecret: 'demo-secret', privateKeyPem: pkcs8 })
  const qr = new URL(`${base}/api/v1/auth/getQR`)
  for (const [k, v] of Object.entries({ clientID: 'demo-client', responseType: 'code', source: 'PC_Browser', redirectURI: 'https://rp.example/cb', scope: 'eidapi_auth', state: 's1' })) qr.searchParams.set(k, v)
  const html = await (await fetch(qr)).text()
  const approve = new URL(html.match(/<a href="([^"]+)">Approve/)[1].replace(/&amp;/g, '&'))
  const token = await client.post('/api/v1/auth/getToken', { code: approve.searchParams.get('code'), grantType: 'authorization_code' })
  assert.equal(token.code, 'D00000')
  assert.equal(token.content.tokenType, 'Bearer')
  const status = await client.post('/api/v1/auth/account/getLastLoginStatus', { accessToken: token.content.accessToken, openID: token.content.openID })
  assert.equal(status.content.loginType, 'BIO')
})
