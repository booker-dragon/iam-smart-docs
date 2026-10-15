#!/usr/bin/env node
// Local mock of the iAM Smart API gateway for developing and testing your integration offline.
// It reproduces the transport behaviour of the real service (iAM Smart API Specification v2.5.2):
//   - verifies the HMAC-SHA256 signature headers (D20006 on mismatch)
//   - issues a CEK wrapped with your KEK public key (getKey) and enforces it (D30002)
//   - decrypts AES-256-GCM request bodies and encrypts response `content`
//   - serves a fake QR page that redirects to your redirectURI with `code` and `state`
//   - can send encrypted callbacks to your endpoints
// Business responses are canned examples from the spec. It is NOT the real service.
//
// Usage:
//   CLIENT_ID=demo CLIENT_SECRET=secret KEK_PUBLIC_KEY=./kek-public.pem node mock-iam-smart.mjs
// Environment:
//   PORT (default 8787) · RSA_PADDING pkcs1 | oaep-sha1 | oaep-sha256 (default pkcs1) · CEK_TTL_MS (default 86400000)

import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'

const PORT = Number(process.env.PORT ?? 8787)
const CLIENT_ID = process.env.CLIENT_ID ?? 'demo-client'
const CLIENT_SECRET = process.env.CLIENT_SECRET ?? 'demo-secret'
const RSA_PADDING = process.env.RSA_PADDING ?? 'pkcs1'
const CEK_TTL_MS = Number(process.env.CEK_TTL_MS ?? 86_400_000)
if (!process.env.KEK_PUBLIC_KEY) {
  console.error('Set KEK_PUBLIC_KEY to the path of your KEK certificate or public key (PEM).')
  process.exit(1)
}
const kekPublicKey = crypto.createPublicKey(fs.readFileSync(process.env.KEK_PUBLIC_KEY))

let cek = null // { key, issueAt, expiresIn }
let lastTimestamp = 0
const seenNonces = new Set()
const codes = new Map() // authCode -> { scope, anonymous, businessID, expiresAt }
const tokens = new Map() // accessToken -> { openID, scope, singleUse }
const tx = () => `<T=${crypto.randomBytes(16).toString('hex')}>`

// ---- crypto (same format as the spec's reference implementation) ----------------
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()])
  const len = Buffer.alloc(4)
  len.writeInt32BE(12)
  return Buffer.concat([len, iv, ct, c.getAuthTag()]).toString('base64')
}
function decrypt(b64, key) {
  const d = Buffer.from(b64, 'base64')
  if (d.readInt32BE(0) !== 12) throw new Error('invalid iv length')
  const dc = crypto.createDecipheriv('aes-256-gcm', key, d.subarray(4, 16))
  dc.setAuthTag(d.subarray(d.length - 16))
  return Buffer.concat([dc.update(d.subarray(16, d.length - 16)), dc.final()]).toString('utf8')
}
function wrap(key) {
  const padding = RSA_PADDING === 'pkcs1' ? crypto.constants.RSA_PKCS1_PADDING : crypto.constants.RSA_PKCS1_OAEP_PADDING
  const oaepHash = RSA_PADDING === 'oaep-sha256' ? 'sha256' : 'sha1'
  return crypto.publicEncrypt({ key: kekPublicKey, padding, oaepHash }, key).toString('base64')
}
function currentCek() {
  return cek && Date.now() < cek.issueAt + cek.expiresIn ? cek : null
}

// ---- canned business responses ---------------------------------------------------
const OPEN_ID = 'liR14%2BvX%2F5hSum5uf4ERczu0KcDnIJA5BM7FoM1ag9c%3D'
const PROFILE = {
  idNo: { Identification: 'A123456', CheckDigit: 'A' },
  enName: { UnstructuredName: 'SAN, Chi Nan' },
  chName: { ChineseName: '申智能' },
  birthDate: '19960128',
  gender: 'M',
  emailAddress: 'scn@digitalpolicy.gov.hk',
  mobileNumber: { CountryCode: '852', SubscriberNumber: '98765432' },
}
function business(path, body) {
  const ticket = () => crypto.randomBytes(16).toString('hex')
  if (path === '/api/v1/auth/getToken') {
    const entry = codes.get(body.code)
    codes.delete(body.code)
    if (!entry || Date.now() > entry.expiresAt) return ['D40004', 'authCode not exist or expired']
    const accessToken = crypto.randomBytes(16).toString('hex')
    tokens.set(accessToken, { openID: OPEN_ID, scope: entry.scope, singleUse: entry.anonymous })
    return ['D00000', 'SUCCESS', { accessToken, tokenType: 'Bearer', issueAt: Date.now(), expiresIn: 14_400_000, openID: OPEN_ID, lastModifiedDate: 1560849218006, userType: 'sign', scope: entry.scope }]
  }
  if ('accessToken' in body) {
    const t = tokens.get(body.accessToken)
    if (!t) return ['D20009', 'accessToken not exist or expired']
    if (body.openID !== t.openID) return ['D20010', 'openID not exist']
    if (t.singleUse) tokens.delete(body.accessToken)
  }
  if (path.includes('/anonymous/') && path.endsWith('/initiateRequest')) return ['D00000', 'SUCCESS', { ticketID: ticket() }]
  if (path === '/api/v1/bdss/anonymous/initiateRequest') return ['D00000', 'SUCCESS', { ticketID: ticket() }]
  if (path.endsWith('/initiateRequest') || path.endsWith('/initiateRequestV2') || path === '/api/v1/cdeg/requestConsent')
    return ['D00000', 'SUCCESS', { authByQR: false, ticketID: ticket() }]
  if (path === '/api/v1/profiles' || path.endsWith('/formFilling/getResult')) return ['D00000', 'SUCCESS', PROFILE]
  if (path === '/api/v1/anonymous/signing/getResult') return ['D00000', 'SUCCESS', { hashCode: 'tGzv3JOkF0XG5Qx2TlKWIA', timestamp: Date.now(), signature: 'bW9jay1zaWduYXR1cmU=', cert: 'bW9jay1jZXJ0' }]
  if (path === '/api/v1/anonymous/pdfsigning/getResult') return ['D00000', 'SUCCESS', { docDigest: 'tGzv3JOkF0XG5Qx2TlKWIA', pdfSignature: 'bW9jay1wa2NzNw==' }]
  if (path === '/api/v1/anonymous/sua/getResult') return ['D00000', 'SUCCESS', { isPassed: true }]
  if (path === '/api/v1/ccic/verifyIsCcic') return ['D00000', 'SUCCESS', { verifyResult: false }]
  if (path === '/api/v1/auth/account/getLastLoginStatus') return ['D00000', 'SUCCESS', { loginType: 'BIO' }]
  if (path === '/api/v1/cdeg/getConsentResult') return ['D00000', 'SUCCESS', { consentResult: false }]
  if (path === '/api/v1/bdss/getBSQCToken') return ['D00000', 'SUCCESS', { BSQCToken: crypto.randomBytes(16).toString('hex') }]
  if (path === '/api/v1/bdss/enquireStatus') return ['D00000', 'SUCCESS', { status: 'SS001' }]
  if (path.endsWith('/ackResult') || path === '/api/v1/bdss/cancelRequest') return ['D00000', 'SUCCESS']
  return ['D20000', 'unknown exception (path not mocked)']
}

// ---- HTTP -------------------------------------------------------------------------
// CORS (and Chrome's Private Network Access) so the "Try it" consoles on the docs site can call the mock.
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, clientID, signatureMethod, timestamp, nonce, signature, rateLimitFactor',
  'Access-Control-Allow-Private-Network': 'true',
  'Access-Control-Max-Age': '600',
}
function send(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS, ...headers })
  res.end(typeof obj === 'string' ? obj : JSON.stringify(obj))
}
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  })
}
function checkSignature(req, body) {
  const h = req.headers
  const required = ['clientid', 'signaturemethod', 'timestamp', 'nonce', 'signature']
  for (const k of required) if (!h[k]) return ['D20001', `parameter {${k}} is missing`]
  if (h.clientid !== CLIENT_ID) return ['D20003', 'invalid parameter {clientID}']
  if (h.signaturemethod !== 'HmacSHA256') return ['D20005', 'unsupported signature method']
  const ts = Number(h.timestamp)
  if (!(ts >= lastTimestamp)) return ['D20003', 'invalid parameter {timestamp}']
  if (seenNonces.has(h.nonce)) return ['D20004', 'duplicated request']
  const message = `${h.clientid}${h.signaturemethod}${h.timestamp}${h.nonce}${body}`
  const expected = crypto.createHmac('sha256', CLIENT_SECRET).update(message, 'utf8').digest('base64')
  const got = decodeURIComponent(h.signature)
  if (got !== expected) return ['D20006', 'signature verification failed']
  lastTimestamp = ts
  seenNonces.add(h.nonce)
  return null
}

async function sendCallback(url, content) {
  const key = crypto.randomBytes(32)
  const body = { txID: tx(), code: 'D00000', message: 'SUCCESS', secretKey: wrap(key), content: encrypt(JSON.stringify(content), key) }
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return r.status
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`)
  const path = url.pathname

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS)
    return res.end()
  }

  if (req.method === 'GET' && path === '/api/v1/auth/getQR') {
    const p = Object.fromEntries(url.searchParams)
    for (const k of ['clientID', 'responseType', 'source', 'redirectURI', 'scope'])
      if (!p[k]) return send(res, 400, { code: 'D20001', message: `parameter {${k}} is missing` })
    const code = crypto.randomBytes(16).toString('hex')
    const anonymous = Boolean(p.ticketID)
    codes.set(code, { scope: p.scope, anonymous, expiresAt: Date.now() + 60_000 })
    const back = new URL(p.redirectURI)
    back.searchParams.set('code', code)
    if (p.state) back.searchParams.set('state', p.state)
    const deny = new URL(p.redirectURI)
    deny.searchParams.set('error_code', 'D40001')
    if (p.state) deny.searchParams.set('state', p.state)
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS })
    return res.end(`<!doctype html><meta name=viewport content="width=device-width"><title>Mock iAM Smart</title>
<body style="font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem">
<h1>Mock iAM Smart</h1><p>Scope: <code>${p.scope}</code>${anonymous ? ` · ticket <code>${p.ticketID}</code>` : ''}</p>
<p><a href="${back}">Approve</a> · <a href="${deny}">Deny</a></p></body>`)
  }

  if (req.method === 'POST' && path === '/__mock/callback') {
    // { "url": "https://your-server/callback", "content": { ...decrypted callback content... } }
    const { url: target, content } = JSON.parse((await readBody(req)) || '{}')
    if (!target) return send(res, 400, { error: 'url is required' })
    return send(res, 200, { status: await sendCallback(target, content ?? { businessID: 'mock', isPassed: true }) })
  }

  if (req.method !== 'POST') return send(res, 404, { error: 'not found' })
  const raw = await readBody(req)
  const sigError = checkSignature(req, raw)
  if (sigError) return send(res, 200, { txID: tx(), code: sigError[0], message: sigError[1] })

  if (path === '/api/v1/security/getKey') {
    if (!currentCek()) cek = { key: crypto.randomBytes(32), issueAt: Date.now(), expiresIn: CEK_TTL_MS }
    const pub = kekPublicKey.export({ type: 'spki', format: 'der' }).toString('base64')
    return send(res, 200, { txID: tx(), code: 'D00000', message: 'SUCCESS', content: { secretKey: wrap(cek.key), pubKey: pub, issueAt: cek.issueAt, expiresIn: cek.expiresIn } })
  }
  if (path === '/api/v1/security/revokeKey') {
    cek = null
    return send(res, 200, { txID: tx(), code: 'D00000', message: 'SUCCESS' })
  }

  const active = currentCek()
  if (!active) return send(res, 200, { txID: tx(), code: 'D30002', message: 'content encryption key not exist or expired' })
  let body
  try {
    body = JSON.parse(decrypt(JSON.parse(raw).content, active.key))
  } catch {
    return send(res, 200, { txID: tx(), code: 'D30004', message: 'decryption exception' })
  }
  const [code, message, content] = business(path, body)
  const out = { txID: tx(), code, message }
  if (content !== undefined) out.content = encrypt(JSON.stringify(content), active.key)
  console.log(`${new Date().toISOString()} POST ${path} -> ${code}`)
  return send(res, 200, out)
})

server.listen(PORT, () => console.log(`Mock iAM Smart listening on http://localhost:${PORT} (client ${CLIENT_ID}, CEK padding ${RSA_PADDING})`))
