// Reference client for the iAM Smart API (Node.js >= 20, no dependencies).
//
// Handles the three things every call needs (iAM Smart API Specification v2.5.2, §2.3–2.4):
//   1. Content encryption key (CEK): fetched from /api/v1/security/getKey, unwrapped with your KEK
//      private key, cached until `issueAt + expiresIn`, refreshed on D30001/D30002.
//   2. AES-256-GCM encryption of request bodies and decryption of response `content`.
//   3. HMAC-SHA256 request signature headers.
// It also decrypts callbacks (JSON and multipart parts) sent to your endpoints.
//
// Usage:
//   const iamSmart = new IamSmartClient({ baseUrl, clientId, clientSecret, privateKeyPem })
//   const res = await iamSmart.post('/api/v1/auth/getToken', { code, grantType: 'authorization_code' })
//
// The spec does not name the RSA padding used to wrap the CEK. `rsaPadding: 'auto'` (default) tries
// PKCS#1 v1.5 first (Java's default for "RSA"), then OAEP-SHA1 and OAEP-SHA256, and remembers what worked.

import crypto from 'node:crypto'

const SIGNATURE_METHOD = 'HmacSHA256'
const CEK_ERRORS = new Set(['D30001', 'D30002'])

export class IamSmartError extends Error {
  constructor(response) {
    super(`${response.code} ${response.message}`)
    this.code = response.code
    this.txID = response.txID
    this.response = response
  }
}

export class IamSmartClient {
  constructor({ baseUrl, clientId, clientSecret, privateKeyPem, rsaPadding = 'auto', fetch: fetchImpl = globalThis.fetch, cekSafetyMarginMs = 60_000 }) {
    if (!baseUrl || !clientId || !clientSecret || !privateKeyPem) throw new Error('baseUrl, clientId, clientSecret and privateKeyPem are required')
    this.baseUrl = baseUrl.replace(/\/$/, '')
    this.clientId = clientId
    this.clientSecret = clientSecret
    this.privateKey = crypto.createPrivateKey(privateKeyPem)
    this.rsaPadding = rsaPadding
    this.fetch = fetchImpl
    this.margin = cekSafetyMarginMs
    this.cek = null // { key: Buffer, expiresAt: number }
    this.lastTimestamp = 0
  }

  // ---- signing -------------------------------------------------------------
  timestamp() {
    // The timestamp must never go backwards (§2.4.1).
    this.lastTimestamp = Math.max(Date.now(), this.lastTimestamp + 1)
    return this.lastTimestamp
  }

  sign(timestamp, nonce, body) {
    const message = `${this.clientId}${SIGNATURE_METHOD}${timestamp}${nonce}${body}`
    const hash = crypto.createHmac('sha256', this.clientSecret).update(message, 'utf8').digest('base64')
    return encodeURIComponent(hash)
  }

  headers(body, { rateLimitFactor } = {}) {
    const timestamp = this.timestamp()
    const nonce = crypto.randomUUID().replace(/-/g, '')
    const headers = {
      'Content-Type': 'application/json',
      clientID: this.clientId,
      signatureMethod: SIGNATURE_METHOD,
      timestamp: String(timestamp),
      nonce,
      signature: this.sign(timestamp, nonce, body),
    }
    if (rateLimitFactor) {
      const json = typeof rateLimitFactor === 'string' ? rateLimitFactor : JSON.stringify(rateLimitFactor)
      headers.rateLimitFactor = Buffer.from(json, 'utf8').toString('base64')
    }
    return headers
  }

  // ---- CEK -----------------------------------------------------------------
  async getCek({ force = false } = {}) {
    if (!force && this.cek && Date.now() < this.cek.expiresAt - this.margin) return this.cek.key
    const res = await this.raw('/api/v1/security/getKey', '')
    if (res.code !== 'D00000') throw new IamSmartError(res)
    const { secretKey, issueAt, expiresIn } = res.content
    const key = this.unwrapKey(secretKey)
    this.cek = { key, expiresAt: Number(issueAt) + Number(expiresIn) }
    return key
  }

  async revokeCek() {
    const res = await this.raw('/api/v1/security/revokeKey', '')
    this.cek = null
    if (res.code !== 'D00000') throw new IamSmartError(res)
    return res
  }

  unwrapKey(secretKeyBase64) {
    const wrapped = Buffer.from(secretKeyBase64, 'base64')
    const order = this.rsaPadding === 'auto' ? ['pkcs1', 'oaep-sha1', 'oaep-sha256'] : [this.rsaPadding]
    let lastError
    for (const padding of order) {
      try {
        const key = rsaDecrypt(this.privateKey, wrapped, padding)
        if (key.length !== 32) throw new Error(`unwrapped key is ${key.length} bytes`)
        if (this.rsaPadding === 'auto') this.rsaPadding = padding
        return key
      } catch (e) {
        lastError = e
      }
    }
    throw new Error(`Could not unwrap the CEK: ${lastError?.message}`)
  }

  // ---- requests --------------------------------------------------------------
  async raw(path, body, options) {
    const response = await this.fetch(this.baseUrl + path, { method: 'POST', headers: this.headers(body, options), body: body || undefined })
    const text = await response.text()
    if (!response.ok) {
      const err = new Error(`HTTP ${response.status} from ${path}: ${text.slice(0, 200)}`)
      err.status = response.status
      throw err
    }
    return JSON.parse(text)
  }

  /** Signed, encrypted POST. Returns the response with `content` decrypted. Retries once if the CEK expired. */
  async post(path, payload, options = {}, retried = false) {
    const cek = await this.getCek()
    const body = JSON.stringify({ content: encryptContent(JSON.stringify(payload), cek) })
    const res = await this.raw(path, body, options)
    if (CEK_ERRORS.has(res.code) && !retried) {
      await this.getCek({ force: true })
      return this.post(path, payload, options, true)
    }
    if (typeof res.content === 'string' && res.content) res.content = JSON.parse(decryptContent(res.content, cek))
    return res
  }

  // ---- callbacks -------------------------------------------------------------
  /** Decrypts a JSON callback body: { txID, code, message, secretKey, content }. */
  decryptCallback(callbackBody) {
    const body = typeof callbackBody === 'string' ? JSON.parse(callbackBody) : callbackBody
    if (typeof body.content !== 'string' || !body.content) return body // errors may carry no encrypted content
    const cek = this.unwrapKey(body.secretKey)
    const { secretKey, ...rest } = body
    return { ...rest, content: JSON.parse(decryptContent(body.content, cek)) }
  }

  /** Decrypts one part of a multipart callback (e.g. `docFile`, `sigFile`) given the CEK from the JSON part. */
  decryptPart(partBuffer, cek) {
    return decryptBytes(Buffer.isBuffer(partBuffer) ? partBuffer.toString('utf8') : partBuffer, cek)
  }
}

// ---- primitives ----------------------------------------------------------------

/** AES/GCM/NoPadding, 12-byte random IV, 128-bit tag. Output: Base64(int32 ivLength ‖ iv ‖ ciphertext ‖ tag). */
export function encryptContent(plaintext, cek) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv)
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const len = Buffer.alloc(4)
  len.writeInt32BE(iv.length)
  return Buffer.concat([len, iv, ct, cipher.getAuthTag()]).toString('base64')
}

export function decryptContent(contentBase64, cek) {
  return decryptBytes(contentBase64, cek).toString('utf8')
}

export function decryptBytes(contentBase64, cek) {
  const data = Buffer.from(contentBase64, 'base64')
  const ivLength = data.readInt32BE(0)
  if (ivLength !== 12) throw new Error('invalid iv length')
  const iv = data.subarray(4, 16)
  const tag = data.subarray(data.length - 16)
  const decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(data.subarray(16, data.length - 16)), decipher.final()])
}

/** SHA-256 of the HKIC identifier without the check digit, Base64 (for HKICHash). */
export function hkicHash(hkic) {
  // Accepts "A123456(7)", "A1234567" or "A123456"; hashes only the identifier, e.g. "A123456".
  const s = String(hkic).toUpperCase().replace(/\s+/g, '')
  const m = s.match(/^([A-Z]{1,2}\d{6})(?:\(([0-9A])\)|([0-9A]))?$/)
  if (!m) throw new Error('Expected an HKIC number such as A123456(7)')
  return crypto.createHash('sha256').update(m[1], 'utf8').digest('base64')
}

function rsaDecrypt(privateKey, data, padding) {
  if (padding === 'pkcs1') {
    // Node >= 20 refuses RSA_PKCS1_PADDING for private decryption (CVE-2023-46809), so unpad manually.
    const em = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, data)
    if (em[0] !== 0x00 || em[1] !== 0x02) throw new Error('not PKCS#1 v1.5')
    const sep = em.indexOf(0x00, 2)
    if (sep < 10) throw new Error('not PKCS#1 v1.5')
    return em.subarray(sep + 1)
  }
  const oaepHash = padding === 'oaep-sha256' ? 'sha256' : 'sha1'
  return crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, data)
}
