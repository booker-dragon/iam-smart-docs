// Browser-side helpers for the iAM Smart API (signing, AES-256-GCM content encryption, CEK unwrap).
// Used by the interactive tools on this site. Runs entirely in the page: nothing is sent anywhere.
// Works in modern browsers and in Node.js >= 20 (WebCrypto is available as globalThis.crypto).

const subtle = () => globalThis.crypto.subtle
const enc = new TextEncoder()
const dec = new TextDecoder()

export function bytesToBase64(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  }
  return btoa(bin)
}

export function base64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** 32 lowercase hex characters, like the nonces in the spec's examples. */
export function randomNonce() {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16)))
}

/** URL-safe random value for the `state` parameter (letters, numbers, `_`, `-`; ≤ 36 chars). */
export function randomState(length = 16) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
  const rnd = globalThis.crypto.getRandomValues(new Uint8Array(length))
  return Array.from(rnd, (b) => alphabet[b % alphabet.length]).join('')
}

/** Random 256-bit key, Base64 encoded (handy for local experiments). */
export function randomCekBase64() {
  return bytesToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32)))
}

async function importAesKey(cekBytes, usage) {
  if (cekBytes.length !== 32) throw new Error(`CEK must be 32 bytes (AES-256); got ${cekBytes.length}`)
  return subtle().importKey('raw', cekBytes, { name: 'AES-GCM' }, false, [usage])
}

/**
 * Encrypts a string the way the spec's reference implementation does (§2.3.5):
 * AES/GCM/NoPadding, random 12-byte IV, 128-bit tag, output = Base64(int32 ivLength ‖ iv ‖ ciphertext ‖ tag).
 */
export async function encryptContent(plaintext, cekBase64) {
  const key = await importAesKey(base64ToBytes(cekBase64), 'encrypt')
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, enc.encode(plaintext)))
  const out = new Uint8Array(4 + iv.length + ct.length)
  new DataView(out.buffer).setInt32(0, iv.length, false)
  out.set(iv, 4)
  out.set(ct, 4 + iv.length)
  return bytesToBase64(out)
}

/** Reverses encryptContent. Throws if the IV length prefix is not 12 or the tag does not verify. */
export async function decryptContent(contentBase64, cekBase64) {
  const data = base64ToBytes(contentBase64)
  if (data.length < 4 + 12 + 16) throw new Error('Ciphertext is too short')
  const ivLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getInt32(0, false)
  if (ivLength !== 12) throw new Error(`Invalid IV length prefix: ${ivLength} (expected 12)`)
  const iv = data.subarray(4, 16)
  const key = await importAesKey(base64ToBytes(cekBase64), 'decrypt')
  try {
    const pt = await subtle().decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data.subarray(16))
    return dec.decode(pt)
  } catch {
    throw new Error('Decryption failed: wrong CEK or corrupted content (GCM tag mismatch)')
  }
}

/**
 * Request signature (§2.4.1):
 * Base64(HMAC-SHA256(clientSecret, clientID + signatureMethod + timestamp + nonce + encryptedBody)).
 * `body` is the exact request body string you send (e.g. '{"content":"…"}'), or '' when there is none.
 */
export async function signRequest({ clientId, clientSecret, timestamp, nonce, body = '', signatureMethod = 'HmacSHA256' }) {
  const message = `${clientId}${signatureMethod}${timestamp}${nonce}${body}`
  const key = await subtle().importKey('raw', enc.encode(clientSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = new Uint8Array(await subtle().sign('HMAC', key, enc.encode(message)))
  const signature = bytesToBase64(mac)
  return { message, signature, signatureUrlEncoded: encodeURIComponent(signature) }
}

/** Builds the full signed + encrypted request for a POST endpoint. */
export async function buildRequest({ clientId, clientSecret, cekBase64, body, timestamp = Date.now(), nonce = randomNonce(), rateLimitFactor }) {
  let wireBody = ''
  if (body !== undefined && body !== null && body !== '') {
    const plaintext = typeof body === 'string' ? body : JSON.stringify(body)
    wireBody = JSON.stringify({ content: await encryptContent(plaintext, cekBase64) })
  }
  const { signature, signatureUrlEncoded, message } = await signRequest({ clientId, clientSecret, timestamp, nonce, body: wireBody })
  const headers = {
    'Content-Type': 'application/json',
    clientID: clientId,
    signatureMethod: 'HmacSHA256',
    timestamp: String(timestamp),
    nonce,
    signature: signatureUrlEncoded,
  }
  if (rateLimitFactor) {
    const json = typeof rateLimitFactor === 'string' ? rateLimitFactor : JSON.stringify(rateLimitFactor)
    headers.rateLimitFactor = bytesToBase64(enc.encode(json))
  }
  return { headers, body: wireBody, signature, signedMessage: message }
}

export async function sha256(text) {
  return new Uint8Array(await subtle().digest('SHA-256', enc.encode(text)))
}

/**
 * HKICHash: SHA-256 of the HKIC identifier without the check digit, Base64 encoded.
 * Accepts "A123456(7)", "A1234567", "a123456 (7)" … and strips the check digit.
 */
export async function hkicHash(input) {
  const identifier = normaliseHkic(input)
  const digest = await sha256(identifier)
  return { identifier, base64: bytesToBase64(digest), hex: bytesToHex(digest) }
}

export function normaliseHkic(input) {
  const s = String(input).toUpperCase().replace(/\s+/g, '')
  const withBrackets = s.match(/^([A-Z]{1,2}\d{6})\(([0-9A])\)$/)
  if (withBrackets) return withBrackets[1]
  const bare = s.match(/^([A-Z]{1,2}\d{6})([0-9A])?$/)
  if (bare) return bare[1]
  throw new Error('Expected an HKIC number such as A123456(7)')
}

// ---------------------------------------------------------------------------
// RSA: unwrap the CEK (getKey `secretKey`, callback `secretKey`) with the KEK private key.
// The spec only says "RSA". PKCS#1 v1.5 is what Java's plain "RSA" cipher uses; OAEP is offered as well.
// WebCrypto has no PKCS#1 v1.5 decryption, so it is implemented here with BigInt.
// ---------------------------------------------------------------------------

function pemToDer(pem) {
  const m = String(pem).match(/-----BEGIN ([A-Z ]+)-----([\s\S]+?)-----END \1-----/)
  if (!m) throw new Error('Paste a PEM private key (-----BEGIN PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----)')
  if (/ENCRYPTED/.test(m[1])) throw new Error('Encrypted private keys are not supported here; export an unencrypted test key')
  return { label: m[1], der: base64ToBytes(m[2]) }
}

function readTlv(bytes, offset) {
  const tag = bytes[offset]
  let len = bytes[offset + 1]
  let head = 2
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let i = 0; i < n; i++) len = len * 256 + bytes[offset + 2 + i]
    head = 2 + n
  }
  return { tag, start: offset + head, end: offset + head + len }
}

function children(bytes, tlv) {
  const out = []
  let p = tlv.start
  while (p < tlv.end) {
    const c = readTlv(bytes, p)
    out.push(c)
    p = c.end
  }
  return out
}

function toBigInt(bytes) {
  let hex = bytesToHex(bytes)
  return hex ? BigInt('0x' + hex) : 0n
}

function parseRsaPrivateKey(pem) {
  const { label, der } = pemToDer(pem)
  let pkcs1 = der
  if (label === 'PRIVATE KEY') {
    // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey OCTET STRING }
    const seq = readTlv(der, 0)
    const parts = children(der, seq)
    const octet = parts[2]
    if (!octet || octet.tag !== 0x04) throw new Error('Unsupported PKCS#8 structure')
    pkcs1 = der.subarray(octet.start, octet.end)
  } else if (label !== 'RSA PRIVATE KEY') {
    throw new Error(`Unsupported key type: ${label}`)
  }
  const seq = readTlv(pkcs1, 0)
  const ints = children(pkcs1, seq).map((t) => toBigInt(pkcs1.subarray(t.start, t.end)))
  // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
  const [, n, e, d] = ints
  if (!n || !d) throw new Error('Could not read the RSA key')
  return { n, e, d, byteLength: Math.ceil(n.toString(16).length / 2) }
}

function modPow(base, exp, mod) {
  let result = 1n
  base %= mod
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    exp >>= 1n
    base = (base * base) % mod
  }
  return result
}

function bigIntToBytes(value, length) {
  const hex = value.toString(16).padStart(length * 2, '0')
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** RSAES-PKCS1-v1_5 decryption (for testing only — not constant time). */
export function rsaDecryptPkcs1v15(pem, ciphertextBase64) {
  const key = parseRsaPrivateKey(pem)
  const c = toBigInt(base64ToBytes(ciphertextBase64))
  if (c >= key.n) throw new Error('Ciphertext does not match this key size')
  const em = bigIntToBytes(modPow(c, key.d, key.n), key.byteLength)
  if (em[0] !== 0x00 || em[1] !== 0x02) throw new Error('PKCS#1 v1.5 padding not found — wrong key, or try OAEP')
  const sep = em.indexOf(0x00, 2)
  if (sep < 10) throw new Error('PKCS#1 v1.5 padding not found — wrong key, or try OAEP')
  return em.subarray(sep + 1)
}

/** RSA-OAEP decryption through WebCrypto (hash: 'SHA-1' or 'SHA-256'). Requires a PKCS#8 key. */
export async function rsaDecryptOaep(pem, ciphertextBase64, hash = 'SHA-1') {
  const { label, der } = pemToDer(pem)
  if (label !== 'PRIVATE KEY') throw new Error('OAEP in the browser needs a PKCS#8 key (-----BEGIN PRIVATE KEY-----)')
  const key = await subtle().importKey('pkcs8', der, { name: 'RSA-OAEP', hash }, false, ['decrypt'])
  try {
    return new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, key, base64ToBytes(ciphertextBase64)))
  } catch {
    throw new Error(`RSA-OAEP (${hash}) decryption failed — wrong key or different padding`)
  }
}

/**
 * Unwraps a CEK. padding: 'pkcs1' | 'oaep-sha1' | 'oaep-sha256' | 'auto' (tries in that order).
 * Returns { cekBase64, padding }.
 */
export async function unwrapCek(pem, secretKeyBase64, padding = 'auto') {
  const attempts = padding === 'auto' ? ['pkcs1', 'oaep-sha1', 'oaep-sha256'] : [padding]
  let lastError
  for (const p of attempts) {
    try {
      const raw = p === 'pkcs1' ? rsaDecryptPkcs1v15(pem, secretKeyBase64) : await rsaDecryptOaep(pem, secretKeyBase64, p === 'oaep-sha1' ? 'SHA-1' : 'SHA-256')
      if (raw.length !== 32) throw new Error(`Unwrapped key is ${raw.length} bytes, expected 32`)
      return { cekBase64: bytesToBase64(raw), padding: p }
    } catch (e) {
      lastError = e
    }
  }
  throw lastError
}

/** Decrypts an encrypted callback body ({ secretKey, content, … }) with the KEK private key. */
export async function decryptCallback(callback, pem, padding = 'auto') {
  const body = typeof callback === 'string' ? JSON.parse(callback) : callback
  if (!body.secretKey || typeof body.content !== 'string') throw new Error('Expected a callback body with "secretKey" and an encrypted "content"')
  const { cekBase64, padding: used } = await unwrapCek(pem, body.secretKey, padding)
  const content = JSON.parse(await decryptContent(body.content, cekBase64))
  const { secretKey, ...rest } = body
  return { decrypted: { ...rest, content }, cekBase64, padding: used }
}
