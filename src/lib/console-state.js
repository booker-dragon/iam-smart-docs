// Shared state for the "Try it" consoles on API pages.
//
// Non-secret settings (environment, client ID) live in localStorage. Session values returned by the API
// (CEK, accessToken, openID, ticketID, BSQC token, auth code) live in sessionStorage so they carry over
// between API pages in this tab. The client secret and KEK private key stay in memory unless the user
// ticks "Keep in this tab", which puts them in sessionStorage (cleared when the tab closes).

const SETTINGS_KEY = 'ist-console-settings'
const SESSION_KEY = 'ist-console-session'
const SECRETS_KEY = 'ist-console-secrets'

export const ENVIRONMENTS = [
  { id: 'testing', label: 'Testing — apigw-isit.staging-eid.gov.hk', url: 'https://apigw-isit.staging-eid.gov.hk', send: true },
  { id: 'mock', label: 'Local mock — http://localhost:8787', url: 'http://localhost:8787', send: true },
  { id: 'custom', label: 'Custom URL…', url: '', send: true },
  { id: 'production', label: 'Production — apigw.iamsmart.gov.hk (build only)', url: 'https://apigw.iamsmart.gov.hk', send: false },
]

/** Values captured from responses and reused to pre-fill later requests. */
export const SESSION_FIELDS = ['accessToken', 'openID', 'ticketID', 'BSQCToken', 'code', 'code_verifier']

function storage(kind) {
  try {
    const s = kind === 'local' ? globalThis.localStorage : globalThis.sessionStorage
    if (!s) return null
    const probe = '__ist_probe__'
    s.setItem(probe, '1')
    s.removeItem(probe)
    return s
  } catch {
    return null
  }
}

function read(kind, key) {
  try {
    return JSON.parse(storage(kind)?.getItem(key) ?? '{}') ?? {}
  } catch {
    return {}
  }
}

function write(kind, key, value) {
  try {
    storage(kind)?.setItem(key, JSON.stringify(value))
  } catch {
    /* storage unavailable */
  }
}

// In-memory copy so secrets survive within the page even when they are not persisted.
const memory = { secrets: null }

export const state = {
  settings() {
    return { env: 'testing', customUrl: '', clientId: '', ...read('local', SETTINGS_KEY) }
  },
  saveSettings(patch) {
    write('local', SETTINGS_KEY, { ...this.settings(), ...patch })
  },

  session() {
    return read('session', SESSION_KEY)
  },
  saveSession(patch) {
    const next = { ...this.session() }
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === null || v === '') delete next[k]
      else next[k] = v
    }
    write('session', SESSION_KEY, next)
    return next
  },
  clearSession() {
    write('session', SESSION_KEY, {})
  },

  /** { clientSecret, privateKeyPem, keep } */
  secrets() {
    if (memory.secrets) return memory.secrets
    const stored = read('session', SECRETS_KEY)
    memory.secrets = { clientSecret: '', privateKeyPem: '', keep: Boolean(stored.keep), ...stored }
    return memory.secrets
  },
  saveSecrets(patch) {
    memory.secrets = { ...this.secrets(), ...patch }
    if (memory.secrets.keep) write('session', SECRETS_KEY, memory.secrets)
    else storage('session')?.removeItem(SECRETS_KEY)
  },
}

/** Base URL for the selected environment. */
export function baseUrl(settings) {
  const env = ENVIRONMENTS.find((e) => e.id === settings.env) ?? ENVIRONMENTS[0]
  return (env.id === 'custom' ? settings.customUrl : env.url).replace(/\/+$/, '')
}

export function canSend(settings) {
  const env = ENVIRONMENTS.find((e) => e.id === settings.env)
  return Boolean(env?.send && baseUrl(settings))
}

/** Is the cached CEK still usable (with a 60 s safety margin)? */
export function cekValid(session, now = Date.now()) {
  return Boolean(session.cek && (!session.cekExpiresAt || now < session.cekExpiresAt - 60_000))
}

function randomHex(bytes = 16) {
  const a = globalThis.crypto.getRandomValues(new Uint8Array(bytes))
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Prepares an example body for sending: fresh businessID / state, and values captured earlier in this
 * session (accessToken, openID, BSQCToken, code, code_verifier) replacing the spec's placeholder values.
 * Returns { body, filled } where `filled` lists the keys that came from the session.
 */
export function fillExample(example, session = {}, { fresh = true } = {}) {
  if (!example || typeof example !== 'object' || Array.isArray(example)) return { body: example ?? null, filled: [] }
  const body = structuredClone(example)
  const filled = []
  for (const key of ['accessToken', 'openID', 'BSQCToken', 'code', 'code_verifier']) {
    if (key in body && session[key]) {
      body[key] = session[key]
      filled.push(key)
    }
  }
  if (fresh && 'businessID' in body) body.businessID = randomHex(16)
  if (fresh && 'state' in body) body.state = randomHex(6)
  return { body, filled }
}

/** Picks the session values worth keeping from a decrypted response `content` (and the request body). */
export function captureFromResponse(content, requestBody) {
  const out = {}
  if (content && typeof content === 'object') {
    for (const key of ['accessToken', 'openID', 'ticketID', 'BSQCToken']) if (content[key]) out[key] = content[key]
    if (content.accessToken && content.issueAt && content.expiresIn) out.accessTokenExpiresAt = Number(content.issueAt) + Number(content.expiresIn)
  }
  // An exchanged auth code is single use: forget it once getToken has been called.
  if (requestBody && typeof requestBody === 'object' && 'code' in requestBody && 'grantType' in requestBody) {
    out.code = ''
    out.code_verifier = ''
  }
  return out
}

/** Parses a redirect URL (or query string) received on an authCode callback. */
export function parseCallbackUrl(input) {
  const text = String(input ?? '').trim()
  if (!text) return null
  let params
  try {
    params = new URL(text).searchParams
  } catch {
    params = new URLSearchParams(text.replace(/^[^?]*\?/, ''))
  }
  const pick = (k) => params.get(k) ?? undefined
  const result = {
    code: pick('code'),
    state: pick('state'),
    businessID: pick('businessID'),
    error_code: pick('error_code'),
    RefID: pick('RefID'),
    code_verifier: pick('code_verifier'),
  }
  return Object.values(result).some(Boolean) ? result : null
}
