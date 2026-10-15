import assert from 'node:assert/strict'
import { test } from 'node:test'
import fs from 'node:fs'

import { baseUrl, canSend, captureFromResponse, cekValid, fillExample, parseCallbackUrl, state } from '../src/lib/console-state.js'

test('fillExample swaps in session values and fresh identifiers', () => {
  const example = { businessID: 'bbb8', accessToken: 'placeholder', openID: 'placeholder', state: 'eddd527b6', hashCode: 'x' }
  const { body, filled } = fillExample(example, { accessToken: 'real-token', openID: 'real-id' })
  assert.equal(body.accessToken, 'real-token')
  assert.equal(body.openID, 'real-id')
  assert.deepEqual(filled, ['accessToken', 'openID'])
  assert.match(body.businessID, /^[0-9a-f]{32}$/)
  assert.notEqual(body.state, 'eddd527b6')
  assert.equal(body.hashCode, 'x')
  assert.equal(example.accessToken, 'placeholder', 'example is not mutated')
})

test('captureFromResponse keeps tokens and forgets a used auth code', () => {
  const out = captureFromResponse({ accessToken: 't', openID: 'o', issueAt: 1000, expiresIn: 500, tokenType: 'Bearer' }, { code: 'c', grantType: 'authorization_code' })
  assert.deepEqual(out, { accessToken: 't', openID: 'o', accessTokenExpiresAt: 1500, code: '', code_verifier: '' })
  assert.deepEqual(captureFromResponse({ ticketID: 'tk' }), { ticketID: 'tk' })
})

test('parseCallbackUrl reads redirects and query strings', () => {
  assert.deepEqual(
    Object.fromEntries(Object.entries(parseCallbackUrl('https://rp/cb?code=abc&state=s1')).filter(([, v]) => v)),
    { code: 'abc', state: 's1' },
  )
  assert.equal(parseCallbackUrl('?error_code=D40001&state=s').error_code, 'D40001')
  assert.equal(parseCallbackUrl('app://landing?code=x&code_verifier=v').code_verifier, 'v')
  assert.equal(parseCallbackUrl('nothing here'), null)
})

test('environment helpers block sending to production', () => {
  assert.equal(baseUrl({ env: 'mock' }), 'http://localhost:8787')
  assert.equal(baseUrl({ env: 'custom', customUrl: 'https://x.test/' }), 'https://x.test')
  assert.equal(canSend({ env: 'production' }), false)
  assert.equal(canSend({ env: 'testing' }), true)
  assert.equal(canSend({ env: 'custom', customUrl: '' }), false)
})

test('cekValid honours the expiry margin', () => {
  assert.equal(cekValid({ cek: 'k', cekExpiresAt: Date.now() + 120_000 }), true)
  assert.equal(cekValid({ cek: 'k', cekExpiresAt: Date.now() + 30_000 }), false)
  assert.equal(cekValid({ cek: 'k' }), true)
  assert.equal(cekValid({}), false)
})

test('state degrades gracefully without browser storage', () => {
  assert.equal(state.settings().env, 'testing')
  state.saveSession({ accessToken: 'x' })
  assert.deepEqual(state.session(), {})
})

test('every API page has console data', () => {
  const spec = fs.readFileSync('schemas/iam-smart-api.yaml', 'utf8')
  const items = JSON.parse(fs.readFileSync('src/data/api-console.json', 'utf8'))
  const ids = new Set(items.map((i) => i.id))
  for (const [, id] of spec.matchAll(/^\s+operationId: (\S+)$/gm)) assert.ok(ids.has(id), `missing console entry for ${id}`)
})
