// End-to-end test of the "Try it" consoles in a real browser (run in CI after `npm run build`).
//   node tests/e2e/consoles.e2e.mjs
// Serves dist/ under SITE_BASE, starts the mock gateway, then drives Chromium through a full login:
// Request CEK → getQR (mock) → authCode callback page → Request accessToken → Obtain Profiles → anonymous step-up.
// Failures are printed as GitHub annotations (::error::).
import { spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { chromium } from 'playwright'

const base = (process.env.SITE_BASE || '/').replace(/\/?$/, '/')
const dist = path.resolve('dist')
const SITE_PORT = 4399
const MOCK_PORT = 8787
const site = `http://localhost:${SITE_PORT}${base}`
let failures = 0

function fail(msg) {
  failures++
  console.log(`::error::${msg.replace(/\n/g, ' ')}`)
}

// ---- static check: every API page has a console ----------------------------------------
const items = JSON.parse(fs.readFileSync('src/data/api-console.json', 'utf8'))
for (const item of items) {
  const dir = item.kind.startsWith('callback') ? 'webhooks' : 'operations'
  const file = path.join(dist, 'api', dir, item.id, 'index.html')
  if (!fs.existsSync(file)) fail(`missing page ${file}`)
  else if (!fs.readFileSync(file, 'utf8').includes('<ist-console')) fail(`no Try it console on /api/${dir}/${item.id}/`)
}
console.log(`static check: ${items.length} API pages`)

// ---- servers ------------------------------------------------------------------------------
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json', '.woff2': 'font/woff2', '.png': 'image/png' }
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname)
  if (!p.startsWith(base)) return res.writeHead(404).end()
  p = path.join(dist, p.slice(base.length))
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, 'index.html')
  if (!fs.existsSync(p)) return res.writeHead(404).end('not found')
  res.writeHead(200, { 'Content-Type': types[path.extname(p)] ?? 'application/octet-stream' })
  fs.createReadStream(p).pipe(res)
})
await new Promise((r) => server.listen(SITE_PORT, r))

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'iamsmart-e2e-'))
fs.writeFileSync(path.join(tmp, 'kek.pem'), publicKey.export({ type: 'spki', format: 'pem' }))
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
const mock = spawn(process.execPath, ['examples/mock-server/mock-iam-smart.mjs'], {
  env: { ...process.env, PORT: String(MOCK_PORT), CLIENT_ID: 'demo-client', CLIENT_SECRET: 'demo-secret', KEK_PUBLIC_KEY: path.join(tmp, 'kek.pem') },
  stdio: ['ignore', 'pipe', 'inherit'],
})
await new Promise((r) => mock.stdout.once('data', r))

const browser = await chromium.launch()
const page = await (await browser.newContext()).newPage()
page.on('pageerror', (e) => fail(`page error on ${page.url()}: ${e.message}`))

async function openConsole(slug) {
  await page.goto(`${site}api/${slug}/`)
  const details = page.locator('ist-console > details')
  if (!(await details.evaluate((d) => d.open))) await page.locator('ist-console > details > summary').click()
}
const c = (name) => page.locator(`ist-console [data-el=${name}]`).first()

async function step(name, fn) {
  try {
    await fn()
    console.log(`ok   ${name}`)
  } catch (e) {
    fail(`${name}: ${e.message.split('\n')[0]}`)
  }
}

async function sendAndExpectSuccess(label) {
  await c('send').click()
  await page.waitForFunction(() => {
    const s = document.querySelector('ist-console [data-el=status]')?.textContent ?? ''
    return /Success|error|could not|Enter|Set a CEK/i.test(s) && !/Sending/.test(s)
  }, null, { timeout: 15000 })
  const status = await c('status').textContent()
  if (!/^Success/.test(status)) throw new Error(`${label}: ${status} — ${(await c('response').textContent()).slice(0, 300)}`)
  return JSON.parse(await c('response').textContent())
}

try {
  await step('Request CEK via the mock', async () => {
    await openConsole('operations/request-cek')
    await c('env').selectOption('mock')
    await c('clientId').fill('demo-client')
    await c('clientId').dispatchEvent('change')
    await c('secret').fill('demo-secret')
    await c('keep').check()
    await page.locator('ist-console [data-el=pemDetails] > summary').click()
    await c('pem').fill(pem)
    await c('pem').dispatchEvent('change')
    await c('secret').dispatchEvent('change')
    const res = await sendAndExpectSuccess('getKey')
    if (!/unwrapped/.test(await c('status').textContent())) throw new Error('CEK was not unwrapped')
    if (!res.content?.secretKey) throw new Error('no secretKey in response')
  })

  await step('getQR → mock approve → authCode callback page', async () => {
    await openConsole('operations/get-qr-page')
    const q = (n) => page.locator(`ist-getqr [data-el=${n}]`)
    await q('env').selectOption('http://localhost:8787')
    await q('clientId').fill('demo-client')
    await q('redirectURI').fill(`${site}api/webhooks/auth-code-callback/`)
    await q('redirectURI').dispatchEvent('input')
    const url = await q('open').getAttribute('href')
    if (!url?.startsWith('http://localhost:8787/api/v1/auth/getQR?')) throw new Error(`unexpected getQR URL ${url}`)
    await page.goto(url)
    await page.getByRole('link', { name: 'Approve' }).click()
    await page.waitForURL(/auth-code-callback/)
    await page.waitForFunction(() => /Code saved/.test(document.querySelector('ist-console [data-el=status]')?.textContent ?? ''), null, { timeout: 10000 })
    const href = await c('exchangeLink').getAttribute('href')
    if (!href?.startsWith(`${base}api/operations/request-access-token/`)) throw new Error(`exchange link not base-prefixed: ${href}`)
  })

  await step('Request accessToken with the saved code', async () => {
    await openConsole('operations/request-access-token')
    const body = JSON.parse(await c('body').inputValue())
    if (!body.code || body.code.startsWith('xxx')) throw new Error(`code was not pre-filled: ${body.code}`)
    const res = await sendAndExpectSuccess('getToken')
    if (!res.content?.accessToken) throw new Error('no accessToken')
  })

  await step('Obtain Profiles with the session token', async () => {
    await openConsole('operations/obtain-profiles')
    if (!/accessToken, openID/.test(await c('filled').textContent())) throw new Error('token not pre-filled')
    const res = await sendAndExpectSuccess('profiles')
    if (res.content?.idNo?.Identification !== 'A123456') throw new Error('unexpected profile content')
  })

  await step('Anonymous step-up with rateLimitFactor', async () => {
    await openConsole('operations/request-anonymous-step-up-authentication')
    const res = await sendAndExpectSuccess('anonymous sua')
    if (!res.content?.ticketID) throw new Error('no ticketID')
    const http = await c('http').textContent()
    if (!/rateLimitFactor: /.test(http)) throw new Error('rateLimitFactor header missing')
  })

  await step('getQR picks up the ticketID', async () => {
    await openConsole('operations/get-qr-page')
    const t = await page.locator('ist-getqr [data-el=ticketID]').inputValue()
    if (!t) throw new Error('ticketID not pre-filled')
  })

  await step('Production cannot be sent from the browser', async () => {
    await openConsole('operations/verify-ccic-user')
    await c('env').selectOption('production')
    if (!(await c('send').isDisabled())) throw new Error('send is enabled for production')
  })

  await step('Callback page decrypts a mock callback', async () => {
    let received
    const sink = http.createServer((req, res) => {
      let b = ''
      req.on('data', (d) => (b += d))
      req.on('end', () => {
        received = b
        res.end('ok')
      })
    })
    await new Promise((r) => sink.listen(4398, r))
    await openConsole('webhooks/step-up-authentication-result-callback')
    await page.locator('ist-console > details details:has([data-el=sendCallback]) > summary').click()
    await c('targetUrl').fill('http://localhost:4398/cb')
    await c('sendCallback').click()
    await page.waitForFunction(() => /HTTP 200/.test(document.querySelector('ist-console [data-el=cbStatus]')?.textContent ?? ''), null, { timeout: 10000 })
    sink.close()
    await page.locator('ist-decrypt [data-el=callback]').fill(received)
    await page.locator('ist-decrypt [data-el=go]').click()
    await page.waitForFunction(() => /isPassed/.test(document.querySelector('ist-decrypt [data-el=out]')?.textContent ?? ''), null, { timeout: 10000 })
  })
  // ---- anonymous step-up playground ------------------------------------------------------
  const pgEl = (step, name) => page.locator(`flow-playground [data-step=${step}] [data-el=${name}]`)
  const pg0 = (name) => page.locator(`flow-playground [data-el=${name}]`).first()
  const waitStatus = (step, re) =>
    page.waitForFunction(
      ([s, src]) => new RegExp(src).test(document.querySelector(`flow-playground [data-step=${s}] [data-el=status]`)?.textContent ?? ''),
      [step, re.source],
      { timeout: 15000 },
    )
  const statusText = (step) => pgEl(step, 'status').textContent()

  await step('Playground: signing check in copy-curl mode', async () => {
    await page.goto(`${site}playground/anonymous-step-up/`)
    await pg0('env').selectOption('mock')
    await pg0('clientId').fill('demo-client')
    await pg0('secret').fill('demo-secret')
    await pg0('pem').fill(pem)
    await pg0('pem').dispatchEvent('change')
    await pg0('modeManual').check()
    await pgEl('sign', 'signGo').click()
    const curl = await page.locator('flow-playground [data-step=sign] [data-el=manual] pre').textContent({ timeout: 10000 })
    // Execute the curl command ourselves, as a user would in a terminal.
    const url = curl.match(/curl -sS -X POST '([^']+)'/)[1]
    const headers = Object.fromEntries([...curl.matchAll(/-H '([^:]+): ([^']*)'/g)].map((m) => [m[1], m[2]]))
    const body = curl.match(/--data-raw '([^']*)'/)?.[1]
    const response = await (await fetch(url, { method: 'POST', headers, body })).text()
    await page.locator('flow-playground [data-step=sign] [data-el=manual] textarea').fill(response)
    await page.locator('flow-playground [data-step=sign] [data-el=manual] button', { hasText: 'Continue' }).click()
    await waitStatus('sign', /Signature accepted|failed|Error/)
    if (!/Signature accepted/.test(await statusText('sign'))) throw new Error(await statusText('sign'))
  })

  await step('Playground: initiateRequest sent from the browser', async () => {
    await pg0('modeSend').check()
    await pgEl('init', 'hkic').fill('A123456(7)')
    await page.locator('flow-playground input[name=sua-method][value="FR,NFC"]').check()
    await pgEl('init', 'initGo').click()
    await waitStatus('init', /ticketID received|D\d{5}|could not|Enter/)
    if (!/ticketID received/.test(await statusText('init'))) throw new Error(await statusText('init'))
    const plain = JSON.parse(await pgEl('init', 'plain').textContent())
    const expectedHash = crypto.createHash('sha256').update('A123456').digest('base64')
    if (plain.HKICHash !== expectedHash) throw new Error('HKICHash mismatch')
    if (plain.suaMethod !== '{"and":["FR","NFC"]}') throw new Error(`suaMethod ${plain.suaMethod}`)
    if (!/rateLimitFactor: /.test(await pgEl('init', 'wire').textContent())) throw new Error('rateLimitFactor header missing')
    if (!(await pgEl('qr', 'ticketID').inputValue())) throw new Error('ticketID not passed to step 3')
  })

  await step('Playground: getQR → approve → result on the playground page', async () => {
    const href = await pgEl('qr', 'qrOpen').getAttribute('href')
    if (!/scope=eidapi_sua/.test(href) || !/ticketID=[0-9a-f]{32}/.test(href)) throw new Error(`bad getQR URL ${href}`)
    await page.goto(href)
    await page.getByRole('link', { name: 'Approve' }).click()
    await page.waitForURL(/playground\/anonymous-step-up\//)
    await page.waitForFunction(() => /isPassed: true/.test(document.querySelector('flow-playground [data-el=verdict]')?.textContent ?? ''), null, { timeout: 15000 })
  })
  await step('Form filling playground: initiateRequest → getQR → approve → data', async () => {
    await page.goto(`${site}playground/anonymous-form-filling/`)
    await pg0('env').selectOption('mock')
    await pg0('clientId').fill('demo-client')
    await pg0('secret').fill('demo-secret')
    await pg0('pem').fill(pem)
    await pg0('pem').dispatchEvent('change')
    await pg0('modeSend').check()
    await page.locator('flow-playground input[name=ff-eme][value=addressDocInfo]').check()
    await pgEl('init', 'initGo').click()
    await waitStatus('init', /ticketID received|D\d{5}|could not|Enter|Select/)
    if (!/ticketID received/.test(await statusText('init'))) throw new Error(await statusText('init'))
    const plain = JSON.parse(await pgEl('init', 'plain').textContent())
    if (!plain.profileFields?.includes('idNo') || !plain.eMEFields?.includes('addressDocInfo')) throw new Error(`fields not sent: ${JSON.stringify(plain)}`)
    if (/rateLimitFactor: /.test(await pgEl('init', 'wire').textContent())) throw new Error('form filling must not send rateLimitFactor')
    const href = await pgEl('qr', 'qrOpen').getAttribute('href')
    if (!/scope=eidapi_formFilling/.test(href)) throw new Error(`bad scope in ${href}`)
    await page.goto(href)
    await page.getByRole('link', { name: 'Approve' }).click()
    await page.waitForURL(/playground\/anonymous-form-filling\//)
    await page.waitForFunction(() => /fields? returned/.test(document.querySelector('flow-playground [data-el=verdict]')?.textContent ?? ''), null, { timeout: 15000 })
    const table = await page.locator('flow-playground [data-el=dataRows]').textContent()
    if (!/A123456\(A\)/.test(table) || !/SAN, Chi Nan/.test(table)) throw new Error(`unexpected data table: ${table.slice(0, 200)}`)
  })
} finally {
  await browser.close()
  mock.kill()
  server.close()
  fs.rmSync(tmp, { recursive: true, force: true })
}

console.log(failures ? `${failures} failure(s)` : 'all console checks passed')
process.exit(failures ? 1 : 0)
