// Regenerates the data used by the interactive tools from schemas/iam-smart-api.yaml:
//   src/data/endpoints.json    — POST endpoints for the request signer on /tools/
//   src/data/api-console.json  — every operation and callback, for the "Try it" console on each API page
// Run after editing the OpenAPI file: npm run sync:endpoints
import fs from 'node:fs'
import YAML from 'yaml'

const doc = YAML.parse(fs.readFileSync('schemas/iam-smart-api.yaml', 'utf8'))

function jsonExamples(media) {
  if (!media) return []
  if (media.examples) return Object.entries(media.examples).map(([name, ex]) => ({ name: ex.summary ?? name, value: ex.value }))
  if (media.example !== undefined) return [{ name: 'Example', value: media.example }]
  return []
}

const endpoints = []
const consoleItems = []

for (const [path, item] of Object.entries(doc.paths)) {
  for (const [method, op] of Object.entries(item)) {
    const rateLimit = (op.parameters ?? []).some((p) => p.$ref?.endsWith('rateLimitFactor'))
    if (method === 'get') {
      consoleItems.push({ id: op.operationId, kind: 'getqr', method: 'GET', path, summary: op.summary, deprecated: Boolean(op.deprecated) })
      continue
    }
    const examples = jsonExamples(op.requestBody?.content?.['application/json'])
    const base = {
      id: op.operationId,
      path,
      summary: op.summary,
      tags: op.tags,
      deprecated: Boolean(op.deprecated),
      encrypted: Boolean(op.requestBody),
      rateLimit,
    }
    endpoints.push({ ...base, example: examples[0]?.value ?? null })
    consoleItems.push({ ...base, kind: 'post', method: 'POST', examples })
  }
}

for (const [id, item] of Object.entries(doc.webhooks ?? {})) {
  for (const [method, op] of Object.entries(item)) {
    const content = op.requestBody?.content ?? {}
    const kind = method === 'get' ? 'callback-get' : content['multipart/form-data'] ? 'callback-multipart' : 'callback-json'
    const example = content['application/json']?.example?.content ?? null
    consoleItems.push({ id, kind, method: method.toUpperCase(), summary: op.summary, deprecated: Boolean(op.deprecated), example })
  }
}

fs.writeFileSync('src/data/endpoints.json', JSON.stringify(endpoints, null, 1) + '\n')
fs.writeFileSync('src/data/api-console.json', JSON.stringify(consoleItems, null, 1) + '\n')
console.log(`Wrote ${endpoints.length} POST endpoints and ${consoleItems.length} console entries`)
