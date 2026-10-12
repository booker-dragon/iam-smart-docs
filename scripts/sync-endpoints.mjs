// Regenerates src/data/endpoints.json (used by the request signer tool) from schemas/iam-smart-api.yaml.
// Run after editing POST operations or their request examples: npm run sync:endpoints
import fs from 'node:fs'
import YAML from 'yaml'

const doc = YAML.parse(fs.readFileSync('schemas/iam-smart-api.yaml', 'utf8'))
const out = []
for (const [path, item] of Object.entries(doc.paths)) {
  const op = item.post
  if (!op) continue
  const media = op.requestBody?.content?.['application/json']
  const example = media?.example ?? (media?.examples ? Object.values(media.examples)[0].value : null)
  out.push({
    id: op.operationId,
    path,
    summary: op.summary,
    tags: op.tags,
    deprecated: Boolean(op.deprecated),
    encrypted: Boolean(op.requestBody),
    rateLimit: (op.parameters ?? []).some((p) => p.$ref?.endsWith('rateLimitFactor')),
    example: example ?? null,
  })
}
fs.writeFileSync('src/data/endpoints.json', JSON.stringify(out, null, 1) + '\n')
console.log(`Wrote ${out.length} POST endpoints to src/data/endpoints.json`)
