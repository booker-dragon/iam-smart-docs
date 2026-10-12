// Post-build: prefix root-relative links with the Astro `base` (e.g. /iam-smart-docs/).
// Links written in Markdown and in the OpenAPI descriptions are root-relative ("/guides/…");
// Astro does not rewrite those, so on a GitHub Pages project site they would 404 without this step.
import fs from 'node:fs'
import path from 'node:path'

const base = (process.env.SITE_BASE || '/').replace(/\/?$/, '/')
if (base === '/') process.exit(0)

const dist = path.resolve('dist')
const prefix = base.slice(0, -1) // "/iam-smart-docs"
let files = 0
let links = 0

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(p)
    else if (entry.name.endsWith('.html')) rewrite(p)
  }
}

function rewrite(file) {
  const html = fs.readFileSync(file, 'utf8')
  const out = html.replace(/(\s(?:href|src)=["'])\/(?!\/)/g, (match, attr, offset) => {
    // Skip links Astro already prefixed.
    if (html.startsWith(prefix + '/', offset + attr.length)) return match
    links++
    return `${attr}${prefix}/`
  })
  if (out !== html) {
    fs.writeFileSync(file, out)
    files++
  }
}

walk(dist)
console.log(`prefix-base: rewrote ${links} links in ${files} files under ${base}`)
