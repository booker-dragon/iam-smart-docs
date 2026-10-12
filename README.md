# iAM Smart API — interactive docs

Interactive documentation for the **iAM Smart API Specification v2.5.2** (February 2026), built with [Starlight](https://starlight.astro.build) and [starlight-openapi](https://github.com/HiDeoo/starlight-openapi).

- **API reference** generated from [`schemas/iam-smart-api.yaml`](schemas/iam-smart-api.yaml) — an OpenAPI 3.1 transcription of all 39 operations and 12 callbacks (as webhooks), with decrypted request/response examples.
- **Guides** for every feature and device scenario (same/different device, website/app, appv1/appv2, anonymous flows).
- **Developer tools** that run in the browser: request signer + encryptor, CEK unwrapper, response/callback decryptor, HKICHash calculator, getQR and app deep link builders, return code lookup.
- **Reference clients** for Node.js and Python, and a **local mock gateway** that enforces signing and encryption — see [`examples/`](examples).

> Unofficial rendering for developer convenience. The [PDF specification](iAM_Smart_API_Specification_v2.5.2.pdf) is authoritative; see `/reference/errata/` for inconsistencies found while transcribing.

## Run locally

Requires Node.js 22.12 or later.

```sh
npm install
npm run dev        # http://localhost:4321
npm test           # crypto helpers, reference client and mock server
npm run build      # static site in dist/
```

## Deploy to GitHub Pages

1. Push this project to `main`.
2. In the repository, open **Settings → Pages** and set **Source** to **GitHub Actions**.
3. The workflow in `.github/workflows/deploy.yml` tests, builds and publishes to `https://<owner>.github.io/<repo>/`.

The site is configured for a project site under `/<repo>/` through the `SITE_URL` and `SITE_BASE` environment variables. Links written as `/guides/…` in Markdown and in the OpenAPI file are prefixed with the base path after the build by `scripts/prefix-base.mjs`. To deploy at a domain root (Netlify, Vercel, Cloudflare Pages, a custom domain), leave `SITE_BASE` unset.

## Project layout

```
schemas/iam-smart-api.yaml      OpenAPI 3.1 description (source of the API reference)
src/content/docs/               Guides and reference pages (MDX)
src/components/                 Interactive tools (Astro components, client-side scripts)
src/lib/iam-smart-crypto.js     Browser crypto: AES-256-GCM, HMAC-SHA256, RSA CEK unwrap
src/data/                       Return codes, source values, scopes, deep links, endpoint list
examples/node/                  Node.js reference client (no dependencies)
examples/python/                Python reference client (needs `cryptography`)
examples/mock-server/           Local mock of the iAM Smart gateway
tests/                          node:test suite
```

## Editing the API description

`schemas/iam-smart-api.yaml` is the single source for the API reference. Request and response bodies are documented **decrypted**; the wire format is described once in the Encryption guide. Each operation description ends with the spec section it came from. If you change POST endpoints or their examples, run `npm run sync:endpoints` to refresh `src/data/endpoints.json`, which the request signer tool uses.

## About the content

The guides and API description paraphrase and restructure the official specification, which is © the Government of the HKSAR and states that it may not be reproduced without permission. If you plan to publish this site publicly, check with the iAM Smart support team (iamsmart@cyberport.hk) first, or deploy it privately (for example as an internal or access-controlled site).
