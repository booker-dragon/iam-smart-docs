# Examples

| Path | What it is |
| --- | --- |
| `node/iam-smart-client.mjs` | Node.js ≥ 20 reference client, no dependencies. Handles the CEK, AES-256-GCM encryption, HMAC-SHA256 signing and callback decryption. |
| `python/iam_smart_client.py` | Python ≥ 3.9 reference client. Needs `pip install cryptography`. |
| `mock-server/mock-iam-smart.mjs` | Local stand-in for the iAM Smart gateway that enforces signing and encryption. |

Quick test with the mock:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=iam-smart-test" -keyout kek-private.pem -out kek-cert.pem
CLIENT_ID=demo-client CLIENT_SECRET=demo-secret KEK_PUBLIC_KEY=./kek-cert.pem node mock-server/mock-iam-smart.mjs
```

```js
import fs from 'node:fs'
import { IamSmartClient } from './node/iam-smart-client.mjs'

const c = new IamSmartClient({
  baseUrl: 'http://localhost:8787',
  clientId: 'demo-client',
  clientSecret: 'demo-secret',
  privateKeyPem: fs.readFileSync('kek-private.pem', 'utf8'),
})
console.log(await c.getCek()) // fetched, unwrapped and cached
```

The spec does not name the RSA padding used to wrap the CEK; both clients default to trying PKCS#1 v1.5, then OAEP. Never commit real keys (`*.pem` is git-ignored).
