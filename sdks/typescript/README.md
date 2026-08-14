# @license-server/sdk

TypeScript client for [license-server](../../README.md). Zero runtime
dependencies (global `fetch` + WebCrypto) — works in Node 18+, Bun, Deno,
browsers, and edge runtimes.

## Install

```bash
npm install @license-server/sdk
# or: pnpm / bun / yarn
```

## Bootstrap your org (once)

```ts
import { LicenseClient } from "@license-server/sdk";

// The only unauthenticated call — creates the org and its FIRST admin token.
const { client, account } = await LicenseClient.bootstrap(
  "http://localhost:8080",
  "acme",
  "ACME Inc.",
);
// persist account.admin_token somewhere safe — it is shown exactly once
```

## Issue licenses

```ts
const product = await client.createProduct("ACME Pro");
const policy  = await client.createPolicy(product.id, "monthly", "ED25519_SIGN");

// The signed key is present ONLY on this response — persist it.
const license = await client.createLicense(product.id, policy.id);
console.log("license key:", license.key);
```

For safe retries on flaky networks, pass an idempotency key (the server
replays the original response when Redis is configured):

```ts
const license = await client.createLicense(product.id, policy.id, crypto.randomUUID());
```

## Validate (device side)

```ts
// By the raw key — the device usually doesn't know the license id.
const result = await client.validateKey(license.key!);
if (!result.valid) {
  console.error(`license invalid (${result.state}): ${result.detail}`);
}
```

## Verify webhooks (receiver side)

```ts
import { verifyWebhook } from "@license-server/sdk";

app.post("/hooks/license", async (req, res) => {
  const raw = await readRawBody(req); // the RAW body — never re-serialized
  const ok = await verifyWebhook(raw, req.header("x-license-signature")!, WEBHOOK_SECRET);
  if (!ok) return res.status(400).end();
  // ...enqueue processing, return 2xx fast (worker times out at 15s)
});
```

## Attach with an existing token

```ts
const client = LicenseClient.new("https://license.example.com", "adm_…", accountId);
```

## Error handling

```ts
import { LicenseError, LicenseErrorKind } from "@license-server/sdk";

try {
  await client.validateKey(key);
} catch (e) {
  if (e instanceof LicenseError) {
    switch (e.kind) {
      case LicenseErrorKind.RateLimited: /* back off, honor e.status */ break;
      case LicenseErrorKind.NotFound:    /* unknown or cross-tenant key */ break;
      case LicenseErrorKind.Auth:        /* bad token */ break;
      default:                           /* see e.code / e.message */ break;
    }
  }
}
```

## API surface

| Method | REST call |
|---|---|
| `LicenseClient.bootstrap(base, slug, name)` | `POST /v1/accounts` |
| `LicenseClient.new(base, token, accountId)` | — (attach) |
| `account()` | `GET /accounts/{id}` |
| `createProduct(name)` / `products(cursor?)` | `POST` / `GET /accounts/{id}/products` |
| `createPolicy(productId, name, scheme)` / `policies(cursor?)` | `…/policies` |
| `createLicense(productId, policyId, idempotencyKey?)` | `…/licenses` |
| `licenses(cursor?)` | `…/licenses` |
| `validateLicense(licenseId)` | `POST …/licenses/{id}/actions/validate` |
| `validateKey(key)` | `POST …/licenses/actions/validate-key` |
| `checkOut(licenseId)` | `POST …/licenses/{id}/actions/check-out` |
| `machines(cursor?)` | `GET …/machines` |
| `createToken(kind, name?)` / `tokens(cursor?)` | `…/tokens` |
| `createWebhook(url, eventTypes?)` / `webhooks(cursor?)` | `…/webhooks/endpoints` |
| `events(cursor?)` | `GET …/events` (audit log) |
| `verifyWebhook(rawBody, header, secret)` | (local crypto, no network) |

Full server docs: [`docs/api-reference.md`](../../docs/api-reference.md)

## Development

```bash
pnpm install
pnpm typecheck   # tsc --noEmit
pnpm test        # node --test (wire tests against an in-process server)
```
