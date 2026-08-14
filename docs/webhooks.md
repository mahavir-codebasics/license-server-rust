# Webhooks Guide

license-server delivers account events to your HTTPS endpoints, signed with
HMAC-SHA256 and retried with exponential backoff.

## Register an endpoint

```bash
curl -X POST http://localhost:8080/v1/accounts/$ACCOUNT_ID/webhooks/endpoints \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"url": "https://example.com/hooks/license", "event_types": ["license.created"]}'
```

Response includes the **signing secret exactly once** — store it. (Empty
`event_types` subscribes to everything.)

## Delivery request

The worker POSTs your URL with:

```
POST /hooks/license
Content-Type: application/json
X-License-Signature: t=1723622400,v1=5257a1f0c...   (64 hex chars)
X-License-Event: license.created
X-License-Delivery: 019f99f9-...                     (delivery id)
Retry-After-n/a

{ "id": "…", "event_type": "license.created", "payload": { … } }
```

## Verifying the signature (critical)

The signature is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`. Always
verify against the **raw request body** — re-serialized JSON will not match.

### TypeScript / Node

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody: string, header: string, secret: string, toleranceSec = 300) {
  const [tPart, v1Part] = header.split(",");
  const timestamp = tPart.slice("t=".length);
  const received = v1Part.slice("v1=".length);

  // 1. Replay protection: reject old timestamps
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > toleranceSec) return false;

  // 2. Recompute + constant-time compare
  const expected = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(received, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
```

### Rust (receiver side)

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify(secret: &str, timestamp: &str, raw_body: &[u8], received_hex: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    // constant-time comparison via subtle
    mac.verify_slice(&hex::decode(received_hex).unwrap()).is_ok()
}
```

## Event types

`account.created`, `product.created`, `policy.created`, `license.created`,
`webhook.endpoint.created` (more are recorded in the audit log as features
land; the delivery worker ships with the same set).

## Retries & failure semantics

| Outcome | Treatment |
|---|---|
| 2xx | delivered ✔ |
| 4xx (except 408/429) | **permanent** — marked done, not retried (fix your endpoint) |
| 5xx / 408 / 429 / network error | retried, backoff 10 s → 20 s → 40 s … capped at 1 h |
| endpoint disabled after enqueue | dropped, marked done |

Attempts and the last error are visible on the delivery record; the queue is
Redis-backed (`webhook-delivery` namespace), worker concurrency 8, 15 s
graceful-drain window.

## Respond fast

Your handler should verify + enqueue work and return 2xx **quickly** — the
worker times out at 15 s. Do heavy processing asynchronously.
