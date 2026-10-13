---
description: Official Rust and TypeScript SDKs for license-server-rust — typed clients for license validation, activation, and the machine lifecycle.
---

# SDK Guide

Official clients for license-server. Both are thin, fully-typed wrappers over
the same REST wire format — pick your language; behavior is identical.

| SDK | Location | Runtime deps | Tests |
|---|---|---|---|
| **Rust** (`license-sdk`) | [`crates/sdk`](https://github.com/mahavirvataliya/license-server-rust/tree/main/crates/sdk) | reqwest, serde | 3 E2E suites against the real in-process server |
| **TypeScript** (`@license-server/sdk`) | [`sdks/typescript`](https://github.com/mahavirvataliya/license-server-rust/tree/main/sdks/typescript) | **zero** (global fetch + WebCrypto) | 13 (wire tests + HMAC verification vectors) |

Both SDKs also verified live against a real `license-server` binary (the
TypeScript `examples/issue-and-validate.ts` runs the complete round trip).

## The mental model

1. **Bootstrap once** — create the org, receive its first `adm_` admin token.
2. **Model** products and policies (the signing scheme + limits).
3. **Issue** licenses — the signed key appears exactly once; persist it.
4. **Validate** by id (server-side) or by raw key (device-side).
5. **React** to lifecycle events via signed webhooks.

## Rust

```rust
use license_sdk::LicenseClient;

#[tokio::main]
async fn main() -> Result<(), license_sdk::LicenseError> {
    // Bootstrap a new org (one-time, unauthenticated).
    let (client, org) = LicenseClient::bootstrap("http://localhost:8080", "acme", "ACME Inc.").await?;

    // Model + issue.
    let product = client.create_product("ACME Pro").await?;
    let policy = client.create_policy(&product.id, "monthly", "ED25519_SIGN").await?;
    let license = client.create_license(&product.id, &policy.id).await?;
    let key = license.key.expect("signed key on creation");

    // Validate both ways.
    assert!(client.validate_license(&license.id).await?.valid);
    assert!(client.validate_key(&key).await?.valid);

    // Safe retries: same idempotency key replays the original response.
    let idem = uuid::Uuid::new_v4().to_string();
    let a = client.create_license_idempotent(&product.id, &policy.id, Some(&idem)).await?;
    let b = client.create_license_idempotent(&product.id, &policy.id, Some(&idem)).await?;
    let _ = (a, b, org);
    Ok(())
}
```

Attaching with an existing token:

```rust
let client = LicenseClient::new("https://license.example.com", "adm_…")?
    .with_account(account_id);
```

Error handling — `LicenseError` carries `status`, `code`, and a `kind`:

```rust
match client.validate_key(&key).await {
    Ok(v) if v.valid => { /* proceed */ }
    Ok(v) => eprintln!("invalid ({}): {}", v.state, v.detail.unwrap_or_default()),
    Err(e) if e.kind == LicenseErrorKind::RateLimited => { /* back off */ }
    Err(e) if e.kind == LicenseErrorKind::NotFound => { /* unknown/cross-tenant key */ }
    Err(e) => return Err(e),
}
```

### Verifying webhooks in Rust

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify(secret: &str, timestamp: &str, raw_body: &[u8], received_hex: &str) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    mac.verify_slice(&hex::decode(received_hex).unwrap()).is_ok() // constant-time
}
```

(Full receiver walkthrough: [webhooks.md](webhooks.md).)

## TypeScript

```ts
import { LicenseClient, LicenseError, LicenseErrorKind, verifyWebhook } from "@license-server/sdk";

// Bootstrap once.
const { client, account } = await LicenseClient.bootstrap("http://localhost:8080", "acme", "ACME Inc.");

// Model + issue (idempotency key = safe retries).
const product = await client.createProduct("ACME Pro");
const policy = await client.createPolicy(product.id, "monthly", "ED25519_SIGN");
const license = await client.createLicense(product.id, policy.id, crypto.randomUUID());
const key = license.key!; // present exactly once — persist it

// Validate both ways.
await client.validateLicense(license.id);   // by id
await client.validateKey(key);              // by raw key (device-side)

// Verify a webhook delivery (constant-time, replay-protected).
// ok = await verifyWebhook(rawBody, signatureHeader, secret);
```

Pagination is cursor-based on both SDKs:

```ts
let cursor: string | undefined;
do {
  const page = await client.licenses(cursor);
  for (const lic of page.items) { /* … */ }
  cursor = page.nextCursor;
} while (cursor);
```

```rust
let mut cursor = None;
loop {
    let items = client.products_after(cursor).await?;
    if items.is_empty() { break; }
    // …
    cursor = None; // pass the last id as the next cursor
}
```

## Device-side integration (any language)

Devices only need three calls, all available over REST and gRPC:

| Need | REST | gRPC |
|---|---|---|
| validate by raw key | `POST …/licenses/actions/validate-key` | `ValidateKey` |
| activate a machine | (gRPC) | `Activate` |
| heartbeat (floating) | (gRPC) | `Ping` |

For maximal throughput use gRPC (`proto/license.proto`); the audit measured
the HTTP framework itself at 178k RPS, so either transport is far from the
bottleneck — the per-request DB round trips are (see
[the audit](security-audit.md#part-2-performance-findings)).

## Publishing

- **Rust**: `cargo publish -p license-sdk` (crate is self-contained; no
  internal-crate dependencies).
- **TypeScript**: `npm publish` from `sdks/typescript/` (source-exported
  package; consumers using tsc/bundlers consume it as-is. If you need plain
  JS output, add your preferred build step — the code intentionally avoids
  non-erasable TS syntax).

## Live verification

The TypeScript SDK ships a runnable end-to-end example:

```bash
cargo run -p license-server &
cd sdks/typescript
node --experimental-strip-types examples/issue-and-validate.ts
```

Output (verified):

```
org: 01a000a1-eb43-…
policy: … (ED25519_SIGN)
license: …
signed key (persist me): djEuMDFhMDAwYTEtZWI0My03YzUzLThk…
validate by id:  { valid: true, state: 'active', detail: null }
validate by key: { valid: true, state: 'active', detail: null }
full round trip OK
```
