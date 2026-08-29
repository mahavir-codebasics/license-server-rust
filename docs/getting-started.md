---
description: Install license-server-rust and issue your first signed license in five minutes — bootstrap an org, create a product and policy, then validate over REST.
---

# Getting Started

Get a licensing server running in under five minutes, then issue and validate your first license.

## 1. Start the stack

The fastest path is Docker Compose (Postgres + Redis + API + UI):

```bash
git clone <this-repo> && cd license-server-rust
docker compose up -d
# API:   http://localhost:8080  (REST)
# gRPC:  localhost:9090
# UI:    http://localhost:3000  (docker compose --profile ui up -d)
```

Or run the binary directly against SQLite (zero external dependencies):

```bash
export LICENSE_SERVER__DATABASE__URL=sqlite:///tmp/license.db
export LICENSE_SERVER__REDIS__URL=redis://localhost:6379/0
export LICENSE_SERVER__CRYPTO__MASTER_KEY=$(openssl rand -hex 32)

cargo run -p license-server
# ... http listening addr=0.0.0.0:8080
# ... grpc listening addr=0.0.0.0:9090
```

> The master key encrypts signing-key material at rest (AES-256-GCM). Losing
> it means losing all license files' decryptability — store it in a secret
> manager for production.

## 2. Create your organization (bootstrap)

`POST /v1/accounts` is the bootstrap call — it creates the org **and** returns
its first admin token. Save the token; it is shown exactly once.

```bash
curl -sS -X POST http://localhost:8080/v1/accounts \
  -H 'content-type: application/json' \
  -d '{"slug": "acme", "name": "ACME Inc."}'
```

```json
{
  "data": {
    "id": "019f99f9-6063-7c02-bca9-04722c894a9c",
    "slug": "acme",
    "name": "ACME Inc.",
    "admin_token": "adm_IwBWEwkHDQFqrVVQoI2OU3kQdP..."
  }
}
```

```bash
ACCOUNT_ID=019f99f9-...   # from above
TOKEN=adm_IwBW...          # from above — store it safely
```

## 3. Model your product and policy

A **product** is what you're licensing. A **policy** is the rule template
licenses inherit — signing scheme, machine limits, heartbeats.

```bash
# Product
PRODUCT_ID=$(curl -sS -X POST http://localhost:8080/v1/accounts/$ACCOUNT_ID/products \
  -H 'content-type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "ACME Pro"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')

# Policy: Ed25519-signed keys, node-locked to 1 machine
POLICY_ID=$(curl -sS -X POST http://localhost:8080/v1/accounts/$ACCOUNT_ID/policies \
  -H 'content-type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d "{\"product_id\": \"$PRODUCT_ID\", \"name\": \"pro-monthly\", \"scheme\": \"ED25519_SIGN\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["id"])')
```

Available schemes: `ED25519_SIGN` (recommended), `ECDSA_P256_SHA256`,
`RSA_2048_PSS_SHA256`, `RSA_2048_PKCS1V15_SHA256`, `JWT_RS256`, `JWT_EDDSA`.

## 4. Issue a license (the signed key is shown ONCE)

```bash
curl -sS -X POST http://localhost:8080/v1/accounts/$ACCOUNT_ID/licenses \
  -H 'content-type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d "{\"product_id\": \"$PRODUCT_ID\", \"policy_id\": \"$POLICY_ID\"}"
```

```json
{
  "data": {
    "id": "019f99f9-aadf-76a0-bd10-0218f9ef6602",
    "key": "djEuMDE5Zjk5ZjktNjA3MC03YjgzLWE4...",
    "state": "active"
  }
}
```

The `key` is the Ed25519-signed license key (`v1.<account>.<license>.<nonce>` +
signature, base64). Hand it to your customer's device. The server stores only
its SHA-256 hash — if you lose it, re-issue the license.

## 5. Validate (from your application)

```bash
# By license id (server-side, authenticated)
curl -sS -X POST \
  http://localhost:8080/v1/accounts/$ACCOUNT_ID/licenses/$LICENSE_ID/actions/validate \
  -H "Authorization: Bearer $TOKEN"
# -> {"data":{"valid":true,"state":"active","detail":null}}
```

Via **gRPC** (the high-throughput path for devices):

```bash
grpcurl -plaintext -d "{\"account_id\":\"$ACCOUNT_ID\",\"license_id\":\"$LICENSE_ID\"}" \
  localhost:9090 licensev1.LicenseService/Validate
```

## 6. Try the admin UI

```bash
cd ui && pnpm install && pnpm dev
# open http://localhost:3000 — sign in with ACCOUNT_ID + TOKEN
```

Create products/policies/licenses, mint tokens, register webhooks, and read
the audit log — all through the console.

## Where to go next

- [API reference](api-reference.md) — every endpoint, envelope, and error code
- [SDK guide](sdk-guide.md) — Rust and TypeScript clients
- [Webhooks](webhooks.md) — HMAC-signed event delivery
- [Deployment](deployment.md) — production hardening checklist
- [Security audit](security-audit.md) — known findings and remediation order
