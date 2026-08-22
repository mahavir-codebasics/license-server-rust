# API Reference

Base URL: `http://localhost:8080` · Version: `v1` · Transports: **REST/JSON** (this page) and **gRPC** (`licensev1.LicenseService`, port 9090 — see `proto/license.proto`).

## Conventions

### Envelope

Every response is wrapped:

```json
// single resource
{ "data": { ... } }

// collection (keyset pagination — no OFFSET anywhere)
{ "data": [ ... ], "meta": { "cursor": "019f99f9-...", "has_more": true } }

// error
{ "errors": [ { "code": "not_found", "title": "Not found", "detail": "...", "status": 404 } ] }
```

Pagination: `?page[limit]=25&page[after]=<cursor>` (limit clamped to 1–100).

### Authentication

`Authorization: Bearer <token>` — the same tokens work on REST and gRPC (gRPC: send the `authorization` metadata; see the security audit's SEC-002 note on gRPC auth enforcement status).

| Token kind | Prefix | Can |
|---|---|---|
| admin | `adm_` | everything in its account, incl. minting tokens |
| product | `prod_` | create licenses for its product |
| license | `lic_` | act on behalf of one license (validate/activate) |
| user / personal | `usr_` / `pat_` | scoped user actions / API automation |

Tokens are stored server-side **only as SHA-256 hashes**; the plaintext is
returned once at creation.

### Common error codes

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | malformed id/body |
| 401 | `unauthorized` | missing/invalid bearer token |
| 403 | `forbidden` | token not allowed for this account/action |
| 404 | `not_found` | missing **or cross-tenant** (existence is never leaked) |
| 409 | `conflict` / `invalid_state` | uniqueness violation / illegal state transition |
| 422 | `policy_violated` | e.g. `max_machines` reached, `max_uses` exceeded |
| 429 | `rate_limited` | see `Retry-After` header |
| 500 | `internal` | sanitized; details only in server logs |

### Rate limits (when Redis is configured)

Per account+route-class token buckets: reads 600/min, mutations 120/min,
`actions/validate` 2,000/min (SDKs hammer it). 429 responses carry
`Retry-After`.

### Idempotency

`POST /v1/accounts/{id}/licenses` accepts an `Idempotency-Key: <uuid>` header
(Redis-backed, 24 h). Retries with the same key replay the original response
instead of double-issuing.

---

## Authentication (self-service signup/login)

Email + password accounts for the admin console and API. Passwords are
hashed with argon2id; the hash is never returned. Both endpoints are
IP-rate-limited. Login failures are a generic 401 (no email enumeration).

### `POST /v1/auth/signup` — create a user + their own org 🔓

Self-service tenant bootstrap: creates the **user**, their **account**
(slug derived from the email, unique), an Owner membership, and a personal
(admin-capable) bearer token — so an individual can immediately manage
products, policies and licenses.

```json
// request
{ "email": "founder@startup.io", "password": "min-8-chars",
  "full_name": "Founder", "org_name": "Startup Inc" }   // name/org optional
// response data
{ "user": { "id": "…", "email": "founder@startup.io", "status": "active", … },
  "account": { "id": "019f…", "slug": "founder", "name": "Startup Inc", … },
  "token": "pat_…" }   // plaintext, shown ONCE
```

Errors: `409` email already registered · `400` invalid email / short password.

### `POST /v1/auth/login` — sign in 🔓

Verifies the password and mints a fresh personal token for the user's
organization (their first membership). `401` invalid credentials · `403`
suspended user.

```json
// request
{ "email": "founder@startup.io", "password": "…" }
// response data — same shape as signup
```

---

## Accounts (organizations)

### `POST /v1/accounts` — bootstrap an org 🔓

Unauthenticated by design (first-boot). Creates the account **and its first
admin token** (shown once). See [security audit SEC-005](security-audit.md)
for the production gating recommendation.

```json
// request
{ "slug": "acme", "name": "ACME Inc." }
// response data
{ "id": "019f…", "slug": "acme", "name": "ACME Inc.", "status": "active",
  "protection_mode": "protected", "admin_token": "adm_…", "created_at": "…" }
```

### `GET /v1/accounts/{id}` — fetch an org
### `GET /v1/accounts` — list orgs for the caller's token (currently the token's own account)

---

## Products

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/accounts/{aid}/products` | admin | create — `{ "name": "ACME Pro" }` |
| `GET /v1/accounts/{aid}/products` | any token | list (paginated) |
| `GET /v1/accounts/{aid}/products/{pid}` | any token | fetch |

## Policies

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/accounts/{aid}/policies` | admin | create |
| `GET /v1/accounts/{aid}/policies` | any token | list |
| `GET /v1/accounts/{aid}/policies/{id}` | any token | fetch |

Create body (defaults shown):

```json
{
  "product_id": "019f…",
  "name": "pro-monthly",
  "scheme": "ED25519_SIGN"
}
```

Policy fields (server defaults: `max_machines=1`, `require_fingerprint=true`,
`renewable=true`): `scheme`, `max_machines`, `max_uses`, `duration_secs`,
`heartbeat_duration_secs`, `require_check_in`, `protected`, `renewable`.

## Licenses

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/accounts/{aid}/licenses` | admin / product | **issue** — signs the key, returns it once |
| `GET /v1/accounts/{aid}/licenses` | any token | list |
| `GET /v1/accounts/{aid}/licenses/{lid}` | any token | fetch (by id) |
| `POST …/licenses/{lid}/actions/validate` | license token or account policy | validity check |
| `POST …/licenses/{lid}/actions/check-out` | any token | offline license-file certificate |

Issue request: `{ "product_id": "…", "policy_id": "…", "max_uses": 100? }`.
Response includes `data.key` — the signed key string.

**Validate response:**

```json
{ "data": { "valid": true, "state": "active", "detail": null,
            "license": { "id": "…", "uses": 0, "max_uses": 100, "expiry": "" } } }
```

License states: `active → suspended ⇄ active`, `active/suspended → expired →
active (renew)`, `any → revoked` (terminal). Validation fails for any
non-active state or past expiry.

**Check-out** returns a PEM license file (`aes-256-gcm+ed25519` by default):

```
-----BEGIN LICENSE FILE-----
<base64 AES-256-GCM ciphertext of the JSON body>
-----END LICENSE FILE-----
Signature: alg=aes-256-gcm+ed25519, kid=v1, sig=<base64>
Iv: <base64>
```

> Until [SEC-009](security-audit.md) lands, checkout signs with a per-request
> keypair whose public half is not yet distributed — treat it as a preview of
> the format.

## Machines (devices)

REST list: `GET /v1/accounts/{aid}/machines` — the full activate/ping/
deactivate lifecycle is served over **gRPC** (below).

## Tokens

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/accounts/{aid}/tokens` | admin | mint `{ "kind": "product", "name": "ci" }` — plaintext returned once |
| `GET /v1/accounts/{aid}/tokens` | admin | list (hashes only, never plaintext) |
| `GET /v1/accounts/{aid}/tokens/{tid}` | admin | fetch |

## Webhooks

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/accounts/{aid}/webhooks/endpoints` | admin | register `{ "url": "https://…", "event_types": ["license.created"] }` — HMAC secret returned once |
| `GET /v1/accounts/{aid}/webhooks/endpoints` | admin | list |

Delivery: HMAC-SHA256 signed, exponential backoff (10 s → 1 h cap), permanent
on 4xx. See the [webhooks guide](webhooks.md).

## Event log (audit)

`GET /v1/accounts/{aid}/events` (admin) — append-only audit trail:
`account.created`, `product.created`, `policy.created`, `license.created`,
`webhook.endpoint.created`, … with severity + timestamps, keyset-paginated.

---

## gRPC API (`licensev1.LicenseService`)

Proto: [`proto/license.proto`](https://github.com/mahavirvataliya/license-server-rust/blob/main/proto/license.proto) · Default port 9090.

| RPC | Request → Response | Notes |
|---|---|---|
| `Validate` | `{account_id, license_id, fingerprint?}` → `{valid, state, detail, license}` | same logic as REST |
| `ValidateKey` | `{key}` → `ValidateResponse` | resolve by the raw signed key |
| `Activate` | `{account_id, license_id, fingerprint, name?, platform?, core_count?}` → `MachineResponse` | enforces `max_machines`; idempotent per fingerprint |
| `Deactivate` | `{account_id, machine_id}` → `{deactivated}` | |
| `Ping` | `{account_id, machine_id}` → `{alive, next_heartbeat}` | floating-license heartbeat |
| `CheckIn` | `{account_id, license_id}` → `{ok, next_check_in}` | license-level heartbeat |
| `CheckOut` | `{account_id, license_id, algorithm?}` → **stream** `CheckOutChunk` | certificate bytes in 4 KB chunks; first chunk carries the algorithm |

Status mapping: `NotFound`, `AlreadyExists`, `InvalidArgument`,
`FailedPrecondition` (policy violations / bad state), `PermissionDenied`,
`Internal`.

---

## Background jobs (roles)

Run via `--role` / `LICENSE_SERVER__ROLE`:

- **api** — REST :8080 + gRPC :9090
- **worker** — Redis-queue webhook delivery (scale horizontally)
- **scheduler** — cron sweeps, run as singleton: license expiry (1/min),
  overdue check-ins (1/min), dead-machine culling (1/min), signing-key
  retirement (1/h). All idempotent.
- **all** — everything in one process (dev/small deploys)
