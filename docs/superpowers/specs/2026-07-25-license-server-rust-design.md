# license-server-rust — Design

**Status:** Approved (2026-07-25)
**Scope:** v1 = licensing core. Distribution registries, SAML, fine-grained
RBAC/environments, import/export, ClickHouse deferred to post-v1.

## Goal

A performance-first, multi-tenant software-licensing & distribution server in
Rust — a self-hostable alternative to [keygen-sh/keygen-api]. **Not**
wire-compatible with keygen: we ship clean idiomatic REST/JSON + a gRPC hot
path and write our own SDKs.

[keygen-sh/keygen-api]: https://github.com/keygen-sh/keygen-api

## Confirmed decisions

| Area | Decision |
|---|---|
| API shape | Plain idiomatic REST/JSON + gRPC hot path; own SDK |
| Databases | PostgreSQL + MySQL/MariaDB + SQLite (Repository trait) |
| SSO | OIDC |
| Crypto | Ed25519-first modern matrix + KMS/HSM abstraction |
| Background jobs | apalis over Redis |
| Admin UI | Next.js 15 + shadcn/ui |
| Deployment | Docker Compose first |
| IDs | UUIDv7 (time-ordered) |

## Architecture — modular monolith (Approach A)

Single async Rust binary, Cargo workspace. Roles via
`--role=api|worker|scheduler|all` (default `all`). Stateless replicas scale
horizontally; scheduler leader-elected via Redis.

```
crates/
├── domain/    pure entities + business rules, no I/O
├── crypto/    KeyScheme signers, license-file PEM, KeyStore trait
├── db/        Repository trait + {pg,mysql,sqlite} impls + migrations
├── api/       axum REST (handlers, envelope, keyset pagination)
├── grpc/      tonic hot path: validate/activate/ping/check-in/check-out
├── jobs/      apalis workers + cron + Redis leader election
├── sso/       OIDC client, JIT provisioning, session
└── bin/       config, telemetry, role dispatch
```

Layering rule: `domain` depends on nothing internal; everything else may
depend on `domain`.

## Domain model (v1)

Multi-tenant (every row → `account_id`), UUIDv7 PKs:

Account, User, AccountMembership, Product, Policy, Key(pool), License, Machine,
Component, Process, Entitlement, Token (SHA-256 hashed), WebhookEndpoint,
WebhookEvent, EventLog, SsoConnection, SigningKey (versioned, active+rotating).

### License state machine (implemented, tested)

```
        ┌────────────────────────────────────────────────────┐
        │                                                    ▼
  Active ──suspend──▶ Suspended ──reinstate──▶ Active      Expired
   │ │                  │                                  ▲
   │ │                  └──────────────┐                   │
   │ └───renew (revives)────────────────┼───────────────────┘
   │                                     │
   └──revoke──▶ Revoked (terminal)       └─(expiry passes)─┘
```

- `revoke` is terminal — no reinstate/renew.
- `renew` revives an `Expired` license and extends expiry.
- Metering (`increment_usage`) enforces `max_uses` atomically.
- `check_in` resets overdue counters and sets the next window.

## Crypto — "better signatures"

Two subsystems (the same separation keygen gets right):

### 1. License-key signing
`KeyScheme` enum → `KeySigner` trait:

| Scheme | Crate |
|---|---|
| `ED25519_SIGN` (default) | ed25519-dalek |
| `ECDSA_P256_SHA256` | p256 |
| `RSA_2048_PSS_SHA256` | rsa + sha2 |
| `RSA_2048_PKCS1V15_SHA256` | rsa + sha2 |
| `JWT_RS256` / `JWT_EDDSA` | jsonwebtoken |

Plaintext key never persisted — only SHA-256 `key_hash` for constant-time lookup.

### 2. License-file (certificate)
PEM block; algorithms `{base64|aes-256-gcm}+{ed25519|ecdsa-p256|rsa-pss-sha256|rsa-sha256}`.

### Hardening beyond keygen's baseline
- **Encrypt-then-sign**: sign ciphertext, not plaintext.
- Random **96-bit AES-GCM IV** per encryption, never reused.
- **Key IDs (`kid`)** + first-class **rotation** with grace-period verify.
- **Constant-time verification** (`subtle`) — no early-exit comparisons.
- **Per-account keypair isolation** enforced in domain layer.
- **`KeyStore` trait**: `LocalKeyStore` (encrypted at rest with master key) +
  `KmsKeyStore` (AWS KMS / GCP KMS / Vault Transit, HSM signing).
- **Audit entry** for every sign/verify.
- **Verified** zero-logging of secrets via tracing filter + unit test.

## API surface

Envelopes `{data, meta:{cursor,has_more}}` / `{errors}`; **keyset pagination**
everywhere (no OFFSET); `Authorization: Bearer <token>`; protected/unprotected
accounts; `Idempotency-Key` (Redis); Redis token-bucket rate limiting;
`x-request-id` propagated.

All tenant-scoped routes under `/v1/accounts/{accountId}/...`. License &
machine actions live under `actions/` (validate, revoke, renew, suspend,
reinstate, check-in, check-out, increment-usage, … ; ping, deactivate,
generate-offline-proof). Natural-key addressing: `/licenses/{key}`,
`/machines/{fingerprint}`.

gRPC (tonic): `Validate`, `ValidateKey`, `Activate`, `Deactivate`, `Ping`,
`CheckIn`, `CheckOut` (server-streams the license-file bytes).

## Database & multi-DB

- Async `Repository` trait in `domain`; 3 sqlx impls in `db`.
- Per-backend migrations (3 folders), logically identical schema.
- **Tenancy enforcement:**
  - Postgres: **Row-Level Security** via `SET LOCAL app.account_id`.
  - MySQL/SQLite: compile-time-enforced `WHERE account_id` + integration test
    asserting no method can return cross-account rows.
- **Metadata JSON**: Postgres `@>`, MySQL `JSON_CONTAINS`, SQLite `json_each`
  behind one `MetadataFilter` abstraction.
- UUIDv7; indices on `(account_id, fingerprint)`, `(account_id, key_hash)`,
  `(account_id, created_at)`.

## Background jobs (apalis + Redis)

Cron (leader-elected): `license-expirations`, `overdue-check-in-sweeper`,
`cull-dead-machines`, `cull-dead-processes`, `prune-{tokens,sessions,webhook-events}`.

Event-driven: `webhook-delivery` (exp backoff + HMAC-SHA256 signing),
`event-log-writer`, `analytics-spark`.

## Admin UI (Next.js 15)

App Router + Server Components + shadcn/ui + Tailwind. Login = email/password
(argon2id) + TOTP and "Sign in with SSO" (OIDC). Pages: org switcher,
dashboard, products, policies, licenses, machines, entitlements, tokens,
webhooks, event log, SSO config, signing-key management + rotation.

## Deployment

`docker-compose.yaml`: `api` (Rust, role=all), `postgres`, `redis`, `ui`.
Multi-stage distroless Dockerfile (~30MB). Env config `LICENSE_SERVER__*`.
Swap DB via `DATABASE_URL` scheme.

## Testing

- Domain unit tests (state machine, policy rules, crypto round-trips). ✅ 15 passing.
- Backend matrix: same contract suite vs Postgres/MySQL/SQLite via testcontainers.
- Crypto test vectors (known-good signed keys + license files) checked in.
- Cross-tenant isolation test (must fail cross-account access).
- `proptest` for license-file encode/decode.

## Phases

| Phase | Deliverable |
|---|---|
| 0 ✅ skeleton | workspace, config, telemetry, health, Dockerfile, 3-DB CI |
| 1 ✅ domain+db | entities, 3×migrations, SQLite Repository impl, tenancy + isolation tests |
| 2 ✅ crypto core | 5 key schemes, 8 license-file algos, KeyStore, rotation, test vectors |
| 3 ✅ core API | accounts, products, policies, licenses (+actions), tokens, E2E tests |
| 4 ✅ auth + multi-db | bearer tokens/bootstrap/token CRUD + **Postgres (RLS) + MySQL backends** |
| 5 ✅ jobs+webhooks | cron sweeps (expiry/cull/retire), HMAC-SHA256 webhooks (exp backoff), audit log |
| 6 ✅ gRPC | tonic validate/activate/ping/check-in/check-out (server-streamed checkout) |
| 7 ✅ admin UI | Next.js 15 console (login/bootstrap, org-scoped dashboard, all resource pages) |
| 8 ✅ hardening | OIDC SSO (JIT), rate limiting (Redis token-bucket), Idempotency-Key, security-review suite (9 properties) |

**Deferred (post-v1):** distribution registries (npm/PyPI/RubyGems/OCI/Tauri),
SAML, environments/fine-grained RBAC, import/export, ClickHouse analytics.
