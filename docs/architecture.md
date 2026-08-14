# Architecture

A performance-first, multi-tenant licensing server in Rust: one modular
monolith, three database backends, two transports, Redis-backed jobs.

```
              SDK / device ────────┐            ┌──────── Admin UI (Next.js 15)
                                    ▼            ▼
                     ┌──────────────────────────────────────┐
                     │        license-server (Rust)          │
                     │  axum REST :8080      tonic gRPC :9090│
                     │  ┌────────────────────────────────┐  │
                     │  │ domain    pure rules, no I/O   │  │
                     │  │ crypto    key/file signing     │  │
                     │  │ db        Repository trait ×3  │  │
                     │  │           sqlite / pg (RLS) /  │  │
                     │  │           mysql                │  │
                     │  │ jobs      apalis cron + redis  │  │
                     │  │ sso       OIDC + JIT           │  │
                     │  └────────────────────────────────┘  │
                     │  roles: api | worker | scheduler |all│
                     └───────┬───────────────────┬──────────┘
                             ▼                   ▼
                     PostgreSQL/MySQL/SQLite   Redis (queue, limiter,
                                                idempotency, future cache)
```

## Crate layering (dependency flow points down)

| Crate | Contains | Depends on |
|---|---|---|
| `domain` | entities, license/machine state machines, `Repository` trait, keyset pagination | — (pure, no I/O) |
| `crypto` | 5 key schemes, 8 license-file algorithms, `KeyStore` (local/KMS seam), token generation, AES derivation | domain |
| `db` | `Repository` impls × 3 backends + embedded migrations + `Pool::connect` URL dispatch | domain |
| `api` | axum REST: envelope, error mapping, auth middleware, rate limiting, idempotency, CORS | domain, db, crypto, jobs |
| `grpc` | tonic `LicenseService` — same handlers, second transport | domain, db, crypto |
| `jobs` | cron sweeps, webhook delivery (HMAC + backoff), audit log | domain, db |
| `sso` | OIDC authorization-code flow (PKCE), JIT provisioning | domain |
| `bin` | config (figment env+toml), telemetry, role dispatch | all |

## Multi-database strategy

One `Repository` trait, three implementations, identical behavior verified by
the same isolation suite (18 tests, all three run live in CI):

- **SQLite** — UUIDs/timestamps/JSON as TEXT; dev, tests, single-node.
- **PostgreSQL** — native UUID/TIMESTAMPTZ/JSONB + **Row-Level Security**:
  every tenant-scoped call wraps `SET LOCAL app.account_id` in a transaction
  (defense-in-depth on top of `WHERE account_id = $1`).
- **MySQL** — BINARY(16) UUIDs (big-endian keeps UUIDv7 time-ordering), JSON
  columns, generated-column uniqueness for active-signing-key.

Schema is logically identical; migration SQL is per-backend and embedded in
the binary. Backend selected by `DATABASE_URL` scheme at boot.

## Multi-tenancy

Every tenant-scoped row carries `account_id`; every repo method takes it.
Cross-tenant access returns **404** (existence never leaked) — enforced by the
query layer everywhere and additionally by PG RLS. 18 isolation tests prove
no cross-account read/list/delete on any backend.

## Identity & auth

- **Bootstrap**: `POST /v1/accounts` mints org + first `adm_` token.
- **Bearer tokens**: `adm_`/`prod_`/`lic_`/`usr_`/`pat_` prefixes; 256-bit
  entropy; stored only as SHA-256 hash; expiry + last-used tracked.
- **OIDC SSO** (`sso` crate): per-account IdP registry, PKCE flow, JIT
  user + membership provisioning. SSO users get a non-argon2 password marker
  (cannot password-login).
- Middleware is soft-fail (anonymous requests flow; handlers enforce via
  `RequiresAuth` / `OptionalAuth`) so unprotected accounts can allow
  client-side validation, mirroring keygen's model.

## Cryptography

Two subsystems (see `license-crypto`):

1. **License-key signing** — `ED25519_SIGN` (default), `ECDSA_P256_SHA256`,
   `RSA_2048_PSS/PKCS1V15_SHA256`, `JWT_RS256/EDDSA`. Key =
   `v1.<account>.<license>.<nonce>` + signature, base64. Only the SHA-256 of
   the key string is persisted.
2. **License files** — `{base64|aes-256-gcm}+{ed25519|ecdsa-p256|rsa-pss-sha256|rsa-sha256}`
   PEM certificates. **Encrypt-then-sign** (signature covers ciphertext —
   tampering detected before decryption), fresh 96-bit IV per issuance,
   constant-time verification, `kid` headers for rotation.

`KeyStore` trait: `LocalKeyStore` (AES-256-GCM under the master key) today;
KMS/HSM backend (signing inside the HSM) is the designed seam.

## Background jobs

- **Cron** (apalis-cron, scheduler role, idempotent): license expirations and
  overdue check-ins (1/min), dead-machine culling for floating licenses
  (1/min), signing-key retirement (1/h).
- **Webhooks** (apalis-redis, worker role, concurrency 8): HMAC-SHA256
  (`t=<ts>,v1=<hmac(ts.body)>`), exponential backoff 10 s→1 h, permanent
  failure on 4xx.
- **Audit log**: fire-and-forget appends; never blocks the request path.

## Scale model ("millions of devices")

- UUIDv7 primary keys → append-mostly B-tree inserts.
- Keyset pagination everywhere (no OFFSET).
- Hot-path indices: `(account_id, key_hash)`, `(account_id, fingerprint)`,
  partial indices on expiry/heartbeat columns.
- Stateless `api`/`worker` roles scale horizontally; singleton `scheduler`.
- gRPC for device-facing throughput; REST for management.
- Read-replica config field exists (wiring tracked as PERF-005 in the audit).

## Performance profile (measured, release build + PG)

- Framework ceiling (`/healthz`): **178k RPS, p50 86 µs**.
- Authenticated validate: **1.1k RPS, p50 15 ms** — three sequential DB round
  trips per request (token lookup, license, policy; PG RLS adds a tx each).
- Full analysis + fixes: [security-audit.md](security-audit.md) Part 2.

## Testing

127 tests: domain state machines (15), crypto round-trips/tamper (18),
per-backend isolation (18, SQLite always-on; PG/MySQL live in CI), REST E2E
lifecycle incl. auth 401/403 (6), gRPC E2E (6), jobs/HMAC (8), OIDC (24),
security-review properties (9), plus config/telemetry/backend units.
