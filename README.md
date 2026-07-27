# license-server-rust

A performance-first, multi-tenant **software-licensing & distribution server**
written in Rust — a self-hostable alternative to [keygen-sh/keygen-api].

> **Status:** Phases 0–8 complete — the full v1 roadmap shipped. Domain core +
> license state machine, **all three databases** (SQLite + PostgreSQL + MySQL)
> with verified multi-tenant isolation, full crypto subsystem
> (Ed25519/ECDSA/RSA/JWT key signing + AES-256-GCM encrypt-then-sign license
> files), bearer-token auth, working REST API, **gRPC hot path**, **background
> jobs** (cron sweeps + HMAC webhooks + audit log), **Next.js 15 admin UI**,
> and **enterprise hardening** (OIDC SSO with JIT provisioning, Redis
> rate-limiting, Idempotency-Key support, security-review test suite) — 127
> tests + live PG/MySQL isolation suites + verified scheduler/worker/gRPC
> roles. See
> [`docs/superpowers/specs/2026-07-25-license-server-rust-design.md`](docs/superpowers/specs/2026-07-25-license-server-rust-design.md)
> for the full design and phase plan.

**Not wire-compatible with keygen.** We ship clean idiomatic REST/JSON + a
gRPC hot path and write our own SDKs.

[keygen-sh/keygen-api]: https://github.com/keygen-sh/keygen-api

## What's here now

- **`crates/domain`** — pure entities + business rules. No I/O. The license
  state machine (suspend/reinstate/revoke/renew/expire, metering, check-in)
  is fully implemented and unit-tested (15 tests).
- **`crates/crypto`** — Ed25519/ECDSA-P256/RSA-2048/JWT license-key signing
  (5 schemes) + PEM license-file certificates with AES-256-GCM encrypt-then-sign
  (8 algorithm tuples) + `KeyStore` trait (Local impl + KMS seam). 18 tests.
- **`crates/db`** — **Three backends** (SQLite, PostgreSQL, MySQL) all
  implementing the full domain `Repository`. SQLite runs in-memory for tests;
  Postgres uses native UUID/JSONB + Row-Level Security (defense-in-depth
  tenancy); MySQL uses BINARY(16) UUIDs. Cross-tenant isolation verified
  against all three (18 isolation tests; PG/MySQL suites run live in CI).
- **`crates/api`** — axum REST API with bearer-token auth: bootstrap
  (`POST /v1/accounts` emits the first admin token), token CRUD, and
  write-gated accounts/products/policies/licenses (create signs the key,
  validate, check-out issues a license file). 5 E2E tests prove the full
  lifecycle through HTTP including 401/403 enforcement.
- **`crates/bin`** — binary entry point. Role-based dispatch
  (`--role=api|worker|scheduler|all`), config loading (env + toml), structured
  tracing with secrets redaction, **auto-selects DB backend from the
  `DATABASE_URL` scheme**, runs migrations, full v1 router + health.
- **`docker/`** — multi-stage distroless Dockerfiles for the API and (future)
  UI, plus a one-command `docker compose up` stack (Postgres + Redis + API).
- **`.github/workflows/ci.yml`** — fmt + clippy gates, unit tests across
  Linux/macOS, and a 3-backend DB contract-test matrix (Postgres/MySQL/SQLite).

## Workspace layout

```
crates/
├── domain/    pure entities + business rules, no I/O
├── crypto/    KeyScheme signers, license-file PEM, KeyStore trait   (Phase 2)
├── db/        Repository trait + {pg,mysql,sqlite} impls            (Phase 1)
├── api/       axum REST (handlers, envelope, keyset pagination)     (Phase 3)
├── grpc/      tonic hot path                                        (Phase 6)
├── jobs/      apalis workers + cron                                 (Phase 5)
├── sso/       OIDC client, JIT provisioning                         (Phase 4)
└── bin/       config, telemetry, role dispatch                      ✅
```

## Quick start

```bash
cp .env.example .env
# generate a real master key (32 bytes hex):
openssl rand -hex 32  # put it in LICENSE_SERVER__CRYPTO__MASTER_KEY

# one command: Postgres + Redis + the API
docker compose up

# or run the binary directly
cargo run -p license-server
curl http://localhost:8080/healthz   # {"status":"ok"}
```

## Config

All config via environment (prefix `LICENSE_SERVER__`, `__` = nesting), or
`config.toml`. See [`.env.example`](.env.example). **Secrets never logged** —
DB passwords are masked, the master key is truncated in the boot line, and a
deny-list of field names (`token`, `secret`, `password`, …) is enforced in
code review.

## IDs & scale

Every primary key is **UUIDv7** (time-ordered) so B-tree insertions stay
append-mostly — index fragmentation stays low at millions of devices.
Pagination is **keyset/cursor-based** everywhere (no `OFFSET`).

## Roadmap (phases)

0. ✅ Skeleton (workspace, config, telemetry, health, Docker, 3-DB CI)
1. ✅ Domain + SQLite DB (migrations × 3, Repository impls, tenancy enforcement, isolation tests)
2. ✅ Crypto core (5 key schemes, 8 license-file algos, KeyStore, rotation)
3. ✅ Core REST API (accounts, products, policies, licenses + validate/check-out)
4. ✅ Auth (bearer tokens, bootstrap, token CRUD) + **Postgres + MySQL backends** (RLS)
5. ✅ Background jobs (cron sweeps: expiry/cull/retire) + HMAC webhooks + audit log
6. ✅ gRPC hot path (Validate/ValidateKey/Activate/Ping/CheckIn/CheckOut)
7. ✅ Next.js 15 admin UI (login, org-scoped dashboard, all resource pages)
8. ✅ Hardening — OIDC SSO (JIT), rate limiting (Redis token-bucket), Idempotency-Key, security-review suite

**Deferred (post-v1):** distribution registries (npm/PyPI/RubyGems/OCI/Tauri),
SAML, fine-grained RBAC/environments, import/export, ClickHouse analytics.

## License

Apache-2.0.
