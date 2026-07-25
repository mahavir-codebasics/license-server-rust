# license-server-rust

A performance-first, multi-tenant **software-licensing & distribution server**
written in Rust — a self-hostable alternative to [keygen-sh/keygen-api].

> **Status:** early (Phase 0–1). The domain core, license state machine, app
> skeleton, config, telemetry, Docker, and CI matrix are in place. Crypto
> subsystem and REST API land next. See
> [`docs/superpowers/specs/2026-07-25-license-server-rust-design.md`](docs/superpowers/specs/2026-07-25-license-server-rust-design.md)
> for the full design and phase plan.

**Not wire-compatible with keygen.** We ship clean idiomatic REST/JSON + a
gRPC hot path and write our own SDKs.

[keygen-sh/keygen-api]: https://github.com/keygen-sh/keygen-api

## What's here now

- **`crates/domain`** — pure entities + business rules. No I/O. The license
  state machine (suspend/reinstate/revoke/renew/expire, metering, check-in)
  is fully implemented and unit-tested (15 tests).
- **`crates/bin`** — binary entry point. Role-based dispatch
  (`--role=api|worker|scheduler|all`), config loading (env + toml), structured
  tracing with secrets redaction, `/healthz` + `/readyz`.
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
1. 🔄 Domain + DB (migrations × 3, Repository impls, tenancy enforcement)
2. ⏳ Crypto core (5 key schemes, 8 license-file algos, KeyStore, rotation)
3. ⏳ Core REST API (accounts, products, policies, licenses, machines, tokens)
4. ⏳ Auth + OIDC SSO + admin surface
5. ⏳ Background jobs + HMAC webhooks + audit log
6. ⏳ gRPC hot path (validate/activate/ping/check-in/check-out)
7. ⏳ Next.js admin UI
8. ⏳ Hardening (rate limiting, idempotency, read replicas, load test, security review)

**Deferred (post-v1):** distribution registries (npm/PyPI/RubyGems/OCI/Tauri),
SAML, fine-grained RBAC/environments, import/export, ClickHouse analytics.

## License

Apache-2.0.
