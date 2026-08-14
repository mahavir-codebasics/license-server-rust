# Deployment Guide

From single-binary dev to hardened production.

## Topology

| Role | What it runs | Replicas |
|---|---|---|
| `api` | REST :8080 + gRPC :9090 | N (stateless, scale behind LB) |
| `worker` | webhook delivery | N |
| `scheduler` | cron sweeps (expiry/cull/retire) | **1** (idempotent, but pointless to duplicate) |
| `all` | everything (dev / small sites) | 1 |

Set via `LICENSE_SERVER__ROLE` or `--role`. All roles need the same `DATABASE_URL`,
`REDIS_URL`, and `CRYPTO__MASTER_KEY`.

## Configuration

All config via `LICENSE_SERVER__*` env (double-underscore nesting) or
`config.toml`. See [`.env.example`](../.env.example) for the full list.

**Production-critical settings:**

```bash
# Database — pick ONE backend (schema migrates on boot; see OPS-001 note below)
LICENSE_SERVER__DATABASE__URL=postgresql://user:pass@db:5432/license
LICENSE_SERVER__DATABASE__MAX_CONNECTIONS=32

# Redis — required for worker role, rate limiting, idempotency
LICENSE_SERVER__REDIS__URL=redis://redis:6379/0

# Master key — 32 bytes hex. encrypts signing-key material at rest.
# Generate once, store in a secret manager, NEVER commit. Losing it makes
# existing sealed keys/license-files undecryptable.
LICENSE_SERVER__CRYPTO__MASTER_KEY=$(openssl rand -hex 32)

# Bind behind the proxy
LICENSE_SERVER__HTTP__HOST=127.0.0.1
LICENSE_SERVER__GRPC__HOST=127.0.0.1

# Logs as JSON for aggregation
LICENSE_SERVER__LOG__FORMAT=json
LICENSE_SERVER__LOG__FILTER=info,license_server=warn
```

## Docker

```bash
# whole stack (postgres + redis + api)
docker compose up -d

# MySQL instead: docker compose --profile mysql up -d
# UI:           docker compose --profile ui up -d
```

Multi-stage distroless images (`docker/Dockerfile.api`, `docker/Dockerfile.ui`)
run as non-root.

## Production checklist

**Edge (mandatory)**

- [ ] TLS termination at a reverse proxy (the app speaks plaintext HTTP/1.1 +
      h2c; do not expose :8080/:9090 directly)
- [ ] Proxy-level rate limiting + body limits (app limiter fails open if
      Redis is down — by design; see SEC-010)
- [ ] Firewall gRPC :9090 to trusted networks until [SEC-002 (gRPC auth)](security-audit.md) lands

**App**

- [ ] Work through the [security audit remediation order](security-audit.md#prioritized-remediation-order) —
      at minimum OPS-001 (migrations), SEC-002, SEC-003, SEC-004, SEC-005
- [ ] Master key from a secret manager; rotation procedure documented
- [ ] `LOG__FORMAT=json`, ship to aggregation; secrets are redacted by the
      app but double-check your proxy logs (Authorization headers!)

**Database**

- [ ] Postgres (recommended for scale; RLS defense-in-depth)
- [ ] Backups + PITR; test restore
- [ ] Connection sizing: start `MAX_CONNECTIONS ≈ (cores × 4)`, watch pool wait
- [ ] **OPS-001 caveat:** migrations currently run raw on boot and are not
      re-run safe — until tracked migrations land, boot new deployments
      against a fresh database and treat schema changes explicitly

**Redis**

- [ ] Persistence (AOF) if webhooks must survive restarts
- [ ] `maxmemory-policy noeviction` (queue data) or accept job loss

**Operations**

- [ ] Health probes: `GET /healthz` (liveness), `GET /readyz` (readiness)
- [ ] Graceful shutdown: SIGTERM drains in-flight (10–15 s windows built in)
- [ ] Monitor: 429 rate (abuse), webhook `attempts`/`last_error` (delivery
      health), cron sweep counts in logs, audit-log volume anomalies

## Scaling notes

- **Devices:** device-facing traffic goes over gRPC; the hot path is
  `Validate`/`ValidateKey`. Read [the audit's performance
  section](security-audit.md#part-2--performance-findings) before sizing —
  the per-request DB round trips (not the framework) set the ceiling, and the
  recommended token cache multiplies capacity cheaply.
- **Read scaling:** a `replica_url` config field exists; wiring is tracked as
  PERF-005.
- **Multi-region:** run `api`/`worker` per region against regional DBs;
  licenses are account-scoped so partitioning by account works today.
