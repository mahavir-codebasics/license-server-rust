---
description: Deploy license-server-rust in production — api/worker/scheduler roles, configuration reference, TLS termination, Docker Compose, and a hardening checklist.
---

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
`config.toml`. See [`.env.example`](https://github.com/mahavirvataliya/license-server-rust/blob/main/.env.example) for the full list.

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
- [ ] Proxy-level rate limiting (app limiter fails open if Redis is down —
      by design; see SEC-010; the app already caps bodies at 1 MiB)
- [ ] Firewall gRPC :9090 to trusted networks (RPCs are now authenticated —
      SEC-002 — but the port still shouldn't be public)
- [ ] Set `LICENSE_SERVER__SECURITY__BOOTSTRAP_SECRET` so `POST /v1/accounts`
      requires an `X-Bootstrap-Secret` header (SEC-005)

**App**

- [ ] Review the [security audit](security-audit.md) — OPS-001 (idempotent
      migrations), SEC-002 (gRPC auth), SEC-003 (async Redis), SEC-004 (CORS
      allow-list), SEC-005 (bootstrap gate), SEC-007 (webhook SSRF), and
      SEC-008 (body limit) are fixed; consider the remaining lower-severity
      items
- [ ] Master key from a secret manager; rotation procedure documented
- [ ] `LOG__FORMAT=json`, ship to aggregation; secrets are redacted by the
      app but double-check your proxy logs (Authorization headers!)

**Database**

- [ ] Postgres (recommended for scale; RLS defense-in-depth)
- [ ] Backups + PITR; test restore
- [ ] Connection sizing: start `MAX_CONNECTIONS ≈ (cores × 4)`, watch pool wait

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
  section](security-audit.md#part-2-performance-findings) before sizing —
  the per-request DB round trips (not the framework) set the ceiling, and the
  recommended token cache multiplies capacity cheaply.
- **Read scaling:** a `replica_url` config field exists; wiring is tracked as
  PERF-005.
- **Multi-region:** run `api`/`worker` per region against regional DBs;
  licenses are account-scoped so partitioning by account works today.

## Reference single-server deployment (this repo's `deploy/`)

`deploy/` contains the toolchain used for the reference instance on an OCI
ARM box (rootless Docker, Tailscale-only networking):

- **`deploy.sh`** — end-to-end: builds nothing itself, but rsyncs the bundle,
  generates `.env` secrets once (kept across redeploys), ships prebuilt
  images via `docker save | ssh docker load`, and brings the stack up.
- **`build-site.mjs`** — renders `docs/*.md` + a landing page into the
  static site served at `/` (re-run after doc edits, then re-deploy).
- **`docker-compose.prod.yml` + `nginx.conf`** — nginx on :80 fronts
  everything: `/` static site, `/v1` + `/healthz` → the API, `/admin` → the
  Next.js console (built with `basePath=/admin` and a same-origin relative
  API base). gRPC :9090 is published directly.

Layout on the host:

```
~/license-server/
├── .env                  # POSTGRES_PASSWORD, MASTER_KEY (0600, generated once)
├── docker-compose.prod.yml
├── nginx.conf
└── site/                 # landing + rendered docs
```

Redeploy after code changes: rebuild both images (linux/arm64), then
`./deploy/deploy.sh ubuntu@<host>`. Notes for rootless Docker hosts: low
ports need `net.ipv4.ip_unprivileged_port_start=80` in `/etc/sysctl.conf`,
and `loginctl enable-linger <user>` so the daemon starts at boot.

### Public hostname via Cloudflare Tunnel

The reference instance is published at **https://license.itih.in** through a
locally-managed Cloudflare Tunnel (coexists with any token-based tunnels on
the same host):

- Tunnel `license-server` (`~/.cloudflared/config.yml`, credentials in
  `~/.cloudflared/`), ingress `license.itih.in → http://localhost:80` (nginx).
- Runs as its own systemd unit `cloudflared-license.service` (restart=always),
  separate from the stock `cloudflared.service`.
- DNS is a CNAME to `<tunnel-id>.cfargotunnel.com`, created with
  `cloudflared tunnel route dns license-server license.itih.in`.
- TLS terminates at Cloudflare's edge; the origin is plain HTTP on localhost.
  Raw TCP gRPC (:9090) is not proxied through the tunnel — point SDKs at the
  tailnet address for the hot path, or front gRPC with an HTTP/2-capable
  origin later.
