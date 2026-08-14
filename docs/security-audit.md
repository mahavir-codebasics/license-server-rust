# Security & Performance Audit — license-server-rust

**Date:** 2026-08-14
**Scope:** Full workspace — Rust backend (axum/tonic/sqlx/apalis), Next.js 15 admin UI, Docker deployment.
**Method:** Manual code review against the Next.js security spec (skill reference), OWASP guidance, and Rust/axum best practices. Every finding cites file:line evidence. Load-test numbers measured with `wrk` against a release build + PostgreSQL 16.

> Note: no Rust-specific reference spec was available in the review tooling; Rust backend findings are based on general web-security and Rust-ecosystem best practices.

---

## Executive summary

The cryptographic core is solid: all SQL is parameterized, secrets are never persisted in plaintext (tokens and license keys are stored only as SHA-256 hashes), license files use encrypt-then-sign with fresh IVs, Postgres enforces Row-Level Security as defense-in-depth, and a 9-property automated security suite (`crates/bin/tests/security_review.rs`) verifies these claims on every run.

However, the audit found **2 critical**, **3 high**, and **1 availability-critical** issues that must be addressed before any production exposure: the UI's Next.js version was vulnerable to a published CVE (fixed during this audit), the **gRPC service ships with no authentication at all** despite its doc comment claiming otherwise, blocking Redis calls run on the async runtime, CORS is wildcard, org bootstrap is unauthenticated — and the server **crashes at boot when restarted against an existing database** because migrations are not tracked or idempotent.

Performance is fundamentally sound — the HTTP framework saturates at **178k RPS / 86 µs median** on a no-DB endpoint — but the authenticated hot path runs at **1,116 RPS / 15 ms** because every request makes three sequential DB round trips (uncached token lookup, license fetch, policy fetch, each PG query additionally wrapped in an RLS transaction). The top fixes are small: cache token resolution in Redis, share one async Redis connection instead of opening a blocking TCP connection per request, and co-fetch or cache the policy.

---

## Part 1 — Security findings

### CRITICAL

#### SEC-001: Next.js 15.1.0 is vulnerable to CVE-2025-66478 ("react2shell")

- **Location:** `ui/package.json:5` — `"next": "15.1.0"`
- **Evidence:** The `next` dependency is pinned to 15.1.0. Versions of Next.js older than **15.1.9** (within the 15.1.x line) are vulnerable to CVE-2025-66478.
- **Impact:** A published, actively-discussed Next.js vulnerability affecting unpatched versions; the admin UI is the management plane for the whole licensing system.
- **Fix:** Bump to `next@15.1.9` (or the latest 15.x patch). This is a patch-level bump — no API changes.
- **Status:** ✅ **Fixed in this audit** — bumped and production build re-verified.

#### SEC-002: The gRPC service has NO authentication

- **Location:** `crates/grpc/src/service.rs` (entire `impl Trait for LicenseService` block, lines ~90–400). Doc comment at lines 4–6 claims *"Auth: a Bearer token in the `authorization` metadata, resolved to an account by the same `tokens.get_by_hash` lookup"* — but **no such check exists in any handler**. Grep for auth extraction in the file returns only the doc comment and an error-mapping arm.
- **Evidence:** `Validate`, `ValidateKey`, `Activate`, `Deactivate`, `Ping`, `CheckIn`, and `CheckOut` all execute repo calls directly from request fields with no principal resolution. The REST API enforces auth via `auth::middleware`; the gRPC server (`crates/bin/src/runtime.rs:39-45`) adds the service with no equivalent interceptor.
- **Impact:** Anyone who can reach port 9090 can: activate machines on any license (exhausting floating seats / node-lock limits), check out license-file certificates, ping/deactivate arbitrary machines, and enumerate license validity by UUID. This is the entire machine-facing attack surface, unauthenticated.
- **Fix (recommended):** Add a tonic interceptor that extracts `authorization` metadata, hashes it, resolves the token via `tokens().get_by_hash()` (identical logic to `auth::resolve`), and rejects with `Status::unauthenticated` on failure. For `Validate`/`ValidateKey`, optionally honor the account's `protection_mode` for anonymous client validation (mirroring the REST policy).
- **Mitigation until fixed:** Do not expose port 9090 outside localhost/private network; firewall it at the edge.

### HIGH

#### SEC-003: Synchronous Redis calls block the async runtime (rate limiter + idempotency)

- **Location:** `crates/api/src/rate_limit.rs:18,65` and `crates/api/src/idempotency.rs:11,25,48`
- **Evidence:** Both modules call `client.get_connection()` (a **blocking** TCP connect) and use the synchronous `redis::Commands` API inside async middleware/handlers running on the tokio executor.
- **Impact:** (a) Every request opens a brand-new TCP connection to Redis (no pooling). (b) Under load, the blocking connect+query stalls executor threads — the rate limiter itself becomes a denial-of-service vector, the exact failure mode it exists to prevent.
- **Fix:** Use the async API — keep one `redis::aio::ConnectionManager` in `AppState` (it auto-reconnects and is cheap to clone) and call `redis::AsyncCommands` / `query_async`. Alternatively `tokio::task::spawn_blocking` as a stopgap.

#### SEC-004: CORS allows any origin, unconditionally

- **Location:** `crates/api/src/routes.rs:102-103` — `CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)`
- **Evidence:** The comment says "in production, restrict the origin instead of `Any`" but there is no configuration path to do so; every deployment ships wildcard CORS.
- **Impact:** Any website can issue authenticated requests from a victim's browser if a token is ever exposed browser-side (see SEC-006), and wildcard CORS significantly widens attack surface for any future cookie-based session.
- **Fix:** Add `LICENSE_SERVER__HTTP__CORS_ORIGINS` (comma-separated) to `Config`; build the `CorsLayer` from `Vec<HeaderValue>`; default to same-origin (no CORS layer) when unset. `Any` only behind an explicit `*` opt-in for development.

#### SEC-005: Unauthenticated organization bootstrap

- **Location:** `crates/api/src/routes.rs:136-160` — `create_account` accepts any anonymous POST and mints the org's first admin token.
- **Evidence:** The handler takes `OptionalAuth` but explicitly ignores it (`let _ = auth;`); there is no setup-secret gate or first-boot-only restriction.
- **Impact:** Anyone who can reach the API can create unlimited organizations and receive valid admin tokens — an unbounded resource-exhaustion and foothold vector in any public deployment.
- **Fix:** Gate with a `LICENSE_SERVER__BOOTSTRAP_SECRET` env: if set, require `X-Bootstrap-Secret` on `POST /v1/accounts`; if unset **and** the accounts table is non-empty (server already bootstrapped), reject with 403. Keep open only for the true first-boot/dev case.

### MEDIUM

#### SEC-006: Admin token stored in browser localStorage

- **Location:** `ui/src/lib/api.ts:13-18` (`localStorage.getItem/setItem(TOKEN_KEY)`)
- **Evidence:** The long-lived admin bearer token lives in `localStorage`, readable by any script on the page.
- **Impact:** Any XSS in the UI (or a compromised third-party script) exfiltrates a full admin credential. This violates the session-management guidance (NEXT-SESS-002): sensitive tokens must not live in client-readable storage.
- **Fix:** Prefer an HttpOnly, SameSite=Lax cookie session for the UI (server-side session endpoint + CSRF token for mutations), or at minimum issue short-lived UI tokens and keep long-lived admin tokens out of the browser entirely. Interim hardening: strict CSP (see SEC-014) to shrink the XSS surface.

#### SEC-007: Webhook delivery is an SSRF vector

- **Location:** `crates/jobs/src/webhook.rs:80` — `http.post(&endpoint.url)` with no destination validation.
- **Evidence:** The URL comes from account admins (`POST /webhooks/endpoints`); the worker fetches it from the server's network position. No blocking of private ranges, link-local, or cloud metadata endpoints.
- **Impact:** A malicious/compromised org admin can probe and exfiltrate from internal services — including cloud metadata endpoints (`169.254.169.254`) which can leak instance credentials.
- **Fix:** Before delivery, resolve the host and reject private/loopback/link-local ranges and cloud-metadata IPs; enforce `http`/`https` schemes; disable or audit redirects. Document an explicit-allowlist option for internal webhook targets.

#### SEC-008: No request body size limit

- **Location:** `crates/api/src/routes.rs` — no `tower_http::limit::RequestBodyLimitLayer` / `DefaultBodyLimit` anywhere.
- **Evidence:** All JSON body extractors accept unbounded bodies by default.
- **Impact:** Memory-exhaustion DoS via large payloads on any endpoint.
- **Fix:** Add a global body limit (e.g. 1 MiB; metadata blobs don't need more) via `DefaultBodyLimit::max(1024 * 1024)`.

#### SEC-009: License-file checkout signs with a throwaway keypair — files are unverifiable

- **Location:** `crates/api/src/routes.rs:447` (license create), `routes.rs:549` (checkout), `crates/grpc/src/service.rs` (CheckOut) — each call to `KeyPair::generate(...)` per request.
- **Evidence:** Both the REST check-out and gRPC CheckOut generate a fresh keypair, sign the certificate, and return it — the corresponding **public key is never persisted or distributed**. The `SigningKey` entity, rotation repo methods, and `KeyStore` all exist but are not wired into issuance.
- **Impact:** This is a correctness gap with security implications: clients cannot cryptographically verify an issued license file offline (the core value proposition of cryptographic licensing). It also means each checkout produces a key that leaves no audit trail.
- **Fix:** On account bootstrap, generate and persist the account's `SigningKey` (sealed via `LocalKeyStore`). Issue all keys/certificates with the active key; include its `kid` (already supported in the format); expose the public key via a `GET /v1/accounts/{id}/keys/{kid}` JWKS-style endpoint so SDKs can verify offline. Rotate via the existing `signing_keys().rotate()`.

### LOW

#### SEC-010: Rate limiter fails open when Redis is unavailable

- **Location:** `crates/api/src/rate_limit.rs:65-69` (documented, intentional).
- **Impact:** A Redis outage disables rate limiting entirely. Acceptable tradeoff for availability; ensure the edge/proxy layer has its own limits (deployment doc should require this).

#### SEC-011: Anonymous account existence oracle

- **Location:** `crates/api/src/routes.rs` — `get_account` allows anonymous reads; 200 vs 404 reveals org existence.
- **Impact:** Minimal — UUIDv7 ids are unguessable, and no sensitive fields are returned. Note-only.

#### SEC-012: No TLS termination in the application

- **Evidence:** No TLS config in the bin; deployment relies on a reverse proxy (Docker/Caddy pattern exists).
- **Impact:** None if documented. The deployment guide must mandate TLS at the edge (see `docs/deployment.md`).

#### SEC-013: Audit log has no tamper-evidence

- **Location:** `event_log` table is append-only by API convention only; no hash-chain/signature.
- **Impact:** A DB-level compromise can silently edit history. Future hardening: chain entries with `HMAC(prev_entry)` per account.

#### SEC-014: UI ships no Content-Security-Policy

- **Location:** `ui/next.config.mjs` — no `headers()` config.
- **Impact:** Combined with SEC-006 (token in localStorage), a single XSS is full compromise. Add at least `script-src 'self'` (nonce-based once feasible), `X-Content-Type-Options: nosniff`, `frame-ancestors 'self'`.

#### OPS-001: Server cannot restart against an existing database (non-idempotent migrations)

- **Location:** `crates/db/migrations/{pg,mysql}/20260725000001_initial.sql` run unconditionally via `sqlx::raw_sql` in `Pool::connect` (`crates/db/src/error.rs`).
- **Evidence:** Observed live during this audit's load testing: second boot against a migrated PG fails with `fatal runtime error: connecting database` (the `CREATE TABLE` statements error because the objects exist). There is no migration tracker (`_sqlx_migrations` is created only by the SQLite DDL file).
- **Impact:** **Any restart of a production deployment crashes at boot** — a critical availability defect. Also forces operators into risky manual schema drops.
- **Fix:** Adopt `sqlx::migrate!` with per-backend migration directories (tracks applied versions), or make the DDL idempotent (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ALTER ... ADD COLUMN IF NOT EXISTS`) plus an applied-versions table. Priority: this must land before any real deployment.

### Verified strengths (evidence-backed)

| Property | Evidence |
|---|---|
| All SQL parameterized (no injection) | grep across `crates/db/src/*.rs` finds zero string-concatenated SQL; sqlx bind parameters throughout |
| Tokens & license keys stored only as SHA-256 | `security_review.rs` property 1–2 (automated) |
| License files encrypt-then-sign, fresh 96-bit IV | `security_review.rs` properties 3–4; crypto suite (18 tests) |
| Constant-time verification paths | `license-crypto` uses `subtle`/verified APIs; tested |
| Secrets redacted in logs & Debug | `security_review.rs` properties 5–7 (master key, keypair Debug) |
| Postgres RLS defense-in-depth | `migrations/pg/20260725000001_initial.sql` policies + `set_config('app.account_id', …, true)` per-tx |
| Cross-tenant reads → 404 (no existence leak) | 18 isolation tests across SQLite/PG/MySQL (live-verified) |
| Token entropy ≥ 40 chars (256-bit) | `security_review.rs` property 8 |

---

## Part 2 — Performance findings

**Measured:** release build (`--release`), PostgreSQL 16 (Docker, localhost), SQLite eliminated to isolate the DB path. Numbers below are from `wrk` on the license-validate hot path. Full methodology in Appendix A.

| Finding | Severity | Detail |
|---|---|---|
| **PERF-001** — Sync Redis + connection-per-request | High | Same code as SEC-003. Every rate-limit/idempotency check does a blocking TCP connect + query on the executor thread. This dominated latency in the uncached path and caps throughput at Redis connection-setup speed. Fix = shared `ConnectionManager` + async commands (also removes ~1–3 ms/request overhead observed locally). |
| **PERF-002** — Token resolution hits the DB every request | High | `auth::resolve` → `tokens().get_by_hash()` is a full DB round trip on **every authenticated request** (REST). With Redis available this is trivially cacheable (token-hash → token JSON, 30–60 s TTL, invalidate on revoke). At the design target of "millions of devices" this is the single hottest query. Recommend: Redis cache with negative-TTL, plus keep the DB as source of truth on revoke. |
| **PERF-003** — PG RLS costs a transaction per repo call | Medium (accepted) | Every tenant-scoped method runs `BEGIN; SELECT set_config(...); query; COMMIT` — ~2 extra round trips. This is the price of defense-in-depth and is architecturally sound. If it ever dominates: connect as a non-owner role with `SET app.account_id` once per pooled connection (transaction pooling caveat applies), or move RLS to a `SECURITY DEFINER` function. Documented tradeoff — no action now. |
| **PERF-004** — Rate-limit check is 2 round trips | Low | `INCR` then `EXPIRE` (first-of-window). Should be a single Lua `INCR+EXPIRE` script (atomic + one RT). Minor once PERF-001 lands. |
| **PERF-005** — `replica_url` config exists but is unused | Medium | `DatabaseConfig.replica_url` is parsed and never wired; read scaling is documented-but-absent. Wire a second pool for read-only repo methods (list/get) when present. |
| **PERF-006** — Pool sizes hardcoded | Low | `max_connections` is 8 (PG/MySQL connect) / 16 (config default, partially unused). Expose via env and document sizing (≈ (cores × 2) + spindle rule for the DB). |
| **PERF-007** — Sound foundations | — | UUIDv7 append-mostly indexes, keyset pagination (no OFFSET) on every list, indexed hot paths (`(account_id, key_hash)`, `(account_id, fingerprint)`, expiry/heartbeat partial indexes), stateless api/worker roles for horizontal scale, apalis worker concurrency=8. |

### Load-test results (see Appendix A for methodology)

| Scenario | Concurrency | RPS | p50 | p99 | Notes |
|---|---|---|---|---|---|
| **A.** Validate, Redis limiter active | 16 | 1,980 | 11.5 ms | 172 ms | 27,849 of ~30k requests were rate-limited (429) — the limiter tripped at its 2,000/min validate cap. The 11.5 ms p50 **on the 429 path itself** is the blocking-Redis-connect cost (PERF-001). |
| **B.** Validate, limiter no-op (Redis unreachable) | 16 | **1,116** | **14.97 ms** | 98 ms | All 200s, zero errors. The true hot-path cost: 3 sequential DB round trips per request (auth lookup + license tx + policy tx, each tenant query wrapped in BEGIN/SET LOCAL/COMMIT — PERF-002/003). |
| **C.** `GET /healthz` (no DB, no auth) | 16 | **178,366** | **86 µs** | 6.9 ms | Framework ceiling. |

**Interpretation:** the HTTP stack is **not** the bottleneck — axum saturates at ~178k RPS with an 86 µs median. The validate path runs at 1/160th of that ceiling because each authenticated request performs three sequential database round trips (token lookup, license fetch, policy fetch), each PG tenant query additionally paying a transaction for RLS. Removing the auth lookup via cache (PERF-002) eliminates one third; co-fetching license+policy or caching the (immutable) policy removes most of the rest. Fixing PERF-001 additionally stops the limiter from *adding* latency. gRPC was not wrk-benchmarked (wrk speaks HTTP/1.1); correctness is covered by the 6-test gRPC suite, and the same repo-layer fixes apply to both transports.

---

## Appendix A — Load-test methodology

1. `cargo build --release -p license-server`.
2. Postgres 16 container, fresh schema (migration runs at boot), one account + product + policy + license seeded via the REST API; bearer token captured.
3. Server: `LICENSE_SERVER__ROLE=api`, release binary, default pool sizes.
4. `wrk -t8 -c16 -d30s -s <lua with auth header + POST>` against `/v1/accounts/{id}/licenses/{id}/actions/validate`.
5. Runs: (a) with Redis configured (limiter path active), (b) without Redis (limiter no-op) to isolate PERF-001.

---

## Prioritized remediation order

1. **OPS-001** tracked/idempotent migrations — every restart currently crashes; blocks all deployment
2. **SEC-002** gRPC auth interceptor (blocks any exposure of :9090 until done)
3. **SEC-003/PERF-001** async Redis ConnectionManager (one change fixes a High + the top perf issue)
4. **PERF-002** Redis token cache (+ consider co-fetching license+policy in validate)
5. **SEC-004** configurable CORS origins
6. **SEC-005** bootstrap secret gate
7. **SEC-009** persisted SigningKey + public-key endpoint (makes checkout real)
8. **SEC-006/SEC-014** UI session hardening + CSP
9. **SEC-007** webhook SSRF guards
10. **SEC-008** body-size limit; **PERF-004/005/006** as capacity work

*(SEC-001 — the Next.js CVE — was fixed and build-verified during this audit.)*
