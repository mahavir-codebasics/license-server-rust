# Open-Source Readiness Program — Design Spec

**Date:** 2026-08-21 · **Status:** Approved design (sections approved in session; implementation planning next)

## 1. Goal

Prepare license-server-rust for public open-source launch: close every known security/robustness gap, stabilize memory under load, publish a complete documentation site with search, ship official SDKs plus REST machine-lifecycle parity, and finish OSS project packaging. Public launch is gated on all phases green.

## 2. Background & evidence

Findings below come from the 2026-08-21 codebase audit (file:line references verified against working tree). Prior art: [`docs/security-audit.md`](../../../security-audit.md) (15 earlier findings + wrk baselines).

| # | Finding | Location | Severity |
|---|---|---|---|
| F1 | gRPC `ValidateKey` is a cross-tenant validation oracle: takes raw key only, no account scoping (REST twin checks `license.account_id` match), no auth, no rate limit anywhere on the gRPC router | `crates/grpc/src/service.rs` (~81–99); contrast `crates/api/src/routes.rs` (~579–582) | Critical |
| F2 | Synchronous Redis (`redis::Commands` + `get_connection()` — a fresh TCP connection per call) executed inside async axum middleware/handlers on every request; `connection-manager` feature enabled but unused | `crates/api/src/rate_limit.rs`:18,65–74; `crates/api/src/idempotency.rs`:11,20–25,38–52 | Critical |
| F3 | Argon2 default parameters (≈19 MiB working set + ~100 ms CPU) run directly on tokio workers in signup/login; `KeyPair::generate` (RSA schemes) also runs CPU-bound work inline in `create_license` | `crates/api/src/password_auth.rs`:34–49; `crates/api/src/routes.rs` (~447–453) | High |
| F4 | Pool sizing knob dead: `Pool::connect` hardcodes `max_connections(8)`; `cfg.database.max_connections` never read; SQLite lacks WAL + `busy_timeout` → `SQLITE_BUSY` surfaces as 500s under concurrent writes | `crates/db/src/error.rs`:80,89,97; `crates/bin/src/runtime.rs`:166,200; config field at `bin/config.rs`:67 | High |
| F5 | No request telemetry: `TraceLayer`/request-id never applied despite tower-http features enabled; no `CatchPanicLayer` (handler panic = connection reset, not 500); CORS wide-open (`Any` × origin/methods/headers) | `crates/api/src/routes.rs`:107–115 (`router()`) | Medium |
| F6 | tonic server lacks `with_graceful_shutdown` → SIGTERM cuts active gRPC streams (check-out!) mid-flight while HTTP drains cleanly | `crates/bin/src/runtime.rs`:44–50 (contrast :61) | Medium |
| F7 | OIDC HTTP client is the crate-default shared client with **no timeout** (discovery/token/userinfo can hang handlers indefinitely); discovery metadata re-fetched on every `begin`/`exchange` | `crates/sso/src/flow.rs`:20,197 | Medium |
| F8 | Rate-limit keying flaws: anonymous bucket trusts client-controlled `X-Forwarded-For` (spoofable → unlimited buckets); requests without XFF share one global `"anon"` bucket (self-DoS); INCR failure fails *closed* (429) contradicting fail-open on connection failure | `crates/api/src/rate_limit.rs`:70,96–103 | High |

Production-code hygiene is otherwise solid: custom error types end-to-end, ~10 non-test unwrap/expect sites all startup-time-safe, keyset pagination everywhere, indexed point lookups only, release profile already optimal (opt-level 3, thin LTO, cg=1, stripped).

## 3. Out of scope

- Keygen wire-compatibility layer; migration/import tools from other vendors
- `utoipa` macro refactor of handlers (upgrade path noted in Phase 3)
- Publishing to crates.io / Maven Central (artifacts attach to GitHub Releases first)
- Custom docs domain; SAML, fine-grained RBAC, distribution registries (existing deferred list)

## 4. Approach

**Chosen: A — Security-first sequential.** Harden → REST activation → SDKs/OpenAPI → docs site → packaging/launch. Each phase ends green (tests pass, diagnostics clean); docs always describe shipped reality; nothing public launches while F1/F2 exist.

Rejected: **B — parallel lanes** (faster wall-clock, but risks documenting behavior that hardening changes: auth envelopes, CORS, error codes); **C — visibility first** (publishing a licensing server with a known cross-tenant validation hole is fatal to credibility).

Code-independent packaging templates (CONTRIBUTING, CoC, SECURITY.md, issue/PR templates, repo metadata) land early inside Phase 1; only the *launch announcement* gates on Phases 1–4.

## 5. Phases

### Phase 1 — Hardening (+ early packaging)

| Fix | Change | Key decision |
|---|---|---|
| F1 | Derive tenant server-side from the key-hash row (`account_id` already on the license row); enforce account match; per-key rate-limit buckets applied to gRPC validate paths | **Non-breaking** — no proto change; existing clients keep working |
| F2 | Replace sync API with `redis::aio::ConnectionManager` stored once in `AppState`; single multiplexed connection replaces per-call TCP churn; uniform fail-open on Redis errors | Feature already compiled |
| F3 | Wrap Argon2 hash/verify and `KeyPair::generate` in `tokio::task::spawn_blocking` | Frees workers; kills per-login 19 MiB spikes |
| F4 | Thread `cfg.database.max_connections` through `Pool::connect`; enable WAL + `busy_timeout(5s)` for SQLite | Config knob starts working |
| F5 | Add `TraceLayer` + `RequestIdLayer` (+ response header) + `CatchPanicLayer` returning the standard error envelope; CORS origins from config (default same-origin) | Features already enabled |
| F6 | `with_graceful_shutdown` on tonic serve, sharing the existing shutdown signal; drain budget aligned with HTTP | Checkout streams stop being cut |
| F7 | Dedicated reqwest client (15 s timeout) injected into openidconnect; discovery metadata cached ~10 min TTL | Login can't hang forever |
| F8 | Client IP extraction honors a configured trusted-proxy count (`X-Forwarded-For` parsed only then); remove global `"anon"` bucket (fall back to connection peer addr); INCR failures fail open like connection failures | Closes spoofable bypass |

Every row ships a regression test: cross-tenant gRPC attempt denied; Redis outage fails open; spawn_blocking keeps runtime responsive under login load; configured pool size observed; WAL asserted on SQLite handle; panic returns JSON 500; SIGTERM drains gRPC stream in-flight; OIDC provider hang times out at 15 s; spoofed XFF does not evade limiting.

**Early packaging:** CONTRIBUTING.md (dev setup, fmt/clippy gates, test matrix), CODE_OF_CONDUCT.md (Contributor Covenant), SECURITY.md (responsible disclosure, supported versions), bug/feature issue templates (YAML forms), PR template with checklist, README badges (CI, license, codecov optional), repo description/topics/social preview.

### Phase 2 — REST machine lifecycle

New routes mirroring gRPC semantics via the same domain layer (handlers are thin translation):

| Route | Mirrors | Notes |
|---|---|---|
| `POST /v1/accounts/:aid/licenses/:lid/actions/activate` | `Activate` | body `{fingerprint, name?, platform?}` → machine; enforces `max_machines`; honors `Idempotency-Key` |
| `POST .../machines/:mid/actions/ping` | `Ping` | bumps heartbeat, returns `next_heartbeat` |
| `POST .../machines/:mid/actions/deactivate` | `Deactivate` | frees a seat |
| `POST .../licenses/:lid/actions/checkin` | `CheckIn` | resets metering window |

Auth semantics identical to existing REST validate: token-scoped; anonymous permitted on unprotected accounts (existing rule, `routes.rs` route-comment). Router middleware (auth, rate-limit, tracing) applies automatically. E2E suite mirrors the existing lifecycle tests **plus a transport-parity test**: REST and gRPC produce identical state transitions for the same operation sequence.

### Phase 3 — SDKs + public contract

- **`openapi.yaml`** (OpenAPI 3.1, hand-authored at repo root) — single source of truth for the REST surface. New CI drift-check: every registered axum route must appear in the spec (build fails on undocumented endpoints). Upgrade path: `utoipa` derive macros replace hand-authoring later.
- **Python SDK** `sdks/python` — stdlib-only (`urllib.request`, matching TS SDK's zero-dep philosophy); full resource coverage + validate/activate/ping/deactivate/checkin/checkout; HMAC webhook-verify helper; pytest E2E boots the real server binary as fixture (SQLite tmpfile, random port).
- **Go SDK** `sdks/go` — `net/http` stdlib only; same surface; same live-server test pattern.
- **Java** — generated, not hand-written: CI job runs `openapi-generator-cli` against `openapi.yaml`, attaches jar to GitHub Releases.
- All SDKs version `0.x` tracking server minor versions; changelogs per SDK.

### Phase 4 — Docs site

- **mkdocs-material**: built-in client-side full-text search, auto sitemap.xml, per-page OpenGraph/Twitter meta, canonical URLs, responsive/dark mode. Chosen over mdBook purely on SEO surface; both have search.
- Existing `docs/*.md` remain the source of truth; site nav references them (no forked copies). Landing page = hero + README screenshot grid (`docs/screenshots/*`).
- Nav: Home → Getting started → API reference → SDK guide ×4 → Architecture → Deployment → Webhooks → Security audit → FAQ (new).
- CI: `mkdocs build --strict` (dead links fail build) on PRs; deploy-to-Pages workflow on push to `main`. `robots.txt` crawl-friendly; custom-domain slot = one config line.

### Phase 5 — Packaging completion + launch gate

**Release workflow:** tag `vX.Y.Z` → release binaries (linux x86_64+arm64, macOS x86_64+arm64, distroless images to GHCR) → GitHub Release with CHANGELOG notes; Java jar attached by the Phase 3 generator job.

**Launch gate — ALL must be green:**
1. Audit items F1–F8 closed with regression tests passing; existing 127+ tests green
2. OpenAPI drift-check passing — zero undocumented routes
3. Four SDK suites green (Rust, TypeScript, Python, Go) against the live server
4. Docs site deployed; search functional; strict-mode link check clean
5. Secrets scan (gitleaks) clean in CI

## 6. Testing strategy

- **Hardening:** one regression test per finding (list in Phase 1).
- **Transport parity:** REST vs gRPC state-transition equivalence suite.
- **SDKs:** live-server E2E per SDK, following the Rust/TS precedent.
- **Docs/site:** strict-mode build + link checking in CI.
- **Performance acceptance:** concurrent-login benchmark before/after F3 — worker stall eliminated and RSS growth sub-linear vs connection count; wrk baseline re-measured post-F2.

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Rate-limit keying change (F8) alters behavior for existing deployments | Documented migration note; trusted-proxy setting defaults preserve direct-exposure correctness |
| mkdocs strict mode fails on pre-existing doc links | Link fixes are part of Phase 4, done once |
| Generated Java SDK quality/idiom | Positioned as generated artifact; native client only on demand |
| SQLite WAL on network filesystems | Deployment doc caveat (WAL auto-disabled where unsupported by sqlite) |
| ConnectionManager changes Redis failure semantics | Uniform fail-open policy + tests for both outage modes |

## 8. Success criteria

Program is complete when the Phase 5 launch gate (§5) is fully green **and** the performance acceptance criteria (§6) hold. Post-launch follow-ups (utoipa, Maven Central, custom domain) are tracked, not blocking.
