//! Runtime — wires together and dispatches the requested role(s).
//!
//!   - `run_api`: serves the v1 REST router + health endpoints.
//!   - `run_worker`: Redis-backed apalis workers (webhook delivery).
//!   - `run_scheduler`: cron sweeps (license expiry, heartbeat cull, key retire).
//!   - `run_all`: api + (cron + workers) concurrently.

use crate::config::Config;
use anyhow::{Context, Result};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use redis::aio::ConnectionManager;
use tokio::signal;
use tracing::{error, info};

/// Entry for the `api` role: HTTP REST + the gRPC hot-path server, concurrently.
pub async fn run_api(cfg: &Config) -> Result<()> {
    let repo = build_repo(cfg).await?;
    let (state, redis_mgr) = build_state(cfg, repo.clone()).await?;
    let master_secret = state.master_secret.clone();
    let app = compose_http(license_api::router(state));

    let http_addr: SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port)
        .parse()
        .context("invalid http bind address")?;
    let grpc_addr: SocketAddr = format!("{}:{}", cfg.grpc.host, cfg.grpc.port)
        .parse()
        .context("invalid grpc bind address")?;

    // gRPC hot path (tonic). Shares the same master secret as the REST API and
    // the same Redis handle for validate rate limiting (fail-open when absent).
    let grpc_svc = license_grpc::proto::license_service_server::LicenseServiceServer::new(
        license_grpc::LicenseService::new(repo.clone(), master_secret).with_limits(redis_mgr),
    );
    info!(addr = %grpc_addr, "grpc listening");
    let grpc_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(grpc_svc)
            .serve_with_shutdown(grpc_addr, shutdown_signal())
            .await
            .context("grpc server")
    });

    // HTTP REST (axum).
    let http_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding http {http_addr}"))?;
    info!(addr = %http_addr, "http listening");
    let http_task = tokio::spawn(async move {
        axum::serve(
            http_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server")
    });

    // Return when either errors.
    tokio::select! {
        res = grpc_task => {
            info!("grpc task finished");
            res.map_err(|e| anyhow::anyhow!("grpc join: {e}"))??;
            Ok(())
        }
        res = http_task => {
            info!("http task finished");
            res.map_err(|e| anyhow::anyhow!("http join: {e}"))??;
            Ok(())
        }
    }
}

/// Entry for the `worker` role: Redis-backed job runners (webhook delivery).
/// Connects the DB + Redis, then runs the apalis workers until shutdown.
pub async fn run_worker(cfg: &Config) -> Result<()> {
    let repo = build_repo(cfg).await?;
    info!("worker role: starting webhook-delivery workers");
    license_jobs::run_worker(repo, &cfg.redis.url, cfg.security.webhooks_allow_private)
        .await
        .map_err(|e| anyhow::anyhow!("worker role: {e}"))?;
    info!("worker role: shutdown");
    Ok(())
}

/// Entry for the `scheduler` role: cron sweeps (license expirations, heartbeat
/// culling, signing-key retirement). Runs as a singleton — the sweeps are
/// idempotent so duplicate runs across replicas are harmless, but a single
/// leader avoids pointless work. (Redis leader election lands in Phase 8.)
pub async fn run_scheduler(cfg: &Config) -> Result<()> {
    let repo = build_repo(cfg).await?;
    info!("scheduler role: starting cron sweeps");
    license_jobs::run_scheduler(repo)
        .await
        .map_err(|e| anyhow::anyhow!("scheduler role: {e}"))?;
    info!("scheduler role: shutdown");
    Ok(())
}

/// Entry for `all`: run the API server + the combined jobs runner (scheduler
/// cron sweeps + redis workers) concurrently, returning when either errors or
/// the process is signaled.
pub async fn run_all(cfg: &Config) -> Result<()> {
    preflight(cfg).await?;

    let repo = build_repo(cfg).await?;
    let (state, _redis_mgr) = build_state(cfg, repo.clone()).await?;

    // API task.
    let api_router = license_api::router(state);
    let http_addr: SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port)
        .parse()
        .context("invalid http bind address")?;
    let api_listener = tokio::net::TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding http {http_addr}"))?;
    info!(addr = %http_addr, "http listening");

    let api_task = tokio::spawn(async move {
        axum::serve(
            api_listener,
            compose_http(api_router).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server")
    });

    // Jobs task (cron + workers together).
    let jobs_repo = repo.clone();
    let jobs_redis = cfg.redis.url.clone();
    let jobs_allow_private = cfg.security.webhooks_allow_private;
    let jobs_task = tokio::spawn(async move {
        license_jobs::run_all_jobs(jobs_repo, &jobs_redis, jobs_allow_private)
            .await
            .map_err(|e| anyhow::anyhow!("jobs: {e}"))
    });

    // Return on the first to finish/error.
    tokio::select! {
        res = api_task => {
            info!("api task finished");
            res.map_err(|e| anyhow::anyhow!("api join: {e}"))??;
        }
        res = jobs_task => {
            info!("jobs task finished");
            res.map_err(|e| anyhow::anyhow!("jobs join: {e}"))??;
        }
    }
    Ok(())
}

/// Connect to the configured DB, run migrations, and return a backend-agnostic
/// `Arc<dyn Repository>`. Shared by every role.
async fn build_repo(cfg: &Config) -> Result<Arc<dyn license_domain::repository::Repository>> {
    Ok(
        license_db::Pool::connect(&cfg.database.url, cfg.database.max_connections)
            .await
            .context("connecting database")?
            .into_repository(),
    )
}

/// Build the AppState from config: DB repo + decoded master secret + optional
/// Redis client (for rate limiting + idempotency). Redis is best-effort — if
/// it's unreachable, the API still works (rate limiting + idempotency no-op).
/// Returns the state plus a clone of the manager so secondary consumers (gRPC)
/// share the same multiplexed connection.
async fn build_state(
    cfg: &Config,
    repo: Arc<dyn license_domain::repository::Repository>,
) -> Result<(license_api::extract::AppState, Option<ConnectionManager>)> {
    let master_secret =
        decode_master_secret(&cfg.crypto.master_key).context("decoding master key")?;
    let mut state = license_api::extract::AppState::new(repo, master_secret);
    state = state.with_trusted_proxies(cfg.security.trusted_proxies);
    state.allowed_origins = license_api::extract::parse_origin_csv(&cfg.security.allowed_origins);
    state.bootstrap_secret = cfg.security.bootstrap_secret.clone();
    state.webhooks_allow_private = cfg.security.webhooks_allow_private;
    let mut redis_mgr: Option<ConnectionManager> = None;
    if !cfg.redis.url.is_empty() {
        match redis::Client::open(cfg.redis.url.as_str()) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(mgr) => {
                    redis_mgr = Some(mgr.clone());
                    state = state.with_redis(mgr);
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "redis unreachable; rate limiting/idempotency disabled"
                ),
            },
            Err(e) => tracing::warn!(
                error = %e,
                "redis url invalid; rate limiting/idempotency disabled"
            ),
        }
    }
    Ok((state, redis_mgr))
}

/// Build the axum app: the v1 API router merged with health endpoints.
#[allow(dead_code)]
async fn build_app(cfg: &Config) -> Result<Router> {
    // Connect to the configured database + run migrations. The pool resolves
    // to the right backend (SQLite/Postgres/MySQL) from the URL scheme.
    let pool = license_db::Pool::connect(&cfg.database.url, cfg.database.max_connections)
        .await
        .context("connecting database")?;
    let repo = pool.into_repository();

    // Decode the master key + build the AppState (repo + master secret + Redis).
    let (state, _redis_mgr) = build_state(cfg, repo).await?;

    let api = license_api::router(state);
    Ok(compose_http(api))
}

/// Compose the served HTTP app: the v1 API router merged with the health
/// endpoints. Each side wraps its OWN routes in the telemetry stack before
/// merging (`Router::layer` skips post-merge routes, so wrapping only the
/// composed router would double-wrap what `router()` already covered).
fn compose_http(api: Router) -> Router {
    api.merge(health_router())
}

fn health_router() -> Router {
    license_api::with_telemetry(
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz)),
    )
}

/// Decode a 64-char hex string into 32 bytes. Returns a zeroed key if unset
/// (the binary refuses to start with a real "all-zeros" key — see main's
/// config check — but we still need a value for tests).
fn decode_master_secret(hex_key: &str) -> anyhow::Result<[u8; 32]> {
    if hex_key.is_empty() || hex_key.chars().all(|c| c == '0') {
        anyhow::bail!(
            "LICENSE_SERVER__CRYPTO__MASTER_KEY is unset/zero — generate one with `openssl rand -hex 32`"
        );
    }
    let bytes = hex::decode(hex_key).context("master key is not valid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "master key must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn healthz() -> Response {
    // Liveness: process is up.
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

async fn readyz() -> Response {
    // Readiness: in Phase 0 we're always ready; later this probes DB+Redis.
    (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
}

/// Best-effort preflight checks for `all` role: connect to Redis, log
/// connectivity. Single-role entrypoints skip this so e.g. a worker can boot
/// independently. Real DB ping lands in Phase 1 once the `db` crate exports
/// a backend-agnostic pool.
async fn preflight(cfg: &Config) -> Result<()> {
    // Best-effort Redis PING.
    match redis::Client::open(cfg.redis.url.as_str()) {
        Ok(client) => match client.get_connection() {
            Ok(mut conn) => {
                let _: () = redis::cmd("PING").query(&mut conn).unwrap_or(());
                info!("preflight: redis ping ok");
            }
            Err(e) => error!("preflight: redis unreachable: {e}"),
        },
        Err(e) => error!("preflight: bad redis url: {e}"),
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl-c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

#[cfg(test)]
mod http_composition {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    /// Health routes must ride the same telemetry stack as the v1 API
    /// (`x-request-id` present) even though they're merged in from outside
    /// `license_api::router`.
    #[tokio::test]
    async fn health_routes_carry_request_id() {
        let res = compose_http(Router::new())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(res.headers().contains_key("x-request-id"));
    }

    /// Unmatched routes through the composed app still get the standard JSON
    /// error envelope shape (api fallback), not an empty body.
    #[tokio::test]
    async fn unmatched_route_returns_envelope_fallback() {
        let res = compose_http(Router::new())
            .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::NOT_FOUND);
        assert!(res.headers().contains_key("x-request-id"));
    }
}
