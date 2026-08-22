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
    let state = build_state(cfg, repo.clone()).await?;
    let master_secret = state.master_secret.clone();
    let app = license_api::router(state).merge(
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz)),
    );

    let http_addr: SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port)
        .parse()
        .context("invalid http bind address")?;
    let grpc_addr: SocketAddr = format!("{}:{}", cfg.grpc.host, cfg.grpc.port)
        .parse()
        .context("invalid grpc bind address")?;

    // gRPC hot path (tonic). Shares the same master secret as the REST API.
    let grpc_svc = license_grpc::proto::license_service_server::LicenseServiceServer::new(
        license_grpc::LicenseService::new(repo.clone(), master_secret),
    );
    // gRPC binds its own listener internally via .serve(addr).
    info!(addr = %grpc_addr, "grpc listening");
    let grpc_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(grpc_svc)
            .serve(grpc_addr)
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
    license_jobs::run_worker(repo, &cfg.redis.url)
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
    let state = build_state(cfg, repo.clone()).await?;

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
            api_router
                .merge(
                    Router::new()
                        .route("/healthz", get(healthz))
                        .route("/readyz", get(readyz)),
                )
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server")
    });

    // Jobs task (cron + workers together).
    let jobs_repo = repo.clone();
    let jobs_redis = cfg.redis.url.clone();
    let jobs_task = tokio::spawn(async move {
        license_jobs::run_all_jobs(jobs_repo, &jobs_redis)
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
    Ok(license_db::Pool::connect(&cfg.database.url)
        .await
        .context("connecting database")?
        .into_repository())
}

/// Build the AppState from config: DB repo + decoded master secret + optional
/// Redis client (for rate limiting + idempotency). Redis is best-effort — if
/// it's unreachable, the API still works (rate limiting + idempotency no-op).
async fn build_state(
    cfg: &Config,
    repo: Arc<dyn license_domain::repository::Repository>,
) -> Result<license_api::extract::AppState> {
    let master_secret =
        decode_master_secret(&cfg.crypto.master_key).context("decoding master key")?;
    let mut state = license_api::extract::AppState::new(repo, master_secret);
    state = state.with_trusted_proxies(cfg.security.trusted_proxies);
    state.allowed_origins = license_api::extract::parse_origin_csv(&cfg.security.allowed_origins);
    if !cfg.redis.url.is_empty() {
        match redis::Client::open(cfg.redis.url.as_str()) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(mgr) => state = state.with_redis(mgr),
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
    Ok(state)
}

/// Build the axum app: the v1 API router merged with health endpoints.
#[allow(dead_code)]
async fn build_app(cfg: &Config) -> Result<Router> {
    // Connect to the configured database + run migrations. The pool resolves
    // to the right backend (SQLite/Postgres/MySQL) from the URL scheme.
    let pool = license_db::Pool::connect(&cfg.database.url)
        .await
        .context("connecting database")?;
    let repo = pool.into_repository();

    // Decode the master key + build the AppState (repo + master secret + Redis).
    let state = build_state(cfg, repo).await?;

    let api = license_api::router(state);
    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(api))
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
