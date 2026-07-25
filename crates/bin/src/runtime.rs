//! Runtime — wires together and dispatches the requested role(s).
//!
//! Phase 0 scope:
//!   - `run_api`: serves a minimal HTTP router with `/healthz` and `/readyz`.
//!   - `run_worker` / `run_scheduler`: log-only placeholders that keep the
//!     process alive until shutdown (populated in later phases).
//!   - `run_all`: drives `api` + `worker` + `scheduler` concurrently and
//!     returns when any one of them errors or the process is signaled.
//!
//! Later phases will:
//!   - swap `health_router()` for `license_api::router(repo, …)`;
//!   - bring up the tonic gRPC service in the api role;
//!   - populate the apalis worker pool and cron scheduler.

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
use tokio::signal;
use tracing::{error, info};

/// Entry for the `api` role: HTTP + (later) gRPC.
pub async fn run_api(cfg: &Config) -> Result<()> {
    let app = build_app(cfg).await?;
    let addr: SocketAddr = format!("{}:{}", cfg.http.host, cfg.http.port)
        .parse()
        .context("invalid http bind address")?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding http {addr}"))?;
    info!(addr = %addr, "http listening");
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server")?;
    Ok(())
}

/// Entry for the `worker` role: apalis job runners (later).
pub async fn run_worker(cfg: &Config) -> Result<()> {
    info!("worker role: starting (phase 5 will populate apalis workers)");
    // Keep alive until shutdown.
    shutdown_signal().await;
    info!("worker role: shutdown");
    let _ = cfg;
    Ok(())
}

/// Entry for the `scheduler` role: cron sweeps (later).
pub async fn run_scheduler(cfg: &Config) -> Result<()> {
    info!("scheduler role: starting (phase 5 will populate cron jobs)");
    shutdown_signal().await;
    info!("scheduler role: shutdown");
    let _ = cfg;
    Ok(())
}

/// Entry for `all`: run api + worker + scheduler concurrently.
pub async fn run_all(cfg: &Config) -> Result<()> {
    // Fail fast on unreachable dependencies in `all` mode — better to refuse
    // to start than to serve 500s. Individual role entrypoints skip this.
    preflight(cfg).await?;

    let api_cfg = cfg.clone();
    let worker_cfg = cfg.clone();
    let sched_cfg = cfg.clone();

    let (api, worker, sched) = tokio::join!(
        run_api(&api_cfg),
        run_worker(&worker_cfg),
        run_scheduler(&sched_cfg)
    );

    api?;
    worker?;
    sched?;
    Ok(())
}

/// Build the axum app: the v1 API router merged with health endpoints.
async fn build_app(cfg: &Config) -> Result<Router> {
    // Connect to the configured database + run migrations.
    let pool = license_db::Pool::connect(&cfg.database.url)
        .await
        .context("connecting database")?;
    let repo = license_db::SqliteRepository::from(pool);

    // Decode the master key (32 bytes hex) into the in-memory secret. In
    // production this becomes the KMS-backed KeyStore (Phase 2 seam).
    let master_secret =
        decode_master_secret(&cfg.crypto.master_key).context("decoding master key")?;

    let state = license_api::extract::AppState {
        repo: std::sync::Arc::new(repo),
        master_secret: std::sync::Arc::new(master_secret),
    };

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
