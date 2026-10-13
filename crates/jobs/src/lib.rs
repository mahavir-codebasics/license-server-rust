//! `license-jobs` — background workers + cron sweeps + audit logging.
//!
//! Three concerns, all async and decoupled from the request path:
//!
//! 1. **Cron sweeps** ([`cron`]) — license expirations, overdue check-ins,
//!    dead-machine culling, signing-key retirement. Run on a schedule.
//! 2. **Webhook delivery** ([`webhook`]) — Redis-queued POST with HMAC-SHA256
//!    signing + exponential backoff retry.
//! 3. **Audit logging** ([`event`]) — fire-and-forget event-log appends.
//!
//! ## Roles
//! The binary selects a role via `--role`:
//!   - `scheduler` — runs ONLY the cron sweeps (run as a singleton; the sweeps
//!     are idempotent so duplicate runs are harmless, but a single leader
//!     avoids pointless work).
//!   - `worker` — runs ONLY the Redis-backed workers (webhook delivery).
//!     Scale horizontally: run N replicas.
//!   - `all` — runs everything in one process (dev / small deployments).
//!
//! Graceful shutdown: the Monitor's `run_with_signal` waits for SIGINT/SIGTERM
//! then drains in-flight jobs up to `shutdown_timeout`.

pub mod cron;
pub mod event;
pub mod webhook;

pub use event::{record, warn};
pub use webhook::{
    deliver_webhook, sign_webhook, validate_endpoint_url, validate_public_url, WebhookDeliveryJob,
};

use apalis::layers::WorkerBuilderExt;
use apalis::prelude::{Monitor, WorkerBuilder, WorkerFactoryFn};
use license_domain::repository::Repository;
use std::sync::Arc;
use std::time::Duration;

/// Run ONLY the cron sweeps, until shutdown. Use for the `scheduler` role.
pub async fn run_scheduler(repo: Arc<dyn Repository>) -> anyhow::Result<()> {
    tracing::info!("scheduler: starting cron sweeps");
    let monitor = Monitor::new()
        .register(
            WorkerBuilder::new("license-expirations")
                .data(repo.clone())
                .backend(cron::license_expiry_stream())
                .build_fn(cron::run_license_expiry_sweep),
        )
        .register(
            WorkerBuilder::new("overdue-check-ins")
                .data(repo.clone())
                .backend(cron::overdue_check_in_stream())
                .build_fn(cron::run_overdue_check_in_sweep),
        )
        .register(
            WorkerBuilder::new("dead-machines-cull")
                .data(repo.clone())
                .backend(cron::dead_machines_cull_stream())
                .build_fn(cron::run_dead_machines_cull),
        )
        .register(
            WorkerBuilder::new("signing-key-retire")
                .data(repo)
                .backend(cron::signing_key_retire_stream())
                .build_fn(cron::run_signing_key_retire_sweep),
        )
        .shutdown_timeout(Duration::from_secs(10));

    monitor
        .run_with_signal(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("scheduler monitor: {e}"))?;
    tracing::info!("scheduler: stopped");
    Ok(())
}

/// Run ONLY the Redis-backed workers (webhook delivery), until shutdown.
/// Use for the `worker` role. `redis_url` connects to the queue. `allow_private`
/// opts out of the webhook SSRF guard for internal-network receivers.
pub async fn run_worker(
    repo: Arc<dyn Repository>,
    redis_url: &str,
    allow_private: bool,
) -> anyhow::Result<()> {
    tracing::info!("worker: starting redis workers");
    let storage = webhook::webhook_storage(redis_url)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let http = webhook_http_client();

    let monitor = Monitor::new()
        .register(
            WorkerBuilder::new("webhook-delivery")
                .data(repo)
                .data(http)
                .data(allow_private)
                // Limits in-flight deliveries. Requires apalis `layers` feature
                // (which pulls `tower/limit`); see Cargo.toml.
                .concurrency(8)
                .backend(storage)
                .build_fn(webhook::deliver_webhook),
        )
        .shutdown_timeout(Duration::from_secs(15));

    monitor
        .run_with_signal(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("worker monitor: {e}"))?;
    tracing::info!("worker: stopped");
    Ok(())
}

/// Delivery client: redirects disabled so a webhook can't 302 its way past the
/// SSRF guard onto a private target.
fn webhook_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds without runtime config")
}

/// Run everything (cron + workers) in one process. Use for `all` / dev.
pub async fn run_all_jobs(
    repo: Arc<dyn Repository>,
    redis_url: &str,
    allow_private: bool,
) -> anyhow::Result<()> {
    tracing::info!("jobs(all): starting scheduler + workers");
    let storage = webhook::webhook_storage(redis_url)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let http = webhook_http_client();

    let monitor = Monitor::new()
        .register(
            WorkerBuilder::new("license-expirations")
                .data(repo.clone())
                .backend(cron::license_expiry_stream())
                .build_fn(cron::run_license_expiry_sweep),
        )
        .register(
            WorkerBuilder::new("overdue-check-ins")
                .data(repo.clone())
                .backend(cron::overdue_check_in_stream())
                .build_fn(cron::run_overdue_check_in_sweep),
        )
        .register(
            WorkerBuilder::new("dead-machines-cull")
                .data(repo.clone())
                .backend(cron::dead_machines_cull_stream())
                .build_fn(cron::run_dead_machines_cull),
        )
        .register(
            WorkerBuilder::new("signing-key-retire")
                .data(repo.clone())
                .backend(cron::signing_key_retire_stream())
                .build_fn(cron::run_signing_key_retire_sweep),
        )
        .register(
            WorkerBuilder::new("webhook-delivery")
                .data(repo)
                .data(http)
                .data(allow_private)
                .concurrency(8)
                .backend(storage)
                .build_fn(webhook::deliver_webhook),
        )
        .shutdown_timeout(Duration::from_secs(10));

    monitor
        .run_with_signal(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("jobs monitor: {e}"))?;
    tracing::info!("jobs(all): stopped");
    Ok(())
}

/// Resolve on SIGINT or SIGTERM (Unix). Used as the shutdown signal for the
/// apalis Monitor.
///
/// apalis 0.7's `Monitor::run_with_signal` requires the signal future to
/// resolve to `std::io::Result<()>`, so this returns `std::io::Error` directly
/// (not `anyhow::Error`). The outer `run_*` functions keep their
/// `anyhow::Result` return type — the io::Error is converted there.
async fn shutdown_signal() -> std::io::Result<()> {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await?;
        tracing::info!("received SIGINT");
        Ok::<(), std::io::Error>(())
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix;
        let mut sig = unix::signal(unix::SignalKind::terminate())?;
        sig.recv().await;
        tracing::info!("received SIGTERM");
        Ok::<(), std::io::Error>(())
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<std::io::Result<()>>();

    tokio::select! {
        res = ctrl_c => res,
        res = terminate => res,
    }
}
