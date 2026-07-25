//! `license-server` — binary entry point.
//!
//! Loads config, initializes telemetry, and dispatches to the requested role
//! (`--role=api|worker|scheduler|all`). In v1 Phase 0 the `api` role serves a
//! `/healthz` endpoint; later phases populate the REST router, gRPC service,
//! and worker/scheduler loops.

mod config;
mod runtime;
mod telemetry;

use crate::config::Role;
use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cfg = match config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: invalid configuration: {e}");
            eprintln!("hint: set LICENSE_SERVER__DATABASE__URL, LICENSE_SERVER__REDIS__URL, LICENSE_SERVER__CRYPTO__MASTER_KEY");
            return ExitCode::from(2);
        }
    };

    telemetry::init(&cfg);
    tracing::info!(target: "license_server::boot", "{}", cfg.display_safe());

    // Install a panic hook that logs the panic so it surfaces in structured
    // logs before the process aborts. (Default hook still writes to stderr.)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "task panicked");
        default_hook(info);
    }));

    match run(cfg).await {
        Ok(()) => {
            tracing::info!("shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "fatal runtime error");
            ExitCode::FAILURE
        }
    }
}

async fn run(cfg: config::Config) -> Result<()> {
    match cfg.role {
        Role::Api => runtime::run_api(&cfg).await,
        Role::Worker => runtime::run_worker(&cfg).await,
        Role::Scheduler => runtime::run_scheduler(&cfg).await,
        Role::All => runtime::run_all(&cfg).await,
    }
}
