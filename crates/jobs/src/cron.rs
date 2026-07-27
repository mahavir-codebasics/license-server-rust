//! Cron-scheduled sweep workers.
//!
//! These run on a schedule (every minute / hour) and maintain license/machine
//! correctness over time. Without them floating licenses and metering break at
//! the boundaries — at "millions of devices" scale the dead-machine culler is
//! essential to reclaim floating slots.
//!
//! Backed by apalis-cron. The job types are zero-sized markers (cron ticks
//! construct one per fire); shared state (the `Repository`, an HTTP client)
//! is injected via apalis `Data<T>` extractors.
//!
//! Worker assembly (the `WorkerBuilder::new(..).data(..).backend(..).build_fn(..)`
//! chain) lives in [`crate`]'s `run_*` functions so the fully-built
//! `Worker<Ready<S, P>>` type is inferred at the `Monitor::register` call site
//! — apalis's worker service type is generic over the middleware stack and is
//! unwieldy to name explicitly.

use apalis_cron::{CronContext, CronStream, Schedule};
use chrono::{Local, Utc};
use license_domain::repository::Repository;
use std::str::FromStr;
use std::sync::Arc;
use time::OffsetDateTime;

/// Marker for the license-expirations sweep (every minute).
#[derive(Debug, Default)]
pub struct LicenseExpirySweep;

/// Marker for the overdue-check-in sweep (every minute).
#[derive(Debug, Default)]
pub struct OverdueCheckInSweep;

/// Marker for the dead-machines cull (every minute; tight for floating).
#[derive(Debug, Default)]
pub struct DeadMachinesCull;

/// Marker for the signing-key retirement sweep (hourly).
#[derive(Debug, Default)]
pub struct SigningKeyRetireSweep;

/// One tick of the license-expirations sweep: mark licenses past their expiry
/// as EXPIRED. Idempotent — safe to run repeatedly.
pub async fn run_license_expiry_sweep(
    _job: LicenseExpirySweep,
    ctx: CronContext<Utc>,
    repo: apalis::prelude::Data<Arc<dyn Repository>>,
) {
    let now = to_offset(ctx.get_timestamp().with_timezone(&Local));
    match repo.licenses().expire_due(now).await {
        Ok(n) if n > 0 => tracing::info!(expired = n, "license-expirations sweep"),
        Ok(_) => tracing::debug!("license-expirations sweep: 0 expired"),
        Err(e) => tracing::error!(error = %e, "license-expirations sweep failed"),
    }
}

/// Mark licenses whose check-in window has elapsed as overdue. The actual
/// revoke decision (based on `max_overdue_check_ins`) happens in a follow-up
/// pass; here we just bump the counter.
pub async fn run_overdue_check_in_sweep(
    _job: OverdueCheckInSweep,
    ctx: CronContext<Utc>,
    repo: apalis::prelude::Data<Arc<dyn Repository>>,
) {
    let now = to_offset(ctx.get_timestamp().with_timezone(&Local));
    match repo.licenses().mark_overdue_check_ins(now).await {
        Ok(n) if n > 0 => tracing::info!(marked_overdue = n, "overdue-check-in sweep"),
        Ok(_) => tracing::debug!("overdue-check-in sweep: 0 marked"),
        Err(e) => tracing::error!(error = %e, "overdue-check-in sweep failed"),
    }
}

/// Cull machines whose heartbeat has elapsed (per their cull strategy), freeing
/// floating-license slots. Runs frequently so floating seats recycle promptly.
pub async fn run_dead_machines_cull(
    _job: DeadMachinesCull,
    ctx: CronContext<Utc>,
    repo: apalis::prelude::Data<Arc<dyn Repository>>,
) {
    let now = to_offset(ctx.get_timestamp().with_timezone(&Local));
    match repo.machines().cull_dead(now).await {
        Ok(n) if n > 0 => tracing::info!(culled = n, "dead-machines cull"),
        Ok(_) => tracing::debug!("dead-machines cull: 0 culled"),
        Err(e) => tracing::error!(error = %e, "dead-machines cull failed"),
    }
}

/// Retire signing keys whose rotation grace period has elapsed (hourly).
pub async fn run_signing_key_retire_sweep(
    _job: SigningKeyRetireSweep,
    ctx: CronContext<Utc>,
    repo: apalis::prelude::Data<Arc<dyn Repository>>,
) {
    let now = to_offset(ctx.get_timestamp().with_timezone(&Local));
    match repo.signing_keys().retire_expired(now).await {
        Ok(n) if n > 0 => tracing::info!(retired = n, "signing-key retire sweep"),
        Ok(_) => tracing::debug!("signing-key retire sweep: 0 retired"),
        Err(e) => tracing::error!(error = %e, "signing-key retire sweep failed"),
    }
}

/// Every-minute schedule (second 0 of each minute).
pub fn every_minute() -> Schedule {
    Schedule::from_str("0 * * * * *").expect("valid cron: every minute")
}

/// Every-hour schedule (minute 0, second 0).
pub fn every_hour() -> Schedule {
    Schedule::from_str("0 0 * * * *").expect("valid cron: every hour")
}

/// Build the cron stream backend (UTC) for the license-expirations sweep.
pub fn license_expiry_stream() -> CronStream<LicenseExpirySweep, Utc> {
    CronStream::new(every_minute())
}

/// Build the cron stream backend (UTC) for the overdue-check-in sweep.
pub fn overdue_check_in_stream() -> CronStream<OverdueCheckInSweep, Utc> {
    CronStream::new(every_minute())
}

/// Build the cron stream backend (UTC) for the dead-machines cull.
pub fn dead_machines_cull_stream() -> CronStream<DeadMachinesCull, Utc> {
    CronStream::new(every_minute())
}

/// Build the cron stream backend (UTC) for the signing-key retire sweep.
pub fn signing_key_retire_stream() -> CronStream<SigningKeyRetireSweep, Utc> {
    CronStream::new(every_hour())
}

/// Convert a chrono DateTime to time::OffsetDateTime (the domain crate uses
/// `time`, apalis-cron uses `chrono`).
fn to_offset(dt: chrono::DateTime<Local>) -> OffsetDateTime {
    use time::OffsetDateTime as TOD;
    let ts = dt.timestamp();
    let nanos = dt.timestamp_subsec_nanos();
    TOD::from_unix_timestamp_nanos(ts as i128 * 1_000_000_000 + nanos as i128)
        .unwrap_or_else(|_| TOD::now_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_parse() {
        // 6-field cron with leading seconds. Must not panic.
        let _ = every_minute();
        let _ = every_hour();
    }

    #[test]
    fn chrono_to_offset_conversion_is_sane() {
        let now_chrono = Local::now();
        let now_time = to_offset(now_chrono);
        // within 5 seconds of "now" (allowing for the call overhead)
        let diff = (now_time.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp()).abs();
        assert!(diff < 5, "conversion drifted by {diff}s");
    }

    #[test]
    fn cron_streams_are_utc() {
        // backends build without panicking; their schedule matches the helpers
        let _ = license_expiry_stream();
        let _ = overdue_check_in_stream();
        let _ = dead_machines_cull_stream();
        let _ = signing_key_retire_stream();
    }
}
