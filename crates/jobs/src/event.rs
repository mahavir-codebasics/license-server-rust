//! Event-log writer — async audit append.
//!
//! API handlers call [`record`] to enqueue an audit event; this spawns a
//! best-effort task that writes it via the `EventLogRepo`. Failures are logged
//! but never bubble up to the caller — the audit log must not break the
//! request path. For high-throughput deployments this would batch/buffer; v1
//! keeps it simple (one append per event, fire-and-forget).

use license_domain::repository::Repository;
use license_domain::{AccountId, EventLog, EventSeverity};
use serde_json::Value;
use std::sync::Arc;

/// Spawn a best-effort task to append an audit event. Returns immediately.
pub fn record(
    repo: Arc<dyn Repository>,
    account_id: AccountId,
    event_type: impl Into<String>,
    payload: Value,
) {
    let mut event = EventLog::new(account_id, event_type, payload);
    event.severity = EventSeverity::Info;
    tokio::spawn(async move {
        if let Err(e) = repo.events().append(&event).await {
            tracing::warn!(error = %e, event_type = %event.event_type, "audit append failed");
        }
    });
}

/// Spawn a warning-level audit event.
pub fn warn(
    repo: Arc<dyn Repository>,
    account_id: AccountId,
    event_type: impl Into<String>,
    payload: Value,
) {
    let mut event = EventLog::new(account_id, event_type, payload);
    event.severity = EventSeverity::Warning;
    tokio::spawn(async move {
        if let Err(e) = repo.events().append(&event).await {
            tracing::warn!(error = %e, "audit append (warn) failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use license_db::{Pool, SqliteRepository};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn record_appends_without_blocking_caller() {
        let pool = Pool::sqlite_in_memory().await.unwrap();
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::from(pool));
        // event_log.account_id has an FK to accounts, so we must create the
        // account row first — otherwise the append silently fails the FK
        // constraint and the spawned task just logs a warning.
        let account = repo
            .accounts()
            .create(&license_domain::Account::new("acme", "Acme"))
            .await
            .unwrap();
        record(
            repo.clone(),
            account.id,
            "license.created",
            serde_json::json!({"id": "lic-1"}),
        );
        // give the spawned task a moment
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let page = repo
            .events()
            .list(account.id, license_domain::repository::PageQuery::default())
            .await
            .unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].event_type, "license.created");
    }
}
