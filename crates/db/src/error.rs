//! Error + pool type aliases.

use license_domain::error::DomainError;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

/// Convert a sqlx error into a domain error, preserving uniqueness violations.
pub(crate) fn map_err(e: sqlx::Error) -> DomainError {
    match &e {
        sqlx::Error::RowNotFound => DomainError::NotFound("row not found".into()),
        sqlx::Error::Database(db) => {
            // SQLite, Postgres, MySQL all report unique violations via code/message.
            let msg = db.message();
            if msg.contains("UNIQUE") || msg.to_lowercase().contains("duplicate") {
                DomainError::Conflict(msg.into())
            } else {
                DomainError::Internal(msg.into())
            }
        }
        _ => DomainError::Internal(e.to_string()),
    }
}

/// Convenience: wrap an "optional row" into a Result, mapping None → NotFound.
/// Accepts `Option<Result<T, DomainError>>` (the shape produced by
/// `row.map(|r| row_to_x(&r))` after the `?` has handled the sqlx error).
pub(crate) fn not_found<T>(res: Option<Result<T, DomainError>>) -> Result<T, DomainError> {
    res.ok_or_else(|| DomainError::NotFound("row not found".into()))?
}

/// The SQLite connection pool. Postgres/MySQL pools are added in their modules.
pub type SqliteConnPool = sqlx::Pool<sqlx::Sqlite>;

/// A backend-agnostic handle. Phase 1 ships SQLite; Phase 1.x adds Postgres.
#[derive(Debug, Clone)]
pub enum Pool {
    Sqlite(SqliteConnPool),
    // Postgres(SqliteConnPool) and Mysql(...) added incrementally.
}

impl Pool {
    /// Build an in-memory SQLite pool and run migrations. Ideal for tests.
    pub async fn sqlite_in_memory() -> Result<Self, DomainError> {
        // create_if_missing keeps the in-memory db alive for the pool's lifetime.
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(map_err)?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1) // in-memory db is per-connection; share one.
            .connect_with(opts)
            .await
            .map_err(map_err)?;
        // Run the migration SQL (idempotency via the _sqlx_migrations table).
        sqlx::raw_sql(crate::migrations::SQLITE)
            .execute(&pool)
            .await
            .map_err(map_err)?;
        Ok(Self::Sqlite(pool))
    }

    /// Connect from a URL, auto-detect backend, and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self, DomainError> {
        let backend = crate::Backend::from_url(database_url)?;
        match backend {
            crate::Backend::Sqlite => {
                let opts = SqliteConnectOptions::from_str(database_url)
                    .map_err(map_err)?
                    .create_if_missing(true);
                let pool = SqlitePoolOptions::new()
                    .max_connections(8)
                    .connect_with(opts)
                    .await
                    .map_err(map_err)?;
                sqlx::raw_sql(crate::migrations::SQLITE)
                    .execute(&pool)
                    .await
                    .map_err(map_err)?;
                Ok(Self::Sqlite(pool))
            }
            crate::Backend::Postgres | crate::Backend::Mysql => {
                // Postgres/MySQL pools land in Phase 1.x. Fail explicitly so
                // callers know to use the SQLite path until then.
                Err(DomainError::Invalid(format!(
                    "backend `{backend}` pool not yet wired in this build; \
                     use SQLite for now (Postgres/MySQL land next)",
                )))
            }
        }
    }
}

/// Re-export the domain's DbError placeholder name for clarity at call sites
/// that want a single error import.
pub use license_domain::DomainError as DbError;
