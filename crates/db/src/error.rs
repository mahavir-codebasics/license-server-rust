//! Error + pool type aliases.

use license_domain::error::DomainError;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
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

/// Per-backend connection pool type aliases.
pub type SqliteConnPool = sqlx::Pool<sqlx::Sqlite>;
pub type PostgresConnPool = sqlx::Pool<sqlx::Postgres>;
pub type MysqlConnPool = sqlx::Pool<sqlx::MySql>;

/// A backend-agnostic handle. Owns one pool per backend.
#[derive(Debug, Clone)]
pub enum Pool {
    Sqlite(SqliteConnPool),
    Postgres(PostgresConnPool),
    Mysql(MysqlConnPool),
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
    ///
    /// Postgres and MySQL require a reachable server (there is no in-memory
    /// equivalent). The migration SQL for the detected backend is run verbatim;
    /// both PG and MySQL migrations are written to be idempotent on objects they
    /// own (`CREATE TABLE` will still fail on re-run — call this on a fresh DB,
    /// or use the per-backend migration tracker in a real deploy).
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
            crate::Backend::Postgres => {
                let pool = PgPoolOptions::new()
                    .max_connections(8)
                    .connect(database_url)
                    .await
                    .map_err(map_err)?;
                sqlx::raw_sql(crate::migrations::POSTGRES)
                    .execute(&pool)
                    .await
                    .map_err(map_err)?;
                Ok(Self::Postgres(pool))
            }
            crate::Backend::Mysql => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(8)
                    .connect(database_url)
                    .await
                    .map_err(map_err)?;
                sqlx::raw_sql(crate::migrations::MYSQL)
                    .execute(&pool)
                    .await
                    .map_err(map_err)?;
                Ok(Self::Mysql(pool))
            }
        }
    }
}

/// Re-export the domain's DbError placeholder name for clarity at call sites
/// that want a single error import.
pub use license_domain::DomainError as DbError;

impl Pool {
    /// Consume the pool and return a backend-agnostic `Arc<dyn Repository>`.
    /// Selects the right concrete `*Repository` based on which variant we are.
    pub fn into_repository(self) -> std::sync::Arc<dyn license_domain::repository::Repository> {
        match self {
            Pool::Sqlite(p) => std::sync::Arc::new(crate::SqliteRepository::new(p)),
            Pool::Postgres(p) => std::sync::Arc::new(crate::PostgresRepository::new(p)),
            Pool::Mysql(p) => std::sync::Arc::new(crate::MysqlRepository::new(p)),
        }
    }
}
