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
    /// equivalent). Migrations run once per bundle version, tracked in a
    /// `_migrations` table — re-boots against an existing database skip
    /// already-applied bundles (OPS-001).
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, DomainError> {
        let backend = crate::Backend::from_url(database_url)?;
        let max = max_connections.max(1);
        match backend {
            crate::Backend::Sqlite => {
                let opts = SqliteConnectOptions::from_str(database_url)
                    .map_err(map_err)?
                    .create_if_missing(true)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                    .busy_timeout(std::time::Duration::from_secs(5));
                let pool = SqlitePoolOptions::new()
                    .max_connections(max)
                    .connect_with(opts)
                    .await
                    .map_err(map_err)?;
                Self::run_migrations_sqlite(&pool).await?;
                Ok(Self::Sqlite(pool))
            }
            crate::Backend::Postgres => {
                let pool = PgPoolOptions::new()
                    .max_connections(max)
                    .connect(database_url)
                    .await
                    .map_err(map_err)?;
                Self::run_migrations_pg(&pool).await?;
                Ok(Self::Postgres(pool))
            }
            crate::Backend::Mysql => {
                let pool = MySqlPoolOptions::new()
                    .max_connections(max)
                    .connect(database_url)
                    .await
                    .map_err(map_err)?;
                Self::run_migrations_mysql(&pool).await?;
                Ok(Self::Mysql(pool))
            }
        }
    }

    /// Run the embedded SQLite bundle if this version hasn't been applied.
    async fn run_migrations_sqlite(pool: &sqlx::SqlitePool) -> Result<(), DomainError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS _migrations (
               version TEXT PRIMARY KEY,
               applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        )
        .execute(pool)
        .await
        .map_err(map_err)?;
        let already: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _migrations WHERE version = ?")
            .bind(crate::migrations::VERSION)
            .fetch_one(pool)
            .await
            .map_err(map_err)?;
        if already > 0 {
            return Ok(());
        }
        sqlx::raw_sql(crate::migrations::SQLITE)
            .execute(pool)
            .await
            .map_err(map_err)?;
        sqlx::query("INSERT INTO _migrations (version) VALUES (?)")
            .bind(crate::migrations::VERSION)
            .execute(pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    /// Run the embedded PostgreSQL bundle if this version hasn't been applied.
    async fn run_migrations_pg(pool: &sqlx::PgPool) -> Result<(), DomainError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS _migrations (
               version TEXT PRIMARY KEY,
               applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .execute(pool)
        .await
        .map_err(map_err)?;
        let already: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM _migrations WHERE version = $1")
                .bind(crate::migrations::VERSION)
                .fetch_one(pool)
                .await
                .map_err(map_err)?;
        if already > 0 {
            return Ok(());
        }
        sqlx::raw_sql(crate::migrations::POSTGRES)
            .execute(pool)
            .await
            .map_err(map_err)?;
        sqlx::query("INSERT INTO _migrations (version) VALUES ($1)")
            .bind(crate::migrations::VERSION)
            .execute(pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    /// Run the embedded MySQL bundle if this version hasn't been applied.
    async fn run_migrations_mysql(pool: &sqlx::MySqlPool) -> Result<(), DomainError> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS _migrations (
               version VARCHAR(64) PRIMARY KEY,
               applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
        )
        .execute(pool)
        .await
        .map_err(map_err)?;
        let already: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _migrations WHERE version = ?")
            .bind(crate::migrations::VERSION)
            .fetch_one(pool)
            .await
            .map_err(map_err)?;
        if already > 0 {
            return Ok(());
        }
        sqlx::raw_sql(crate::migrations::MYSQL)
            .execute(pool)
            .await
            .map_err(map_err)?;
        sqlx::query("INSERT INTO _migrations (version) VALUES (?)")
            .bind(crate::migrations::VERSION)
            .execute(pool)
            .await
            .map_err(map_err)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_pool_honors_size_and_wal() {
        // :memory: reports journal_mode "memory"; use a real file for the WAL check.
        std::fs::create_dir_all("target").unwrap();
        let db_url = "sqlite://target/test-wal-task6.db?mode=rwc";
        let pool = Pool::connect(db_url, 3).await.expect("connect");
        let Pool::Sqlite(ref p) = pool else {
            panic!("sqlite expected")
        };
        assert_eq!(
            p.options().get_max_connections(),
            3,
            "max_connections must be honored"
        );
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(p.acquire().await.unwrap().as_mut())
            .await
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(pool);
        std::fs::remove_file("target/test-wal-task6.db").ok();
    }
}
