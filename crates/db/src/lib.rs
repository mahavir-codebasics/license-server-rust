//! `license-db` — Repository implementations for PostgreSQL, MySQL, SQLite.
//!
//! One logical schema, three concrete backends (see `backend.rs` for the
//! detection logic and `migrations/{pg,mysql,sqlite}/` for the DDL).
//!
//! Tenancy: every method takes `account_id`. PostgreSQL additionally
//! enforces this with Row-Level Security; MySQL and SQLite enforce it in
//! the SQL and a contract test asserts cross-account reads return nothing.

pub mod backend;
pub mod error;
pub mod mysql;
mod mysql_licenses;
mod mysql_machines;
mod mysql_misc;
pub mod pg;
mod pg_licenses;
mod pg_machines;
mod pg_misc;
pub mod sqlite;
mod sqlite_licenses;
mod sqlite_machines;
mod sqlite_misc;

pub use backend::Backend;
pub use error::{DbError, Pool};
pub use mysql::MysqlRepository;
pub use pg::PostgresRepository;
pub use sqlite::SqliteRepository;

/// Embed the per-backend migration SQL into the binary so a fresh deploy
/// self-migrates without needing the migrations/ folder on disk.
pub mod migrations {
    /// PostgreSQL migration SQL.
    pub const POSTGRES: &str = include_str!("../migrations/pg/20260725000001_initial.sql");
    /// MySQL migration SQL.
    pub const MYSQL: &str = include_str!("../migrations/mysql/20260725000001_initial.sql");
    /// SQLite migration SQL.
    pub const SQLITE: &str = include_str!("../migrations/sqlite/20260725000001_initial.sql");

    /// Look up the migration bundle for the given backend.
    pub fn for_backend(b: crate::Backend) -> &'static str {
        match b {
            crate::Backend::Postgres => POSTGRES,
            crate::Backend::Mysql => MYSQL,
            crate::Backend::Sqlite => SQLITE,
        }
    }

    /// Version key of the current bundle. `Pool::connect` records it in a
    /// `_migrations` tracker table and runs the SQL only when it hasn't been
    /// applied yet, so boots against an existing database are safe (OPS-001).
    pub const VERSION: &str = "20260725000001_initial";
}
