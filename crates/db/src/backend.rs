//! Backend abstraction.
//!
//! Three backends share one logical schema but differ in:
//!   - native UUID type (pg: uuid / mysql: binary(16) / sqlite: text)
//!   - JSON containment operator (pg `@>`, mysql `JSON_CONTAINS`, sqlite `json_each`)
//!   - RLS availability (pg only)
//!
//! We expose a [`Backend`] enum and a [`Pool`] wrapper that owns a backend
//! and its connection pool. Repository impls branch on `Backend` only for
//! the handful of genuinely backend-specific operations; the bulk of SQL is
//! shared via parameterized helpers.

use license_domain::error::{DomainError, Result};
use std::fmt;
use std::str::FromStr;

/// Which database backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Postgres,
    Mysql,
    Sqlite,
}

impl Backend {
    /// Detect the backend from a connection URL's scheme.
    pub fn from_url(url: &str) -> Result<Self> {
        let scheme = url
            .split("://")
            .next()
            .ok_or_else(|| DomainError::Invalid(format!("invalid database url: {url}")))?;
        match scheme {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "mysql" | "mariadb" => Ok(Self::Mysql),
            "sqlite" => Ok(Self::Sqlite),
            other => Err(DomainError::Invalid(format!(
                "unsupported database scheme `{other}`; expected postgres|mysql|sqlite"
            ))),
        }
    }

    pub fn migration_dir(self) -> &'static str {
        match self {
            Self::Postgres => "migrations/pg",
            Self::Mysql => "migrations/mysql",
            Self::Sqlite => "migrations/sqlite",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres => f.write_str("postgres"),
            Self::Mysql => f.write_str("mysql"),
            Self::Sqlite => f.write_str("sqlite"),
        }
    }
}

impl FromStr for Backend {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Ok(Self::Postgres),
            "mysql" | "mariadb" => Ok(Self::Mysql),
            "sqlite" => Ok(Self::Sqlite),
            other => Err(DomainError::Invalid(format!("unknown backend `{other}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_scheme() {
        assert_eq!(
            Backend::from_url("postgresql://u:p@h/db").unwrap(),
            Backend::Postgres
        );
        assert_eq!(
            Backend::from_url("mysql://u:p@h/db").unwrap(),
            Backend::Mysql
        );
        assert_eq!(
            Backend::from_url("sqlite:///data/app.db").unwrap(),
            Backend::Sqlite
        );
        assert!(Backend::from_url("oracle://h/db").is_err());
    }

    #[test]
    fn migration_dirs_per_backend() {
        assert!(Backend::Postgres.migration_dir().ends_with("pg"));
        assert!(Backend::Mysql.migration_dir().ends_with("mysql"));
        assert!(Backend::Sqlite.migration_dir().ends_with("sqlite"));
    }
}
