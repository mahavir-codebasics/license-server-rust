//! `license-domain` — the pure business core of the licensing server.
//!
//! This crate has **no I/O**: no database, no HTTP, no filesystem. It defines
//! the domain entities, value objects, state machines, and the abstract
//! [`Repository`] trait that the `db` crate implements for PostgreSQL, MySQL,
//! and SQLite.
//!
//! Layering rule: `domain` depends on nothing but itself. Every other crate
//! may depend on `domain`; `domain` depends on no internal crate.

#[macro_use]
mod macros;

pub mod error;
pub mod id;
pub mod value;

// Entities
pub mod account;
pub mod entitlement;
pub mod event_log;
pub mod license;
pub mod machine;
pub mod policy;
pub mod product;
pub mod signing_key;
pub mod token;
pub mod user;
pub mod webhook;

// Persistence abstraction
pub mod repository;

// Re-exports for ergonomic use at call sites (`use license_domain::{Account, License}`).
pub use account::{Account, AccountId, AccountSettings, AccountStatus, ProtectionMode};
pub use entitlement::{Entitlement, EntitlementCode, EntitlementId};
pub use error::{DomainError, Result};
pub use event_log::{EventLog, EventLogId, EventSeverity};
pub use id::{SigningKeyId, TokenId};
pub use license::{
    ExpiryBasis, ExpiryStrategy, License, LicenseId, LicenseState, LicenseType, UsageCounter,
};
pub use machine::{
    CullStrategy, HeartbeatStatus, Machine, MachineId, MachineState, ResurrectionStrategy,
};
pub use policy::{FloatingStrategy, Policy, PolicyId, PolicyScheme};
pub use product::{Product, ProductId};
pub use signing_key::{KeyAlgorithm, KeyStatus, KeyUsage, SigningKey};
pub use token::{Token, TokenKind, TokenScope};
pub use user::{AccountMembership, MembershipId, MembershipRole, User, UserId, UserStatus};
pub use value::{Metadata, NaturalKey};
pub use webhook::{
    WebhookEndpoint, WebhookEndpointId, WebhookEvent, WebhookEventId, WebhookStatus,
};

pub use repository::{
    AccountRepo, EntitlementRepo, EventLogRepo, LicenseRepo, MachineRepo, PolicyRepo, ProductRepo,
    Repository, SigningKeyRepo, TokenRepo, UserRepo, WebhookRepo,
};
