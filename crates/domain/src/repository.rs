//! Repository — the persistence abstraction.
//!
//! Each entity gets its own `*Repo` async trait. The `db` crate provides one
//! impl per backend (Postgres, MySQL, SQLite). Generic helpers (`Page`,
//! `PageQuery`) live here so every backend shares the same pagination shape.
//!
//! **Tenancy invariant:** every method that reads or writes a tenant-scoped
//! resource takes an `account_id` parameter. Backends MUST scope all queries
//! by it. The Postgres backend additionally enforces this with Row-Level
//! Security; MySQL/SQLite enforce it in SQL and an integration test asserts
//! no method can return cross-account rows.

use crate::account::{Account, AccountId};
use crate::entitlement::{Entitlement, EntitlementId};
use crate::error::Result;
use crate::event_log::{EventLog, EventLogId};
use crate::id::{SigningKeyId, TokenId};
use crate::license::{License, LicenseId};
use crate::machine::{Machine, MachineId};
use crate::policy::{Policy, PolicyId};
use crate::product::{Product, ProductId};
use crate::signing_key::SigningKey;
use crate::token::Token;
use crate::user::{AccountMembership, User, UserId};
use crate::webhook::{WebhookEndpoint, WebhookEndpointId, WebhookEvent};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Keyset pagination request. `limit` caps page size; `after` is an opaque
/// cursor (typically `<created_at>,<id>`) returned in the previous page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageQuery {
    pub limit: u32,
    pub after: Option<String>,
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            limit: 25,
            after: None,
        }
    }
}

/// A page of results plus the cursor to fetch the next page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn map<U>(self, f: impl Fn(T) -> U) -> Page<U> {
        Page {
            data: self.data.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
        }
    }

    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            next_cursor: None,
        }
    }
}

/// Root marker trait — every repo is `Send + Sync`.
#[async_trait]
pub trait Repository: Send + Sync {
    fn accounts(&self) -> &dyn AccountRepo;
    fn products(&self) -> &dyn ProductRepo;
    fn policies(&self) -> &dyn PolicyRepo;
    fn licenses(&self) -> &dyn LicenseRepo;
    fn machines(&self) -> &dyn MachineRepo;
    fn entitlements(&self) -> &dyn EntitlementRepo;
    fn tokens(&self) -> &dyn TokenRepo;
    fn users(&self) -> &dyn UserRepo;
    fn signing_keys(&self) -> &dyn SigningKeyRepo;
    fn webhooks(&self) -> &dyn WebhookRepo;
    fn events(&self) -> &dyn EventLogRepo;
}

#[async_trait]
pub trait AccountRepo: Send + Sync {
    async fn create(&self, account: &Account) -> Result<Account>;
    async fn get(&self, id: AccountId) -> Result<Account>;
    async fn get_by_slug(&self, slug: &str) -> Result<Account>;
    async fn update(&self, account: &Account) -> Result<Account>;
    /// List accounts a user belongs to.
    async fn list_for_user(&self, user_id: UserId, page: PageQuery) -> Result<Page<Account>>;
}

#[async_trait]
pub trait ProductRepo: Send + Sync {
    async fn create(&self, product: &Product) -> Result<Product>;
    async fn get(&self, account_id: AccountId, id: ProductId) -> Result<Product>;
    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Product>>;
    async fn update(&self, product: &Product) -> Result<Product>;
    async fn delete(&self, account_id: AccountId, id: ProductId) -> Result<()>;
}

#[async_trait]
pub trait PolicyRepo: Send + Sync {
    async fn create(&self, policy: &Policy) -> Result<Policy>;
    async fn get(&self, account_id: AccountId, id: PolicyId) -> Result<Policy>;
    async fn list(
        &self,
        account_id: AccountId,
        product_id: Option<ProductId>,
        page: PageQuery,
    ) -> Result<Page<Policy>>;
    async fn update(&self, policy: &Policy) -> Result<Policy>;
    async fn delete(&self, account_id: AccountId, id: PolicyId) -> Result<()>;
}

#[async_trait]
pub trait LicenseRepo: Send + Sync {
    async fn create(&self, license: &License) -> Result<License>;
    async fn get(&self, account_id: AccountId, id: LicenseId) -> Result<License>;
    /// Fetch by the natural key (the raw license key string). Backends look
    /// up by `key_hash` (SHA-256 of the key) — the raw key is never stored.
    async fn get_by_key_hash(&self, key_hash: &str) -> Result<License>;
    async fn list(
        &self,
        account_id: AccountId,
        policy_id: Option<PolicyId>,
        page: PageQuery,
    ) -> Result<Page<License>>;
    async fn update(&self, license: &License) -> Result<License>;
    /// Bulk-update licenses whose expiry has passed into EXPIRED state.
    /// Used by the license-expirations cron job.
    async fn expire_due(&self, now: OffsetDateTime) -> Result<u64>;
    /// Mark licenses with overdue check-ins. Returns count affected.
    async fn mark_overdue_check_ins(&self, now: OffsetDateTime) -> Result<u64>;
}

#[async_trait]
pub trait MachineRepo: Send + Sync {
    async fn create(&self, machine: &Machine) -> Result<Machine>;
    async fn get(&self, account_id: AccountId, id: MachineId) -> Result<Machine>;
    async fn get_by_fingerprint(
        &self,
        account_id: AccountId,
        license_id: LicenseId,
        fingerprint: &str,
    ) -> Result<Machine>;
    async fn list(
        &self,
        account_id: AccountId,
        license_id: Option<LicenseId>,
        page: PageQuery,
    ) -> Result<Page<Machine>>;
    async fn update(&self, machine: &Machine) -> Result<Machine>;
    async fn delete(&self, account_id: AccountId, id: MachineId) -> Result<()>;
    /// Count active machines for a license (for max_machines enforcement).
    async fn count_active(&self, account_id: AccountId, license_id: LicenseId) -> Result<u64>;
    /// Cull machines whose heartbeat has expired, per their cull strategy.
    /// Used by the cull-dead-machines cron job.
    async fn cull_dead(&self, now: OffsetDateTime) -> Result<u64>;
}

#[async_trait]
pub trait EntitlementRepo: Send + Sync {
    async fn create(&self, entitlement: &Entitlement) -> Result<Entitlement>;
    async fn get(&self, account_id: AccountId, id: EntitlementId) -> Result<Entitlement>;
    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Entitlement>>;
    async fn update(&self, entitlement: &Entitlement) -> Result<Entitlement>;
    async fn delete(&self, account_id: AccountId, id: EntitlementId) -> Result<()>;
}

#[async_trait]
pub trait TokenRepo: Send + Sync {
    async fn create(&self, token: &Token) -> Result<Token>;
    async fn get(&self, account_id: AccountId, id: TokenId) -> Result<Token>;
    /// Lookup by SHA-256 hash of the bearer string. Cross-account safe: the
    /// hash is globally unique (32 bytes of entropy in the token).
    async fn get_by_hash(&self, token_hash: &str) -> Result<Token>;
    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<Token>>;
    async fn revoke(&self, account_id: AccountId, id: TokenId) -> Result<()>;
    async fn touch_last_used(&self, id: TokenId, at: OffsetDateTime) -> Result<()>;
}

#[async_trait]
pub trait UserRepo: Send + Sync {
    async fn create(&self, user: &User) -> Result<User>;
    async fn get(&self, id: UserId) -> Result<User>;
    async fn get_by_email(&self, email: &str) -> Result<User>;
    async fn update(&self, user: &User) -> Result<User>;
    async fn add_membership(&self, membership: &AccountMembership) -> Result<()>;
    async fn memberships(&self, user_id: UserId) -> Result<Vec<AccountMembership>>;
}

#[async_trait]
pub trait SigningKeyRepo: Send + Sync {
    async fn create(&self, key: &SigningKey) -> Result<SigningKey>;
    async fn get(&self, account_id: AccountId, id: SigningKeyId) -> Result<SigningKey>;
    /// The currently-active key for an account.
    async fn active(&self, account_id: AccountId) -> Result<SigningKey>;
    /// All keys still accepted for verification (active + rotating).
    async fn verifiable(&self, account_id: AccountId) -> Result<Vec<SigningKey>>;
    /// Demote the current active key to rotating, set a new active key.
    async fn rotate(&self, account_id: AccountId, new_key: &SigningKey) -> Result<SigningKey>;
    /// Mark rotating keys past their grace period as retired.
    async fn retire_expired(&self, now: OffsetDateTime) -> Result<u64>;
}

#[async_trait]
pub trait WebhookRepo: Send + Sync {
    async fn create_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<WebhookEndpoint>;
    async fn get_endpoint(
        &self,
        account_id: AccountId,
        id: WebhookEndpointId,
    ) -> Result<WebhookEndpoint>;
    async fn list_endpoints(
        &self,
        account_id: AccountId,
        page: PageQuery,
    ) -> Result<Page<WebhookEndpoint>>;
    async fn enqueue(&self, event: &WebhookEvent) -> Result<WebhookEvent>;
    /// Fetch a batch of due deliveries for the worker.
    async fn due(&self, now: OffsetDateTime, limit: u32) -> Result<Vec<WebhookEvent>>;
    async fn mark_attempt(
        &self,
        id: crate::webhook::WebhookEventId,
        delivered: bool,
        status: Option<u16>,
        error: Option<String>,
        next_retry_at: Option<OffsetDateTime>,
    ) -> Result<()>;
}

#[async_trait]
pub trait EventLogRepo: Send + Sync {
    async fn append(&self, event: &EventLog) -> Result<EventLogId>;
    async fn list(&self, account_id: AccountId, page: PageQuery) -> Result<Page<EventLog>>;
}
