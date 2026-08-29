//! Just-in-time (JIT) user provisioning.
//!
//! Given a verified [`crate::OidcUserInfo`] (from [`crate::exchange`]) and the
//! [`AccountId`] the sign-in was scoped to, [`provision_or_login`] makes sure
//! the user exists in our system and is a member of that account, then returns
//! the [`User`].
//!
//! Semantics:
//!  - If a user with the IdP email already exists → reuse them.
//!  - Otherwise → create a new `User` (no password: they authenticate via SSO).
//!  - If they already have a membership on the account → leave it untouched
//!    (we never silently downgrade/upgrade an existing role).
//!  - Otherwise → add a membership with the supplied `default_role`.
//!
//! This function deliberately does **not** issue an admin token. Token
//! issuance lives in the API layer (it needs the `Token` entity + a signing
//! key), so `provision_or_login` returns the resolved `User` for the caller to
//! act on.

use license_domain::{
    AccountId, AccountMembership, DomainError, MembershipRole, Repository, User, UserId,
};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};

use crate::error::{Result, SsoError};
use crate::flow::OidcUserInfo;

/// Marker password hash stored on JIT-provisioned users.
///
/// These users never log in with a password — authentication always flows
/// through SSO — so there is no real hash to store. We use a non-argon2
/// sentinel that no valid password will ever match (argon2 hashes start with
/// `$argon2`), which keeps the `User` invariant satisfied while making
/// password login provably impossible for SSO users.
pub const SSO_PASSWORD_MARKER: &str = "!sso-only-no-password";

/// Ensure the SSO user exists and is a member of the given account.
///
/// Returns the [`User`] (existing or freshly created). The caller is then
/// responsible for issuing an admin token and setting up the session.
///
/// # Arguments
/// * `repo` — the persistence layer.
/// * `account_id` — the account this SSO connection belongs to.
/// * `info` — the normalized IdP userinfo.
/// * `default_role` — the role assigned to **new** memberships. Existing
///   memberships are never modified.
#[instrument(skip(repo), fields(email = %info.email, %account_id, role = ?default_role))]
pub async fn provision_or_login(
    repo: &dyn Repository,
    account_id: AccountId,
    info: &OidcUserInfo,
    default_role: MembershipRole,
) -> Result<User> {
    // 1) Resolve-or-create the user by email. We key on email (not `sub`)
    //    so a user who signs in via a second IdP later is still recognized.
    let user = match repo.users().get_by_email(&info.email).await {
        Ok(user) => {
            debug!(user_id = %user.id, "existing SSO user found");
            user
        }
        Err(DomainError::NotFound(_)) => {
            let mut new_user = User::new(info.email.clone(), SSO_PASSWORD_MARKER);
            new_user.full_name = info.name.clone();
            let created = repo.users().create(&new_user).await?;
            info!(user_id = %created.id, "JIT-created new SSO user");
            created
        }
        Err(other) => {
            return Err(SsoError::from(other));
        }
    };

    // 2) Ensure a membership exists. We list the user's memberships and look
    //    for this account rather than relying on a dedicated "has_membership"
    //    method, so this is the only query shape required from the repo.
    ensure_membership(repo, user.id, account_id, default_role).await?;

    Ok(user)
}

/// Add a membership if one does not already exist for `(user_id, account_id)`.
async fn ensure_membership(
    repo: &dyn Repository,
    user_id: UserId,
    account_id: AccountId,
    default_role: MembershipRole,
) -> Result<()> {
    let memberships = repo.users().memberships(user_id).await?;
    let already_member = memberships
        .iter()
        .any(|m| m.account_id == account_id && m.user_id == user_id);

    if already_member {
        debug!(%user_id, %account_id, "user already a member; leaving role untouched");
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let membership = AccountMembership {
        id: license_domain::MembershipId::now(),
        user_id,
        account_id,
        role: default_role,
        created_at: now,
        updated_at: now,
    };
    repo.users().add_membership(&membership).await?;
    info!(%user_id, %account_id, role = ?default_role, "JIT-added account membership");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use license_domain::repository::{Page, PageQuery};
    use license_domain::{
        Account, AccountRepo, AccountStatus, Entitlement, EntitlementId, EntitlementRepo, EventLog,
        EventLogId, EventLogRepo, License, LicenseId, LicenseRepo, Machine, MachineId, MachineRepo,
        Policy, PolicyId, PolicyRepo, Product, ProductId, ProductRepo, SigningKey, SigningKeyId,
        SigningKeyRepo, Token, TokenId, TokenRepo, UserRepo, WebhookEndpoint, WebhookEndpointId,
        WebhookEvent, WebhookEventId, WebhookRepo,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ---------------------------------------------------------------------
    // A minimal in-memory Repository sufficient to exercise JIT logic.
    // We only implement the handful of methods `provision_or_login` touches;
    // the rest panic so any accidental drift in what JIT calls surfaces
    // loudly rather than silently passing.
    // ---------------------------------------------------------------------

    type UserStore = HashMap<UserId, User>;
    type EmailIndex = HashMap<String, UserId>;
    type MembershipSet = Vec<AccountMembership>;

    #[derive(Default)]
    struct InMemoryRepo {
        users: Mutex<UserStore>,
        by_email: Mutex<EmailIndex>,
        memberships: Mutex<MembershipSet>,
    }

    impl InMemoryRepo {
        fn seed_user(&self, user: User) {
            let id = user.id;
            let email = user.email.clone();
            self.users.lock().unwrap().insert(id, user);
            self.by_email.lock().unwrap().insert(email, id);
        }
    }

    #[async_trait]
    impl Repository for InMemoryRepo {
        fn accounts(&self) -> &dyn AccountRepo {
            self
        }
        fn products(&self) -> &dyn ProductRepo {
            self
        }
        fn policies(&self) -> &dyn PolicyRepo {
            self
        }
        fn licenses(&self) -> &dyn LicenseRepo {
            self
        }
        fn machines(&self) -> &dyn MachineRepo {
            self
        }
        fn entitlements(&self) -> &dyn EntitlementRepo {
            self
        }
        fn tokens(&self) -> &dyn TokenRepo {
            self
        }
        fn users(&self) -> &dyn UserRepo {
            self
        }
        fn signing_keys(&self) -> &dyn SigningKeyRepo {
            self
        }
        fn webhooks(&self) -> &dyn WebhookRepo {
            self
        }
        fn events(&self) -> &dyn EventLogRepo {
            self
        }
    }

    #[async_trait]
    impl UserRepo for InMemoryRepo {
        async fn create(&self, user: &User) -> license_domain::Result<User> {
            let id = user.id;
            if self.users.lock().unwrap().contains_key(&id) {
                return Err(DomainError::Conflict(format!("user {id} already exists")));
            }
            self.by_email.lock().unwrap().insert(user.email.clone(), id);
            self.users.lock().unwrap().insert(id, user.clone());
            Ok(user.clone())
        }

        async fn get(&self, id: UserId) -> license_domain::Result<User> {
            self.users
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .ok_or_else(|| DomainError::not_found(format!("user {id}")))
        }

        async fn get_by_email(&self, email: &str) -> license_domain::Result<User> {
            let id = self
                .by_email
                .lock()
                .unwrap()
                .get(email)
                .copied()
                .ok_or_else(|| DomainError::not_found(format!("user email={email}")))?;
            // Disambiguate from the other repo traits' `get` methods.
            UserRepo::get(self, id).await
        }

        async fn update(&self, user: &User) -> license_domain::Result<User> {
            let id = user.id;
            let mut store = self.users.lock().unwrap();
            let entry = store
                .get_mut(&id)
                .ok_or_else(|| DomainError::not_found(format!("user {id}")))?;
            *entry = user.clone();
            Ok(user.clone())
        }

        async fn add_membership(
            &self,
            membership: &AccountMembership,
        ) -> license_domain::Result<()> {
            self.memberships.lock().unwrap().push(membership.clone());
            Ok(())
        }

        async fn memberships(
            &self,
            user_id: UserId,
        ) -> license_domain::Result<Vec<AccountMembership>> {
            Ok(self
                .memberships
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m.user_id == user_id)
                .cloned()
                .collect())
        }
    }

    // ---------------------------------------------------------------------
    // Stub implementations for every other repo trait. None are invoked by
    // JIT; each method panics so accidental drift surfaces loudly.
    // ---------------------------------------------------------------------

    #[async_trait]
    impl AccountRepo for InMemoryRepo {
        async fn create(&self, _account: &Account) -> license_domain::Result<Account> {
            unimplemented!("not used by JIT")
        }
        async fn get(&self, _id: AccountId) -> license_domain::Result<Account> {
            unimplemented!("not used by JIT")
        }
        async fn get_by_slug(&self, _slug: &str) -> license_domain::Result<Account> {
            unimplemented!("not used by JIT")
        }
        async fn update(&self, _account: &Account) -> license_domain::Result<Account> {
            unimplemented!("not used by JIT")
        }
        async fn count(&self) -> license_domain::Result<u64> {
            unimplemented!("not used by JIT")
        }
        async fn list_for_user(
            &self,
            _user_id: UserId,
            _page: PageQuery,
        ) -> license_domain::Result<Page<Account>> {
            unimplemented!("not used by JIT")
        }
    }

    #[async_trait]
    impl ProductRepo for InMemoryRepo {
        async fn create(&self, _p: &Product) -> license_domain::Result<Product> {
            unimplemented!()
        }
        async fn get(&self, _a: AccountId, _id: ProductId) -> license_domain::Result<Product> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _p: PageQuery,
        ) -> license_domain::Result<Page<Product>> {
            unimplemented!()
        }
        async fn update(&self, _p: &Product) -> license_domain::Result<Product> {
            unimplemented!()
        }
        async fn delete(&self, _a: AccountId, _id: ProductId) -> license_domain::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl PolicyRepo for InMemoryRepo {
        async fn create(&self, _p: &Policy) -> license_domain::Result<Policy> {
            unimplemented!()
        }
        async fn get(&self, _a: AccountId, _id: PolicyId) -> license_domain::Result<Policy> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _pid: Option<ProductId>,
            _p: PageQuery,
        ) -> license_domain::Result<Page<Policy>> {
            unimplemented!()
        }
        async fn update(&self, _p: &Policy) -> license_domain::Result<Policy> {
            unimplemented!()
        }
        async fn delete(&self, _a: AccountId, _id: PolicyId) -> license_domain::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl LicenseRepo for InMemoryRepo {
        async fn create(&self, _l: &License) -> license_domain::Result<License> {
            unimplemented!()
        }
        async fn get(&self, _a: AccountId, _id: LicenseId) -> license_domain::Result<License> {
            unimplemented!()
        }
        async fn get_by_key_hash(&self, _h: &str) -> license_domain::Result<License> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _pid: Option<PolicyId>,
            _p: PageQuery,
        ) -> license_domain::Result<Page<License>> {
            unimplemented!()
        }
        async fn update(&self, _l: &License) -> license_domain::Result<License> {
            unimplemented!()
        }
        async fn expire_due(&self, _now: OffsetDateTime) -> license_domain::Result<u64> {
            unimplemented!()
        }
        async fn mark_overdue_check_ins(
            &self,
            _now: OffsetDateTime,
        ) -> license_domain::Result<u64> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl MachineRepo for InMemoryRepo {
        async fn create(&self, _m: &Machine) -> license_domain::Result<Machine> {
            unimplemented!()
        }
        async fn get(&self, _a: AccountId, _id: MachineId) -> license_domain::Result<Machine> {
            unimplemented!()
        }
        async fn get_by_fingerprint(
            &self,
            _a: AccountId,
            _l: LicenseId,
            _f: &str,
        ) -> license_domain::Result<Machine> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _l: Option<LicenseId>,
            _p: PageQuery,
        ) -> license_domain::Result<Page<Machine>> {
            unimplemented!()
        }
        async fn update(&self, _m: &Machine) -> license_domain::Result<Machine> {
            unimplemented!()
        }
        async fn delete(&self, _a: AccountId, _id: MachineId) -> license_domain::Result<()> {
            unimplemented!()
        }
        async fn count_active(&self, _a: AccountId, _l: LicenseId) -> license_domain::Result<u64> {
            unimplemented!()
        }
        async fn cull_dead(&self, _now: OffsetDateTime) -> license_domain::Result<u64> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl EntitlementRepo for InMemoryRepo {
        async fn create(&self, _e: &Entitlement) -> license_domain::Result<Entitlement> {
            unimplemented!()
        }
        async fn get(
            &self,
            _a: AccountId,
            _id: EntitlementId,
        ) -> license_domain::Result<Entitlement> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _p: PageQuery,
        ) -> license_domain::Result<Page<Entitlement>> {
            unimplemented!()
        }
        async fn update(&self, _e: &Entitlement) -> license_domain::Result<Entitlement> {
            unimplemented!()
        }
        async fn delete(&self, _a: AccountId, _id: EntitlementId) -> license_domain::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl TokenRepo for InMemoryRepo {
        async fn create(&self, _t: &Token) -> license_domain::Result<Token> {
            unimplemented!()
        }
        async fn get(&self, _a: AccountId, _id: TokenId) -> license_domain::Result<Token> {
            unimplemented!()
        }
        async fn get_by_hash(&self, _h: &str) -> license_domain::Result<Token> {
            unimplemented!()
        }
        async fn list(&self, _a: AccountId, _p: PageQuery) -> license_domain::Result<Page<Token>> {
            unimplemented!()
        }
        async fn revoke(&self, _a: AccountId, _id: TokenId) -> license_domain::Result<()> {
            unimplemented!()
        }
        async fn touch_last_used(
            &self,
            _id: TokenId,
            _at: OffsetDateTime,
        ) -> license_domain::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SigningKeyRepo for InMemoryRepo {
        async fn create(&self, _k: &SigningKey) -> license_domain::Result<SigningKey> {
            unimplemented!()
        }
        async fn get(
            &self,
            _a: AccountId,
            _id: SigningKeyId,
        ) -> license_domain::Result<SigningKey> {
            unimplemented!()
        }
        async fn active(&self, _a: AccountId) -> license_domain::Result<SigningKey> {
            unimplemented!()
        }
        async fn verifiable(&self, _a: AccountId) -> license_domain::Result<Vec<SigningKey>> {
            unimplemented!()
        }
        async fn rotate(
            &self,
            _a: AccountId,
            _k: &SigningKey,
        ) -> license_domain::Result<SigningKey> {
            unimplemented!()
        }
        async fn retire_expired(&self, _now: OffsetDateTime) -> license_domain::Result<u64> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl WebhookRepo for InMemoryRepo {
        async fn create_endpoint(
            &self,
            _e: &WebhookEndpoint,
        ) -> license_domain::Result<WebhookEndpoint> {
            unimplemented!()
        }
        async fn get_endpoint(
            &self,
            _a: AccountId,
            _id: WebhookEndpointId,
        ) -> license_domain::Result<WebhookEndpoint> {
            unimplemented!()
        }
        async fn list_endpoints(
            &self,
            _a: AccountId,
            _p: PageQuery,
        ) -> license_domain::Result<Page<WebhookEndpoint>> {
            unimplemented!()
        }
        async fn enqueue(&self, _e: &WebhookEvent) -> license_domain::Result<WebhookEvent> {
            unimplemented!()
        }
        async fn due(
            &self,
            _now: OffsetDateTime,
            _limit: u32,
        ) -> license_domain::Result<Vec<WebhookEvent>> {
            unimplemented!()
        }
        async fn mark_attempt(
            &self,
            _id: WebhookEventId,
            _delivered: bool,
            _status: Option<u16>,
            _error: Option<String>,
            _next_retry_at: Option<OffsetDateTime>,
        ) -> license_domain::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl EventLogRepo for InMemoryRepo {
        async fn append(&self, _e: &EventLog) -> license_domain::Result<EventLogId> {
            unimplemented!()
        }
        async fn list(
            &self,
            _a: AccountId,
            _p: PageQuery,
        ) -> license_domain::Result<Page<EventLog>> {
            unimplemented!()
        }
    }

    // ---------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------

    fn sample_account() -> Account {
        let mut a = Account::new("acme", "Acme");
        a.status = AccountStatus::Active;
        a
    }

    fn sample_info(email: &str, name: Option<&str>) -> OidcUserInfo {
        OidcUserInfo {
            subject: "idp-sub-123".to_string(),
            email: email.to_string(),
            name: name.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn provision_creates_user_and_membership_when_both_absent() {
        let repo = InMemoryRepo::default();
        let account = sample_account();
        let info = sample_info("alice@example.com", Some("Alice"));

        let user = provision_or_login(&repo, account.id, &info, MembershipRole::Developer)
            .await
            .expect("ok");

        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.full_name.as_deref(), Some("Alice"));
        // Password marker is set so password login is impossible.
        assert_eq!(user.password_hash, SSO_PASSWORD_MARKER);

        let memberships = repo
            .users()
            .memberships(user.id)
            .await
            .expect("memberships");
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].account_id, account.id);
        assert_eq!(memberships[0].role, MembershipRole::Developer);
    }

    #[tokio::test]
    async fn provision_reuses_existing_user_by_email() {
        let repo = InMemoryRepo::default();
        let account = sample_account();

        let mut existing = User::new("alice@example.com", "$argon2id$real-hash");
        existing.full_name = Some("Alice Old".to_string());
        let existing_id = existing.id;
        repo.seed_user(existing);

        let info = sample_info("alice@example.com", Some("Alice New"));
        let user = provision_or_login(&repo, account.id, &info, MembershipRole::Admin)
            .await
            .expect("ok");

        assert_eq!(user.id, existing_id, "should reuse the existing user");
        // Existing user's fields are NOT overwritten.
        assert_eq!(user.full_name.as_deref(), Some("Alice Old"));
        assert_eq!(user.password_hash, "$argon2id$real-hash");

        // But a membership is still added for the account.
        let memberships = repo
            .users()
            .memberships(user.id)
            .await
            .expect("memberships");
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].role, MembershipRole::Admin);
    }

    #[tokio::test]
    async fn provision_leaves_existing_membership_role_untouched() {
        let repo = InMemoryRepo::default();
        let account = sample_account();

        let mut existing = User::new("alice@example.com", "$argon2id$hash");
        existing.full_name = Some("Alice".to_string());
        let uid = existing.id;
        repo.seed_user(existing);

        // Pre-existing Owner membership.
        let now = OffsetDateTime::now_utc();
        repo.users()
            .add_membership(&AccountMembership {
                id: license_domain::MembershipId::now(),
                user_id: uid,
                account_id: account.id,
                role: MembershipRole::Owner,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("add");

        let info = sample_info("alice@example.com", Some("Alice"));
        let user = provision_or_login(&repo, account.id, &info, MembershipRole::Viewer)
            .await
            .expect("ok");

        let memberships = repo
            .users()
            .memberships(user.id)
            .await
            .expect("memberships");
        assert_eq!(memberships.len(), 1, "no duplicate membership added");
        // Role NOT downgraded to Viewer.
        assert_eq!(memberships[0].role, MembershipRole::Owner);
    }

    #[tokio::test]
    async fn provision_adds_second_account_membership_without_duplication() {
        // A user already a member of account A signs in via account B's SSO:
        // they should get a new membership on B, and A is left alone.
        let repo = InMemoryRepo::default();
        let account_a = sample_account();
        let account_b = Account::new("globex", "Globex");

        let mut existing = User::new("alice@example.com", "$argon2id$hash");
        existing.full_name = Some("Alice".to_string());
        let uid = existing.id;
        repo.seed_user(existing);

        let now = OffsetDateTime::now_utc();
        repo.users()
            .add_membership(&AccountMembership {
                id: license_domain::MembershipId::now(),
                user_id: uid,
                account_id: account_a.id,
                role: MembershipRole::Owner,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("add A");

        let info = sample_info("alice@example.com", Some("Alice"));
        let user = provision_or_login(&repo, account_b.id, &info, MembershipRole::Developer)
            .await
            .expect("ok");

        let memberships = repo
            .users()
            .memberships(user.id)
            .await
            .expect("memberships");
        assert_eq!(memberships.len(), 2);
        assert!(memberships
            .iter()
            .any(|m| m.account_id == account_a.id && m.role == MembershipRole::Owner));
        assert!(memberships
            .iter()
            .any(|m| m.account_id == account_b.id && m.role == MembershipRole::Developer));
    }

    #[tokio::test]
    async fn provision_finds_user_by_normalized_email() {
        // JIT keys on the email as given; the flow module lowercases the email
        // from the IdP before reaching JIT. Verify that a pre-seeded user with
        // the lowercased email is found when JIT receives the lowercased form.
        let repo = InMemoryRepo::default();
        let account = sample_account();

        let existing = User::new("alice@example.com", "$argon2id$hash");
        let existing_id = existing.id;
        repo.seed_user(existing);

        let info = sample_info("alice@example.com", None);
        let user = provision_or_login(&repo, account.id, &info, MembershipRole::Admin)
            .await
            .expect("ok");
        assert_eq!(user.id, existing_id);
    }

    #[test]
    fn sso_password_marker_is_distinct() {
        // The marker we use for SSO-provisioned users (so they can't log in
        // via password) must be a non-argon2 sentinel.
        assert!(!SSO_PASSWORD_MARKER.starts_with("$argon2"));
        assert!(!SSO_PASSWORD_MARKER.is_empty());
    }
}
