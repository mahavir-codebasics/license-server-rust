-- Initial schema for license-server (SQLite).
--
-- Used for self-hosted single-node / dev / embedded deployments. Not ideal
-- for "millions of devices" but excellent for small orgs and tests.
--
-- Differences from Postgres:
--   * UUIDs stored as TEXT (canonical 36-char form). SQLite has no native
--     UUID type; storing as TEXT keeps `WHERE id = ?` straightforward and
--     lexicographic ordering of UUIDv7 hex == chronological order.
--   * metadata is TEXT (JSON); containment emulated via json_each at query
--     time in the db crate.
--   * No RLS — tenancy enforced in SQL (`account_id = ?`) + contract test.
--   * Timestamps stored as TEXT in RFC3339 (UTC).

CREATE TABLE accounts (
    id               TEXT PRIMARY KEY,
    slug             TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    protection_mode  TEXT NOT NULL DEFAULT 'protected',
    settings         TEXT NOT NULL DEFAULT '{}',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    full_name       TEXT,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active',
    avatar_url      TEXT,
    last_login_at   TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE account_memberships (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'admin',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (user_id, account_id)
);
CREATE INDEX account_memberships_account_idx ON account_memberships(account_id);
CREATE INDEX account_memberships_user_idx     ON account_memberships(user_id);

CREATE TABLE products (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    url         TEXT,
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX products_account_created_idx ON products(account_id, created_at);

CREATE TABLE policies (
    id                       TEXT PRIMARY KEY,
    account_id               TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id               TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    key                      TEXT,
    scheme                   TEXT NOT NULL DEFAULT 'ED25519_SIGN',
    max_machines             INTEGER,
    floating_strategy        TEXT NOT NULL DEFAULT 'strict',
    max_components           INTEGER,
    max_processes            INTEGER,
    max_uses                 INTEGER,
    max_users                INTEGER,
    max_cores                INTEGER,
    max_memory               INTEGER,
    max_disk                 INTEGER,
    duration_secs            INTEGER,
    heartbeat_duration_secs  INTEGER,
    require_check_in         INTEGER NOT NULL DEFAULT 0,
    max_overdue_check_ins    INTEGER,
    require_product_scope    INTEGER NOT NULL DEFAULT 0,
    require_user             INTEGER NOT NULL DEFAULT 0,
    require_fingerprint      INTEGER NOT NULL DEFAULT 1,
    protected                INTEGER NOT NULL DEFAULT 0,
    renewable                INTEGER NOT NULL DEFAULT 1,
    metadata                 TEXT NOT NULL DEFAULT '{}',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL
);
CREATE INDEX policies_account_product_idx ON policies(account_id, product_id);
CREATE INDEX policies_account_created_idx  ON policies(account_id, created_at);
CREATE UNIQUE INDEX policies_account_key_idx ON policies(account_id, key) WHERE key IS NOT NULL;

CREATE TABLE licenses (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id          TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    policy_id           TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    key_hash            TEXT NOT NULL UNIQUE,
    state               TEXT NOT NULL DEFAULT 'active',
    license_type        TEXT NOT NULL DEFAULT 'node_locked',
    uses                INTEGER NOT NULL DEFAULT 0,
    max_uses            INTEGER,
    expiry_basis        TEXT NOT NULL DEFAULT 'from_creation',
    expiry_strategy     TEXT NOT NULL DEFAULT 'restrict_access',
    expiry              TEXT,
    last_check_in       TEXT,
    next_check_in       TEXT,
    overdue_check_ins   INTEGER NOT NULL DEFAULT 0,
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX licenses_account_created_idx  ON licenses(account_id, created_at);
CREATE INDEX licenses_account_policy_idx   ON licenses(account_id, policy_id);
CREATE INDEX licenses_expiry_idx           ON licenses(expiry);

CREATE TABLE machines (
    id                     TEXT PRIMARY KEY,
    account_id             TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    license_id             TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    fingerprint            TEXT NOT NULL,
    name                   TEXT,
    platform               TEXT,
    core_count             INTEGER,
    metadata               TEXT NOT NULL DEFAULT '{}',
    state                  TEXT NOT NULL DEFAULT 'active',
    cull_strategy          TEXT NOT NULL DEFAULT 'deactivate_dead',
    resurrection_strategy  TEXT NOT NULL DEFAULT 'no_revive',
    last_heartbeat         TEXT,
    next_heartbeat         TEXT,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL,
    UNIQUE (license_id, fingerprint)
);
CREATE INDEX machines_account_license_idx ON machines(account_id, license_id);
CREATE INDEX machines_account_created_idx ON machines(account_id, created_at);
CREATE INDEX machines_heartbeat_idx       ON machines(next_heartbeat);

CREATE TABLE entitlements (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code        TEXT NOT NULL,
    name        TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (account_id, code)
);
CREATE INDEX entitlements_account_idx ON entitlements(account_id);

CREATE TABLE tokens (
    id             TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    name           TEXT,
    token_hash     TEXT NOT NULL UNIQUE,
    expiry         TEXT,
    last_used_at   TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX tokens_account_idx ON tokens(account_id);

CREATE TABLE signing_keys (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    algorithm    TEXT NOT NULL,
    usage        TEXT NOT NULL DEFAULT 'license',
    status       TEXT NOT NULL DEFAULT 'active',
    version      INTEGER NOT NULL DEFAULT 1,
    material     BLOB NOT NULL,
    public_pem   TEXT NOT NULL,
    retired_at   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX signing_keys_account_idx ON signing_keys(account_id);
-- "at most one active key per (account, usage)": SQLite partial unique index.
CREATE UNIQUE INDEX signing_keys_active_idx
    ON signing_keys(account_id, usage) WHERE status = 'active';

CREATE TABLE webhook_endpoints (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    event_types  TEXT NOT NULL DEFAULT '[]',
    secret       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    metadata     TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX webhook_endpoints_account_idx ON webhook_endpoints(account_id);

CREATE TABLE webhook_events (
    id                   TEXT PRIMARY KEY,
    account_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id          TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type           TEXT NOT NULL,
    payload              TEXT NOT NULL,
    attempts             INTEGER NOT NULL DEFAULT 0,
    delivered            INTEGER NOT NULL DEFAULT 0,
    last_response_status INTEGER,
    last_error           TEXT,
    next_retry_at        TEXT,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);
CREATE INDEX webhook_events_due_idx ON webhook_events(next_retry_at) WHERE delivered = 0;

CREATE TABLE event_log (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info',
    actor_id      TEXT,
    resource_type TEXT,
    resource_id   TEXT,
    payload       TEXT NOT NULL DEFAULT '{}',
    request_id    TEXT,
    ip            TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX event_log_account_created_idx ON event_log(account_id, created_at);

-- migration tracking table (sqlx-style)
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version    BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TEXT NOT NULL,
    success     INTEGER NOT NULL,
    checksum    BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
