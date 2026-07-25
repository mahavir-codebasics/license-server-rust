-- Initial schema for license-server (Postgres).
--
-- Conventions:
--   * All PKs are UUID v7 (time-ordered) — better B-tree locality than v4 at
--     millions of rows.
--   * Every tenant-scoped table has `account_id UUID NOT NULL` and a composite
--     index on `(account_id, <natural key>)`. Row-Level Security (RLS) below
--     additionally enforces tenancy at the database tier; the app sets the
--     current account via `SET LOCAL app.account_id`.
--   * `metadata` is JSONB and supports containment filtering via `@>`.
--   * Timestamps are `TIMESTAMPTZ` (UTC).

-- The RLS session variable lives here.
-- (No table needed; SET LOCAL app.account_id = $1 is used per-transaction.)

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- uuid_generate_v4() fallback

-- accounts (the tenant root — NOT account-scoped itself)
CREATE TABLE accounts (
    id               UUID         PRIMARY KEY,
    slug             TEXT         NOT NULL UNIQUE,
    name             TEXT         NOT NULL,
    status           TEXT         NOT NULL DEFAULT 'active',
    protection_mode  TEXT         NOT NULL DEFAULT 'protected',
    settings         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    metadata         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- users (global across accounts — an admin may belong to many orgs)
CREATE TABLE users (
    id              UUID         PRIMARY KEY,
    email           TEXT         NOT NULL UNIQUE,
    full_name       TEXT,
    password_hash   TEXT         NOT NULL,    -- argon2id
    totp_secret     TEXT,
    totp_enabled    BOOLEAN      NOT NULL DEFAULT false,
    status          TEXT         NOT NULL DEFAULT 'active',
    avatar_url      TEXT,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE account_memberships (
    id          UUID         PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id  UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role        TEXT         NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (user_id, account_id)
);
CREATE INDEX account_memberships_account_idx ON account_memberships(account_id);
CREATE INDEX account_memberships_user_idx     ON account_memberships(user_id);

CREATE TABLE products (
    id          UUID         PRIMARY KEY,
    account_id  UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        TEXT         NOT NULL,
    url         TEXT,
    metadata    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX products_account_created_idx ON products(account_id, created_at);

CREATE TABLE policies (
    id                       UUID         PRIMARY KEY,
    account_id               UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id               UUID         NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name                     TEXT         NOT NULL,
    key                      TEXT,
    scheme                   TEXT         NOT NULL DEFAULT 'ED25519_SIGN',
    max_machines             INTEGER,
    floating_strategy        TEXT         NOT NULL DEFAULT 'strict',
    max_components           INTEGER,
    max_processes            INTEGER,
    max_uses                 BIGINT,
    max_users                INTEGER,
    max_cores                INTEGER,
    max_memory               BIGINT,
    max_disk                 BIGINT,
    duration_secs            BIGINT,
    heartbeat_duration_secs  BIGINT,
    require_check_in         BOOLEAN      NOT NULL DEFAULT false,
    max_overdue_check_ins    INTEGER,
    require_product_scope    BOOLEAN      NOT NULL DEFAULT false,
    require_user             BOOLEAN      NOT NULL DEFAULT false,
    require_fingerprint      BOOLEAN      NOT NULL DEFAULT true,
    protected                BOOLEAN      NOT NULL DEFAULT false,
    renewable                BOOLEAN      NOT NULL DEFAULT true,
    metadata                 JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX policies_account_product_idx ON policies(account_id, product_id);
CREATE INDEX policies_account_created_idx  ON policies(account_id, created_at);
CREATE UNIQUE INDEX policies_account_key_idx ON policies(account_id, key) WHERE key IS NOT NULL;

CREATE TABLE licenses (
    id                  UUID         PRIMARY KEY,
    account_id          UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id          UUID         NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    policy_id           UUID         NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    -- the signed key string is NEVER stored; only its SHA-256 hash:
    key_hash            TEXT         NOT NULL UNIQUE,
    state               TEXT         NOT NULL DEFAULT 'active',
    license_type        TEXT         NOT NULL DEFAULT 'node_locked',
    uses                BIGINT       NOT NULL DEFAULT 0,
    max_uses            BIGINT,
    expiry_basis        TEXT         NOT NULL DEFAULT 'from_creation',
    expiry_strategy     TEXT         NOT NULL DEFAULT 'restrict_access',
    expiry              TIMESTAMPTZ,
    last_check_in       TIMESTAMPTZ,
    next_check_in       TIMESTAMPTZ,
    overdue_check_ins   INTEGER      NOT NULL DEFAULT 0,
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX licenses_account_created_idx  ON licenses(account_id, created_at);
CREATE INDEX licenses_account_policy_idx   ON licenses(account_id, policy_id);
CREATE INDEX licenses_expiry_idx           ON licenses(expiry) WHERE state = 'active' AND expiry IS NOT NULL;
CREATE INDEX licenses_checkin_idx          ON licenses(next_check_in) WHERE state = 'active' AND next_check_in IS NOT NULL;

CREATE TABLE machines (
    id                     UUID         PRIMARY KEY,
    account_id             UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    license_id             UUID         NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    fingerprint            TEXT         NOT NULL,
    name                   TEXT,
    platform               TEXT,
    core_count             INTEGER,
    metadata               JSONB        NOT NULL DEFAULT '{}'::jsonb,
    state                  TEXT         NOT NULL DEFAULT 'active',
    cull_strategy          TEXT         NOT NULL DEFAULT 'deactivate_dead',
    resurrection_strategy  TEXT         NOT NULL DEFAULT 'no_revive',
    last_heartbeat         TIMESTAMPTZ,
    next_heartbeat         TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (license_id, fingerprint)
);
CREATE INDEX machines_account_license_idx  ON machines(account_id, license_id);
CREATE INDEX machines_account_created_idx  ON machines(account_id, created_at);
CREATE INDEX machines_heartbeat_idx        ON machines(next_heartbeat) WHERE state = 'active' AND next_heartbeat IS NOT NULL;

CREATE TABLE entitlements (
    id          UUID         PRIMARY KEY,
    account_id  UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code        TEXT         NOT NULL,
    name        TEXT         NOT NULL,
    metadata    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (account_id, code)
);
CREATE INDEX entitlements_account_idx ON entitlements(account_id);

CREATE TABLE tokens (
    id             UUID         PRIMARY KEY,
    account_id     UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind           TEXT         NOT NULL,
    name           TEXT,
    token_hash     TEXT         NOT NULL UNIQUE,   -- SHA-256 hex of the bearer
    expiry         TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX tokens_account_idx ON tokens(account_id);

CREATE TABLE signing_keys (
    id           UUID         PRIMARY KEY,
    account_id   UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    algorithm    TEXT         NOT NULL,
    usage        TEXT         NOT NULL DEFAULT 'license',
    status       TEXT         NOT NULL DEFAULT 'active',
    version      INTEGER      NOT NULL DEFAULT 1,
    material     BYTEA        NOT NULL,           -- encrypted at rest by KeyStore
    public_pem   TEXT         NOT NULL,
    retired_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
-- at most one active key per (account, usage)
CREATE UNIQUE INDEX signing_keys_active_idx
    ON signing_keys(account_id, usage) WHERE status = 'active';

CREATE TABLE webhook_endpoints (
    id           UUID         PRIMARY KEY,
    account_id   UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url          TEXT         NOT NULL,
    event_types  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    secret       TEXT         NOT NULL,
    status       TEXT         NOT NULL DEFAULT 'active',
    metadata     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_account_idx ON webhook_endpoints(account_id);

CREATE TABLE webhook_events (
    id                   UUID         PRIMARY KEY,
    account_id           UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id          UUID         NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type           TEXT         NOT NULL,
    payload              JSONB        NOT NULL,
    attempts             INTEGER      NOT NULL DEFAULT 0,
    delivered            BOOLEAN      NOT NULL DEFAULT false,
    last_response_status INTEGER,
    last_error           TEXT,
    next_retry_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX webhook_events_due_idx ON webhook_events(next_retry_at) WHERE delivered = false;

CREATE TABLE event_log (
    id            UUID         PRIMARY KEY,   -- uuid v7, time-ordered
    account_id    UUID         NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_type    TEXT         NOT NULL,
    severity      TEXT         NOT NULL DEFAULT 'info',
    actor_id      TEXT,
    resource_type TEXT,
    resource_id   TEXT,
    payload       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    request_id    TEXT,
    ip            TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX event_log_account_created_idx ON event_log(account_id, created_at);

-- ──────────────────────────────────────────────────────────────────────────
-- Row-Level Security: defense-in-depth tenancy enforcement.
--
-- The app sets the current tenant per-transaction:
--     SET LOCAL app.account_id = '<uuid>';
-- Queries on these tables then see only rows where account_id matches.
-- `accounts` and `users` are exempt (they're the cross-tenant identity tables).
-- A NULL/empty session variable denies all rows (fail-closed).
-- ──────────────────────────────────────────────────────────────────────────

ALTER TABLE products        ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies        ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses        ENABLE ROW LEVEL SECURITY;
ALTER TABLE machines        ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements    ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens          ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys    ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_log       ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON products
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON policies
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON licenses
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON machines
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON entitlements
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON tokens
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON signing_keys
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON webhook_endpoints
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON webhook_events
    USING (account_id::text = current_setting('app.account_id', true));
CREATE POLICY tenant_isolation ON event_log
    USING (account_id::text = current_setting('app.account_id', true));

-- updated_at trigger helper
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply the touch trigger to every table that has updated_at.
DO $$
DECLARE t TEXT;
BEGIN
    FOR t IN SELECT unnest(ARRAY[
        'accounts','users','products','policies','licenses','machines',
        'entitlements','tokens','signing_keys','webhook_endpoints','webhook_events'
    ])
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS %I_touch ON %I; CREATE TRIGGER %I_touch BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION touch_updated_at();',
            t, t, t, t
        );
    END LOOP;
END $$;
