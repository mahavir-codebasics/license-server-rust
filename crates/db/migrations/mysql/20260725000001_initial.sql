-- Initial schema for license-server (MySQL 8).
--
-- Differences from the Postgres schema:
--   * UUIDs stored as BINARY(16) with a generated `id_str CHAR(36)` column
--     for debugging. The app converts between UUID and BINARY(16) via
--     `UUID_TO_BIN(id, true)` (swap for v7 time-ordering) / `BIN_TO_UUID`.
--   * JSON instead of JSONB; metadata containment uses JSON_CONTAINS.
--   * No Row-Level Security (MySQL has none) — tenancy is enforced in the
--     query layer (every statement carries `account_id = ?`) plus a contract
--     test that asserts cross-account reads return nothing.
--   * `DATETIME(6)` instead of TIMESTAMPTZ; values stored in UTC.
--   * updated_at handled by `ON UPDATE CURRENT_TIMESTAMP(6)`.

CREATE TABLE accounts (
    id               BINARY(16)   PRIMARY KEY,
    slug             VARCHAR(255) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    status           VARCHAR(32)  NOT NULL DEFAULT 'active',
    protection_mode  VARCHAR(32)  NOT NULL DEFAULT 'protected',
    settings         JSON         NOT NULL,
    metadata         JSON         NOT NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY accounts_slug_uq (slug)
) ENGINE=InnoDB;

CREATE TABLE users (
    id              BINARY(16)   PRIMARY KEY,
    email           VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255),
    password_hash   VARCHAR(255) NOT NULL,
    totp_secret     VARCHAR(255),
    totp_enabled    TINYINT(1)   NOT NULL DEFAULT 0,
    status          VARCHAR(32)  NOT NULL DEFAULT 'active',
    avatar_url      VARCHAR(512),
    last_login_at   DATETIME(6),
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY users_email_uq (email)
) ENGINE=InnoDB;

CREATE TABLE account_memberships (
    id          BINARY(16)   PRIMARY KEY,
    user_id     BINARY(16)   NOT NULL,
    account_id  BINARY(16)   NOT NULL,
    role        VARCHAR(32)  NOT NULL DEFAULT 'admin',
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY memberships_user_account_uq (user_id, account_id),
    KEY memberships_account_idx (account_id),
    KEY memberships_user_idx (user_id),
    CONSTRAINT memberships_user_fk    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE,
    CONSTRAINT memberships_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE products (
    id          BINARY(16)   PRIMARY KEY,
    account_id  BINARY(16)   NOT NULL,
    name        VARCHAR(255) NOT NULL,
    url         VARCHAR(512),
    metadata    JSON         NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY products_account_created_idx (account_id, created_at),
    CONSTRAINT products_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE policies (
    id                       BINARY(16)   PRIMARY KEY,
    account_id               BINARY(16)   NOT NULL,
    product_id               BINARY(16)   NOT NULL,
    name                     VARCHAR(255) NOT NULL,
    `key`                    VARCHAR(255),
    scheme                   VARCHAR(64)  NOT NULL DEFAULT 'ED25519_SIGN',
    max_machines             INT,
    floating_strategy        VARCHAR(32)  NOT NULL DEFAULT 'strict',
    max_components           INT,
    max_processes            INT,
    max_uses                 BIGINT,
    max_users                INT,
    max_cores                INT,
    max_memory               BIGINT,
    max_disk                 BIGINT,
    duration_secs            BIGINT,
    heartbeat_duration_secs  BIGINT,
    require_check_in         TINYINT(1)   NOT NULL DEFAULT 0,
    max_overdue_check_ins    INT,
    require_product_scope    TINYINT(1)   NOT NULL DEFAULT 0,
    require_user             TINYINT(1)   NOT NULL DEFAULT 0,
    require_fingerprint      TINYINT(1)   NOT NULL DEFAULT 1,
    protected                TINYINT(1)   NOT NULL DEFAULT 0,
    renewable                TINYINT(1)   NOT NULL DEFAULT 1,
    metadata                 JSON         NOT NULL,
    created_at               DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at               DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY policies_account_product_idx (account_id, product_id),
    KEY policies_account_created_idx  (account_id, created_at),
    CONSTRAINT policies_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT policies_product_fk FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE licenses (
    id                  BINARY(16)   PRIMARY KEY,
    account_id          BINARY(16)   NOT NULL,
    product_id          BINARY(16)   NOT NULL,
    policy_id           BINARY(16)   NOT NULL,
    key_hash            VARCHAR(128) NOT NULL,
    state               VARCHAR(32)  NOT NULL DEFAULT 'active',
    license_type        VARCHAR(32)  NOT NULL DEFAULT 'node_locked',
    uses                BIGINT       NOT NULL DEFAULT 0,
    max_uses            BIGINT,
    expiry_basis        VARCHAR(32)  NOT NULL DEFAULT 'from_creation',
    expiry_strategy     VARCHAR(32)  NOT NULL DEFAULT 'restrict_access',
    expiry              DATETIME(6),
    last_check_in       DATETIME(6),
    next_check_in       DATETIME(6),
    overdue_check_ins   INT          NOT NULL DEFAULT 0,
    metadata            JSON         NOT NULL,
    created_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY licenses_key_hash_uq (key_hash),
    KEY licenses_account_created_idx (account_id, created_at),
    KEY licenses_account_policy_idx  (account_id, policy_id),
    KEY licenses_expiry_idx (expiry),
    CONSTRAINT licenses_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT licenses_product_fk FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    CONSTRAINT licenses_policy_fk  FOREIGN KEY (policy_id)  REFERENCES policies(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE machines (
    id                     BINARY(16)   PRIMARY KEY,
    account_id             BINARY(16)   NOT NULL,
    license_id             BINARY(16)   NOT NULL,
    fingerprint            VARCHAR(255) NOT NULL,
    name                   VARCHAR(255),
    platform               VARCHAR(255),
    core_count             INT,
    metadata               JSON         NOT NULL,
    state                  VARCHAR(32)  NOT NULL DEFAULT 'active',
    cull_strategy          VARCHAR(32)  NOT NULL DEFAULT 'deactivate_dead',
    resurrection_strategy  VARCHAR(32)  NOT NULL DEFAULT 'no_revive',
    last_heartbeat         DATETIME(6),
    next_heartbeat         DATETIME(6),
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY machines_license_fp_uq (license_id, fingerprint),
    KEY machines_account_license_idx (account_id, license_id),
    KEY machines_account_created_idx (account_id, created_at),
    KEY machines_heartbeat_idx (next_heartbeat),
    CONSTRAINT machines_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id)    ON DELETE CASCADE,
    CONSTRAINT machines_license_fk FOREIGN KEY (license_id) REFERENCES licenses(id)    ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE entitlements (
    id          BINARY(16)   PRIMARY KEY,
    account_id  BINARY(16)   NOT NULL,
    code        VARCHAR(128) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    metadata    JSON         NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY entitlements_account_code_uq (account_id, code),
    KEY entitlements_account_idx (account_id),
    CONSTRAINT entitlements_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE tokens (
    id             BINARY(16)   PRIMARY KEY,
    account_id     BINARY(16)   NOT NULL,
    kind           VARCHAR(32)  NOT NULL,
    name           VARCHAR(255),
    token_hash     VARCHAR(128) NOT NULL,
    expiry         DATETIME(6),
    last_used_at   DATETIME(6),
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY tokens_hash_uq (token_hash),
    KEY tokens_account_idx (account_id),
    CONSTRAINT tokens_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE signing_keys (
    id           BINARY(16)   PRIMARY KEY,
    account_id   BINARY(16)   NOT NULL,
    algorithm    VARCHAR(32)  NOT NULL,
    usage        VARCHAR(32)  NOT NULL DEFAULT 'license',
    status       VARCHAR(32)  NOT NULL DEFAULT 'active',
    version      INT          NOT NULL DEFAULT 1,
    material     BLOB         NOT NULL,
    public_pem   TEXT         NOT NULL,
    retired_at   DATETIME(6),
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY signing_keys_account_idx (account_id)
) ENGINE=InnoDB;
-- "at most one active key per (account, usage)" — enforced via a generated column trick
-- (MySQL unique indexes can't carry WHERE; we use a generated `status_active` that's
-- NULL unless status='active'):
ALTER TABLE signing_keys
    ADD COLUMN status_active_gen VARCHAR(32) GENERATED ALWAYS AS
        (CASE WHEN status = 'active' THEN CONCAT(BIN_TO_UUID(account_id), ':', usage) END) STORED;
CREATE UNIQUE INDEX signing_keys_active_uq ON signing_keys(status_active_gen);

CREATE TABLE webhook_endpoints (
    id           BINARY(16)   PRIMARY KEY,
    account_id   BINARY(16)   NOT NULL,
    url          VARCHAR(512) NOT NULL,
    event_types  JSON         NOT NULL,
    secret       VARCHAR(255) NOT NULL,
    status       VARCHAR(32)  NOT NULL DEFAULT 'active',
    metadata     JSON         NOT NULL,
    created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY webhook_endpoints_account_idx (account_id),
    CONSTRAINT webhook_endpoints_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE webhook_events (
    id                   BINARY(16)   PRIMARY KEY,
    account_id           BINARY(16)   NOT NULL,
    endpoint_id          BINARY(16)   NOT NULL,
    event_type           VARCHAR(128) NOT NULL,
    payload              JSON         NOT NULL,
    attempts             INT          NOT NULL DEFAULT 0,
    delivered            TINYINT(1)   NOT NULL DEFAULT 0,
    last_response_status INT,
    last_error           TEXT,
    next_retry_at        DATETIME(6),
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    KEY webhook_events_due_idx (next_retry_at),
    CONSTRAINT webhook_events_account_fk  FOREIGN KEY (account_id)  REFERENCES accounts(id)         ON DELETE CASCADE,
    CONSTRAINT webhook_events_endpoint_fk FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE event_log (
    id            BINARY(16)   PRIMARY KEY,
    account_id    BINARY(16)   NOT NULL,
    event_type    VARCHAR(128) NOT NULL,
    severity      VARCHAR(32)  NOT NULL DEFAULT 'info',
    actor_id      VARCHAR(128),
    resource_type VARCHAR(64),
    resource_id   VARCHAR(128),
    payload       JSON         NOT NULL,
    request_id    VARCHAR(128),
    ip            VARCHAR(64),
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY event_log_account_created_idx (account_id, created_at),
    CONSTRAINT event_log_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB;
