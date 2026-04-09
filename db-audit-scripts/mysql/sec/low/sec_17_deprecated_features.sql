-- =============================================================================
-- sec_17_deprecated_features.sql
-- Priority: LOW
-- Purpose: Detect deprecated authentication mechanisms and old features
--          that should be migrated.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL deprecation landscape differs from PostgreSQL:
--       - mysql_native_password is deprecated in MySQL 8.0.34+ and
--         will be removed in a future version
--       - sha256_password is deprecated in MySQL 8.0
--       - query_cache was removed in MySQL 8.0 (deprecated in 5.7)
--       - OLD_PASSWORD() function was removed in MySQL 8.0
--       - MySQL does not have TLS 1.0/1.1 config in the same format
--         as PostgreSQL ssl_min_protocol_version; use tls_version instead

-- ---------------------------------------------------------------------------
-- Default authentication plugin (should be caching_sha2_password in MySQL 8.0)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'default_authentication_plugin',
    'authentication_policy'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Accounts still using deprecated authentication plugins
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin,
    account_locked,
    CASE plugin
        WHEN 'mysql_native_password'
            THEN 'deprecated in MySQL 8.0.34+ — migrate to caching_sha2_password'
        WHEN 'sha256_password'
            THEN 'deprecated in MySQL 8.0 — migrate to caching_sha2_password'
        WHEN 'mysql_old_password'
            THEN 'REMOVED in MySQL 8.0 — should not appear'
        ELSE 'ok'
    END                                                     AS finding
FROM mysql.user
WHERE plugin IN ('mysql_native_password', 'sha256_password', 'mysql_old_password')
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- TLS protocol version configuration
-- MySQL uses the tls_version variable (comma-separated list).
-- TLSv1 and TLSv1.1 are deprecated and should be removed.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'tls_version',
    'tls_ciphersuites',
    'admin_tls_version',
    'mysqlx_tls_version'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Deprecated / removed features check via global variables
-- (These variables exist in older MySQL versions but are removed/deprecated in 8.0+)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'query_cache_type',          -- removed in 8.0
    'query_cache_size',          -- removed in 8.0
    'innodb_file_format',        -- removed in 8.0
    'innodb_large_prefix',       -- removed in 8.0
    'old_passwords',             -- removed in 8.0
    'secure_auth',               -- removed in 8.0
    'log_bin_use_v1_row_events', -- removed in 8.0
    'master_verify_checksum',    -- renamed in 8.0.26+
    'slave_parallel_workers',    -- deprecated in 8.0.26+
    'expire_logs_days'           -- deprecated in 8.0.3+
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- MyISAM tables (MyISAM is considered legacy; InnoDB is the default engine)
-- MyISAM lacks transactions, FK constraints, and crash recovery guarantees.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    CREATE_TIME
FROM information_schema.TABLES
WHERE ENGINE = 'MyISAM'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Other non-InnoDB / non-standard engines (ARCHIVE, BLACKHOLE, MEMORY for
-- persistent tables, FEDERATED)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_TYPE
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND TABLE_TYPE = 'BASE TABLE'
  AND ENGINE NOT IN ('InnoDB', NULL)
ORDER BY ENGINE, TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Accounts with password_policy not enforced (no validate_password plugin)
-- ---------------------------------------------------------------------------
SELECT
    CASE WHEN COUNT(*) > 0 THEN 'validate_password plugin is ACTIVE'
         ELSE 'validate_password plugin NOT installed — password policy not enforced'
    END                                                     AS password_policy_status
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE 'validate_password%'
  AND PLUGIN_STATUS = 'ACTIVE';

-- ---------------------------------------------------------------------------
-- Accounts with no password expiry (never-expiring passwords)
-- password_lifetime = 0 means never expires (explicit override).
-- NULL means inherits default_password_lifetime (0 by default = never).
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    password_lifetime,
    password_last_changed,
    plugin
FROM mysql.user
WHERE account_locked = 'N'
  AND (password_lifetime = 0 OR password_lifetime IS NULL)
  AND User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- ALGORITHM and SQL_MODE issues in views (degraded behavior indicators)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    VIEW_DEFINITION IS NULL                                 AS definition_hidden,
    IS_UPDATABLE,
    DEFINER,
    SECURITY_TYPE,
    CHARACTER_SET_CLIENT
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND IS_UPDATABLE = 'NO'
ORDER BY TABLE_SCHEMA, TABLE_NAME
LIMIT 30;
