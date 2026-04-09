-- =============================================================================
-- sec_05_authentication_and_passwords.sql
-- Priority: CRITICAL
-- Purpose: Inspect authentication configuration, password policy,
--          and accounts with weak / missing / expired credentials.
--
-- Privileges:
--   * Requires SELECT on mysql.user (DBA/root or equivalent).
--   * MySQL does not have pg_hba_file_rules; network access rules are
--     controlled by the Host column in mysql.user and SSL requirements.
--   * MySQL does not have pg_ident_file_mappings.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL authentication configuration is split between:
--       - mysql.user (per-account settings)
--       - global variables (server-level password policy, plugins)
--       - validate_password plugin/component (password strength policy)
--       There is no pg_hba.conf equivalent; host-based access is
--       controlled by the Host column in mysql.user (which supports
--       exact hostnames, IP addresses, and % wildcard).

-- ---------------------------------------------------------------------------
-- Authentication-related server settings
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'default_authentication_plugin',
    'authentication_policy',
    'require_secure_transport',
    'validate_password.policy',
    'validate_password.length',
    'validate_password.mixed_case_count',
    'validate_password.number_count',
    'validate_password.special_char_count',
    'validate_password.check_user_name',
    'password_history',
    'password_reuse_interval',
    'disconnect_on_expired_password',
    'connect_timeout',
    'wait_timeout',
    'interactive_timeout',
    'net_read_timeout',
    'net_write_timeout'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Accounts with NO password set (empty authentication_string)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv                                              AS has_super,
    plugin,
    password_expired
FROM mysql.user
WHERE (authentication_string = '' OR authentication_string IS NULL)
  AND account_locked = 'N'
  AND plugin NOT IN ('mysql_no_login', 'auth_socket', 'unix_socket')
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts using deprecated or weak authentication plugins
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin,
    CASE plugin
        WHEN 'mysql_native_password'
            THEN 'MEDIUM: legacy SHA1-based, migrate to caching_sha2_password'
        WHEN 'sha256_password'
            THEN 'MEDIUM: deprecated in MySQL 8.0, migrate to caching_sha2_password'
        WHEN 'mysql_old_password'
            THEN 'CRITICAL: very old and insecure'
        WHEN ''
            THEN 'HIGH: no plugin set'
        ELSE 'ok'
    END                                                     AS finding,
    account_locked,
    password_expired
FROM mysql.user
WHERE plugin NOT IN ('caching_sha2_password', 'mysql_no_login',
                     'auth_socket', 'unix_socket',
                     'authentication_fido', 'authentication_webauthn',
                     'authentication_ldap_simple', 'authentication_ldap_sasl',
                     'authentication_kerberos')
  AND account_locked = 'N'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with password set but no expiry (password_lifetime = NULL)
-- NULL means the global default_password_lifetime applies.
-- 0 means password never expires (override — CRITICAL for privileged accounts).
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin,
    Super_priv                                              AS has_super,
    Create_user_priv,
    Repl_slave_priv,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE account_locked = 'N'
  AND (authentication_string != '' OR authentication_string IS NOT NULL)
  AND (password_lifetime = 0 OR password_lifetime IS NULL)
ORDER BY Super_priv DESC, User, Host;

-- ---------------------------------------------------------------------------
-- Expired accounts (password_expired = 'Y')
-- These accounts require a password change before full use.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    password_expired,
    password_last_changed,
    plugin
FROM mysql.user
WHERE password_expired = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with passwords expiring soon (within 30 days)
-- Only applicable when password_lifetime is explicitly set.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin,
    password_last_changed,
    password_lifetime,
    DATE_ADD(password_last_changed,
             INTERVAL password_lifetime DAY)                AS expires_at,
    DATEDIFF(DATE_ADD(password_last_changed,
                      INTERVAL password_lifetime DAY),
             NOW())                                         AS days_left
FROM mysql.user
WHERE password_lifetime IS NOT NULL
  AND password_lifetime > 0
  AND password_expired = 'N'
  AND account_locked = 'N'
  AND DATE_ADD(password_last_changed, INTERVAL password_lifetime DAY)
      BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY)
ORDER BY days_left;

-- ---------------------------------------------------------------------------
-- High-privilege accounts with no password expiry policy
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    Super_priv,
    Grant_priv,
    Create_user_priv,
    Repl_slave_priv,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE account_locked = 'N'
  AND (Super_priv = 'Y' OR Grant_priv = 'Y'
    OR Create_user_priv = 'Y' OR Repl_slave_priv = 'Y')
  AND (password_lifetime = 0 OR password_lifetime IS NULL)
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Network access patterns (Host column analysis)
-- NOTE: MySQL has no pg_hba_file_rules equivalent. The Host column in
--       mysql.user controls which hosts can connect. % means any host.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    plugin,
    CASE
        WHEN Host = '%'           THEN 'CRITICAL: accessible from any host'
        WHEN Host = '0.0.0.0'    THEN 'CRITICAL: accessible from any IPv4'
        WHEN Host LIKE '%.%'
             AND Host NOT LIKE '%/%'
             AND Host NOT LIKE 'localhost'
             AND Host NOT LIKE '127.0.0.1'
             AND Host NOT LIKE '::1'
                                  THEN 'review: specific hostname'
        WHEN Host = 'localhost'
          OR Host = '127.0.0.1'
          OR Host = '::1'         THEN 'ok: loopback only'
        ELSE 'review'
    END                                                     AS host_finding
FROM mysql.user
WHERE User != ''
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- SSL / TLS requirements per account
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    ssl_type,
    ssl_cipher,
    x509_issuer,
    x509_subject,
    CASE ssl_type
        WHEN ''      THEN 'no SSL requirement'
        WHEN 'ANY'   THEN 'SSL required (any cert)'
        WHEN 'X509'  THEN 'X.509 certificate required'
        WHEN 'SPECIFIED' THEN 'specific cert required'
    END                                                     AS ssl_policy
FROM mysql.user
WHERE User != ''
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'default_authentication_plugin')    AS default_auth_plugin,
    (SELECT COUNT(*) FROM mysql.user
     WHERE password_expired = 'Y')                             AS expired_accounts,
    (SELECT COUNT(*) FROM mysql.user
     WHERE (authentication_string = '' OR authentication_string IS NULL)
       AND account_locked = 'N')                               AS no_password_accounts,
    (SELECT COUNT(*) FROM mysql.user
     WHERE (Super_priv = 'Y' OR Grant_priv = 'Y')
       AND (password_lifetime = 0 OR password_lifetime IS NULL)
       AND account_locked = 'N')                               AS high_priv_no_expiry;
