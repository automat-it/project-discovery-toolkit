-- =============================================================================
-- sec_22_cert_and_key_expiry.sql
-- Priority: HIGH
-- Purpose: Surface TLS certificate expiry (MySQL exposes the server
--          cert not-before / not-after via status variables),
--          password expiry per account, and keyring-plugin state.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Server-side TLS config
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'ssl_ca',
    'ssl_capath',
    'ssl_cert',
    'ssl_cipher',
    'ssl_crl',
    'ssl_crlpath',
    'ssl_fips_mode',
    'ssl_key',
    'tls_version',
    'require_secure_transport',
    'caching_sha2_password_auto_generate_rsa_keys',
    'have_ssl',
    'have_openssl'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Server certificate validity window — MySQL 8.0+ exposes the active
-- server certificate not-before / not-after via performance_schema.
-- On older builds these variables are absent — an empty result is safe.
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE,
    CASE VARIABLE_NAME
        WHEN 'Ssl_server_not_after'  THEN 'certificate expires'
        WHEN 'Ssl_server_not_before' THEN 'certificate valid from'
        ELSE NULL
    END                                                   AS meaning
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Ssl_server_not_before',
    'Ssl_server_not_after',
    'Current_tls_ca',
    'Current_tls_cert',
    'Current_tls_key',
    'Ssl_version',
    'Ssl_cipher'
)
ORDER BY VARIABLE_NAME;

-- Days until server cert expiry (computed from Ssl_server_not_after).
-- The variable is a human-readable timestamp string in MySQL; use STR_TO_DATE.
SELECT
    VARIABLE_VALUE                                        AS not_after_raw,
    STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT')  AS not_after_parsed,
    DATEDIFF(
        STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT'),
        UTC_TIMESTAMP()
    )                                                     AS days_until_expiry,
    CASE
        WHEN STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT') IS NULL
          THEN 'unable to parse — check variable format'
        WHEN STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT') < UTC_TIMESTAMP()
          THEN 'EXPIRED'
        WHEN DATEDIFF(
              STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT'),
              UTC_TIMESTAMP()) < 30
          THEN 'expiring within 30 days'
        WHEN DATEDIFF(
              STR_TO_DATE(VARIABLE_VALUE, '%b %e %H:%i:%s %Y GMT'),
              UTC_TIMESTAMP()) < 90
          THEN 'expiring within 90 days'
        ELSE 'ok'
    END                                                   AS expiry_state
FROM performance_schema.global_status
WHERE VARIABLE_NAME = 'Ssl_server_not_after';

-- ---------------------------------------------------------------------------
-- Per-account password expiry + lock state
-- ---------------------------------------------------------------------------
SELECT
    User, Host,
    account_locked,
    password_expired,
    password_last_changed,
    password_lifetime,
    CASE
        WHEN password_expired = 'Y' THEN 'EXPIRED'
        WHEN password_lifetime IS NOT NULL AND password_last_changed IS NOT NULL
             AND DATE_ADD(password_last_changed, INTERVAL password_lifetime DAY) < NOW()
          THEN 'EXPIRED (policy)'
        WHEN password_lifetime IS NOT NULL AND password_last_changed IS NOT NULL
             AND DATEDIFF(
                   DATE_ADD(password_last_changed, INTERVAL password_lifetime DAY),
                   NOW()) < 30
          THEN 'expiring within 30 days'
        WHEN password_lifetime IS NULL THEN 'no expiry policy'
        ELSE 'ok'
    END                                                   AS password_state,
    CASE
        WHEN password_lifetime IS NOT NULL AND password_last_changed IS NOT NULL
        THEN DATEDIFF(
               DATE_ADD(password_last_changed, INTERVAL password_lifetime DAY),
               NOW())
    END                                                   AS days_until_policy_expiry
FROM mysql.user
WHERE User <> ''
ORDER BY password_state, User, Host;

-- ---------------------------------------------------------------------------
-- Currently-connected SSL sessions (confirms the cert is actually used)
-- ---------------------------------------------------------------------------
SELECT
    COUNT(*)                                              AS total_sessions,
    SUM(CASE WHEN CONNECTION_TYPE = 'SSL/TLS' THEN 1 ELSE 0 END) AS ssl_sessions,
    SUM(CASE WHEN CONNECTION_TYPE <> 'SSL/TLS' THEN 1 ELSE 0 END) AS plaintext_sessions
FROM performance_schema.threads
WHERE PROCESSLIST_ID IS NOT NULL
  AND CONNECTION_TYPE IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Keyring / encryption-at-rest plugin state
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_STATUS,
    PLUGIN_VERSION,
    PLUGIN_TYPE,
    PLUGIN_LIBRARY
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE 'keyring%'
   OR PLUGIN_NAME LIKE '%encryption%'
ORDER BY PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Summary + operator action
-- ---------------------------------------------------------------------------
SELECT CONCAT(
    'require_secure_transport=',
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='require_secure_transport'),
    '; tls_version=',
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='tls_version'),
    '; server cert file=',
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='ssl_cert')
) AS tls_summary;
