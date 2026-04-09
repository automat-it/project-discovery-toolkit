-- =============================================================================
-- sec_07_encryption_status.sql
-- Priority: HIGH
-- Purpose: Verify encryption in transit (SSL/TLS) and check what the
--          database knows about encryption at rest.
-- Note: Encryption at rest is handled at the storage/OS layer or via
--       InnoDB tablespace encryption (MySQL 8.0+). Verify it through
--       the cloud console or OS tools for filesystem-level encryption.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL SSL/TLS configuration is controlled by:
--       - require_secure_transport = ON forces SSL for all connections
--       - mysql.user.ssl_type controls per-account SSL requirements
--       - Information about active SSL sessions is in
--         performance_schema.session_status (per-session SSL variables)
--       - InnoDB tablespace encryption (at-rest) is tracked in
--         information_schema.INNODB_TABLESPACES
--       There is no pg_stat_ssl view in MySQL; session SSL info must be
--       queried via STATUS or per-session variables.

-- ---------------------------------------------------------------------------
-- SSL / TLS server configuration
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'have_ssl',
    'have_openssl',
    'ssl_ca',
    'ssl_capath',
    'ssl_cert',
    'ssl_key',
    'ssl_cipher',
    'ssl_crl',
    'ssl_crlpath',
    'tls_version',
    'tls_ciphersuites',
    'require_secure_transport',
    'admin_ssl_ca',
    'admin_ssl_cert',
    'admin_ssl_key',
    'admin_tls_version'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- SSL status (server-level)
-- ---------------------------------------------------------------------------
SHOW GLOBAL STATUS LIKE 'Ssl_%';

-- ---------------------------------------------------------------------------
-- Per-account SSL requirements
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    ssl_type,
    ssl_cipher,
    x509_issuer,
    x509_subject,
    CASE ssl_type
        WHEN ''          THEN 'no SSL requirement'
        WHEN 'ANY'       THEN 'SSL required (any cert)'
        WHEN 'X509'      THEN 'X.509 certificate required'
        WHEN 'SPECIFIED' THEN 'specific cipher/cert required'
        ELSE ssl_type
    END                                                     AS ssl_policy,
    account_locked
FROM mysql.user
WHERE User != ''
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Current connections — SSL state per session
-- NOTE: performance_schema.session_status shows the SSL status of the
--       current session only. To inspect other sessions' SSL state,
--       query performance_schema.status_by_thread joined with threads.
-- ---------------------------------------------------------------------------
SELECT
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_HOST                                      AS host,
    MAX(CASE WHEN svt.VARIABLE_NAME = 'Ssl_cipher'
             THEN svt.VARIABLE_VALUE END)                   AS ssl_cipher,
    MAX(CASE WHEN svt.VARIABLE_NAME = 'Ssl_version'
             THEN svt.VARIABLE_VALUE END)                   AS tls_version,
    MAX(CASE WHEN svt.VARIABLE_NAME = 'Ssl_cipher_list'
             THEN svt.VARIABLE_VALUE END)                   AS cipher_list
FROM performance_schema.threads t
LEFT JOIN performance_schema.status_by_thread svt
  ON  svt.THREAD_ID = t.THREAD_ID
  AND svt.VARIABLE_NAME IN ('Ssl_cipher', 'Ssl_version', 'Ssl_cipher_list')
WHERE t.TYPE = 'FOREGROUND'
  AND t.PROCESSLIST_USER IS NOT NULL
GROUP BY t.PROCESSLIST_ID, t.PROCESSLIST_USER, t.PROCESSLIST_HOST
ORDER BY t.PROCESSLIST_ID;

-- ---------------------------------------------------------------------------
-- Non-SSL connections from non-localhost
-- NOTE: ssl_cipher being empty means the connection is not encrypted.
-- ---------------------------------------------------------------------------
SELECT
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_HOST                                      AS host,
    svt.VARIABLE_VALUE                                      AS ssl_cipher
FROM performance_schema.threads t
LEFT JOIN performance_schema.status_by_thread svt
  ON  svt.THREAD_ID = t.THREAD_ID
  AND svt.VARIABLE_NAME = 'Ssl_cipher'
WHERE t.TYPE = 'FOREGROUND'
  AND t.PROCESSLIST_HOST IS NOT NULL
  AND t.PROCESSLIST_HOST NOT IN ('localhost', '127.0.0.1', '::1')
  AND (svt.VARIABLE_VALUE = '' OR svt.VARIABLE_VALUE IS NULL)
ORDER BY t.PROCESSLIST_HOST;

-- ---------------------------------------------------------------------------
-- InnoDB tablespace encryption (at-rest encryption — MySQL 8.0+)
-- Encrypted tablespaces show ENCRYPTION = 'Y'
-- ---------------------------------------------------------------------------
SELECT
    SPACE                                                   AS tablespace_id,
    NAME                                                    AS tablespace_name,
    ENCRYPTION,
    STATE,
    SPACE_TYPE
FROM information_schema.INNODB_TABLESPACES
ORDER BY ENCRYPTION DESC, NAME;

-- ---------------------------------------------------------------------------
-- Encryption summary: how many tablespaces are encrypted vs unencrypted
-- ---------------------------------------------------------------------------
SELECT
    ENCRYPTION,
    COUNT(*)                                                AS tablespace_count
FROM information_schema.INNODB_TABLESPACES
GROUP BY ENCRYPTION;

-- ---------------------------------------------------------------------------
-- Keyring plugin / component (required for InnoDB tablespace encryption)
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_STATUS,
    PLUGIN_TYPE
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE '%keyring%'
   OR PLUGIN_NAME LIKE '%key_management%'
ORDER BY PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Cloud / RDS specific: check for require_secure_transport enforcement
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'require_secure_transport';
