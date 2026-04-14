-- =============================================================================
-- sec_08_network_exposure.sql
-- Priority: HIGH
-- Purpose: Determine attack surface — listen addresses, allowed networks,
--          remote access patterns.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL has no pg_hba_file_rules equivalent. Network access control
--       is enforced by:
--         1. The Host column in mysql.user (per-account host restriction)
--         2. bind_address server variable (which interfaces MySQL listens on)
--         3. require_secure_transport (enforce SSL/TLS for all connections)
--         4. OS-level firewall rules (external to MySQL — not visible here)
--       There is no pg_ident_file_mappings equivalent; external auth
--       (LDAP, Kerberos) is configured per account via the plugin column.

-- ---------------------------------------------------------------------------
-- Listen address and port configuration
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'bind_address',
    'port',
    'mysqlx_bind_address',
    'mysqlx_port',
    'socket',
    'admin_address',
    'admin_port',
    'enable_named_pipe',
    'named_pipe',
    'shared_memory',
    'require_secure_transport'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Account host patterns with risk classification
-- NOTE: This is the MySQL equivalent of pg_hba_file_rules risk analysis.
--       The Host column controls which client hosts can use this account.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    plugin,
    Super_priv,
    CASE
        WHEN Host = '%'
            THEN 'CRITICAL: accessible from any host'
        WHEN Host = '0.0.0.0'
            THEN 'CRITICAL: accessible from any IPv4'
        WHEN Host LIKE '%.0'
            THEN 'HIGH: broad network range'
        WHEN Host LIKE '192.168.%'
          OR Host LIKE '10.%'
          OR Host LIKE '172.16.%'
            THEN 'MEDIUM: private network'
        WHEN Host = 'localhost'
          OR Host = '127.0.0.1'
          OR Host = '::1'
            THEN 'LOW: loopback only'
        WHEN Host = ''
            THEN 'HIGH: anonymous (any user)'
        ELSE 'review'
    END                                                     AS risk
FROM mysql.user
ORDER BY risk, User, Host;

-- ---------------------------------------------------------------------------
-- Accounts reachable from the internet (non-RFC1918, non-loopback)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    plugin,
    Super_priv,
    Grant_priv
FROM mysql.user
WHERE Host NOT IN ('localhost', '127.0.0.1', '::1', '')
  AND Host NOT LIKE '192.168.%'
  AND Host NOT LIKE '10.%'
  AND Host NOT LIKE '172.16.%'
  AND Host NOT LIKE '172.17.%'
  AND Host NOT LIKE '172.18.%'
  AND Host NOT LIKE '172.19.%'
  AND Host NOT LIKE '172.2%.%'
  AND Host NOT LIKE '172.30.%'
  AND Host NOT LIKE '172.31.%'
  AND Host <> '%'              -- already covered in broad access check
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Distinct client hosts currently connected
-- ---------------------------------------------------------------------------
SELECT
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    COUNT(*)                                                AS sessions,
    GROUP_CONCAT(DISTINCT USER ORDER BY USER SEPARATOR ', ') AS users,
    -- `databases` is a reserved keyword in MySQL; quote the alias.
    GROUP_CONCAT(DISTINCT DB ORDER BY DB SEPARATOR ', ')    AS `databases`
FROM information_schema.PROCESSLIST
GROUP BY SUBSTRING_INDEX(HOST, ':', 1)
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Remote (non-localhost) connections right now
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    SUBSTRING_INDEX(HOST, ':', -1)                          AS client_port,
    DB,
    COMMAND,
    TIME                                                     AS seconds,
    STATE,
    LEFT(INFO, 200)                                         AS query
FROM information_schema.PROCESSLIST
WHERE HOST NOT LIKE 'localhost%'
  AND HOST NOT LIKE '127.0.0.1%'
  AND HOST NOT LIKE '::1%'
  AND HOST != ''
ORDER BY client_host, ID;

-- ---------------------------------------------------------------------------
-- Accounts with external authentication plugins
-- (LDAP, Kerberos, PAM — these control authentication outside of MySQL)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin,
    account_locked
FROM mysql.user
WHERE plugin IN (
    'authentication_ldap_simple',
    'authentication_ldap_sasl',
    'authentication_kerberos',
    'authentication_pam',
    'auth_socket',
    'unix_socket',
    'authentication_fido',
    'authentication_webauthn'
)
ORDER BY plugin, User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with explicit SSL/TLS requirements (additional network hardening)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    ssl_type,
    ssl_cipher,
    x509_issuer,
    x509_subject
FROM mysql.user
WHERE ssl_type != ''
  AND User != ''
ORDER BY User, Host;
