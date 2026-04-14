-- =============================================================================
-- sec_07_encryption_status.sql
-- Priority: HIGH
-- Purpose: Verify encryption in transit (SSL/TLS) and check what the
--          database knows about encryption at rest.
-- Note: Encryption at rest is handled at the storage layer (filesystem,
--       LUKS, AWS KMS, etc.) and is NOT directly visible to PostgreSQL.
--       Verify it through the cloud console or OS tools.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- SSL configuration on the server side
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'ssl',
    'ssl_ca_file',
    'ssl_cert_file',
    'ssl_key_file',
    'ssl_crl_file',
    'ssl_ciphers',
    'ssl_prefer_server_ciphers',
    'ssl_min_protocol_version',
    'ssl_max_protocol_version',
    'ssl_dh_params_file',
    'ssl_passphrase_command'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Current connections — SSL state per session
-- ---------------------------------------------------------------------------
SELECT
    a.pid,
    a.usename,
    a.application_name,
    a.client_addr,
    s.ssl                                                AS ssl_in_use,
    s.version                                            AS tls_version,
    s.cipher,
    s.bits                                               AS key_bits,
    s.client_dn                                          AS client_certificate
FROM pg_stat_activity a
LEFT JOIN pg_stat_ssl s ON s.pid = a.pid
WHERE a.backend_type = 'client backend'
  AND a.pid <> pg_backend_pid()
ORDER BY a.pid;

-- ---------------------------------------------------------------------------
-- SSL usage summary
-- ---------------------------------------------------------------------------
SELECT
    coalesce(s.ssl::text, 'unknown')                     AS ssl_state,
    coalesce(s.version, '-')                             AS tls_version,
    count(*)                                             AS connections
FROM pg_stat_activity a
LEFT JOIN pg_stat_ssl s ON s.pid = a.pid
WHERE a.backend_type = 'client backend'
GROUP BY s.ssl, s.version
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Plaintext (non-SSL) connections from non-localhost
-- ---------------------------------------------------------------------------
SELECT
    a.pid,
    a.usename,
    a.application_name,
    a.client_addr,
    a.backend_start
FROM pg_stat_activity a
LEFT JOIN pg_stat_ssl s ON s.pid = a.pid
WHERE a.backend_type = 'client backend'
  AND (s.ssl = false OR s.ssl IS NULL)
  AND a.client_addr IS NOT NULL
  AND a.client_addr <> '127.0.0.1'::inet
  AND a.client_addr <> '::1'::inet
ORDER BY a.client_addr;

-- ---------------------------------------------------------------------------
-- pg_hba.conf entries — look for 'host' (no SSL required) vs 'hostssl'.
-- pg_hba_file_rules is restricted to superusers / pg_read_server_files on
-- most deployments; guard so the script does not error on RDS / least-privilege
-- audit roles.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_hba_file_rules', 'SELECT') AS can_read_pg_hba
\gset
\if :can_read_pg_hba
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method,
    CASE
        WHEN type = 'host'
         AND auth_method NOT IN ('reject', 'cert')
         AND address NOT IN ('127.0.0.1/32', '::1/128')
         AND (SELECT setting FROM pg_settings WHERE name = 'ssl') = 'on'
        THEN 'allows non-SSL when SSL is available'
        ELSE 'ok'
    END                                                  AS ssl_finding
FROM pg_hba_file_rules
WHERE type IN ('host', 'hostssl', 'hostnossl')
ORDER BY line_number;
\else
SELECT 'Skipped: pg_hba_file_rules is not readable by ' || current_user
       || ' — re-run as superuser / pg_read_server_files to inspect HBA SSL rules.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- pgcrypto extension (column-level encryption helper)
-- ---------------------------------------------------------------------------
SELECT extname, extversion
FROM pg_extension
WHERE extname = 'pgcrypto';

-- ---------------------------------------------------------------------------
-- Cloud / RDS-specific SSL enforcement parameters (NULL on non-RDS)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN ('rds.force_ssl');
