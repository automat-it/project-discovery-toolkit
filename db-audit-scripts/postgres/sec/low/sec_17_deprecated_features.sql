-- =============================================================================
-- sec_17_deprecated_features.sql
-- Priority: LOW
-- Purpose: Detect deprecated authentication mechanisms and old features
--          that should be migrated.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- password_encryption setting (md5 is deprecated, scram-sha-256 is current)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name = 'password_encryption';

-- ---------------------------------------------------------------------------
-- Accounts still using MD5 password hashes.
-- pg_authid requires elevated privileges; skip cleanly when not available.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_authid', 'SELECT') AS can_read_pg_authid
\gset
\if :can_read_pg_authid
SELECT
    rolname                                              AS role,
    r.rolcanlogin,
    r.rolsuper
FROM pg_roles r
LEFT JOIN pg_authid a USING (rolname)
WHERE r.rolcanlogin
  AND a.rolpassword LIKE 'md5%'
ORDER BY rolname;
\else
SELECT 'Skipped: pg_authid is not readable by ' || current_user
       || ' — re-run as superuser / rds_superuser to detect MD5 hashes.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- pg_hba.conf entries using deprecated auth methods.
-- pg_hba_file_rules is restricted to elevated roles; guard access.
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
    CASE auth_method
        WHEN 'md5'      THEN 'deprecated — use scram-sha-256'
        WHEN 'password' THEN 'deprecated — sends password in clear'
        WHEN 'crypt'    THEN 'removed in modern PG'
        WHEN 'ident'    THEN 'fragile, prefer peer or scram'
        ELSE 'ok'
    END                                                  AS finding
FROM pg_hba_file_rules
WHERE auth_method IN ('md5', 'password', 'crypt', 'ident')
ORDER BY line_number;

-- ---------------------------------------------------------------------------
-- Use of unencrypted host (instead of hostssl) for non-loopback connections
-- ---------------------------------------------------------------------------
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method
FROM pg_hba_file_rules
WHERE type = 'host'
  AND address NOT IN ('127.0.0.1/32', '::1/128')
  AND (SELECT setting FROM pg_settings WHERE name = 'ssl') = 'on'
ORDER BY line_number;
\else
SELECT 'Skipped: pg_hba_file_rules is not readable by ' || current_user
       || ' — re-run as superuser / pg_read_server_files to inspect HBA auth methods.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Untrusted procedural languages installed (deprecated in favor of trusted variants)
-- ---------------------------------------------------------------------------
SELECT
    lanname                                              AS language,
    lanpltrusted                                         AS trusted,
    pg_get_userbyid(lanowner)                            AS owner
FROM pg_language
WHERE NOT lanpltrusted
  AND lanname NOT IN ('internal', 'c')
ORDER BY lanname;

-- ---------------------------------------------------------------------------
-- TLS protocol settings — TLS 1.0 and 1.1 are deprecated
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN ('ssl_min_protocol_version', 'ssl_max_protocol_version');

-- ---------------------------------------------------------------------------
-- Large object usage (the lo / pg_largeobject API is legacy in most cases)
-- ---------------------------------------------------------------------------
SELECT
    count(*)                                             AS large_object_count
FROM pg_largeobject_metadata;

-- ---------------------------------------------------------------------------
-- Accounts that pre-date last password rotation policy (no valid_until set)
-- This is a heuristic — adjust the cutoff date as needed.
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolvaliduntil
FROM pg_roles
WHERE rolcanlogin
  AND rolvaliduntil IS NULL
  AND rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY rolname;
