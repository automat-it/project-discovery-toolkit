-- =============================================================================
-- sec_05_authentication_and_passwords.sql
-- Priority: CRITICAL
-- Purpose: Inspect authentication configuration, password policy,
--          and accounts with weak / missing / expired credentials.
--
-- Privileges:
--   * pg_settings, pg_roles, expiration data:
--       work for any login role
--   * pg_authid (rolpassword hashes):
--       requires superuser / rds_superuser / equivalent elevated access
--   * pg_hba_file_rules, pg_ident_file_mappings:
--       may require superuser / elevated access depending on environment
--
-- This script is guarded so privileged blocks are skipped instead of failing.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Password / auth-related settings
-- ---------------------------------------------------------------------------
SELECT
    name,
    setting
FROM pg_settings
WHERE name IN (
    'password_encryption',
    'authentication_timeout',
    'krb_caseins_users',
    'db_user_namespace'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Can current user read pg_authid?
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_authid', 'SELECT') AS can_read_pg_authid
\gset

-- ---------------------------------------------------------------------------
-- Accounts with NO password set
-- Guarded by pg_authid access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_authid
SELECT
    r.rolname                                            AS role,
    r.rolcanlogin,
    r.rolsuper,
    r.rolvaliduntil
FROM pg_roles r
LEFT JOIN pg_authid a
  ON a.oid = r.oid
WHERE r.rolcanlogin
  AND a.rolpassword IS NULL
ORDER BY r.rolname;
\else
SELECT
    'Skipped: pg_authid is not readable by ' || current_user
    || '. Re-run as superuser / rds_superuser to inspect password presence.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Accounts with non-SCRAM password hashes
-- Guarded by pg_authid access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_authid
SELECT
    r.rolname                                            AS role,
    CASE
        WHEN a.rolpassword IS NULL THEN 'none'
        WHEN a.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256'
        WHEN a.rolpassword LIKE 'md5%' THEN 'MD5 (deprecated)'
        ELSE 'plain or unknown'
    END                                                  AS password_type,
    r.rolcanlogin,
    r.rolsuper
FROM pg_roles r
LEFT JOIN pg_authid a
  ON a.oid = r.oid
WHERE r.rolcanlogin
ORDER BY password_type, r.rolname;
\else
SELECT
    'Skipped: pg_authid is not readable by ' || current_user
    || '. Re-run as superuser / rds_superuser to inspect hash types.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Roles with password set but no expiry
-- Guarded by pg_authid access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_authid
SELECT
    r.rolname                                            AS role,
    r.rolsuper,
    r.rolcreaterole,
    r.rolcreatedb,
    r.rolreplication
FROM pg_roles r
LEFT JOIN pg_authid a
  ON a.oid = r.oid
WHERE r.rolcanlogin
  AND a.rolpassword IS NOT NULL
  AND r.rolvaliduntil IS NULL
ORDER BY r.rolsuper DESC, r.rolname;
\else
SELECT
    'Skipped: pg_authid is not readable by ' || current_user
    || '. Re-run as superuser / rds_superuser to inspect password+expiry posture.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Expired accounts
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolcanlogin,
    r.rolvaliduntil                                      AS expired_at,
    now() - r.rolvaliduntil                              AS expired_for
FROM pg_roles r
WHERE r.rolcanlogin
  AND r.rolvaliduntil IS NOT NULL
  AND r.rolvaliduntil < now()
ORDER BY r.rolvaliduntil;

-- ---------------------------------------------------------------------------
-- Accounts expiring soon (within 30 days)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolcanlogin,
    r.rolvaliduntil                                      AS expires_at,
    r.rolvaliduntil - now()                              AS time_left
FROM pg_roles r
WHERE r.rolcanlogin
  AND r.rolvaliduntil IS NOT NULL
  AND r.rolvaliduntil >= now()
  AND r.rolvaliduntil < now() + interval '30 days'
ORDER BY r.rolvaliduntil;

-- ---------------------------------------------------------------------------
-- High-privilege login roles with no expiry
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolsuper,
    r.rolcreaterole,
    r.rolcreatedb,
    r.rolreplication,
    r.rolbypassrls,
    r.rolvaliduntil
FROM pg_roles r
WHERE r.rolcanlogin
  AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
  AND r.rolvaliduntil IS NULL
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- Can current user read pg_hba_file_rules?
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_hba_file_rules', 'SELECT') AS can_read_pg_hba
\gset

-- ---------------------------------------------------------------------------
-- pg_hba rules
-- Guarded by access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_hba
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    netmask,
    auth_method,
    options,
    error
FROM pg_hba_file_rules
ORDER BY line_number;
\else
SELECT
    'Skipped: pg_hba_file_rules is not readable by ' || current_user
    || '. Re-run as superuser / elevated role to inspect HBA rules.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Risky HBA entries
-- Guarded by access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_hba
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method,
    CASE
        WHEN auth_method = 'trust'
            THEN 'CRITICAL: trust authentication'
        WHEN auth_method = 'password'
            THEN 'HIGH: cleartext password auth'
        WHEN auth_method = 'md5'
            THEN 'MEDIUM: deprecated, migrate to SCRAM'
        WHEN type = 'hostnossl'
            THEN 'HIGH: non-SSL host access'
        WHEN address IN ('0.0.0.0/0', '::/0')
            THEN 'HIGH: open network scope'
        WHEN address = 'all'
            THEN 'HIGH: unrestricted address token'
        ELSE 'review'
    END                                                  AS finding
FROM pg_hba_file_rules
WHERE
      auth_method IN ('trust', 'password', 'md5')
   OR type = 'hostnossl'
   OR address IN ('0.0.0.0/0', '::/0')
   OR address = 'all'
ORDER BY line_number;
\else
SELECT
    'Skipped: pg_hba_file_rules is not readable by ' || current_user
    || '. Re-run as superuser / elevated role to inspect risky auth rules.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Can current user read pg_ident_file_mappings?
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_ident_file_mappings', 'SELECT') AS can_read_pg_ident
\gset

-- ---------------------------------------------------------------------------
-- pg_ident mappings
-- Guarded by access check.
-- ---------------------------------------------------------------------------
\if :can_read_pg_ident
SELECT
    line_number,
    map_name,
    sys_name                                             AS system_user,
    pg_username                                          AS database_user,
    error
FROM pg_ident_file_mappings
ORDER BY line_number;
\else
SELECT
    'Skipped: pg_ident_file_mappings is not readable by ' || current_user
    || '. Re-run as superuser / elevated role to inspect ident mappings.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting FROM pg_settings WHERE name = 'password_encryption') AS password_encryption,
    (SELECT count(*) FROM pg_roles r
      WHERE r.rolcanlogin
        AND r.rolvaliduntil IS NOT NULL
        AND r.rolvaliduntil < now())                                    AS expired_accounts,
    (SELECT count(*) FROM pg_roles r
      WHERE r.rolcanlogin
        AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
        AND r.rolvaliduntil IS NULL)                                    AS high_priv_no_expiry;