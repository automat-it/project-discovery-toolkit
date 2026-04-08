-- =============================================================================
-- sec_05_authentication_and_passwords.sql
-- Priority: CRITICAL
-- Purpose: Inspect authentication configuration, password policy,
--          and accounts with weak / missing / expired credentials.
--
-- Privileges (IMPORTANT):
--   * pg_settings, pg_roles, expiration data    — work for any login role
--   * pg_authid (rolpassword hashes)            — superuser / rds_superuser
--                                                 / pg_read_server_files
--   * pg_hba_file_rules, pg_ident_file_mappings — superuser / rds_superuser
--
-- Each block that needs elevated access is guarded by a runtime privilege
-- check and falls back to a "skipped" note instead of erroring out.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Password encryption method in use
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'password_encryption',
    'authentication_timeout',
    'krb_caseins_users',
    'db_user_namespace'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- The next three blocks read pg_authid.rolpassword. Guarded by privilege
-- check so the script does not fail for non-privileged login roles.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_authid', 'SELECT') AS can_read_pg_authid
\gset
\if :can_read_pg_authid

-- ---------------------------------------------------------------------------
-- Accounts with NO password set (rely on host-based / peer / IAM auth)
-- This may be intentional (IAM, certificate auth) — verify each.
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper,
    rolvaliduntil
FROM pg_roles
LEFT JOIN pg_authid USING (rolname)
WHERE rolcanlogin
  AND rolpassword IS NULL
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Accounts with non-SCRAM password hashes
-- (md5 is deprecated, plain is never acceptable)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    CASE
        WHEN rolpassword IS NULL THEN 'none'
        WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256'
        WHEN rolpassword LIKE 'md5%' THEN 'MD5 (deprecated)'
        ELSE 'plain or unknown'
    END                                                  AS password_type,
    rolcanlogin,
    rolsuper
FROM pg_roles
LEFT JOIN pg_authid USING (rolname)
WHERE rolcanlogin
ORDER BY password_type, rolname;

\else
SELECT 'pg_authid blocks skipped — current user cannot read password hashes' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Expired accounts (rolvaliduntil in the past)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolvaliduntil                                        AS expired_at,
    now() - rolvaliduntil                                AS expired_for
FROM pg_roles
WHERE rolvaliduntil IS NOT NULL
  AND rolvaliduntil < now()
ORDER BY rolvaliduntil;

-- ---------------------------------------------------------------------------
-- Accounts expiring soon (within 30 days)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolvaliduntil                                        AS expires_at,
    rolvaliduntil - now()                                AS expires_in
FROM pg_roles
WHERE rolvaliduntil IS NOT NULL
  AND rolvaliduntil > now()
  AND rolvaliduntil < now() + interval '30 days'
ORDER BY rolvaliduntil;

-- ---------------------------------------------------------------------------
-- Accounts with NO expiration (potentially long-lived credentials)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolsuper,
    rolcanlogin,
    rolvaliduntil
FROM pg_roles
WHERE rolcanlogin
  AND rolvaliduntil IS NULL
  AND rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- The next two blocks read pg_hba_file_rules. Guarded by privilege check
-- because this catalog requires superuser / rds_superuser access.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_hba_file_rules', 'SELECT') AS can_read_hba
\gset
\if :can_read_hba

-- ---------------------------------------------------------------------------
-- pg_hba.conf rules (PG 10+ via pg_hba_file_rules)
-- Look for: trust, password (plain), broad CIDR, host instead of hostssl
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- Insecure pg_hba.conf rules (trust, password, very broad networks)
-- ---------------------------------------------------------------------------
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method,
    CASE
        WHEN auth_method = 'trust'    THEN 'CRITICAL: trust (no auth)'
        WHEN auth_method = 'password' THEN 'HIGH: cleartext password'
        WHEN auth_method = 'ident'    THEN 'MEDIUM: ident is weak'
        WHEN address IN ('0.0.0.0/0', '::/0') THEN 'HIGH: open to internet'
        WHEN address LIKE '0.0.0.0/%' AND substring(address from '/(\d+)')::int < 16
                                      THEN 'HIGH: very broad CIDR'
        WHEN type = 'host' AND auth_method NOT IN ('reject', 'cert')
                                      THEN 'MEDIUM: non-SSL host entry'
        ELSE 'review'
    END                                                  AS finding
FROM pg_hba_file_rules
WHERE auth_method IN ('trust', 'password', 'ident')
   OR address IN ('0.0.0.0/0', '::/0')
   OR (type = 'host' AND auth_method NOT IN ('reject', 'cert', 'scram-sha-256'))
ORDER BY line_number;

\else
SELECT 'pg_hba_file_rules blocks skipped — current user cannot read pg_hba.conf catalog' AS note;
\endif
