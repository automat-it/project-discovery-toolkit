-- =============================================================================
-- sec_01_users_and_roles_inventory.sql
-- Priority: CRITICAL
-- Purpose: Complete inventory of server logins, database users, and role
--          memberships. The foundation for every other security audit.
-- Sources: sys.server_principals, sys.sql_logins, sys.database_principals,
--          sys.server_role_members, sys.database_role_members.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- All server-level principals (logins, server roles, certificates, etc.)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS principal_name,
    sp.type_desc                                      AS principal_type,
    sp.is_disabled,
    sp.create_date,
    sp.modify_date,
    sp.default_database_name,
    sl.is_policy_checked                              AS check_policy,
    sl.is_expiration_checked                          AS check_expiration,
    -- sys.sql_logins does not expose password_last_set_time / is_expired
    -- as columns; LOGINPROPERTY is the supported accessor.
    LOGINPROPERTY(sp.name, 'PasswordLastSetTime')     AS password_last_set_time,
    LOGINPROPERTY(sp.name, 'IsExpired')               AS password_expired
FROM sys.server_principals sp
LEFT JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type IN ('S','U','G','R','C','K')             -- SQL / Windows / Group / Role / Cert / Key
ORDER BY sp.type_desc, sp.name;

-- ---------------------------------------------------------------------------
-- Fixed-role membership (sysadmin, securityadmin, serveradmin, etc.)
-- ---------------------------------------------------------------------------
SELECT
    r.name                                            AS server_role,
    m.name                                            AS member_name,
    m.type_desc                                       AS member_type,
    m.is_disabled,
    m.create_date
FROM sys.server_role_members srm
JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
ORDER BY r.name, m.name;

-- ---------------------------------------------------------------------------
-- Custom (user-defined) server roles
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS custom_server_role,
    owning_principal_id,
    SUSER_NAME(owning_principal_id)                   AS owner,
    create_date,
    modify_date
FROM sys.server_principals
WHERE type = 'R'
  AND is_fixed_role = 0
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Database users per database (this script runs against the current db;
-- re-run with USE <db> for each database you care about)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    dp.name                                           AS database_user,
    dp.type_desc                                      AS user_type,
    dp.default_schema_name,
    SUSER_NAME(dp.sid)                                AS mapped_login,
    dp.create_date,
    dp.authentication_type_desc,
    dp.is_fixed_role
FROM sys.database_principals dp
WHERE dp.type IN ('S','U','G','R','C','K','E','X')
ORDER BY dp.type_desc, dp.name;

-- ---------------------------------------------------------------------------
-- Database role membership (current database)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    r.name                                            AS database_role,
    m.name                                            AS member_name,
    m.type_desc                                       AS member_type
FROM sys.database_role_members drm
JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
ORDER BY r.name, m.name;

-- ---------------------------------------------------------------------------
-- Orphan database users (no matching server principal / SID)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    dp.name                                           AS database_user,
    dp.type_desc,
    dp.sid,
    dp.create_date
FROM sys.database_principals dp
WHERE dp.type IN ('S','U','G')
  AND dp.sid IS NOT NULL
  AND dp.authentication_type_desc = 'INSTANCE'
  AND NOT EXISTS (
      SELECT 1 FROM sys.server_principals sp
       WHERE sp.sid = dp.sid
  )
  AND dp.name NOT IN ('dbo','guest','sys','INFORMATION_SCHEMA');

-- ---------------------------------------------------------------------------
-- Count summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_principals WHERE type = 'S') AS sql_logins,
    (SELECT COUNT(*) FROM sys.server_principals WHERE type = 'U') AS windows_logins,
    (SELECT COUNT(*) FROM sys.server_principals WHERE type = 'G') AS windows_group_logins,
    (SELECT COUNT(*) FROM sys.server_principals WHERE type = 'R' AND is_fixed_role = 0) AS custom_server_roles,
    (SELECT COUNT(*) FROM sys.server_principals WHERE is_disabled = 1) AS disabled_principals,
    (SELECT COUNT(*) FROM sys.database_principals
      WHERE type IN ('S','U','G')
        AND name NOT IN ('dbo','guest','sys','INFORMATION_SCHEMA')) AS db_users_current_db;
