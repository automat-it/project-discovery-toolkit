-- =============================================================================
-- sec_03_admin_and_superusers.sql
-- Priority: CRITICAL
-- Purpose: List every principal with admin-level authority. These
--          represent the highest compromise risk.
-- Sources: sys.server_role_members, sys.server_principals,
--          sys.server_permissions, sys.database_principals.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- sysadmin server-role members (direct effective "superusers")
-- ---------------------------------------------------------------------------
SELECT
    m.name                                            AS member,
    m.type_desc                                       AS member_type,
    m.is_disabled,
    m.create_date,
    sl.is_policy_checked                              AS check_policy,
    sl.is_expiration_checked                          AS check_expiration,
    LOGINPROPERTY(m.name, 'IsExpired')                AS password_expired
FROM sys.server_role_members srm
JOIN sys.server_principals r   ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m   ON m.principal_id = srm.member_principal_id
LEFT JOIN sys.sql_logins sl    ON sl.principal_id = m.principal_id
WHERE r.name = 'sysadmin'
ORDER BY m.name;

-- ---------------------------------------------------------------------------
-- securityadmin / serveradmin / setupadmin / processadmin / diskadmin /
-- bulkadmin members (each fixed role confers significant admin surface)
-- ---------------------------------------------------------------------------
SELECT
    r.name                                            AS fixed_role,
    m.name                                            AS member,
    m.type_desc                                       AS member_type,
    m.is_disabled
FROM sys.server_role_members srm
JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
WHERE r.name IN ('securityadmin','serveradmin','setupadmin',
                 'processadmin','diskadmin','bulkadmin','dbcreator')
ORDER BY r.name, m.name;

-- ---------------------------------------------------------------------------
-- Logins with CONTROL SERVER (the most dangerous explicit grant —
-- effectively sysadmin without being labeled as such)
-- ---------------------------------------------------------------------------
SELECT
    gp.name                                           AS grantee,
    gp.type_desc,
    p.permission_name,
    p.state_desc
FROM sys.server_permissions p
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.permission_name IN ('CONTROL SERVER',
                            'ALTER ANY LOGIN',
                            'ALTER ANY SERVER ROLE',
                            'ALTER ANY CREDENTIAL',
                            'IMPERSONATE ANY LOGIN',
                            'CREATE SERVER ROLE',
                            'UNSAFE ASSEMBLY',
                            'EXTERNAL ACCESS ASSEMBLY')
ORDER BY gp.name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Recursive chain: every login that ends up a member of sysadmin via
-- nested custom server roles
-- ---------------------------------------------------------------------------
;WITH role_chain AS (
    SELECT
        srm.role_principal_id,
        srm.member_principal_id,
        CAST(r.name + ' -> ' + m.name AS NVARCHAR(MAX)) AS path,
        1                                             AS level
    FROM sys.server_role_members srm
    JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
    JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
    WHERE r.name = 'sysadmin'
    UNION ALL
    SELECT
        srm.role_principal_id,
        srm.member_principal_id,
        rc.path + ' -> ' + m.name,
        rc.level + 1
    FROM role_chain rc
    JOIN sys.server_role_members srm ON srm.role_principal_id = rc.member_principal_id
    JOIN sys.server_principals m     ON m.principal_id = srm.member_principal_id
    WHERE rc.level < 10
)
SELECT DISTINCT
    SUSER_NAME(member_principal_id)                   AS effective_sysadmin,
    path
FROM role_chain
ORDER BY effective_sysadmin;

-- ---------------------------------------------------------------------------
-- Database-level admin: db_owner members in the current database
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    r.name                                            AS role,
    m.name                                            AS member,
    m.type_desc
FROM sys.database_role_members drm
JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
WHERE r.name IN ('db_owner','db_securityadmin','db_accessadmin',
                 'db_ddladmin','db_backupoperator')
ORDER BY r.name, m.name;

-- ---------------------------------------------------------------------------
-- Principals with CONTROL on the current database
-- ---------------------------------------------------------------------------
SELECT
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 0                                      -- DATABASE class
  AND p.permission_name IN ('CONTROL','ALTER','ALTER ANY USER','ALTER ANY ROLE',
                            'ALTER ANY SCHEMA','ALTER ANY APPLICATION ROLE',
                            'IMPERSONATE ANY LOGIN')
ORDER BY gp.name;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_role_members srm
       JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
      WHERE r.name = 'sysadmin')                      AS sysadmin_members,
    (SELECT COUNT(*) FROM sys.server_role_members srm
       JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
      WHERE r.name = 'securityadmin')                 AS securityadmin_members,
    (SELECT COUNT(*) FROM sys.server_permissions
      WHERE permission_name = 'CONTROL SERVER')       AS control_server_grants,
    (SELECT COUNT(*) FROM sys.database_role_members drm
       JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
      WHERE r.name = 'db_owner')                      AS db_owner_members_here;
