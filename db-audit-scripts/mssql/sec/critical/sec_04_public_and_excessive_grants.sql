-- =============================================================================
-- sec_04_public_and_excessive_grants.sql
-- Priority: CRITICAL
-- Purpose: Privileges granted to [public] and any overly-broad grants
--          (GRANT OPTION chains, CONNECT SQL to everyone, etc.).
--          SQL Server's "public" role is the analog of PostgreSQL PUBLIC.
-- Sources: sys.server_permissions, sys.database_permissions.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Server-level permissions granted to [public]
-- ---------------------------------------------------------------------------
SELECT
    p.permission_name,
    p.state_desc,
    p.class_desc,
    CASE p.class
        WHEN 100 THEN 'SERVER'
        WHEN 101 THEN SUSER_NAME(p.major_id)
        WHEN 105 THEN (SELECT name FROM sys.endpoints WHERE endpoint_id = p.major_id)
        ELSE CAST(p.class AS NVARCHAR(50))
    END                                               AS object_name
FROM sys.server_permissions p
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name = 'public'
ORDER BY p.permission_name;

-- ---------------------------------------------------------------------------
-- Database-level permissions granted to [public] in the current database
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    p.permission_name,
    p.state_desc,
    p.class_desc,
    -- Normalise to DATABASE_DEFAULT so CASE branches share one collation.
    CASE p.class
        WHEN 0 THEN DB_NAME()                                                           COLLATE DATABASE_DEFAULT
        WHEN 1 THEN (OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id))   COLLATE DATABASE_DEFAULT
        WHEN 3 THEN SCHEMA_NAME(p.major_id)                                             COLLATE DATABASE_DEFAULT
        WHEN 6 THEN (SELECT name COLLATE DATABASE_DEFAULT FROM sys.types
                      WHERE user_type_id = p.major_id)
        ELSE CAST(p.class_desc AS NVARCHAR(50))                                         COLLATE DATABASE_DEFAULT
    END                                               AS object_name
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name = 'public'
ORDER BY p.class_desc, p.permission_name;

-- ---------------------------------------------------------------------------
-- Objects in this database whose access to [public] means any user
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(p.major_id)                    AS schema_name,
    OBJECT_NAME(p.major_id)                           AS object_name,
    o.type_desc                                       AS object_type,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.objects o              ON o.object_id = p.major_id
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name = 'public'
  AND p.class = 1
  AND o.is_ms_shipped = 0
ORDER BY schema_name, object_name;

-- ---------------------------------------------------------------------------
-- Schema-level grants to [public]
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(p.major_id)                           AS schema_name,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name = 'public'
  AND p.class = 3
ORDER BY schema_name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Guest account status — it should be disabled in every user database.
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    dp.name                                           AS user_name,
    HAS_PERMS_BY_NAME(NULL, NULL, 'CONNECT')          AS can_connect_as_current_user,
    CASE
        WHEN EXISTS (
            SELECT 1 FROM sys.database_permissions p
             JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
            WHERE gp.name = 'guest' AND p.permission_name = 'CONNECT' AND p.state_desc = 'GRANT'
        ) THEN 'GUEST ENABLED'
        ELSE 'guest disabled'
    END                                               AS guest_state
FROM sys.database_principals dp
WHERE dp.name = 'guest';

-- ---------------------------------------------------------------------------
-- CONNECT SQL at server scope granted to [public] (default, but worth
-- asserting — if this is revoked, only explicit grantees can log in)
-- ---------------------------------------------------------------------------
SELECT
    p.permission_name,
    p.state_desc
FROM sys.server_permissions p
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name = 'public'
  AND p.permission_name IN ('CONNECT SQL','VIEW ANY DATABASE','VIEW ANY DEFINITION');

-- ---------------------------------------------------------------------------
-- Excessive grants: permissions on system schemas to non-sa principals
-- ---------------------------------------------------------------------------
SELECT
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc,
    SCHEMA_NAME(p.major_id)                           AS schema_name,
    p.class_desc
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 3
  AND SCHEMA_NAME(p.major_id) IN ('sys','INFORMATION_SCHEMA','guest')
  AND gp.name NOT IN ('dbo','public')
ORDER BY gp.name, schema_name;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_permissions p
       JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
      WHERE gp.name = 'public')                       AS server_grants_to_public,
    (SELECT COUNT(*) FROM sys.database_permissions p
       JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
      WHERE gp.name = 'public')                       AS db_grants_to_public,
    (SELECT COUNT(*) FROM sys.database_permissions
      WHERE state_desc = 'GRANT_WITH_GRANT_OPTION')   AS with_grant_option_grants;
