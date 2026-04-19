-- =============================================================================
-- sec_02_effective_privileges.sql
-- Priority: CRITICAL
-- Purpose: Map who actually has access to what — through direct grants
--          and role / nested-role inheritance.
-- Sources: sys.server_permissions, sys.database_permissions,
--          sys.fn_my_permissions (per-user effective perms),
--          sys.server_role_members, sys.database_role_members.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Server-level permissions (explicit grants at the instance level)
-- ---------------------------------------------------------------------------
SELECT
    gp.name                                           AS grantee,
    gp.type_desc                                      AS grantee_type,
    p.permission_name,
    p.state_desc                                      AS state,
    p.class_desc                                      AS class,
    CASE p.class
        WHEN 100 THEN 'SERVER'
        WHEN 101 THEN SUSER_NAME(p.major_id)
        WHEN 105 THEN (SELECT name FROM sys.endpoints WHERE endpoint_id = p.major_id)
        ELSE CAST(p.class AS NVARCHAR(50))
    END                                               AS object_name
FROM sys.server_permissions p
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name NOT IN ('public','sa')
ORDER BY gp.name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Database-level permissions (current database, explicit grants only)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    gp.name                                           AS grantee,
    gp.type_desc                                      AS grantee_type,
    p.permission_name,
    p.state_desc                                      AS state,
    p.class_desc                                      AS class,
    -- Normalise every branch to DATABASE_DEFAULT collation; catalog
    -- functions return mixed collations and CASE insists on a single one.
    CASE p.class
        WHEN 0 THEN DB_NAME()                                                           COLLATE DATABASE_DEFAULT
        WHEN 1 THEN (OBJECT_SCHEMA_NAME(p.major_id) + N'.' + OBJECT_NAME(p.major_id))   COLLATE DATABASE_DEFAULT
        WHEN 3 THEN SCHEMA_NAME(p.major_id)                                             COLLATE DATABASE_DEFAULT
        WHEN 4 THEN USER_NAME(p.major_id)                                               COLLATE DATABASE_DEFAULT
        WHEN 5 THEN (SELECT name COLLATE DATABASE_DEFAULT FROM sys.assemblies
                      WHERE assembly_id = p.major_id)
        WHEN 6 THEN (SELECT name COLLATE DATABASE_DEFAULT FROM sys.types
                      WHERE user_type_id = p.major_id)
        WHEN 10 THEN (SELECT name COLLATE DATABASE_DEFAULT FROM sys.xml_schema_collections
                       WHERE xml_collection_id = p.major_id)
        ELSE CAST(p.class_desc AS NVARCHAR(50))                                         COLLATE DATABASE_DEFAULT
    END                                               AS object_name
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE gp.name NOT IN ('dbo','public','INFORMATION_SCHEMA','sys')
  AND p.permission_name IS NOT NULL
ORDER BY gp.name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Schema-level grants (current database)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    SCHEMA_NAME(p.major_id)                           AS schema_name,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 3                                      -- SCHEMA
  AND gp.name NOT IN ('dbo','public','INFORMATION_SCHEMA','sys')
ORDER BY schema_name, gp.name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Object-level grants (tables, views, procedures)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    OBJECT_SCHEMA_NAME(p.major_id)                    AS schema_name,
    OBJECT_NAME(p.major_id)                           AS object_name,
    o.type_desc                                       AS object_type,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.objects o              ON o.object_id = p.major_id
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 1                                      -- OBJECT
  AND o.is_ms_shipped = 0
ORDER BY schema_name, object_name, gp.name, p.permission_name;

-- ---------------------------------------------------------------------------
-- Column-level grants (current database)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    OBJECT_SCHEMA_NAME(p.major_id)                    AS schema_name,
    OBJECT_NAME(p.major_id)                           AS object_name,
    c.name                                            AS column_name,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.columns c              ON c.object_id = p.major_id AND c.column_id = p.minor_id
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 1
  AND p.minor_id > 0
ORDER BY schema_name, object_name, column_name;

-- ---------------------------------------------------------------------------
-- Effective permissions per login user on every user table
-- (expensive but authoritative — respects role expansion).
--
-- PERFORMANCE NOTE: this evaluates HAS_PERMS_BY_NAME for every (user x
-- table) pair. On databases with 1000+ tables and many principals it
-- can run for minutes. The call returns permissions for the CURRENT
-- connection by default; to audit a specific login wrap the query in
-- EXECUTE AS LOGIN = 'target'; ... REVERT;.
-- ---------------------------------------------------------------------------
DECLARE @tables TABLE (object_id INT, schema_name SYSNAME, object_name SYSNAME);
INSERT INTO @tables
SELECT o.object_id, SCHEMA_NAME(o.schema_id), o.name
  FROM sys.objects o
 WHERE o.type IN ('U','V')
   AND o.is_ms_shipped = 0;

SELECT
    DB_NAME()                                         AS database_name,
    dp.name                                           AS database_user,
    t.schema_name,
    t.object_name,
    MAX(CASE WHEN HAS_PERMS_BY_NAME(QUOTENAME(t.schema_name) + '.' + QUOTENAME(t.object_name), 'OBJECT', 'SELECT') = 1 THEN 1 END) AS can_select,
    MAX(CASE WHEN HAS_PERMS_BY_NAME(QUOTENAME(t.schema_name) + '.' + QUOTENAME(t.object_name), 'OBJECT', 'INSERT') = 1 THEN 1 END) AS can_insert,
    MAX(CASE WHEN HAS_PERMS_BY_NAME(QUOTENAME(t.schema_name) + '.' + QUOTENAME(t.object_name), 'OBJECT', 'UPDATE') = 1 THEN 1 END) AS can_update,
    MAX(CASE WHEN HAS_PERMS_BY_NAME(QUOTENAME(t.schema_name) + '.' + QUOTENAME(t.object_name), 'OBJECT', 'DELETE') = 1 THEN 1 END) AS can_delete
FROM @tables t
CROSS JOIN sys.database_principals dp
WHERE dp.type IN ('S','U','G')
  AND dp.name NOT IN ('dbo','guest','sys','INFORMATION_SCHEMA')
GROUP BY dp.name, t.schema_name, t.object_name
ORDER BY dp.name, t.schema_name, t.object_name;

-- ---------------------------------------------------------------------------
-- Grants made WITH GRANT OPTION (privilege-propagation surface)
-- ---------------------------------------------------------------------------
SELECT
    'SERVER'                                          AS scope,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.server_permissions p
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.state_desc = 'GRANT_WITH_GRANT_OPTION'

UNION ALL

SELECT
    DB_NAME()                                         AS scope,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.database_permissions p
JOIN sys.database_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.state_desc = 'GRANT_WITH_GRANT_OPTION';
