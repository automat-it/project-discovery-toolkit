-- =============================================================================
-- sec_02_effective_privileges.sql
-- Priority: CRITICAL
-- Purpose: Map who actually has access to what — through direct grants and
--          role membership. Find over-privileged users.
-- Read-only.
--
-- Notes:
--   * information_schema.USER_PRIVILEGES shows global privileges.
--   * information_schema.SCHEMA_PRIVILEGES shows database-level privileges.
--   * information_schema.TABLE_PRIVILEGES shows table-level privileges.
--   * information_schema.COLUMN_PRIVILEGES shows column-level privileges.
--   * Role-inherited privileges require joining mysql.role_edges.
-- =============================================================================

-- NOTE: MySQL privilege model differs from PostgreSQL:
--       - Privileges are per (user, host, object) tuples, not per role membership.
--       - Effective privileges include those granted directly AND via roles
--         (MySQL 8.0+ roles are activated at session start or via SET ROLE).
--       - There is no has_table_privilege() function equivalent in MySQL;
--         check information_schema tables directly.
--       - "GRANT OPTION" = PostgreSQL WITH GRANT OPTION.

-- ---------------------------------------------------------------------------
-- Global privileges per account
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
ORDER BY GRANTEE, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Database-level privileges (GRANT privilege ON db.*)
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA                                            AS database_name,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Table-level privileges (GRANT privilege ON db.table)
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    TABLE_NAME,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.TABLE_PRIVILEGES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Column-level privileges
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    TABLE_NAME,
    COLUMN_NAME,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.COLUMN_PRIVILEGES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Routine-level privileges (GRANT EXECUTE ON PROCEDURE/FUNCTION)
-- ---------------------------------------------------------------------------
-- NOTE: information_schema.ROUTINE_PRIVILEGES was dropped in MySQL 8.0 as
-- part of the data-dictionary migration and is no longer populated on
-- current MySQL / Aurora MySQL. Query mysql.procs_priv directly instead;
-- it is the authoritative source for routine grants.
SELECT
    CONCAT('''', pp.User, '''@''', pp.Host, '''')            AS GRANTEE,
    pp.Db                                                    AS ROUTINE_SCHEMA,
    pp.Routine_name                                          AS ROUTINE_NAME,
    pp.Routine_type                                          AS ROUTINE_TYPE,
    pp.Proc_priv                                             AS PRIVILEGE_TYPES,
    pp.Grantor                                               AS GRANTOR,
    pp.Timestamp                                             AS GRANTED_AT
FROM mysql.procs_priv pp
WHERE pp.Db NOT IN ('mysql', 'information_schema',
                    'performance_schema', 'sys')
ORDER BY pp.User, pp.Host, pp.Db, pp.Routine_name;

-- ---------------------------------------------------------------------------
-- Object ownership (tables, views, routines)
-- NOTE: MySQL does not have an owner concept like PostgreSQL. The DEFINER
--       attribute on views and routines is the closest analog.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_TYPE,
    NULL                                                    AS owner
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND TABLE_TYPE IN ('BASE TABLE', 'VIEW')
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Views with DEFINER (effective access via SECURITY DEFINER / INVOKER)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME                                              AS view_name,
    DEFINER,
    SECURITY_TYPE,
    IS_UPDATABLE
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Effective privilege summary per account
-- (count of distinct database-level and table-level grants)
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    COUNT(DISTINCT TABLE_SCHEMA)                            AS schemas_with_access,
    COUNT(DISTINCT CONCAT(TABLE_SCHEMA, '.', TABLE_NAME))   AS tables_with_access
FROM information_schema.TABLE_PRIVILEGES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
GROUP BY GRANTEE
ORDER BY tables_with_access DESC, schemas_with_access DESC, GRANTEE;

-- ---------------------------------------------------------------------------
-- Accounts with ALL PRIVILEGES at the global level (highest risk)
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES'
   OR PRIVILEGE_TYPE = 'SUPER'
ORDER BY GRANTEE;

-- ---------------------------------------------------------------------------
-- Role membership chain (MySQL 8.0+)
-- Shows which accounts are members of which roles.
-- ---------------------------------------------------------------------------
SELECT
    re.FROM_USER                                            AS role,
    re.FROM_HOST                                            AS role_host,
    re.TO_USER                                              AS member,
    re.TO_HOST                                              AS member_host,
    re.WITH_ADMIN_OPTION,
    -- Is the role in the member's default_roles (activated automatically)?
    CASE WHEN dr.DEFAULT_ROLE_USER IS NOT NULL
         THEN 'YES'
         ELSE 'NO (must run SET ROLE)'
    END                                                     AS auto_activated
FROM mysql.role_edges re
LEFT JOIN mysql.default_roles dr
  ON  dr.USER              = re.TO_USER
  AND dr.HOST              = re.TO_HOST
  AND dr.DEFAULT_ROLE_USER = re.FROM_USER
  AND dr.DEFAULT_ROLE_HOST = re.FROM_HOST
ORDER BY re.FROM_USER, re.TO_USER;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM mysql.user WHERE account_locked = 'N')
                                                            AS login_accounts,
    (SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES
     WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys'))
                                                            AS direct_table_grants,
    (SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES
     WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys'))
                                                            AS database_grants,
    (SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES
     WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys'))
                                                            AS column_grants,
    (SELECT COUNT(*) FROM mysql.procs_priv
     WHERE Db NOT IN ('mysql', 'information_schema',
                      'performance_schema', 'sys'))
                                                            AS routine_grants;
