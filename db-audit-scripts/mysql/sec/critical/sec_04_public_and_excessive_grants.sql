-- =============================================================================
-- sec_04_public_and_excessive_grants.sql
-- Priority: CRITICAL
-- Purpose: Find privileges granted to broad/anonymous accounts or
--          overly permissive patterns. MySQL has no PUBLIC role, but
--          wildcard host accounts ('%') and anonymous users serve a
--          similar role.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have a PUBLIC role equivalent like PostgreSQL.
--       The closest analogs are:
--         - Anonymous accounts: User='' (empty string) — match any username
--         - Wildcard host '%' accounts — match connections from any host
--         - Grants on '%.tablename' patterns
--       Pre-MySQL 8.0 had anonymous accounts by default; they should be removed.

-- ---------------------------------------------------------------------------
-- Anonymous accounts (User = '') — accessible by anyone connecting
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv,
    Grant_priv,
    plugin,
    password_expired
FROM mysql.user
WHERE User = ''
ORDER BY Host;

-- ---------------------------------------------------------------------------
-- Wildcard-host accounts (Host = '%') — accessible from any network location
-- These are the MySQL analog of PostgreSQL's PUBLIC privilege in terms of
-- network exposure.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv,
    Grant_priv,
    Create_user_priv,
    Repl_slave_priv,
    max_connections,
    plugin,
    password_expired
FROM mysql.user
WHERE Host = '%'
  AND User != ''
ORDER BY User;

-- ---------------------------------------------------------------------------
-- Global privileges granted to wildcard-host accounts
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
WHERE GRANTEE LIKE '%@%'
  AND SUBSTRING_INDEX(GRANTEE, '@', -1) LIKE "'%'"
  -- Accounts where host part is '%'
  AND REPLACE(SUBSTRING_INDEX(GRANTEE, '@', -1), "'", '') = '%'
ORDER BY GRANTEE, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Database-level grants to wildcard-host or anonymous accounts
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND (GRANTEE LIKE "''@%"          -- anonymous user
    OR GRANTEE LIKE "%'@'%'")       -- wildcard host
ORDER BY GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Table-level grants to wildcard-host or anonymous accounts
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
  AND (GRANTEE LIKE "''@%"
    OR GRANTEE LIKE "%'@'%'")
ORDER BY GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Accounts with ALL PRIVILEGES on all databases (dangerous broad grants)
-- GRANT ALL PRIVILEGES ON *.* TO user@host
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES'
ORDER BY GRANTEE;

-- ---------------------------------------------------------------------------
-- Accounts with ALL PRIVILEGES on a specific database
-- GRANT ALL PRIVILEGES ON db.* TO user@host
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY GRANTEE, TABLE_SCHEMA;

-- ---------------------------------------------------------------------------
-- Grants with GRANT OPTION (allow re-granting privileges to others)
-- These can be used for privilege escalation.
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    TABLE_NAME,
    PRIVILEGE_TYPE
FROM information_schema.TABLE_PRIVILEGES
WHERE IS_GRANTABLE = 'YES'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY GRANTEE, TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Column-level grants (granular — check if overly broad)
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
ORDER BY GRANTEE, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME;

-- ---------------------------------------------------------------------------
-- Summary: exposure surface
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM mysql.user WHERE User = '')              AS anonymous_accounts,
    (SELECT COUNT(*) FROM mysql.user WHERE Host = '%' AND User != '') AS wildcard_host_accounts,
    (SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES
     WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES')                      AS all_priv_global,
    (SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES
     WHERE PRIVILEGE_TYPE = 'ALL PRIVILEGES'
       AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys'))      AS all_priv_schema,
    (SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES
     WHERE IS_GRANTABLE = 'YES'
       AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys'))      AS grantable_table_grants;
