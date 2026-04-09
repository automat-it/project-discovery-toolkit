-- =============================================================================
-- sec_03_admin_and_superusers.sql
-- Priority: CRITICAL
-- Purpose: List all admin-level accounts. These represent the highest
--          compromise risk.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have a single "superuser" flag. Superuser-equivalent
--       access in MySQL 8.0 is expressed through:
--         - Super_priv = 'Y' (legacy SUPER privilege)
--         - SYSTEM_USER dynamic privilege (true admin)
--         - SUPER or SYSTEM_VARIABLES_ADMIN for SET GLOBAL
--       BYPASSRLS does not exist in MySQL (no row-level security at the
--       SQL privilege layer — RLS must be implemented via views or stored procedures).
--       CREATEROLE equivalent is CREATE ROLE and CREATE USER privileges.
--       CREATEDB equivalent is the CREATE privilege at the global level.

-- ---------------------------------------------------------------------------
-- Accounts with SUPER privilege (legacy superuser)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    password_expired,
    max_connections,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE Super_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with CREATE USER privilege (can create / alter / drop users)
-- Equivalent to PostgreSQL CREATEROLE
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv                                              AS has_super,
    password_expired
FROM mysql.user
WHERE Create_user_priv = 'Y'
  AND Super_priv = 'N'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with GRANT OPTION at the global level
-- (can re-grant their own privileges — privilege escalation vector)
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.USER_PRIVILEGES
WHERE IS_GRANTABLE = 'YES'
ORDER BY GRANTEE, PRIVILEGE_TYPE;

-- ---------------------------------------------------------------------------
-- Accounts with REPLICATION SLAVE privilege
-- (can read all binary log data — equivalent to PostgreSQL REPLICATION)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv                                              AS has_super,
    password_expired
FROM mysql.user
WHERE Repl_slave_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with REPLICATION CLIENT privilege
-- (can check replication status)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked
FROM mysql.user
WHERE Repl_client_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Dynamic privilege assignments (MySQL 8.0+)
-- Includes SYSTEM_USER, BINLOG_ADMIN, REPLICATION_SLAVE_ADMIN, etc.
-- These are the modern equivalent of the legacy global privileges.
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    PRIV                                                    AS dynamic_privilege,
    WITH_GRANT_OPTION
FROM mysql.global_grants
ORDER BY USER, HOST, PRIV;

-- ---------------------------------------------------------------------------
-- Accounts with SYSTEM_USER dynamic privilege (true MySQL 8.0+ admin)
-- SYSTEM_USER cannot be killed or modified by non-SYSTEM_USER accounts.
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    WITH_GRANT_OPTION
FROM mysql.global_grants
WHERE PRIV = 'SYSTEM_USER'
ORDER BY USER, HOST;

-- ---------------------------------------------------------------------------
-- Members of high-privilege roles (MySQL 8.0+ roles)
-- ---------------------------------------------------------------------------
SELECT
    re.FROM_USER                                            AS privileged_role,
    re.FROM_HOST,
    re.TO_USER                                              AS member,
    re.TO_HOST,
    re.WITH_ADMIN_OPTION
FROM mysql.role_edges re
JOIN mysql.user role_u
  ON  role_u.User = re.FROM_USER
  AND role_u.Host = re.FROM_HOST
WHERE role_u.Super_priv = 'Y'
   OR role_u.Create_user_priv = 'Y'
   OR role_u.Grant_priv = 'Y'
ORDER BY re.FROM_USER, re.TO_USER;

-- ---------------------------------------------------------------------------
-- Owners of built-in system schemas (mysql, performance_schema)
-- NOTE: MySQL system schema access is controlled via privileges, not ownership.
--       List accounts with ALL PRIVILEGES or SELECT on the mysql schema.
-- ---------------------------------------------------------------------------
SELECT
    GRANTEE,
    TABLE_SCHEMA,
    PRIVILEGE_TYPE,
    IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
WHERE TABLE_SCHEMA IN ('mysql', 'performance_schema', 'information_schema')
ORDER BY TABLE_SCHEMA, GRANTEE;

-- ---------------------------------------------------------------------------
-- Total admin surface area
-- ---------------------------------------------------------------------------
SELECT
    SUM(CASE WHEN Super_priv = 'Y' THEN 1 ELSE 0 END)          AS super_accounts,
    SUM(CASE WHEN Grant_priv = 'Y' THEN 1 ELSE 0 END)          AS grant_accounts,
    SUM(CASE WHEN Create_user_priv = 'Y' THEN 1 ELSE 0 END)     AS create_user_accounts,
    SUM(CASE WHEN Repl_slave_priv = 'Y' THEN 1 ELSE 0 END)      AS replication_accounts,
    SUM(CASE WHEN Create_priv = 'Y' THEN 1 ELSE 0 END)          AS create_db_accounts
FROM mysql.user;
