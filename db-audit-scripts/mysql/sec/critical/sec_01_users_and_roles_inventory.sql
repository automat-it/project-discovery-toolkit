-- =============================================================================
-- sec_01_users_and_roles_inventory.sql
-- Priority: CRITICAL
-- Purpose: Complete inventory of all users and roles with their attributes.
--          The foundation for all security analysis.
--
-- Privileges:
--   * All queries below require SELECT on mysql.user, which is restricted
--     to users with the SELECT privilege on the mysql schema (root, DBA).
--     On RDS/Aurora: use the rds_superuser-equivalent role.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL roles were introduced in MySQL 8.0. In earlier versions,
--       only user accounts exist. MySQL does not have BYPASSRLS, REPLICATION
--       LOGIN, or BYPASSRLS privileges as PostgreSQL attributes.
--       The closest analogs are documented below.

-- ---------------------------------------------------------------------------
-- All accounts (users + roles) with key attributes
-- ---------------------------------------------------------------------------
SELECT
    User                                                    AS account,
    Host,
    -- NOTE: account_locked = 'Y' means the account cannot log in (like NOLOGIN in PG)
    account_locked                                          AS is_locked,
    -- NOTE: There is no direct 'superuser' flag in MySQL 8.0+;
    --       superuser-equivalent = SUPER privilege or SYSTEM_USER dynamic privilege
    -- NOTE: Super_priv maps to the legacy SUPER privilege
    Super_priv                                              AS has_super,
    Grant_priv                                              AS can_grant,
    Create_user_priv                                        AS can_create_user,
    Create_priv                                             AS can_create_db,
    Repl_slave_priv                                         AS replication,
    Repl_client_priv                                        AS replication_client,
    max_connections                                         AS conn_limit,
    max_user_connections,
    -- NOTE: password_expired = 'Y' means user must change password at next login
    password_expired,
    password_lifetime,
    password_last_changed
FROM mysql.user
ORDER BY Super_priv DESC, account_locked ASC, User, Host;

-- ---------------------------------------------------------------------------
-- Password state per account
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    CASE
        WHEN authentication_string = '' OR authentication_string IS NULL
            THEN 'unset'
        WHEN plugin = 'caching_sha2_password'
            THEN 'caching_sha2_password (current)'
        WHEN plugin = 'mysql_native_password'
            THEN 'mysql_native_password (legacy)'
        WHEN plugin = 'sha256_password'
            THEN 'sha256_password (deprecated)'
        WHEN plugin = 'auth_socket' OR plugin = 'unix_socket'
            THEN 'socket (no password)'
        WHEN plugin = 'mysql_no_login'
            THEN 'no_login (locked out)'
        ELSE CONCAT('plugin: ', plugin)
    END                                                     AS password_state,
    plugin                                                  AS auth_plugin,
    password_expired,
    password_last_changed,
    password_lifetime
FROM mysql.user
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Login-capable accounts (not locked, has authentication)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    plugin                                                  AS auth_plugin,
    Super_priv                                              AS has_super,
    Grant_priv                                              AS can_grant,
    max_connections                                         AS conn_limit,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE account_locked = 'N'
  AND plugin NOT IN ('mysql_no_login')
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Roles (non-loginable accounts used for privilege grouping — MySQL 8.0+)
-- In MySQL, roles are user accounts with account_locked = 'Y' and
-- host = '%' by convention, but the system tracks them via mysql.default_roles
-- and mysql.role_edges.
-- ---------------------------------------------------------------------------
SELECT
    User                                                    AS role_name,
    Host,
    account_locked,
    plugin
FROM mysql.user
WHERE account_locked = 'Y'
  AND Host = '%'
ORDER BY User;

-- ---------------------------------------------------------------------------
-- Role membership (MySQL 8.0+)
-- Equivalent to pg_auth_members
-- ---------------------------------------------------------------------------
SELECT
    FROM_USER                                               AS role,
    FROM_HOST                                               AS role_host,
    TO_USER                                                 AS member,
    TO_HOST                                                 AS member_host,
    WITH_ADMIN_OPTION                                       AS with_admin
FROM mysql.role_edges
ORDER BY FROM_USER, TO_USER;

-- ---------------------------------------------------------------------------
-- Default roles per account (automatically activated at login)
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    DEFAULT_ROLE_USER                                       AS default_role,
    DEFAULT_ROLE_HOST
FROM mysql.default_roles
ORDER BY USER, HOST, DEFAULT_ROLE_USER;

-- ---------------------------------------------------------------------------
-- Total counts by category
-- ---------------------------------------------------------------------------
SELECT
    COUNT(*)                                                AS total_accounts,
    SUM(CASE WHEN account_locked = 'N' THEN 1 ELSE 0 END)  AS login_accounts,
    SUM(CASE WHEN account_locked = 'Y' THEN 1 ELSE 0 END)  AS locked_accounts,
    SUM(CASE WHEN Super_priv = 'Y' THEN 1 ELSE 0 END)      AS super_accounts,
    SUM(CASE WHEN Grant_priv = 'Y' THEN 1 ELSE 0 END)      AS grant_accounts,
    SUM(CASE WHEN Create_user_priv = 'Y' THEN 1 ELSE 0 END) AS create_user_accounts,
    SUM(CASE WHEN Repl_slave_priv = 'Y' THEN 1 ELSE 0 END) AS replication_accounts,
    SUM(CASE WHEN password_expired = 'Y' THEN 1 ELSE 0 END) AS expired_passwords
FROM mysql.user;
