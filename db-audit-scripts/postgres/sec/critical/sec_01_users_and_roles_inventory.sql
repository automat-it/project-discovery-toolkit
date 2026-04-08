-- =============================================================================
-- sec_01_users_and_roles_inventory.sql
-- Priority: CRITICAL
-- Purpose: Complete inventory of all roles (users and groups) with their
--          attributes. The foundation for all security analysis.
--
-- Privileges:
--   * Most queries below work with default privileges of any login role.
--   * The "password_state" column reads pg_authid.rolpassword which
--     requires superuser / rds_superuser / pg_read_server_files. On a
--     non-privileged role the pg_authid block returns "permission denied"
--     and is automatically skipped via the version/permission guard below.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- All roles with full attribute set (no password info — works for everyone)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolsuper                                             AS is_superuser,
    rolinherit                                           AS inherits,
    rolcreaterole                                        AS can_create_role,
    rolcreatedb                                          AS can_create_db,
    rolcanlogin                                          AS can_login,
    rolreplication                                       AS replication,
    rolbypassrls                                         AS bypass_rls,
    rolconnlimit                                         AS conn_limit,
    rolvaliduntil                                        AS valid_until
FROM pg_roles
ORDER BY rolsuper DESC, rolcanlogin DESC, rolname;

-- ---------------------------------------------------------------------------
-- Password state (requires read access to pg_authid).
-- Guarded by has_table_privilege so the script does not fail for users
-- without elevated privileges.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_authid', 'SELECT') AS can_read_pg_authid
\gset
\if :can_read_pg_authid
SELECT
    rolname                                              AS role,
    CASE WHEN rolpassword IS NOT NULL THEN 'set' ELSE 'unset' END AS password_state
FROM pg_authid
ORDER BY rolname;
\else
SELECT 'pg_authid not readable by ' || current_user
       || ' — re-run as superuser / rds_superuser to see password state' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Login roles (users) only
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS user,
    rolsuper                                             AS is_superuser,
    rolcreaterole                                        AS can_create_role,
    rolcreatedb                                          AS can_create_db,
    rolreplication                                       AS replication,
    rolbypassrls                                         AS bypass_rls,
    rolconnlimit                                         AS conn_limit,
    rolvaliduntil                                        AS valid_until
FROM pg_roles
WHERE rolcanlogin
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Group roles (NOLOGIN — used for grouping privileges)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS group,
    rolinherit                                           AS inherits,
    (SELECT count(*) FROM pg_auth_members WHERE roleid = r.oid)
                                                         AS member_count
FROM pg_roles r
WHERE NOT rolcanlogin
  AND rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Built-in PostgreSQL predefined roles in use
-- ---------------------------------------------------------------------------
SELECT
    g.rolname                                            AS predefined_role,
    r.rolname                                            AS member,
    am.admin_option
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles r ON r.oid = am.member
WHERE g.rolname IN (
    'pg_read_all_data',
    'pg_write_all_data',
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_stat_scan_tables',
    'pg_monitor',
    'pg_signal_backend',
    'pg_read_server_files',
    'pg_write_server_files',
    'pg_execute_server_program',
    'pg_checkpoint'
)
ORDER BY g.rolname, r.rolname;

-- ---------------------------------------------------------------------------
-- Total counts by category
-- ---------------------------------------------------------------------------
SELECT
    count(*) FILTER (WHERE rolcanlogin)                  AS login_users,
    count(*) FILTER (WHERE NOT rolcanlogin
                       AND rolname NOT LIKE 'pg\_%' ESCAPE '\') AS group_roles,
    count(*) FILTER (WHERE rolsuper)                     AS superusers,
    count(*) FILTER (WHERE rolcreaterole)                AS can_create_role,
    count(*) FILTER (WHERE rolcreatedb)                  AS can_create_db,
    count(*) FILTER (WHERE rolreplication)               AS replication_roles,
    count(*) FILTER (WHERE rolbypassrls)                 AS bypass_rls_roles
FROM pg_roles;
