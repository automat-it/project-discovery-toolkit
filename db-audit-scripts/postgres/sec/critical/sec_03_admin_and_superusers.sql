-- =============================================================================
-- sec_03_admin_and_superusers.sql
-- Priority: CRITICAL
-- Purpose: List all admin-level accounts. These represent the highest
--          compromise risk.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Direct superusers
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin                                          AS can_login,
    rolinherit                                           AS inherits,
    rolvaliduntil                                        AS valid_until,
    rolconnlimit                                         AS conn_limit
FROM pg_roles
WHERE rolsuper
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Effective superusers (direct OR via group membership chain)
-- ---------------------------------------------------------------------------
WITH RECURSIVE role_chain AS (
    SELECT oid, rolname, rolsuper, rolname::text AS path
    FROM pg_roles
    WHERE rolsuper
    UNION
    SELECT r.oid, r.rolname, r.rolsuper, rc.path || ' <- ' || r.rolname
    FROM pg_roles r
    JOIN pg_auth_members am ON am.member = r.oid
    JOIN role_chain rc ON rc.oid = am.roleid
)
SELECT DISTINCT
    rolname                                              AS effective_superuser,
    path                                                 AS inheritance_path
FROM role_chain
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Roles with CREATEROLE (can create / alter / drop other roles)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper,
    rolcreatedb,
    rolvaliduntil
FROM pg_roles
WHERE rolcreaterole
  AND NOT rolsuper
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Roles with CREATEDB
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper
FROM pg_roles
WHERE rolcreatedb
  AND NOT rolsuper
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Roles with REPLICATION (can read all data via streaming replication)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper
FROM pg_roles
WHERE rolreplication
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Roles with BYPASSRLS (skip Row Level Security policies)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper
FROM pg_roles
WHERE rolbypassrls
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Members of high-privilege built-in roles
-- ---------------------------------------------------------------------------
SELECT
    g.rolname                                            AS privileged_role,
    r.rolname                                            AS member,
    r.rolcanlogin,
    am.admin_option
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles r ON r.oid = am.member
WHERE g.rolname IN (
    'pg_read_all_data',
    'pg_write_all_data',
    'pg_execute_server_program',
    'pg_read_server_files',
    'pg_write_server_files',
    'pg_signal_backend',
    'pg_checkpoint',
    'rds_superuser'
)
ORDER BY g.rolname, r.rolname;

-- ---------------------------------------------------------------------------
-- Owners of the public schema and built-in extensions
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    pg_get_userbyid(n.nspowner)                          AS owner
FROM pg_namespace n
WHERE n.nspname IN ('public', 'pg_catalog', 'information_schema')
ORDER BY n.nspname;

-- ---------------------------------------------------------------------------
-- Total admin surface area
-- ---------------------------------------------------------------------------
SELECT
    count(*) FILTER (WHERE rolsuper)         AS superusers,
    count(*) FILTER (WHERE rolcreaterole)    AS create_role,
    count(*) FILTER (WHERE rolcreatedb)      AS create_db,
    count(*) FILTER (WHERE rolreplication)   AS replication,
    count(*) FILTER (WHERE rolbypassrls)     AS bypass_rls
FROM pg_roles;
