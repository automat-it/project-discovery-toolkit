-- =============================================================================
-- sec_02_effective_privileges.sql
-- Priority: CRITICAL
-- Purpose: Map who actually has access to what — through direct grants and
--          group membership inheritance. Find over-privileged users.
-- Read-only.
--
-- Notes:
--   * Direct GRANT views from information_schema show explicit grants only.
--   * Effective privilege checks using has_*_privilege() respect inheritance.
--   * This script avoids non-portable columns and alias-ordering issues.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database-level privileges (effective)
-- ---------------------------------------------------------------------------
SELECT
    d.datname                                            AS database,
    r.rolname                                            AS grantee,
    has_database_privilege(r.rolname, d.datname, 'CONNECT') AS can_connect,
    has_database_privilege(r.rolname, d.datname, 'CREATE')  AS can_create,
    has_database_privilege(r.rolname, d.datname, 'TEMP')    AS can_temp
FROM pg_database d
CROSS JOIN pg_roles r
WHERE NOT d.datistemplate
  AND r.rolcanlogin
  AND has_database_privilege(r.rolname, d.datname, 'CONNECT')
ORDER BY d.datname, r.rolname;

-- ---------------------------------------------------------------------------
-- Schema-level privileges (effective)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    r.rolname                                            AS grantee,
    has_schema_privilege(r.rolname, n.nspname, 'USAGE')  AS usage,
    has_schema_privilege(r.rolname, n.nspname, 'CREATE') AS create
FROM pg_namespace n
CROSS JOIN pg_roles r
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
  AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
  AND r.rolcanlogin
  AND (
        has_schema_privilege(r.rolname, n.nspname, 'USAGE')
        OR has_schema_privilege(r.rolname, n.nspname, 'CREATE')
      )
ORDER BY n.nspname, r.rolname;

-- ---------------------------------------------------------------------------
-- DIRECT table-level grants
-- Explicit GRANTs only, not inherited through role membership.
-- ---------------------------------------------------------------------------
SELECT
    grantee,
    table_schema                                         AS schema,
    table_name                                           AS table,
    string_agg(privilege_type, ', ' ORDER BY privilege_type)
                                                         AS privileges,
    bool_or(is_grantable = 'YES')                        AS with_grant_option
FROM information_schema.role_table_grants
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
GROUP BY grantee, table_schema, table_name
ORDER BY grantee, table_schema, table_name;

-- ---------------------------------------------------------------------------
-- DIRECT column-level grants
-- ---------------------------------------------------------------------------
SELECT
    grantee,
    table_schema                                         AS schema,
    table_name                                           AS table,
    column_name                                          AS column,
    privilege_type                                       AS privilege,
    is_grantable
FROM information_schema.column_privileges
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY grantee, table_schema, table_name, column_name, privilege_type;

-- ---------------------------------------------------------------------------
-- DIRECT routine-level grants
-- routine_type is taken from information_schema.routines
-- ---------------------------------------------------------------------------
SELECT
    rp.grantee,
    rp.routine_schema                                    AS schema,
    rp.routine_name                                      AS routine,
    coalesce(r.routine_type, 'UNKNOWN')                  AS routine_type,
    rp.privilege_type,
    rp.is_grantable
FROM information_schema.routine_privileges rp
LEFT JOIN information_schema.routines r
  ON r.specific_schema = rp.specific_schema
 AND r.specific_name   = rp.specific_name
WHERE rp.routine_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY rp.grantee, rp.routine_schema, rp.routine_name, rp.privilege_type;

-- ---------------------------------------------------------------------------
-- DIRECT sequence privileges
-- ---------------------------------------------------------------------------
SELECT
    grantee,
    object_schema                                        AS schema,
    object_name                                          AS sequence,
    privilege_type
FROM information_schema.usage_privileges
WHERE object_type = 'SEQUENCE'
  AND object_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY grantee, object_schema, object_name, privilege_type;

-- ---------------------------------------------------------------------------
-- Object owners (tables/views/materialized views/sequences/foreign tables)
-- Ownership implies broad control over the object.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS object_name,
    CASE c.relkind
        WHEN 'r' THEN 'table'
        WHEN 'p' THEN 'partitioned table'
        WHEN 'v' THEN 'view'
        WHEN 'm' THEN 'materialized view'
        WHEN 'S' THEN 'sequence'
        WHEN 'f' THEN 'foreign table'
        ELSE c.relkind::text
    END                                                  AS object_type,
    pg_get_userbyid(c.relowner)                          AS owner
FROM pg_class c
JOIN pg_namespace n
  ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Effective table access counts per login user
-- Uses has_table_privilege(), so inherited role memberships are respected.
-- ---------------------------------------------------------------------------
WITH user_table_access AS (
    SELECT
        r.rolname                                        AS grantee,
        n.nspname                                        AS schema,
        c.relname                                        AS table_name,
        has_table_privilege(r.rolname, c.oid, 'SELECT')  AS can_select,
        has_table_privilege(r.rolname, c.oid, 'INSERT')  AS can_insert,
        has_table_privilege(r.rolname, c.oid, 'UPDATE')  AS can_update,
        has_table_privilege(r.rolname, c.oid, 'DELETE')  AS can_delete
    FROM pg_roles r
    CROSS JOIN pg_class c
    JOIN pg_namespace n
      ON n.oid = c.relnamespace
    WHERE r.rolcanlogin
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
      AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
),
rollup AS (
    SELECT
        grantee,
        count(*) FILTER (WHERE can_select)               AS readable_tables,
        count(*) FILTER (WHERE can_insert OR can_update OR can_delete)
                                                         AS writable_tables,
        count(*) FILTER (WHERE can_select OR can_insert OR can_update OR can_delete)
                                                         AS any_access_tables
    FROM user_table_access
    GROUP BY grantee
)
SELECT
    grantee,
    readable_tables,
    writable_tables,
    any_access_tables
FROM rollup
ORDER BY (readable_tables + writable_tables) DESC, grantee;

-- ---------------------------------------------------------------------------
-- Effective routine EXECUTE counts per login user
-- ---------------------------------------------------------------------------
WITH user_routine_access AS (
    SELECT
        r.rolname                                        AS grantee,
        n.nspname                                        AS schema,
        p.proname                                        AS routine,
        has_function_privilege(r.rolname, p.oid, 'EXECUTE') AS can_execute
    FROM pg_roles r
    CROSS JOIN pg_proc p
    JOIN pg_namespace n
      ON n.oid = p.pronamespace
    WHERE r.rolcanlogin
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
),
routine_rollup AS (
    SELECT
        grantee,
        count(*) FILTER (WHERE can_execute)              AS executable_routines
    FROM user_routine_access
    GROUP BY grantee
)
SELECT
    grantee,
    executable_routines
FROM routine_rollup
WHERE executable_routines > 0
ORDER BY executable_routines DESC, grantee;

-- ---------------------------------------------------------------------------
-- Effective access to schemas by login user
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS grantee,
    count(*) FILTER (
        WHERE has_schema_privilege(r.rolname, n.nspname, 'USAGE')
    )                                                    AS usable_schemas,
    count(*) FILTER (
        WHERE has_schema_privilege(r.rolname, n.nspname, 'CREATE')
    )                                                    AS creatable_schemas
FROM pg_roles r
CROSS JOIN pg_namespace n
WHERE r.rolcanlogin
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
  AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
GROUP BY r.rolname
ORDER BY creatable_schemas DESC, usable_schemas DESC, r.rolname;

-- ---------------------------------------------------------------------------
-- Login users with broad built-in privileged role memberships
-- ---------------------------------------------------------------------------
SELECT
    g.rolname                                            AS privileged_role,
    r.rolname                                            AS member,
    r.rolcanlogin,
    am.admin_option
FROM pg_auth_members am
JOIN pg_roles g
  ON g.oid = am.roleid
JOIN pg_roles r
  ON r.oid = am.member
WHERE g.rolname IN (
    'pg_read_all_data',
    'pg_write_all_data',
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_monitor',
    'pg_signal_backend',
    'pg_execute_server_program',
    'pg_read_server_files',
    'pg_write_server_files'
)
ORDER BY g.rolname, r.rolname;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM pg_roles WHERE rolcanlogin)    AS login_roles,
    (SELECT count(*) FROM (
        SELECT 1
        FROM information_schema.role_table_grants
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
        GROUP BY grantee, table_schema, table_name
    ) t)                                                 AS direct_table_grant_rows,
    (SELECT count(*) FROM (
        SELECT 1
        FROM information_schema.routine_privileges
        WHERE routine_schema NOT IN ('pg_catalog', 'information_schema')
        GROUP BY grantee, routine_schema, routine_name
    ) r)                                                 AS direct_routine_grant_rows,
    (SELECT count(*) FROM (
        SELECT 1
        FROM information_schema.column_privileges
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
        GROUP BY grantee, table_schema, table_name, column_name
    ) c)                                                 AS direct_column_grant_rows;