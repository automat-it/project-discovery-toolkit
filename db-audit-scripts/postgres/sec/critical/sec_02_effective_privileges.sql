-- =============================================================================
-- sec_02_effective_privileges.sql
-- Priority: CRITICAL
-- Purpose: Map who actually has access to what — through direct grants and
--          group membership inheritance. Find over-privileged users.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database-level privileges
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
  AND (has_schema_privilege(r.rolname, n.nspname, 'USAGE')
       OR has_schema_privilege(r.rolname, n.nspname, 'CREATE'))
ORDER BY n.nspname, r.rolname;

-- ---------------------------------------------------------------------------
-- DIRECT table-level grants (information_schema.role_table_grants).
-- This shows ONLY explicit GRANT statements per grantee — it does NOT
-- expand role inheritance. A login user may have additional access via
-- group memberships not visible here. For full effective access by login
-- user, see the per-user table access count block at the bottom of this
-- file (which uses has_table_privilege and respects inheritance).
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
ORDER BY table_schema, table_name, grantee;

-- ---------------------------------------------------------------------------
-- Column-level privileges (rare — usually a sign of fine-grained design)
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
ORDER BY table_schema, table_name, column_name, grantee;

-- ---------------------------------------------------------------------------
-- Function / procedure execute privileges
-- ---------------------------------------------------------------------------
SELECT
    grantee,
    routine_schema                                       AS schema,
    routine_name                                         AS routine,
    routine_type,
    privilege_type,
    is_grantable
FROM information_schema.routine_privileges
WHERE routine_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY routine_schema, routine_name, grantee;

-- ---------------------------------------------------------------------------
-- Sequence privileges
-- ---------------------------------------------------------------------------
SELECT
    grantee,
    object_schema                                        AS schema,
    object_name                                          AS sequence,
    privilege_type
FROM information_schema.usage_privileges
WHERE object_type = 'SEQUENCE'
  AND object_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY object_schema, object_name, grantee;

-- ---------------------------------------------------------------------------
-- Per-user effective table access count (over-privileged user detector)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS user,
    count(*) FILTER (
        WHERE has_table_privilege(r.rolname, c.oid, 'SELECT')
    )                                                    AS readable_tables,
    count(*) FILTER (
        WHERE has_table_privilege(r.rolname, c.oid, 'INSERT')
    )                                                    AS writable_tables,
    count(*) FILTER (
        WHERE has_table_privilege(r.rolname, c.oid, 'UPDATE')
    )                                                    AS updatable_tables,
    count(*) FILTER (
        WHERE has_table_privilege(r.rolname, c.oid, 'DELETE')
    )                                                    AS deletable_tables,
    count(*) FILTER (
        WHERE has_table_privilege(r.rolname, c.oid, 'TRUNCATE')
    )                                                    AS truncatable_tables
FROM pg_roles r
CROSS JOIN pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE r.rolcanlogin
  AND NOT r.rolsuper
  AND c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
GROUP BY r.rolname
ORDER BY readable_tables + writable_tables DESC;

-- ---------------------------------------------------------------------------
-- EFFECTIVE per-table access by login user (full inheritance expansion).
-- For each login role and each user table, this lists exactly which
-- privileges the role effectively has — including those granted via group
-- membership chains. This is the authoritative effective-access view.
--
-- Warning: cardinality is (login_users × user_tables × 6 privileges).
-- On very large schemas this may be slow. Restrict via WHERE if needed.
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS user,
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    array_remove(ARRAY[
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'SELECT')     THEN 'SELECT'     END,
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'INSERT')     THEN 'INSERT'     END,
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'UPDATE')     THEN 'UPDATE'     END,
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'DELETE')     THEN 'DELETE'     END,
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'TRUNCATE')   THEN 'TRUNCATE'   END,
        CASE WHEN has_table_privilege(r.rolname, c.oid, 'REFERENCES') THEN 'REFERENCES' END
    ], NULL)                                             AS effective_privileges
FROM pg_roles r
CROSS JOIN pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE r.rolcanlogin
  AND NOT r.rolsuper
  AND c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND has_table_privilege(r.rolname, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES')
ORDER BY r.rolname, n.nspname, c.relname;
