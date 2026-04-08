-- =============================================================================
-- sec_04_public_and_excessive_grants.sql
-- Priority: CRITICAL
-- Purpose: Find privileges granted to PUBLIC or to overly broad roles.
--          PUBLIC means "everyone who can connect" — a classic security hole.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Databases granted to PUBLIC
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    has_database_privilege('public', datname, 'CONNECT') AS public_connect,
    has_database_privilege('public', datname, 'CREATE')  AS public_create,
    has_database_privilege('public', datname, 'TEMP')    AS public_temp
FROM pg_database
WHERE NOT datistemplate
ORDER BY datname;

-- ---------------------------------------------------------------------------
-- Schemas granted to PUBLIC
-- (Pre-PG15: public schema is granted CREATE+USAGE to PUBLIC by default)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    pg_get_userbyid(n.nspowner)                          AS owner,
    has_schema_privilege('public', n.nspname, 'USAGE')   AS public_usage,
    has_schema_privilege('public', n.nspname, 'CREATE')  AS public_create
FROM pg_namespace n
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
  AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
  AND (has_schema_privilege('public', n.nspname, 'USAGE')
       OR has_schema_privilege('public', n.nspname, 'CREATE'))
ORDER BY n.nspname;

-- ---------------------------------------------------------------------------
-- Tables with privileges granted to PUBLIC
-- ---------------------------------------------------------------------------
SELECT
    table_schema                                         AS schema,
    table_name                                           AS table,
    string_agg(privilege_type, ', ' ORDER BY privilege_type)
                                                         AS privileges
FROM information_schema.role_table_grants
WHERE grantee = 'PUBLIC'
  AND table_schema NOT IN ('pg_catalog', 'information_schema')
GROUP BY table_schema, table_name
ORDER BY table_schema, table_name;

-- ---------------------------------------------------------------------------
-- Functions / procedures with EXECUTE granted to PUBLIC
-- (PostgreSQL grants EXECUTE to PUBLIC by default — verify each is intended)
-- ---------------------------------------------------------------------------
SELECT
    routine_schema                                       AS schema,
    routine_name                                         AS routine,
    routine_type
FROM information_schema.routine_privileges
WHERE grantee = 'PUBLIC'
  AND privilege_type = 'EXECUTE'
  AND routine_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY routine_schema, routine_name;

-- ---------------------------------------------------------------------------
-- Sequences with privileges to PUBLIC
-- ---------------------------------------------------------------------------
SELECT
    object_schema                                        AS schema,
    object_name                                          AS sequence,
    privilege_type
FROM information_schema.usage_privileges
WHERE grantee = 'PUBLIC'
  AND object_type = 'SEQUENCE'
  AND object_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY object_schema, object_name;

-- ---------------------------------------------------------------------------
-- Default privileges that grant to PUBLIC
-- (These apply to FUTURE objects — silent over-privileging)
-- ---------------------------------------------------------------------------
SELECT
    pg_get_userbyid(d.defaclrole)                        AS owner,
    n.nspname                                            AS schema,
    CASE d.defaclobjtype
        WHEN 'r' THEN 'table'
        WHEN 'S' THEN 'sequence'
        WHEN 'f' THEN 'function'
        WHEN 'T' THEN 'type'
        WHEN 'n' THEN 'schema'
    END                                                  AS object_type,
    d.defaclacl                                          AS default_acl
FROM pg_default_acl d
LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
WHERE array_to_string(d.defaclacl::text[], ' ') LIKE '%=%'
  AND array_to_string(d.defaclacl::text[], ' ') ~ '(^|[^a-z])=[^/]*'
ORDER BY owner, schema;

-- ---------------------------------------------------------------------------
-- Grant counts to PUBLIC across the cluster
-- ---------------------------------------------------------------------------
SELECT
    'tables'    AS object_type,
    count(*)    AS public_grants
FROM information_schema.role_table_grants
WHERE grantee = 'PUBLIC'
  AND table_schema NOT IN ('pg_catalog', 'information_schema')
UNION ALL
SELECT
    'routines',
    count(*)
FROM information_schema.routine_privileges
WHERE grantee = 'PUBLIC'
  AND routine_schema NOT IN ('pg_catalog', 'information_schema')
UNION ALL
SELECT
    'sequences',
    count(*)
FROM information_schema.usage_privileges
WHERE grantee = 'PUBLIC'
  AND object_type = 'SEQUENCE'
  AND object_schema NOT IN ('pg_catalog', 'information_schema');
