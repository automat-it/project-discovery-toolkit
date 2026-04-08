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
  AND (
        has_schema_privilege('public', n.nspname, 'USAGE')
        OR has_schema_privilege('public', n.nspname, 'CREATE')
      )
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
-- Routines with privileges granted to PUBLIC
-- routine_type comes from information_schema.routines, not routine_privileges
-- ---------------------------------------------------------------------------
SELECT
    rp.routine_schema                                    AS schema,
    rp.routine_name                                      AS routine,
    r.routine_type,
    string_agg(rp.privilege_type, ', ' ORDER BY rp.privilege_type)
                                                         AS privileges,
    bool_or(rp.is_grantable = 'YES')                     AS with_grant_option
FROM information_schema.routine_privileges rp
LEFT JOIN information_schema.routines r
  ON r.specific_schema = rp.specific_schema
 AND r.specific_name   = rp.specific_name
WHERE rp.grantee = 'PUBLIC'
  AND rp.routine_schema NOT IN ('pg_catalog', 'information_schema')
GROUP BY rp.routine_schema, rp.routine_name, r.routine_type
ORDER BY rp.routine_schema, rp.routine_name;

-- ---------------------------------------------------------------------------
-- Sequences with privileges granted to PUBLIC
-- ---------------------------------------------------------------------------
SELECT
    object_schema                                        AS schema,
    object_name                                          AS sequence,
    string_agg(privilege_type, ', ' ORDER BY privilege_type)
                                                         AS privileges
FROM information_schema.usage_privileges
WHERE grantee = 'PUBLIC'
  AND object_type = 'SEQUENCE'
  AND object_schema NOT IN ('pg_catalog', 'information_schema')
GROUP BY object_schema, object_name
ORDER BY object_schema, object_name;

-- ---------------------------------------------------------------------------
-- Columns with privileges granted to PUBLIC
-- Usually rare, but still worth checking explicitly
-- ---------------------------------------------------------------------------
SELECT
    table_schema                                         AS schema,
    table_name                                           AS table,
    column_name                                          AS column,
    privilege_type,
    is_grantable
FROM information_schema.column_privileges
WHERE grantee = 'PUBLIC'
  AND table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_name, column_name, privilege_type;

-- ---------------------------------------------------------------------------
-- Default privileges that grant access to PUBLIC for future TABLES
-- ---------------------------------------------------------------------------
SELECT
    pg_get_userbyid(d.defaclrole)                        AS owner,
    n.nspname                                            AS schema,
    d.defaclobjtype                                      AS object_type,
    d.defaclacl::text                                    AS acl
FROM pg_default_acl d
LEFT JOIN pg_namespace n
  ON n.oid = d.defaclnamespace
WHERE d.defaclacl::text ILIKE '%=r/%'
   OR d.defaclacl::text ILIKE '%=arwdDxt/%'
   OR d.defaclacl::text ILIKE '%=X/%'
ORDER BY owner, schema, object_type;

-- ---------------------------------------------------------------------------
-- Effective PUBLIC privileges on schemas and DBs summarized
-- ---------------------------------------------------------------------------
SELECT
    (SELECT count(*)
     FROM pg_database
     WHERE NOT datistemplate
       AND has_database_privilege('public', datname, 'CONNECT'))        AS public_connect_dbs,
    (SELECT count(*)
     FROM pg_database
     WHERE NOT datistemplate
       AND has_database_privilege('public', datname, 'CREATE'))         AS public_create_dbs,
    (SELECT count(*)
     FROM pg_namespace n
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
       AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
       AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
       AND has_schema_privilege('public', n.nspname, 'USAGE'))         AS public_usage_schemas,
    (SELECT count(*)
     FROM pg_namespace n
     WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
       AND n.nspname NOT LIKE 'pg\_temp\_%' ESCAPE '\'
       AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ESCAPE '\'
       AND has_schema_privilege('public', n.nspname, 'CREATE'))        AS public_create_schemas;

-- ---------------------------------------------------------------------------
-- Built-in broad roles: members of predefined high-visibility roles
-- These are not PUBLIC, but often represent broad access and are useful
-- in the same review.
-- ---------------------------------------------------------------------------
SELECT
    g.rolname                                            AS broad_role,
    r.rolname                                            AS member,
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
-- Summary: object grants to PUBLIC
-- ---------------------------------------------------------------------------
SELECT
    (SELECT count(*)
     FROM (
         SELECT 1
         FROM information_schema.role_table_grants
         WHERE grantee = 'PUBLIC'
           AND table_schema NOT IN ('pg_catalog', 'information_schema')
         GROUP BY table_schema, table_name
     ) t)                                                 AS public_tables,
    (SELECT count(*)
     FROM (
         SELECT 1
         FROM information_schema.routine_privileges rp
         WHERE rp.grantee = 'PUBLIC'
           AND rp.routine_schema NOT IN ('pg_catalog', 'information_schema')
         GROUP BY rp.routine_schema, rp.routine_name
     ) r)                                                 AS public_routines,
    (SELECT count(*)
     FROM (
         SELECT 1
         FROM information_schema.usage_privileges
         WHERE grantee = 'PUBLIC'
           AND object_type = 'SEQUENCE'
           AND object_schema NOT IN ('pg_catalog', 'information_schema')
         GROUP BY object_schema, object_name
     ) s)                                                 AS public_sequences,
    (SELECT count(*)
     FROM (
         SELECT 1
         FROM information_schema.column_privileges
         WHERE grantee = 'PUBLIC'
           AND table_schema NOT IN ('pg_catalog', 'information_schema')
         GROUP BY table_schema, table_name, column_name
     ) c)                                                 AS public_columns;