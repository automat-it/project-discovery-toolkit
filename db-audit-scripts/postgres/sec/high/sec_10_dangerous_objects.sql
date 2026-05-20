-- =============================================================================
-- sec_10_dangerous_objects.sql
-- Priority: HIGH
-- Purpose: Find code paths that could enable privilege escalation:
--          SECURITY DEFINER functions, untrusted languages, event triggers,
--          superuser-owned objects with broad EXECUTE.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER functions (execute with owner's privileges)
-- These bypass normal RBAC and require careful review.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS function,
    pg_get_userbyid(p.proowner)                          AS owner,
    l.lanname                                            AS language,
    p.prosecdef                                          AS security_definer,
    p.proconfig                                          AS config_overrides,
    array_to_string(p.proacl::text[], ', ')              AS acl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l  ON l.oid = p.prolang
WHERE p.prosecdef
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER functions owned by superusers (highest risk)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS function,
    pg_get_userbyid(p.proowner)                          AS owner,
    l.lanname                                            AS language,
    has_function_privilege('public', p.oid, 'EXECUTE')   AS executable_by_public
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l  ON l.oid = p.prolang
JOIN pg_roles r     ON r.oid = p.proowner
WHERE p.prosecdef
  AND r.rolsuper
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- Functions written in untrusted procedural languages (plperlu, plpythonu,
-- pltclu, c). These can execute arbitrary OS commands and read/write files
-- as the postgres OS user — they are the highest privilege escalation risk.
--
-- The "internal" language is intentionally NOT in this list: it refers to
-- functions implemented in the PostgreSQL backend itself (built-ins). Those
-- are not user-supplied code and are tracked separately below.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS function,
    pg_get_userbyid(p.proowner)                          AS owner,
    l.lanname                                            AS language
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l  ON l.oid = p.prolang
WHERE l.lanname IN ('plperlu', 'plpythonu', 'plpython3u', 'pltclu', 'c')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY l.lanname, n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- Informational: user-defined functions implemented in language 'internal'
-- (i.e. wrappers over built-in C functions). These should be extremely
-- rare in user schemas and warrant a manual look if any appear.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS function,
    pg_get_userbyid(p.proowner)                          AS owner
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l  ON l.oid = p.prolang
WHERE l.lanname = 'internal'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- All installed procedural languages
-- ---------------------------------------------------------------------------
SELECT
    lanname                                              AS language,
    lanpltrusted                                         AS trusted,
    pg_get_userbyid(lanowner)                            AS owner,
    lanacl                                               AS acl
FROM pg_language
ORDER BY lanpltrusted, lanname;

-- ---------------------------------------------------------------------------
-- Event triggers (run on DDL events — can intercept all schema changes)
-- ---------------------------------------------------------------------------
SELECT
    evtname                                              AS trigger_name,
    evtevent                                             AS event,
    pg_get_userbyid(evtowner)                            AS owner,
    evtenabled                                           AS state,
    evttags                                              AS tags
FROM pg_event_trigger
ORDER BY evtname;

-- ---------------------------------------------------------------------------
-- Regular triggers owned by superusers on user tables
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    t.tgname                                             AS trigger,
    pg_get_userbyid(c.relowner)                          AS table_owner,
    t.tgenabled                                          AS state
FROM pg_trigger t
JOIN pg_class c     ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r     ON r.oid = c.relowner
WHERE NOT t.tgisinternal
  AND r.rolsuper
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname, t.tgname;

-- ---------------------------------------------------------------------------
-- Foreign Data Wrappers (network egress points)
-- ---------------------------------------------------------------------------
SELECT
    fdw.fdwname                                          AS fdw,
    pg_get_userbyid(fdw.fdwowner)                        AS owner,
    fdw.fdwacl                                           AS acl,
    fdw.fdwoptions                                       AS options
FROM pg_foreign_data_wrapper fdw;

-- ---------------------------------------------------------------------------
-- Foreign servers and their connection info
-- ---------------------------------------------------------------------------
SELECT
    s.srvname                                            AS server,
    fdw.fdwname                                          AS fdw,
    pg_get_userbyid(s.srvowner)                          AS owner,
    s.srvacl                                             AS acl,
    s.srvoptions                                         AS options
FROM pg_foreign_server s
JOIN pg_foreign_data_wrapper fdw ON fdw.oid = s.srvfdw;

-- ---------------------------------------------------------------------------
-- User mappings to foreign servers (potential credential leak)
-- We query pg_user_mappings (the view) rather than pg_user_mapping (the
-- table). The view is granted to the public role -- the table requires
-- server ownership or membership in pg_read_server_files. The view also
-- automatically masks umoptions to NULL when the caller can't see them.
-- ---------------------------------------------------------------------------
SELECT
    COALESCE(um.usename, 'PUBLIC')                       AS local_user,
    um.srvname                                           AS foreign_server,
    um.umoptions                                         AS options
FROM pg_user_mappings um;

-- ---------------------------------------------------------------------------
-- Functions executable by PUBLIC and owned by superusers (escalation risk)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS function,
    pg_get_userbyid(p.proowner)                          AS owner,
    p.prosecdef                                          AS security_definer,
    l.lanname                                            AS language
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l  ON l.oid = p.prolang
JOIN pg_roles r     ON r.oid = p.proowner
WHERE r.rolsuper
  AND has_function_privilege('public', p.oid, 'EXECUTE')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND p.prosecdef
ORDER BY n.nspname, p.proname;
