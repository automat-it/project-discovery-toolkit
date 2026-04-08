-- =============================================================================
-- sec_15_external_integrations.sql
-- Priority: MEDIUM
-- Purpose: Audit Foreign Data Wrappers, foreign servers, user mappings,
--          and dblink usage. These are network egress points and may
--          carry credentials.
-- Read-only.
--
-- Usage:
--   Default (safe, masked only):
--     psql -X -v ON_ERROR_STOP=1 -f sec_15_external_integrations.sql
--
--   Unmasked secrets (authorized review only):
--     psql -X -v ON_ERROR_STOP=1 -v unmask_secrets=true -f sec_15_external_integrations.sql
--
-- Notes:
--   * Safe if "unmask_secrets" is not provided.
--   * Masked section always runs.
--   * Unmasked section runs only when explicitly enabled.
-- =============================================================================

\if :{?unmask_secrets}
\else
\set unmask_secrets false
\endif

-- ---------------------------------------------------------------------------
-- Installed FDW / external integration extensions
-- ---------------------------------------------------------------------------
SELECT
    extname                                              AS extension,
    extversion
FROM pg_extension
WHERE extname IN (
    'postgres_fdw',
    'file_fdw',
    'mysql_fdw',
    'oracle_fdw',
    'tds_fdw',
    'mongo_fdw',
    'redis_fdw',
    'kafka_fdw',
    's3_fdw',
    'dblink'
)
ORDER BY extname;

-- ---------------------------------------------------------------------------
-- Foreign Data Wrappers
-- ---------------------------------------------------------------------------
SELECT
    fdwname                                              AS fdw,
    pg_get_userbyid(fdwowner)                            AS owner,
    fdwhandler::regproc                                  AS handler,
    fdwvalidator::regproc                                AS validator,
    fdwacl                                               AS acl,
    fdwoptions                                           AS options
FROM pg_foreign_data_wrapper
ORDER BY fdwname;

-- ---------------------------------------------------------------------------
-- Foreign servers
-- ---------------------------------------------------------------------------
SELECT
    s.srvname                                            AS server,
    fdw.fdwname                                          AS fdw,
    pg_get_userbyid(s.srvowner)                          AS owner,
    s.srvtype                                            AS type,
    s.srvversion                                         AS version,
    s.srvacl                                             AS acl,
    s.srvoptions                                         AS options
FROM pg_foreign_server s
JOIN pg_foreign_data_wrapper fdw
  ON fdw.oid = s.srvfdw
ORDER BY s.srvname;

-- ---------------------------------------------------------------------------
-- User mappings (MASKED)
-- ---------------------------------------------------------------------------
SELECT
    CASE
        WHEN um.umuser = 0 THEN 'PUBLIC'
        ELSE pg_get_userbyid(um.umuser)
    END                                                  AS local_user,
    s.srvname                                            AS foreign_server,
    fdw.fdwname                                          AS fdw,
    COALESCE(
        (
            SELECT string_agg(
                CASE
                    WHEN opt ~* '^(password|passwd|pwd|secret|api_?key|token|auth|access_key|secret_key)='
                        THEN regexp_replace(opt, '=(.*)$', '=***MASKED***')
                    ELSE opt
                END,
                ', ' ORDER BY ord
            )
            FROM unnest(COALESCE(um.umoptions, ARRAY[]::text[])) WITH ORDINALITY AS u(opt, ord)
        ),
        ''
    )                                                    AS options_masked
FROM pg_user_mapping um
JOIN pg_foreign_server s
  ON s.oid = um.umserver
JOIN pg_foreign_data_wrapper fdw
  ON fdw.oid = s.srvfdw
ORDER BY local_user, foreign_server;

-- ---------------------------------------------------------------------------
-- User mappings (UNMASKED) — authorized review only
-- ---------------------------------------------------------------------------
\if :unmask_secrets
SELECT
    'UNMASKED OUTPUT ENABLED — handle with care'         AS warning;

SELECT
    CASE
        WHEN um.umuser = 0 THEN 'PUBLIC'
        ELSE pg_get_userbyid(um.umuser)
    END                                                  AS local_user,
    s.srvname                                            AS foreign_server,
    fdw.fdwname                                          AS fdw,
    COALESCE(array_to_string(um.umoptions, ', '), '')    AS options_unmasked
FROM pg_user_mapping um
JOIN pg_foreign_server s
  ON s.oid = um.umserver
JOIN pg_foreign_data_wrapper fdw
  ON fdw.oid = s.srvfdw
ORDER BY local_user, foreign_server;
\else
SELECT
    'Unmasked user-mapping options skipped. Re-run with -v unmask_secrets=true if explicitly needed.' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Foreign tables
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS foreign_table,
    s.srvname                                            AS foreign_server,
    ft.ftoptions                                         AS options
FROM pg_foreign_table ft
JOIN pg_class c
  ON c.oid = ft.ftrelid
JOIN pg_namespace n
  ON n.oid = c.relnamespace
JOIN pg_foreign_server s
  ON s.oid = ft.ftserver
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- dblink extension installed?
-- ---------------------------------------------------------------------------
SELECT
    extname,
    extversion
FROM pg_extension
WHERE extname = 'dblink';

-- ---------------------------------------------------------------------------
-- Functions / procedures whose definition references dblink
-- Exclude aggregates, window funcs, etc. to avoid pg_get_functiondef errors.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    p.proname                                            AS routine,
    CASE p.prokind
        WHEN 'f' THEN 'FUNCTION'
        WHEN 'p' THEN 'PROCEDURE'
        WHEN 'w' THEN 'WINDOW'
        WHEN 'a' THEN 'AGGREGATE'
        ELSE p.prokind::text
    END                                                  AS routine_type,
    pg_get_userbyid(p.proowner)                          AS owner,
    l.lanname                                            AS language
FROM pg_proc p
JOIN pg_namespace n
  ON n.oid = p.pronamespace
JOIN pg_language l
  ON l.oid = p.prolang
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND p.prokind IN ('f', 'p')
  AND pg_get_functiondef(p.oid) ILIKE '%dblink%'
ORDER BY n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM pg_foreign_data_wrapper)       AS fdw_count,
    (SELECT count(*) FROM pg_foreign_server)             AS foreign_server_count,
    (SELECT count(*) FROM pg_user_mapping)               AS user_mapping_count,
    (SELECT count(*) FROM pg_foreign_table)              AS foreign_table_count,
    (SELECT count(*) FROM pg_extension WHERE extname = 'dblink') AS dblink_installed;