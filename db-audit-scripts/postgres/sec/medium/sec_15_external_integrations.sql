-- =============================================================================
-- sec_15_external_integrations.sql
-- Priority: MEDIUM
-- Purpose: Audit Foreign Data Wrappers, foreign servers, user mappings,
--          and dblink usage. These are network egress points and may
--          carry credentials.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Installed FDW extensions
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
FROM pg_foreign_data_wrapper;

-- ---------------------------------------------------------------------------
-- Foreign servers (the destinations)
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
JOIN pg_foreign_data_wrapper fdw ON fdw.oid = s.srvfdw
ORDER BY s.srvname;

-- ---------------------------------------------------------------------------
-- User mappings (local user -> foreign credentials) — MASKED VERSION.
-- WARNING: umoptions can contain plaintext passwords for the foreign
-- system. This block masks any option that looks like a credential
-- (password, secret, key, token) so the result can be safely shared.
-- For the unmasked version, see the next block (run only as authorized
-- security reviewer and do NOT export the result).
-- ---------------------------------------------------------------------------
SELECT
    pg_get_userbyid(um.umuser)                           AS local_user,
    s.srvname                                            AS foreign_server,
    fdw.fdwname                                          AS fdw,
    (
        SELECT string_agg(
            CASE
                WHEN opt ~* '^(password|passwd|pwd|secret|api_?key|token|auth)='
                    THEN regexp_replace(opt, '=.*$', '=***MASKED***')
                ELSE opt
            END, ', '
        )
        FROM unnest(coalesce(um.umoptions, ARRAY[]::text[])) AS opt
    )                                                    AS options_masked
FROM pg_user_mapping um
JOIN pg_foreign_server s        ON s.oid = um.umserver
JOIN pg_foreign_data_wrapper fdw ON fdw.oid = s.srvfdw
ORDER BY local_user, foreign_server;

-- ---------------------------------------------------------------------------
-- User mappings — UNMASKED VERSION.
-- Disabled by default. Set :unmask_secrets to true on the psql command line
-- to enable: psql -v unmask_secrets=true -f sec_15_external_integrations.sql
-- ---------------------------------------------------------------------------
SELECT coalesce(:'unmask_secrets', 'false')::boolean AS unmask_secrets
\gset
\if :unmask_secrets
SELECT
    pg_get_userbyid(um.umuser)                           AS local_user,
    s.srvname                                            AS foreign_server,
    array_to_string(um.umoptions, ', ')                  AS options_full
FROM pg_user_mapping um
JOIN pg_foreign_server s ON s.oid = um.umserver
ORDER BY local_user, foreign_server;
\else
SELECT 'unmasked user mappings skipped — set -v unmask_secrets=true to view' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Foreign tables (data exposed via FDW)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS foreign_table,
    pg_get_userbyid(c.relowner)                          AS owner,
    s.srvname                                            AS foreign_server,
    ft.ftoptions                                         AS table_options
FROM pg_foreign_table ft
JOIN pg_class c           ON c.oid = ft.ftrelid
JOIN pg_namespace n       ON n.oid = c.relnamespace
JOIN pg_foreign_server s  ON s.oid = ft.ftserver
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- dblink connections currently established (function exists only if dblink extension loaded)
-- ---------------------------------------------------------------------------
SELECT
    p.proname                                            AS dblink_function,
    n.nspname                                            AS schema
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proname IN ('dblink_connect', 'dblink', 'dblink_exec', 'dblink_get_connections')
ORDER BY n.nspname, p.proname;

-- ---------------------------------------------------------------------------
-- Logical replication subscriptions (incoming external data) — MASKED.
-- subconninfo is a libpq connection string that often includes password=...
-- This block masks credential parameters; for the unmasked view set
-- -v unmask_secrets=true on the psql command line.
-- ---------------------------------------------------------------------------
SELECT
    subname                                              AS subscription,
    pg_get_userbyid(subowner)                            AS owner,
    subenabled                                           AS enabled,
    regexp_replace(
        regexp_replace(subconninfo, '(password|sslpassword)=[^ ]*', '\1=***MASKED***', 'gi'),
        '(://[^:]+:)[^@]+(@)', '\1***MASKED***\2', 'g'
    )                                                    AS connection_info_masked,
    subslotname                                          AS slot,
    subpublications                                      AS publications
FROM pg_subscription;

SELECT coalesce(:'unmask_secrets', 'false')::boolean AS unmask_secrets
\gset
\if :unmask_secrets
SELECT
    subname                                              AS subscription,
    subconninfo                                          AS connection_info_full
FROM pg_subscription;
\else
SELECT 'unmasked subscription conninfo skipped — set -v unmask_secrets=true to view' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Logical replication publications (outgoing external data)
-- ---------------------------------------------------------------------------
SELECT
    pubname                                              AS publication,
    pg_get_userbyid(pubowner)                            AS owner,
    puballtables                                         AS all_tables,
    pubinsert,
    pubupdate,
    pubdelete,
    pubtruncate
FROM pg_publication;
