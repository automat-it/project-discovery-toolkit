-- =============================================================================
-- sec_19_schema_change_history.sql
-- Priority: MEDIUM
-- Purpose: Surface evidence of DDL / schema-change activity. PostgreSQL
--          does not persist a native DDL audit trail by default, so we
--          combine object modification timestamps, event triggers, and
--          any common audit-logging extensions (pgaudit, pgmemento,
--          pg_activity).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Are any DDL-logging / audit extensions installed?
-- ---------------------------------------------------------------------------
SELECT
    extname                                              AS extension,
    extversion,
    nspname                                              AS schema
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE extname IN (
    'pgaudit',
    'pgmemento',
    'pg_activity',
    'audit',
    'pgaudit_log_to_file',
    'set_user',
    'pg_ddl_deploy'
)
ORDER BY extname;

-- ---------------------------------------------------------------------------
-- pgaudit configuration (if loaded)
-- ---------------------------------------------------------------------------
SELECT
    name,
    setting,
    source,
    short_desc
FROM pg_settings
WHERE name LIKE 'pgaudit.%'
ORDER BY name;

-- ---------------------------------------------------------------------------
-- log_statement / log_min_duration_statement — indirect DDL trail
-- log_statement = 'ddl' or 'all' means DDL shows up in the server log.
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'log_statement',
    'log_min_duration_statement',
    'log_connections',
    'log_disconnections',
    'log_line_prefix',
    'logging_collector',
    'log_destination'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Event triggers (custom DDL-change hooks)
-- ---------------------------------------------------------------------------
SELECT
    evtname                                              AS trigger_name,
    evtevent                                             AS event,
    pg_get_userbyid(evtowner)                            AS owner,
    evtenabled                                           AS enabled,
    p.proname                                            AS function,
    n.nspname                                            AS function_schema,
    evttags                                              AS filtered_tags
FROM pg_event_trigger et
JOIN pg_proc p     ON p.oid = et.evtfoid
JOIN pg_namespace n ON n.oid = p.pronamespace
ORDER BY evtname;

-- ---------------------------------------------------------------------------
-- Recently modified objects (tables/views/sequences/functions)
-- PostgreSQL does not track per-object modification time directly; the
-- closest signals are pg_stat_all_tables.last_analyze / last_vacuum and
-- pg_class.relfrozenxid deltas. We also pull extension install times.
-- ---------------------------------------------------------------------------
SELECT
    schemaname                                           AS schema,
    relname                                              AS relation,
    n_live_tup                                           AS rows,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_all_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND (last_analyze   > now() - interval '30 days'
    OR last_vacuum    > now() - interval '30 days'
    OR last_autovacuum> now() - interval '30 days'
    OR last_autoanalyze> now() - interval '30 days')
ORDER BY GREATEST(
    COALESCE(last_analyze,    'epoch'::timestamptz),
    COALESCE(last_vacuum,     'epoch'::timestamptz),
    COALESCE(last_autovacuum, 'epoch'::timestamptz),
    COALESCE(last_autoanalyze,'epoch'::timestamptz)
) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Objects whose OID falls into the most recently allocated band — these
-- were created most recently (useful when there is no DDL log at all).
-- Top 50 newest user objects by OID.
-- ---------------------------------------------------------------------------
SELECT
    c.oid,
    n.nspname                                            AS schema,
    c.relname                                            AS object,
    c.relkind                                            AS kind,
    pg_get_userbyid(c.relowner)                          AS owner
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND c.relkind IN ('r','v','m','S','i','p')
ORDER BY c.oid DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- pgmemento (row-level history) installed schemas, if any
-- ---------------------------------------------------------------------------
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_schema = 'pgmemento'
ORDER BY table_name;

-- ---------------------------------------------------------------------------
-- Summary: is there any persistent DDL trail on this server?
-- ---------------------------------------------------------------------------
SELECT
    EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgaudit')  AS pgaudit_installed,
    EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgmemento') AS pgmemento_installed,
    (SELECT setting FROM pg_settings WHERE name = 'log_statement') AS log_statement_setting,
    (SELECT count(*) FROM pg_event_trigger)                        AS event_trigger_count,
    CASE
        WHEN EXISTS(SELECT 1 FROM pg_extension WHERE extname IN ('pgaudit','pgmemento'))
          OR (SELECT setting FROM pg_settings WHERE name = 'log_statement') IN ('ddl','mod','all')
        THEN 'DDL trail present'
        ELSE 'NO persistent DDL trail — recommend enabling pgaudit or log_statement=ddl'
    END                                                           AS assessment;
