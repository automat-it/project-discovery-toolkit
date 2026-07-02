-- =============================================================================
-- perf_20_workload_management.sql
-- Priority: MEDIUM
-- Purpose: Surface workload-management signals — concurrency limits,
--          per-role resource caps, long-running maintenance progress,
--          autovacuum / autoanalyze worker load, and any in-flight
--          operations visible via the pg_stat_progress_* views.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Concurrency caps and worker limits
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source, short_desc
FROM pg_settings
WHERE name IN (
    'max_connections',
    'superuser_reserved_connections',
    'max_worker_processes',
    'max_parallel_workers',
    'max_parallel_workers_per_gather',
    'max_parallel_maintenance_workers',
    'max_logical_replication_workers',
    'autovacuum_max_workers',
    'autovacuum_work_mem',
    'maintenance_work_mem',
    'work_mem',
    'idle_in_transaction_session_timeout',
    'statement_timeout',
    'lock_timeout'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Per-role caps (connection / rate-limit style knobs live in pg_roles)
-- ---------------------------------------------------------------------------
SELECT
    rolname,
    rolcanlogin,
    rolconnlimit,
    rolbypassrls,
    rolreplication,
    rolsuper
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY rolconnlimit DESC NULLS LAST, rolname;

-- ---------------------------------------------------------------------------
-- Per-role / per-database GUC overrides (ALTER ROLE ... SET ...,
-- ALTER DATABASE ... SET ...) — hidden workload isolation knobs.
-- ---------------------------------------------------------------------------
SELECT
    CASE WHEN s.setrole    = 0 THEN NULL ELSE r.rolname END AS role,
    CASE WHEN s.setdatabase= 0 THEN NULL ELSE d.datname END AS database,
    s.setconfig
FROM pg_db_role_setting s
LEFT JOIN pg_roles    r ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
ORDER BY role NULLS LAST, database NULLS LAST;

-- ---------------------------------------------------------------------------
-- Current activity by state + wait class (what the workload is doing)
-- ---------------------------------------------------------------------------
SELECT
    COALESCE(state,'(null)')                              AS state,
    COALESCE(wait_event_type,'(none)')                    AS wait_event_type,
    COUNT(*)                                              AS sessions,
    COUNT(*) FILTER (WHERE query_start IS NOT NULL
                     AND query_start < now() - interval '5 minutes') AS over_5min
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY state, wait_event_type
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Running autovacuum workers (autovacuum is the largest background
-- workload on any busy cluster)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    datname,
    usename,
    state,
    backend_start,
    xact_start,
    query_start,
    wait_event_type,
    wait_event,
    LEFT(query, 200)                                     AS query
FROM pg_stat_activity
WHERE backend_type = 'autovacuum worker'
   OR query ILIKE 'autovacuum:%'
ORDER BY xact_start;

-- ---------------------------------------------------------------------------
-- In-flight operations (pg_stat_progress_* — added incrementally across
-- 9.6 → 14; missing ones are simply empty).
--
-- Version note: PostgreSQL 17 replaced the dead-tuple COUNT columns
-- (max_dead_tuples, num_dead_tuples) with BYTE-oriented columns
-- (max_dead_tuple_bytes, dead_tuple_bytes, num_dead_item_ids,
-- indexes_total, indexes_processed). We pick the right set per version.
-- ---------------------------------------------------------------------------
SELECT current_setting('server_version_num')::int >= 170000 AS pg17_or_newer
\gset
\if :pg17_or_newer
SELECT
    'vacuum'       AS progress_type,
    pid, datname,
    phase, heap_blks_total, heap_blks_scanned, heap_blks_vacuumed,
    index_vacuum_count,
    max_dead_tuple_bytes, dead_tuple_bytes, num_dead_item_ids,
    indexes_total, indexes_processed
FROM pg_stat_progress_vacuum;
\else
SELECT
    'vacuum'       AS progress_type,
    pid, datname,
    phase, heap_blks_total, heap_blks_scanned, heap_blks_vacuumed,
    index_vacuum_count, max_dead_tuples, num_dead_tuples
FROM pg_stat_progress_vacuum;
\endif

SELECT 'analyze' AS progress_type, * FROM pg_stat_progress_analyze;

SELECT 'cluster' AS progress_type, * FROM pg_stat_progress_cluster;

SELECT 'create_index' AS progress_type, * FROM pg_stat_progress_create_index;

SELECT 'basebackup' AS progress_type, * FROM pg_stat_progress_basebackup;

-- pg_stat_progress_copy is PostgreSQL 14+; skip on PG 13.
SELECT current_setting('server_version_num')::int >= 140000 AS pg14_or_newer
\gset
\if :pg14_or_newer
SELECT 'copy' AS progress_type, * FROM pg_stat_progress_copy;
\else
SELECT 'pg_stat_progress_copy requires PostgreSQL 14+ - skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Prepared transactions — each holds locks and prevents vacuum
-- ---------------------------------------------------------------------------
SELECT
    gid,
    prepared,
    owner,
    database,
    age(now(), prepared)                                  AS age
FROM pg_prepared_xacts
ORDER BY prepared;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting::int FROM pg_settings WHERE name='max_connections')        AS max_conn,
    (SELECT COUNT(*) FROM pg_stat_activity WHERE backend_type='client backend') AS clients,
    (SELECT COUNT(*) FROM pg_stat_activity WHERE backend_type='autovacuum worker') AS autovac_workers,
    (SELECT setting::int FROM pg_settings WHERE name='autovacuum_max_workers') AS autovac_max,
    (SELECT COUNT(*) FROM pg_stat_progress_vacuum)                             AS vacuums_running,
    (SELECT COUNT(*) FROM pg_stat_progress_create_index)                       AS index_builds_running;
