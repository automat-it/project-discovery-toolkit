-- =============================================================================
-- perf_13_deadlock_history.sql
-- Priority: MEDIUM
-- Purpose: Surface deadlock counters and conflict statistics. PostgreSQL
--          itself does not store full deadlock history (only counters);
--          full text of deadlocks is in the server log when log_lock_waits
--          and log_min_messages are configured appropriately.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Deadlock counters per database
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    deadlocks,
    conflicts                                            AS recovery_conflicts,
    xact_commit,
    xact_rollback,
    CASE WHEN xact_commit + xact_rollback > 0
         THEN round(100.0 * xact_rollback
                    / (xact_commit + xact_rollback), 2)
         ELSE 0
    END                                                  AS rollback_pct,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY deadlocks DESC;

-- ---------------------------------------------------------------------------
-- Standby query conflicts breakdown (replicas only)
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    confl_tablespace,
    confl_lock,
    confl_snapshot,
    confl_bufferpin,
    confl_deadlock
FROM pg_stat_database_conflicts
WHERE datname IS NOT NULL
ORDER BY datname;

-- ---------------------------------------------------------------------------
-- Logging settings relevant to deadlock investigation
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'deadlock_timeout',
    'log_lock_waits',
    'log_min_messages',
    'log_min_error_statement',
    'log_statement',
    'log_line_prefix'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Current waiters on locks (live snapshot — not history)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    wait_event_type,
    wait_event,
    now() - query_start                                  AS wait_duration,
    left(query, 200)                                     AS query
FROM pg_stat_activity
WHERE wait_event_type = 'Lock'
ORDER BY query_start;

-- ---------------------------------------------------------------------------
-- Top queries by rollback ratio (often the same as deadlock victims)
-- ---------------------------------------------------------------------------
SELECT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
) AS has_pgss
\gset
\if :has_pgss
SELECT
    calls,
    rows,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE query ILIKE '%UPDATE%'
   OR query ILIKE '%DELETE%'
   OR query ILIKE '%INSERT%'
ORDER BY calls DESC
LIMIT 25;
\else
SELECT 'pg_stat_statements not installed - section skipped' AS note;
\endif
