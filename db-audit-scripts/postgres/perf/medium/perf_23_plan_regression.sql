-- =============================================================================
-- perf_23_plan_regression.sql
-- Priority: MEDIUM
-- Purpose: Flag statements whose plans are probably regressing.
--          PostgreSQL has no first-class plan history; the signal
--          available is (a) high variance within pg_stat_statements
--          (stddev_exec_time, min/max gap), (b) presence of auto_explain
--          + pg_stat_statements settings, (c) plan-cache dependencies
--          via pg_prepared_statements on the current session.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- pg_stat_statements presence check — without it this script is empty.
-- ---------------------------------------------------------------------------
SELECT
    EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements') AS pgss_installed,
    (SELECT setting FROM pg_settings WHERE name = 'shared_preload_libraries') AS preloaded,
    (SELECT setting FROM pg_settings WHERE name = 'pg_stat_statements.track') AS pgss_track,
    (SELECT setting FROM pg_settings WHERE name = 'pg_stat_statements.max')   AS pgss_max,
    (SELECT setting FROM pg_settings WHERE name = 'auto_explain.log_min_duration') AS auto_explain_threshold,
    (SELECT setting FROM pg_settings WHERE name = 'auto_explain.log_analyze')     AS auto_explain_analyze,
    (SELECT setting FROM pg_settings WHERE name = 'plan_cache_mode')          AS plan_cache_mode;

-- ---------------------------------------------------------------------------
-- High-variance statements — stddev_exec_time / mean_exec_time ratio
-- > 1.0 usually means bimodal plans or cache-cold vs warm. Filtered to
-- calls > 50 to suppress one-off noise.
-- Gracefully skips if pg_stat_statements is not available.
-- ---------------------------------------------------------------------------
SELECT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
) AS has_pgss
\gset
\if :has_pgss

-- Highest coefficient of variation first (bimodal / plan-flip candidates).
SELECT
    queryid,
    LEFT(query, 200)                                   AS query_sample,
    calls,
    ROUND(mean_exec_time::numeric, 2)                  AS mean_ms,
    ROUND(stddev_exec_time::numeric, 2)                AS stddev_ms,
    CASE WHEN mean_exec_time > 0
         THEN ROUND((stddev_exec_time/mean_exec_time)::numeric, 2)
    END                                                AS cv,
    ROUND(min_exec_time::numeric, 2)                   AS min_ms,
    ROUND(max_exec_time::numeric, 2)                   AS max_ms,
    CASE WHEN min_exec_time > 0
         THEN ROUND((max_exec_time / min_exec_time)::numeric, 1)
    END                                                AS max_over_min,
    rows,
    shared_blks_hit,
    shared_blks_read
FROM pg_stat_statements
WHERE calls >= 50
ORDER BY CASE WHEN mean_exec_time > 0
              THEN stddev_exec_time / mean_exec_time
         END DESC NULLS LAST
LIMIT 50;

-- Widest max/min execution-time gap first (extreme outliers).
SELECT
    queryid,
    LEFT(query, 200)                                   AS query_sample,
    calls,
    ROUND(mean_exec_time::numeric, 2)                  AS mean_ms,
    ROUND(stddev_exec_time::numeric, 2)                AS stddev_ms,
    CASE WHEN mean_exec_time > 0
         THEN ROUND((stddev_exec_time/mean_exec_time)::numeric, 2)
    END                                                AS cv,
    ROUND(min_exec_time::numeric, 2)                   AS min_ms,
    ROUND(max_exec_time::numeric, 2)                   AS max_ms,
    CASE WHEN min_exec_time > 0
         THEN ROUND((max_exec_time / min_exec_time)::numeric, 1)
    END                                                AS max_over_min,
    rows,
    shared_blks_hit,
    shared_blks_read
FROM pg_stat_statements
WHERE calls >= 50
ORDER BY CASE WHEN min_exec_time > 0
              THEN max_exec_time / min_exec_time
         END DESC NULLS LAST
LIMIT 25;

\else
SELECT 'pg_stat_statements not installed - section skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Prepared statements on the *current session* with plan-cache status
-- ---------------------------------------------------------------------------
SELECT name, statement, prepare_time, parameter_types, generic_plans, custom_plans
FROM pg_prepared_statements
ORDER BY prepare_time DESC;

-- ---------------------------------------------------------------------------
-- Cache hit vs read distribution per database — plan regression often
-- reveals itself as a sudden drop in shared_blks_hit / shared_blks_read
-- ratio for a specific digest. Scope snapshot is per-database.
-- ---------------------------------------------------------------------------
SELECT
    datname,
    blks_hit,
    blks_read,
    CASE WHEN (blks_hit + blks_read) > 0
         THEN ROUND((blks_hit::numeric * 100) / (blks_hit + blks_read), 2)
    END                                                   AS cache_hit_pct,
    tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted,
    temp_files, temp_bytes,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY blks_read DESC;

-- ---------------------------------------------------------------------------
-- Operator guidance
-- ---------------------------------------------------------------------------
SELECT
    'High cv queryids are candidates for EXPLAIN (ANALYZE, BUFFERS) under '
    'both cache-cold and cache-warm states. auto_explain (contrib) is the '
    'canonical way to log plans in PostgreSQL — set '
    'auto_explain.log_min_duration to a value just below p95 latency.'     AS operator_action;
