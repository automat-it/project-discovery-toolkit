-- =============================================================================
-- perf_16_plan_instability.sql
-- Priority: LOW
-- Purpose: Detect query plan instability via execution time variance.
--          High stddev relative to mean suggests the planner picks
--          different plans or hits very different data sizes.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Queries with high coefficient of variation (stddev / mean)
-- ---------------------------------------------------------------------------
SELECT
    queryid,
    calls,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    round(stddev_exec_time::numeric, 2)                  AS stddev_ms,
    round(min_exec_time::numeric, 2)                     AS min_ms,
    round(max_exec_time::numeric, 2)                     AS max_ms,
    CASE WHEN mean_exec_time > 0
         THEN round((stddev_exec_time / mean_exec_time)::numeric, 2)
         ELSE 0
    END                                                  AS cv,
    CASE WHEN min_exec_time > 0
         THEN round((max_exec_time / min_exec_time)::numeric, 2)
         ELSE NULL
    END                                                  AS max_min_ratio,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE calls > 50
  AND mean_exec_time > 1
  AND stddev_exec_time > mean_exec_time
ORDER BY (stddev_exec_time / NULLIF(mean_exec_time, 0)) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Queries with very large min/max gap (extreme outliers)
-- ---------------------------------------------------------------------------
SELECT
    queryid,
    calls,
    round(min_exec_time::numeric, 2)                     AS min_ms,
    round(max_exec_time::numeric, 2)                     AS max_ms,
    round((max_exec_time - min_exec_time)::numeric, 2)   AS spread_ms,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE calls > 20
  AND min_exec_time > 0
  AND max_exec_time > min_exec_time * 100
ORDER BY (max_exec_time - min_exec_time) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Plan-cache mode and prepared statement settings
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'plan_cache_mode',
    'from_collapse_limit',
    'join_collapse_limit',
    'cursor_tuple_fraction',
    'default_statistics_target'
)
ORDER BY name;
