-- =============================================================================
-- perf_16_plan_instability.sql
-- Priority: LOW
-- Purpose: Detect query plan instability via execution time variance.
--          High max/min ratio suggests the optimizer picks different plans
--          or hits very different data sizes across executions.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL performance_schema.events_statements_summary_by_digest
--       exposes MIN_TIMER_WAIT and MAX_TIMER_WAIT per digest, enabling
--       max/min ratio analysis. There is no stddev per digest (unlike
--       PostgreSQL pg_stat_statements.stddev_exec_time).
--       The coefficient of variation (CV) cannot be computed without stddev.
--       Use MAX_TIMER_WAIT / MIN_TIMER_WAIT as the primary instability signal.

-- ---------------------------------------------------------------------------
-- Queries with very large min/max execution time gap (extreme outliers)
-- ---------------------------------------------------------------------------
SELECT
    COUNT_STAR                                              AS calls,
    ROUND(MIN_TIMER_WAIT / 1e9, 2)                          AS min_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                          AS max_ms,
    ROUND((MAX_TIMER_WAIT - MIN_TIMER_WAIT) / 1e9, 2)       AS spread_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    ROUND(MAX_TIMER_WAIT / NULLIF(MIN_TIMER_WAIT, 0), 1)    AS max_min_ratio,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE COUNT_STAR > 20
  AND MIN_TIMER_WAIT > 0
  AND MAX_TIMER_WAIT > MIN_TIMER_WAIT * 100
  AND DIGEST_TEXT IS NOT NULL
ORDER BY MAX_TIMER_WAIT / NULLIF(MIN_TIMER_WAIT, 0) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Queries with high absolute spread (many calls, wide execution range)
-- These are the most operationally disruptive — high call volume + variance.
-- ---------------------------------------------------------------------------
SELECT
    COUNT_STAR                                              AS calls,
    ROUND(MIN_TIMER_WAIT / 1e9, 2)                          AS min_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                          AS max_ms,
    ROUND((MAX_TIMER_WAIT - MIN_TIMER_WAIT) / 1e9, 2)       AS spread_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE COUNT_STAR > 50
  AND ROUND(AVG_TIMER_WAIT / 1e9, 2) > 1
  AND DIGEST_TEXT IS NOT NULL
ORDER BY (MAX_TIMER_WAIT - MIN_TIMER_WAIT) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Optimizer and plan cache related parameters
-- (analogous to PostgreSQL plan_cache_mode, join_collapse_limit)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'optimizer_switch',
    'optimizer_prune_level',
    'optimizer_search_depth',
    'eq_range_index_dive_limit',
    'range_optimizer_max_mem_size',
    'max_seeks_for_key',
    'innodb_stats_persistent',
    'innodb_stats_auto_recalc',
    'innodb_stats_sample_pages',
    'query_cache_type',        -- deprecated in MySQL 8.0 (removed)
    'query_cache_size',        -- deprecated in MySQL 8.0 (removed)
    'max_prepared_stmt_count', -- prepared statement cache size
    'join_buffer_size',
    'sort_buffer_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Prepared statement cache usage
-- NOTE: MySQL caches prepared statements per connection.
--       max_prepared_stmt_count is the global limit.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Prepared_stmt_count',
    'Com_stmt_prepare',
    'Com_stmt_execute',
    'Com_stmt_reset',
    'Com_stmt_close'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Queries with high error rate (may indicate plan changes causing failures)
-- ---------------------------------------------------------------------------
SELECT
    SUM_ERRORS                                              AS errors,
    SUM_WARNINGS                                            AS warnings,
    COUNT_STAR                                              AS calls,
    ROUND(100.0 * SUM_ERRORS / NULLIF(COUNT_STAR, 0), 2)   AS error_pct,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ERRORS > 0
  AND COUNT_STAR > 10
  AND DIGEST_TEXT IS NOT NULL
ORDER BY error_pct DESC
LIMIT 25;
