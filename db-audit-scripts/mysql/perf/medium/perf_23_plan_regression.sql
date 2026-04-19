-- =============================================================================
-- perf_23_plan_regression.sql
-- Priority: MEDIUM
-- Purpose: Flag statement digests whose execution time is bimodal
--          (max >> avg), errors spiking, rows-examined / rows-sent
--          ratio deteriorating. MySQL does not track plan history
--          natively; performance_schema digest stats are the best
--          signal available.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- performance_schema feature flags — the script depends on
-- events_statements_summary_by_digest being enabled + populated.
-- ---------------------------------------------------------------------------
SELECT
    @@performance_schema                                  AS perf_schema_enabled,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
      WHERE VARIABLE_NAME = 'performance_schema_max_digest_length')   AS max_digest_length,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
      WHERE VARIABLE_NAME = 'performance_schema_digests_size')        AS digests_size;

-- ---------------------------------------------------------------------------
-- Bimodal digests — max_timer_wait / avg_timer_wait is the closest
-- analog to coefficient-of-variation. Filter calls >= 50 to ignore
-- warm-up samples.
-- Timer units are picoseconds; divide by 1e9 for milliseconds.
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME,
    LEFT(DIGEST_TEXT, 200)                                AS digest_sample,
    COUNT_STAR                                            AS calls,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                        AS avg_ms,
    ROUND(MIN_TIMER_WAIT / 1e9, 2)                        AS min_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                        AS max_ms,
    CASE WHEN AVG_TIMER_WAIT > 0
         THEN ROUND(MAX_TIMER_WAIT / AVG_TIMER_WAIT, 1)
    END                                                   AS max_over_avg,
    CASE WHEN MIN_TIMER_WAIT > 0
         THEN ROUND(MAX_TIMER_WAIT / MIN_TIMER_WAIT, 1)
    END                                                   AS max_over_min,
    SUM_ROWS_SENT,
    SUM_ROWS_EXAMINED,
    CASE WHEN SUM_ROWS_SENT > 0
         THEN ROUND(SUM_ROWS_EXAMINED / SUM_ROWS_SENT, 1)
    END                                                   AS examined_per_sent,
    SUM_CREATED_TMP_TABLES,
    SUM_CREATED_TMP_DISK_TABLES,
    SUM_SORT_MERGE_PASSES,
    SUM_NO_INDEX_USED,
    SUM_NO_GOOD_INDEX_USED,
    LAST_SEEN
FROM performance_schema.events_statements_summary_by_digest
WHERE COUNT_STAR >= 50
ORDER BY max_over_avg DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Index-less digests — queries marked NO_INDEX_USED or NO_GOOD_INDEX_USED
-- are latent plan-regression candidates because any data-shape shift
-- triggers a disproportionate slowdown.
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME,
    LEFT(DIGEST_TEXT, 200)                                AS digest_sample,
    COUNT_STAR                                            AS calls,
    SUM_NO_INDEX_USED,
    SUM_NO_GOOD_INDEX_USED,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                        AS avg_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                        AS max_ms
FROM performance_schema.events_statements_summary_by_digest
WHERE (SUM_NO_INDEX_USED > 0 OR SUM_NO_GOOD_INDEX_USED > 0)
  AND COUNT_STAR >= 20
ORDER BY SUM_NO_INDEX_USED DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Recent errors / warnings per digest — spikes often track plan change
-- (e.g. ER_LOCK_WAIT_TIMEOUT, ER_DEADLOCK, ER_QUERY_INTERRUPTED).
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME,
    LEFT(DIGEST_TEXT, 200)                                AS digest_sample,
    COUNT_STAR, SUM_ERRORS, SUM_WARNINGS,
    ROUND(SUM_ERRORS   * 100 / NULLIF(COUNT_STAR,0), 2)   AS err_pct,
    ROUND(SUM_WARNINGS * 100 / NULLIF(COUNT_STAR,0), 2)   AS warn_pct,
    LAST_SEEN
FROM performance_schema.events_statements_summary_by_digest
WHERE (SUM_ERRORS > 0 OR SUM_WARNINGS > 0)
  AND COUNT_STAR >= 20
ORDER BY err_pct DESC, warn_pct DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Optimizer switches — a non-default optimizer_switch / optimizer_trace
-- configuration is a common silent cause of plan shifts across versions.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'optimizer_switch',
    'optimizer_search_depth',
    'optimizer_prune_level',
    'optimizer_trace',
    'use_stat_tables',
    'histogram_generation_max_mem_size',
    'eq_range_index_dive_limit',
    'range_optimizer_max_mem_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Operator guidance
-- ---------------------------------------------------------------------------
SELECT CONCAT(
    'For high max_over_avg digests run EXPLAIN FORMAT=JSON on a ',
    'representative sample, then EXPLAIN ANALYZE under realistic load. ',
    'Check sys.statements_with_runtimes_in_95th_percentile for the ',
    'reference baseline. The optimizer_trace plugin gives per-decision ',
    'visibility into plan choice.'
) AS operator_action;
