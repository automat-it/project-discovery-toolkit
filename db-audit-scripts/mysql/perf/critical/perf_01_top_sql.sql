-- =============================================================================
-- perf_01_top_sql.sql
-- Priority: CRITICAL
-- Purpose: Identify the most expensive SQL by total time, mean latency,
--          call frequency, CPU, and I/O. This is the single most useful
--          query for finding the real cause of database load.
-- Requires: performance_schema enabled (default in MySQL 8.0).
--           performance_schema.events_statements_summary_by_digest must
--           be populated (requires performance_schema=ON and the statement
--           consumer enabled).
-- Read-only.
-- =============================================================================

-- NOTE: MySQL equivalent of pg_stat_statements is
--       performance_schema.events_statements_summary_by_digest.
--       It tracks normalized digests (parameterized queries) with
--       cumulative counters since last TRUNCATE or server restart.
--       sys.statement_analysis is a convenience view over this table
--       (sys schema ships by default in MySQL 8.0).

-- ---------------------------------------------------------------------------
-- Verify performance_schema digest instrumentation is active
-- ---------------------------------------------------------------------------
SELECT
    NAME                                                    AS consumer,
    ENABLED
FROM performance_schema.setup_consumers
WHERE NAME IN ('events_statements_current',
               'events_statements_history',
               'events_statements_history_long');

-- ---------------------------------------------------------------------------
-- Top 25 queries by TOTAL execution time (overall load contributors)
-- ---------------------------------------------------------------------------
SELECT
    ROUND(SUM_TIMER_WAIT / 1e12, 2)                         AS total_ms,
    ROUND(SUM_TIMER_WAIT / 1e12 / 60, 2)                    AS total_min,
    COUNT_STAR                                               AS calls,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    -- NOTE: MySQL does not expose stddev of execution time per digest
    ROUND(MIN_TIMER_WAIT / 1e9, 2)                          AS min_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                          AS max_ms,
    SUM_ROWS_SENT                                            AS total_rows,
    ROUND(100.0 * SUM_TIMER_WAIT
          / NULLIF(SUM(SUM_TIMER_WAIT) OVER (), 0), 2)      AS pct_total,
    ROUND(100.0 * COUNT_STAR
          / NULLIF(SUM(COUNT_STAR) OVER (), 0), 2)          AS pct_calls,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE DIGEST_TEXT IS NOT NULL
ORDER BY SUM_TIMER_WAIT DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top 25 queries by MEAN execution time (slowest individual calls)
-- Filter out one-shot queries to reduce noise.
-- ---------------------------------------------------------------------------
SELECT
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    ROUND(MIN_TIMER_WAIT / 1e9, 2)                          AS min_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                          AS max_ms,
    COUNT_STAR                                               AS calls,
    ROUND(SUM_TIMER_WAIT / 1e9, 2)                          AS total_ms,
    -- `rows` is a reserved keyword in MySQL 8.0+ (window-function clause),
    -- so the alias must be quoted with backticks to parse.
    SUM_ROWS_SENT                                            AS `rows`,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE COUNT_STAR > 10
  AND DIGEST_TEXT IS NOT NULL
ORDER BY AVG_TIMER_WAIT DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top 25 queries by CALL FREQUENCY (find chatty clients / N+1 patterns)
-- ---------------------------------------------------------------------------
SELECT
    COUNT_STAR                                               AS calls,
    ROUND(SUM_TIMER_WAIT / 1e9, 2)                          AS total_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    SUM_ROWS_SENT                                            AS `rows`,
    ROUND(SUM_ROWS_SENT / NULLIF(COUNT_STAR, 0), 2)         AS rows_per_call,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE DIGEST_TEXT IS NOT NULL
ORDER BY COUNT_STAR DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top queries by CPU-bound indicator
-- NOTE: MySQL does not directly separate CPU time from wall time.
--       Low SUM_ROWS_EXAMINED with high SUM_TIMER_WAIT suggests CPU work.
--       SUM_NO_INDEX_USED > 0 means full table scans (often CPU-heavy).
-- ---------------------------------------------------------------------------
SELECT
    ROUND(SUM_TIMER_WAIT / 1e9, 2)                          AS total_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    COUNT_STAR                                               AS calls,
    SUM_ROWS_EXAMINED                                        AS rows_examined,
    SUM_NO_INDEX_USED                                        AS full_scans,
    SUM_NO_GOOD_INDEX_USED                                   AS bad_index_uses,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ROWS_EXAMINED < 1000
  AND ROUND(AVG_TIMER_WAIT / 1e9, 2) > 10
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_TIMER_WAIT DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top queries by I/O (disk reads — likely bottleneck on slow storage)
-- NOTE: MySQL uses SUM_ROWS_EXAMINED as proxy for I/O; for actual disk
--       I/O per statement use performance_schema.file_summary_by_event_name
--       combined with events_statements, but per-digest I/O is not exposed
--       directly. SUM_ROWS_EXAMINED is the best available approximation.
-- ---------------------------------------------------------------------------
SELECT
    SUM_ROWS_EXAMINED                                        AS rows_examined,
    SUM_ROWS_SENT                                            AS rows_sent,
    ROUND(SUM_ROWS_EXAMINED / NULLIF(SUM_ROWS_SENT, 0), 0)  AS examine_to_send_ratio,
    COUNT_STAR                                               AS calls,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    SUM_NO_INDEX_USED                                        AS full_scans,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ROWS_EXAMINED > 0
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_ROWS_EXAMINED DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top WRITE-heavy queries (DML pressure)
-- NOTE: MySQL does not expose per-digest WAL/redo log bytes.
--       SUM_ROWS_AFFECTED is the closest analog to write volume.
-- ---------------------------------------------------------------------------
SELECT
    SUM_ROWS_AFFECTED                                        AS rows_affected,
    COUNT_STAR                                               AS calls,
    ROUND(SUM_ROWS_AFFECTED / NULLIF(COUNT_STAR, 0), 2)     AS rows_affected_per_call,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    ROUND(SUM_TIMER_WAIT / 1e9, 2)                          AS total_ms,
    DIGEST                                                   AS queryid,
    LEFT(DIGEST_TEXT, 300)                                   AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ROWS_AFFECTED > 0
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_ROWS_AFFECTED DESC
LIMIT 25;
