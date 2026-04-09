-- =============================================================================
-- perf_12_sequential_scans.sql
-- Priority: MEDIUM
-- Purpose: Tables with high full-scan activity — typically a missing index
--          indicator (or appropriate for very small / very hot tables).
-- Read-only.
-- =============================================================================

-- NOTE: MySQL exposes full scan activity via:
--       1. performance_schema.table_io_waits_summary_by_index_usage
--          (index_name IS NULL = full scan rows)
--       2. Handler_read_rnd_next global status (full scan row reads)
--       3. events_statements_summary_by_digest.SUM_NO_INDEX_USED
--       There is no direct equivalent of pg_stat_user_tables seq_scan /
--       seq_tup_read per table with persistent counters like PostgreSQL.

-- ---------------------------------------------------------------------------
-- Tables with high full-scan I/O (no index used)
-- from performance_schema.table_io_waits_summary_by_index_usage
-- ---------------------------------------------------------------------------
SELECT
    tiu_full.object_schema                                  AS schema_name,
    tiu_full.object_name                                    AS table_name,
    tiu_full.count_read                                     AS full_scan_reads,
    COALESCE(tiu_idx.total_index_reads, 0)                  AS index_reads,
    COALESCE(tiu_idx.total_index_reads, 0)
        + tiu_full.count_read                               AS total_reads,
    ROUND(100.0 * tiu_full.count_read
          / NULLIF(tiu_full.count_read
                   + COALESCE(tiu_idx.total_index_reads, 0), 0), 2)
                                                            AS full_scan_pct,
    ROUND(tiu_full.sum_timer_wait / 1e12, 2)                AS full_scan_wait_ms
FROM performance_schema.table_io_waits_summary_by_index_usage tiu_full
LEFT JOIN (
    SELECT object_schema, object_name, SUM(count_read) AS total_index_reads
    FROM performance_schema.table_io_waits_summary_by_index_usage
    WHERE index_name IS NOT NULL
    GROUP BY object_schema, object_name
) tiu_idx
  ON  tiu_idx.object_schema = tiu_full.object_schema
  AND tiu_idx.object_name   = tiu_full.object_name
WHERE tiu_full.index_name IS NULL     -- NULL = full table scan I/O
  AND tiu_full.count_read > 0
  AND tiu_full.object_schema NOT IN ('mysql', 'information_schema',
                                      'performance_schema', 'sys')
ORDER BY tiu_full.count_read DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Tables where full scans dominate over index reads (5:1 ratio)
-- ---------------------------------------------------------------------------
SELECT
    tiu_full.object_schema                                  AS schema_name,
    tiu_full.object_name                                    AS table_name,
    tiu_full.count_read                                     AS full_scan_reads,
    COALESCE(tiu_idx.total_index_reads, 0)                  AS index_reads
FROM performance_schema.table_io_waits_summary_by_index_usage tiu_full
LEFT JOIN (
    SELECT object_schema, object_name, SUM(count_read) AS total_index_reads
    FROM performance_schema.table_io_waits_summary_by_index_usage
    WHERE index_name IS NOT NULL
    GROUP BY object_schema, object_name
) tiu_idx
  ON  tiu_idx.object_schema = tiu_full.object_schema
  AND tiu_idx.object_name   = tiu_full.object_name
WHERE tiu_full.index_name IS NULL
  AND tiu_full.count_read > COALESCE(tiu_idx.total_index_reads, 0) * 5
  AND tiu_full.count_read > 100
  AND tiu_full.object_schema NOT IN ('mysql', 'information_schema',
                                      'performance_schema', 'sys')
ORDER BY tiu_full.count_read DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Tables with no indexes at all (excluding small tables)
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.ENGINE,
    t.TABLE_ROWS                                            AS approx_rows,
    ROUND(t.DATA_LENGTH / 1024 / 1024, 2)                   AS data_mb
FROM information_schema.TABLES t
WHERE t.TABLE_TYPE = 'BASE TABLE'
  AND t.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND NOT EXISTS (
      SELECT 1
      FROM information_schema.STATISTICS s
      WHERE s.TABLE_SCHEMA = t.TABLE_SCHEMA
        AND s.TABLE_NAME   = t.TABLE_NAME
  )
  AND t.DATA_LENGTH > 1024 * 1024   -- > 1 MB
ORDER BY t.DATA_LENGTH DESC;

-- ---------------------------------------------------------------------------
-- Statements with full scans (no index used per digest)
-- SUM_NO_INDEX_USED = number of executions where no index was used at all
-- ---------------------------------------------------------------------------
SELECT
    SUM_NO_INDEX_USED                                       AS no_index_executions,
    COUNT_STAR                                              AS total_executions,
    ROUND(100.0 * SUM_NO_INDEX_USED
          / NULLIF(COUNT_STAR, 0), 2)                       AS no_index_pct,
    SUM_ROWS_EXAMINED                                       AS rows_examined,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_NO_INDEX_USED > 0
  AND COUNT_STAR > 10
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_NO_INDEX_USED DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Global full-scan counters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Handler_read_rnd_next',
    'Handler_read_rnd',
    'Handler_read_first',
    'Handler_read_key',
    'Handler_read_next',
    'Handler_read_prev',
    'Handler_read_last',
    'Select_scan',
    'Select_full_join',
    'Select_full_range_join'
)
ORDER BY VARIABLE_NAME;
