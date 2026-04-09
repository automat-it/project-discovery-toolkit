-- =============================================================================
-- perf_09_temp_and_memory_pressure.sql
-- Priority: HIGH
-- Purpose: Detect spills to disk caused by undersized sort/tmp buffers,
--          large sorts/hashes/joins, and temp table usage.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL uses internal temporary tables for GROUP BY, ORDER BY,
--       UNION, and subquery materialization. When they exceed tmp_table_size
--       or max_heap_table_size, they spill to disk (temp files in tmpdir).
--       There is no per-database temp file counter like pg_stat_database;
--       MySQL exposes global counters via global status variables.
--       The pg_stat_statements temp_blks_* columns have no direct MySQL
--       equivalent per digest — only global counters are available.

-- ---------------------------------------------------------------------------
-- Global temp table usage counters (cumulative since server start/reset)
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Created_tmp_tables',
    'Created_tmp_disk_tables',
    'Created_tmp_files'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Derived: disk spill ratio for temp tables
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Created_tmp_tables') + 0       AS tmp_tables_total,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Created_tmp_disk_tables') + 0  AS tmp_disk_tables,
    ROUND(
        100.0
        * (SELECT VARIABLE_VALUE FROM performance_schema.global_status
           WHERE VARIABLE_NAME = 'Created_tmp_disk_tables') + 0
        / NULLIF(
            (SELECT VARIABLE_VALUE FROM performance_schema.global_status
             WHERE VARIABLE_NAME = 'Created_tmp_tables') + 0, 0),
        2)                                                  AS disk_spill_pct;

-- ---------------------------------------------------------------------------
-- Top queries that generate the most temp tables (spill candidates)
-- NOTE: SUM_CREATED_TMP_TABLES and SUM_CREATED_TMP_DISK_TABLES are
--       available per-digest in MySQL 8.0.
-- ---------------------------------------------------------------------------
SELECT
    SUM_CREATED_TMP_DISK_TABLES                             AS tmp_disk_tables,
    SUM_CREATED_TMP_TABLES                                  AS tmp_tables,
    ROUND(100.0 * SUM_CREATED_TMP_DISK_TABLES
          / NULLIF(SUM_CREATED_TMP_TABLES, 0), 2)           AS disk_pct,
    COUNT_STAR                                              AS calls,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_CREATED_TMP_DISK_TABLES > 0
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_CREATED_TMP_DISK_TABLES DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Currently active queries creating temp tables
-- ---------------------------------------------------------------------------
SELECT
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_HOST                                      AS host,
    t.PROCESSLIST_STATE                                     AS state,
    t.PROCESSLIST_TIME                                      AS seconds,
    LEFT(t.PROCESSLIST_INFO, 300)                           AS query
FROM performance_schema.threads t
WHERE t.PROCESSLIST_STATE LIKE '%tmp%'
   OR t.PROCESSLIST_STATE LIKE '%copying%'
   OR t.PROCESSLIST_STATE LIKE '%Sorting%'
   OR t.PROCESSLIST_STATE LIKE '%filesort%'
ORDER BY t.PROCESSLIST_TIME DESC;

-- ---------------------------------------------------------------------------
-- Sort and join related global counters
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Sort_merge_passes',
    'Sort_range',
    'Sort_rows',
    'Sort_scan',
    'Select_full_join',
    'Select_full_range_join',
    'Select_range_check',
    'Select_scan'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Memory / temp table related parameters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'tmp_table_size',
    'max_heap_table_size',
    'sort_buffer_size',
    'join_buffer_size',
    'read_buffer_size',
    'read_rnd_buffer_size',
    'bulk_insert_buffer_size',
    'tmpdir',
    'temptable_max_ram',
    'temptable_max_mmap',
    'temptable_use_mmap',
    'internal_tmp_mem_storage_engine',
    'innodb_sort_buffer_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Per-session sort / tmp table stats (current statements)
-- ---------------------------------------------------------------------------
SELECT
    es.THREAD_ID,
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    es.CREATED_TMP_DISK_TABLES,
    es.CREATED_TMP_TABLES,
    es.SORT_MERGE_PASSES,
    es.SORT_ROWS,
    ROUND(es.TIMER_WAIT / 1e9, 2)                           AS elapsed_ms,
    LEFT(es.SQL_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_current es
JOIN performance_schema.threads t
  ON t.THREAD_ID = es.THREAD_ID
WHERE es.CREATED_TMP_DISK_TABLES > 0
   OR es.SORT_MERGE_PASSES > 0
ORDER BY es.CREATED_TMP_DISK_TABLES DESC, es.SORT_MERGE_PASSES DESC;
