-- =============================================================================
-- perf_11_bloat_estimation.sql
-- Priority: MEDIUM
-- Purpose: Estimate table and index bloat / wasted space. Affects I/O
--          and cache efficiency.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL / InnoDB does not have the concept of dead tuples or VACUUM.
--       MVCC cleanup is performed automatically by the InnoDB purge thread.
--       "Bloat" in MySQL terms means:
--         1. DATA_FREE — allocated but unused pages in the tablespace
--            (reclaimed by OPTIMIZE TABLE, which is equivalent to pg VACUUM FULL)
--         2. Index fragmentation (ANALYZE TABLE updates stats; actual
--            defragmentation requires OPTIMIZE TABLE)
--         3. Undo log accumulation from long-running transactions
--       The heuristic bloat CTE in the PostgreSQL version cannot be
--       directly translated; we use DATA_FREE and fragmentation ratios instead.

-- ---------------------------------------------------------------------------
-- Quick wasted space indicator: DATA_FREE per table
-- DATA_FREE = pages allocated to the tablespace but not currently used.
-- Tables with high DATA_FREE benefit from OPTIMIZE TABLE.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    ROUND(DATA_FREE / 1024 / 1024, 2)                       AS free_mb,
    ROUND(100.0 * DATA_FREE
          / NULLIF(DATA_LENGTH + INDEX_LENGTH + DATA_FREE, 0), 2)
                                                            AS free_pct
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND DATA_FREE > 1024 * 1024      -- > 1 MB free
ORDER BY DATA_FREE DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Tables with high DATA_FREE relative to DATA_LENGTH (most fragmented)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(DATA_FREE / 1024 / 1024, 2)                       AS free_mb,
    ROUND(100.0 * DATA_FREE
          / NULLIF(DATA_LENGTH, 0), 2)                      AS bloat_pct,
    TABLE_ROWS                                              AS approx_rows,
    UPDATE_TIME                                             AS last_modified
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND DATA_LENGTH > 10 * 1024 * 1024   -- > 10 MB tables only
  AND DATA_FREE > DATA_LENGTH * 0.1     -- > 10% free
ORDER BY bloat_pct DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Index size vs data size (very large index relative to small table)
-- Often indicates accumulation of index pages that could be reclaimed.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND(INDEX_LENGTH / NULLIF(DATA_LENGTH, 0), 2)         AS index_to_data_ratio
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND DATA_LENGTH > 10 * 1024 * 1024
  AND INDEX_LENGTH > DATA_LENGTH
ORDER BY INDEX_LENGTH DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- InnoDB undo log size (long-running transactions cause undo log growth,
-- which is the InnoDB analog of PostgreSQL dead tuple accumulation)
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Innodb_undo_tablespaces_total',
    'Innodb_undo_tablespaces_implicit',
    'Innodb_undo_tablespaces_explicit',
    'Innodb_undo_tablespaces_active'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB buffer pool dirty page ratio
-- (high dirty page ratio = pending write pressure, similar concept to bloat)
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_dirty')   AS dirty_pages,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_total')   AS total_pages,
    ROUND(100.0
          * (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
             WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_dirty')
          / NULLIF(
              (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
               WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_total'), 0),
          2)                                                    AS dirty_pct;

-- ---------------------------------------------------------------------------
-- InnoDB tablespace free space (innodb_data_free)
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    ROUND(VARIABLE_VALUE / 1024 / 1024, 2)                  AS value_mb
FROM performance_schema.global_status
WHERE VARIABLE_NAME = 'Innodb_data_fsyncs'
   OR VARIABLE_NAME LIKE 'Innodb_data_%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB fragmentation status per table from sys schema
-- NOTE: sys.innodb_buffer_stats_by_table shows buffer usage which
--       indirectly reflects how much of each table is in memory.
-- ---------------------------------------------------------------------------
SELECT
    object_schema,
    object_name,
    allocated,
    data,
    pages,
    pages_hashed,
    pages_old,
    rows_cached
FROM sys.innodb_buffer_stats_by_table
WHERE object_schema NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
ORDER BY allocated DESC
LIMIT 30;
