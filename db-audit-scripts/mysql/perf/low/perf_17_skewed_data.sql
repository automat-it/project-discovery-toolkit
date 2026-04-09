-- =============================================================================
-- perf_17_skewed_data.sql
-- Priority: LOW
-- Purpose: Detect uneven data distribution (skew) which leads to bad plans,
--          uneven parallel work, and partition hot spots.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not expose per-column statistics in a queryable catalog
--       like PostgreSQL's pg_stats (which contains n_distinct, null_frac,
--       most_common_vals, correlation, etc.).
--       InnoDB column-level statistics are limited:
--         - mysql.innodb_index_stats: n_diff_pfx01 gives approximate
--           distinct values for the leading column of each index.
--         - information_schema.COLUMNS: CARDINALITY (on STATISTICS) is
--           per-index, not per-column for non-indexed columns.
--       Full distribution analysis requires running ANALYZE TABLE and
--       reading mysql.innodb_index_stats, or using INFORMATION_SCHEMA.COLUMNS.
--       There is no built-in most_common_vals / most_common_freqs.

-- ---------------------------------------------------------------------------
-- Columns with low cardinality (potential skew if used in WHERE/JOIN)
-- Uses index cardinality from information_schema.STATISTICS as proxy.
-- ---------------------------------------------------------------------------
SELECT
    s.TABLE_SCHEMA,
    s.TABLE_NAME,
    s.INDEX_NAME,
    s.COLUMN_NAME,
    s.SEQ_IN_INDEX,
    s.CARDINALITY,
    t.TABLE_ROWS                                            AS approx_table_rows,
    CASE WHEN t.TABLE_ROWS > 0
         THEN ROUND(100.0 * s.CARDINALITY / t.TABLE_ROWS, 2)
         ELSE NULL
    END                                                     AS selectivity_pct,
    s.NULLABLE
FROM information_schema.STATISTICS s
JOIN information_schema.TABLES t
  ON  t.TABLE_SCHEMA = s.TABLE_SCHEMA
  AND t.TABLE_NAME   = s.TABLE_NAME
WHERE s.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND s.SEQ_IN_INDEX = 1
  AND s.CARDINALITY IS NOT NULL
  AND s.CARDINALITY BETWEEN 1 AND 100
  AND t.TABLE_ROWS > 1000
ORDER BY s.TABLE_SCHEMA, s.TABLE_NAME, s.CARDINALITY;

-- ---------------------------------------------------------------------------
-- Indexes with very low selectivity (cardinality < 1% of table rows)
-- These often indicate skewed data or poor index choices.
-- ---------------------------------------------------------------------------
SELECT
    s.TABLE_SCHEMA,
    s.TABLE_NAME,
    s.INDEX_NAME,
    s.COLUMN_NAME,
    s.CARDINALITY,
    t.TABLE_ROWS                                            AS approx_table_rows,
    ROUND(100.0 * s.CARDINALITY / NULLIF(t.TABLE_ROWS, 0), 4)
                                                            AS selectivity_pct
FROM information_schema.STATISTICS s
JOIN information_schema.TABLES t
  ON  t.TABLE_SCHEMA = s.TABLE_SCHEMA
  AND t.TABLE_NAME   = s.TABLE_NAME
WHERE s.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND s.SEQ_IN_INDEX = 1
  AND s.CARDINALITY IS NOT NULL
  AND t.TABLE_ROWS > 10000
  AND (100.0 * s.CARDINALITY / NULLIF(t.TABLE_ROWS, 0)) < 1.0
ORDER BY selectivity_pct ASC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Nullable columns in indexes (NULLs are invisible to unique constraints
-- and can cause unexpected distribution issues)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    INDEX_NAME,
    COLUMN_NAME,
    SEQ_IN_INDEX,
    NULLABLE,
    CARDINALITY
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND NULLABLE = 'YES'
  AND INDEX_NAME <> 'PRIMARY'
ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;

-- ---------------------------------------------------------------------------
-- Partition row count skew (for partitioned tables)
-- Uneven partition sizes indicate skewed partition keys.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    PARTITION_NAME,
    PARTITION_METHOD,
    PARTITION_EXPRESSION,
    PARTITION_DESCRIPTION,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb
FROM information_schema.PARTITIONS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND PARTITION_NAME IS NOT NULL
ORDER BY TABLE_SCHEMA, TABLE_NAME, TABLE_ROWS DESC;

-- ---------------------------------------------------------------------------
-- InnoDB index statistics: n_diff (distinct values per index prefix)
-- This is the optimizer's view of column cardinality.
-- ---------------------------------------------------------------------------
SELECT
    database_name,
    table_name,
    index_name,
    stat_name,
    stat_value                                              AS distinct_values,
    sample_size,
    stat_description,
    last_update
FROM mysql.innodb_index_stats
WHERE stat_name LIKE 'n_diff%'
ORDER BY database_name, table_name, index_name, stat_name;

-- ---------------------------------------------------------------------------
-- Tables with very high row count but low data size (may have many NULLs
-- or very narrow rows — potential skew in sparse columns)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    CASE WHEN TABLE_ROWS > 0
         THEN ROUND(DATA_LENGTH / TABLE_ROWS, 0)
         ELSE NULL
    END                                                     AS avg_bytes_per_row
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND TABLE_ROWS > 10000
ORDER BY avg_bytes_per_row ASC
LIMIT 30;
