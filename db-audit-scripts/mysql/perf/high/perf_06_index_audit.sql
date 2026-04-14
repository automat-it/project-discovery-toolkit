-- =============================================================================
-- perf_06_index_audit.sql
-- Priority: HIGH
-- Purpose: Find unused, duplicate, invalid, and missing indexes.
--          Direct impact on read latency and write overhead.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL index statistics come from information_schema.STATISTICS and
--       performance_schema / sys.schema_unused_indexes. There is no
--       pg_stat_user_indexes equivalent with idx_scan counters per index
--       unless performance_schema table_io_waits_summary_by_index_usage
--       is used. Unused index detection relies on
--       performance_schema.table_io_waits_summary_by_index_usage.
--       sys.schema_unused_indexes is a convenience view (requires sys schema).

-- ---------------------------------------------------------------------------
-- Unused indexes (zero I/O waits recorded since last stats reset)
-- Requires: performance_schema = ON and table_io_waits instrumented.
-- Excludes PRIMARY KEY indexes.
-- ---------------------------------------------------------------------------
SELECT
    object_schema                                           AS schema_name,
    object_name                                             AS table_name,
    index_name,
    -- NOTE: MySQL does not store index sizes in information_schema directly;
    --       see sys.schema_index_statistics for size approximations.
    -- `reads` and `writes` are reserved in MySQL (READS SQL DATA clause
    -- for routines); quote the aliases so the statement parses.
    count_read                                              AS `reads`,
    count_write                                             AS `writes`,
    count_fetch                                             AS fetches
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NOT NULL
  AND index_name <> 'PRIMARY'
  AND count_star = 0
  AND object_schema NOT IN ('mysql', 'information_schema',
                             'performance_schema', 'sys')
ORDER BY object_schema, object_name, index_name;

-- ---------------------------------------------------------------------------
-- sys convenience view for unused indexes
-- NOTE: sys schema must be installed (default in MySQL 8.0).
-- ---------------------------------------------------------------------------
SELECT
    object_schema,
    object_name                                             AS table_name,
    index_name
FROM sys.schema_unused_indexes
WHERE object_schema NOT IN ('mysql', 'information_schema',
                             'performance_schema', 'sys')
ORDER BY object_schema, object_name, index_name;

-- ---------------------------------------------------------------------------
-- All user-defined indexes (full inventory)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA                                            AS schema_name,
    TABLE_NAME,
    INDEX_NAME,
    INDEX_TYPE,
    NON_UNIQUE,
    SEQ_IN_INDEX,
    COLUMN_NAME,
    CARDINALITY,
    NULLABLE,
    INDEX_COMMENT
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;

-- ---------------------------------------------------------------------------
-- Duplicate indexes: same table + same column set (first columns match)
-- NOTE: MySQL allows duplicate indexes — they impose write overhead and
--       waste space but are not automatically prevented.
-- ---------------------------------------------------------------------------
SELECT
    s1.TABLE_SCHEMA                                         AS schema_name,
    s1.TABLE_NAME,
    s1.INDEX_NAME                                           AS index_a,
    s2.INDEX_NAME                                           AS index_b,
    s1.COLUMN_NAME                                          AS column_name,
    s1.SEQ_IN_INDEX                                         AS position,
    'Review — indexes share the same leading columns' AS note
FROM information_schema.STATISTICS s1
JOIN information_schema.STATISTICS s2
  ON  s1.TABLE_SCHEMA   = s2.TABLE_SCHEMA
  AND s1.TABLE_NAME     = s2.TABLE_NAME
  AND s1.SEQ_IN_INDEX   = s2.SEQ_IN_INDEX
  AND s1.COLUMN_NAME    = s2.COLUMN_NAME
  AND s1.INDEX_NAME    <> s2.INDEX_NAME
  AND s1.INDEX_NAME     < s2.INDEX_NAME
WHERE s1.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                               'performance_schema', 'sys')
  AND s1.INDEX_NAME <> 'PRIMARY'
ORDER BY s1.TABLE_SCHEMA, s1.TABLE_NAME, s1.INDEX_NAME, s2.INDEX_NAME;

-- ---------------------------------------------------------------------------
-- Tables with no indexes at all (excluding small tables by row estimate)
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
  AND t.TABLE_ROWS > 1000
ORDER BY t.TABLE_ROWS DESC;

-- ---------------------------------------------------------------------------
-- Missing index hints: tables with high full-scan I/O (rows fetched with
-- no index use vs total rows fetched)
-- ---------------------------------------------------------------------------
SELECT
    object_schema                                           AS schema_name,
    object_name                                             AS table_name,
    count_read                                              AS full_table_reads,
    count_fetch                                             AS index_fetches,
    ROUND(100.0 * count_read
          / NULLIF(count_read + count_fetch, 0), 2)         AS full_scan_pct
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NULL        -- NULL index_name = full table scan (no index)
  AND count_read > 100
  AND object_schema NOT IN ('mysql', 'information_schema',
                             'performance_schema', 'sys')
ORDER BY count_read DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Foreign keys and their supporting indexes.
-- InnoDB requires an index on the referencing column(s) and creates one
-- automatically if none exists, but for a COMPOSITE foreign key a manually
-- chosen index may cover only the leading column — leaving the FK unsupported
-- for cascades / lookups on the full column set. The previous query matched
-- ONLY on SEQ_IN_INDEX = 1, so it always returned "supported" for any FK
-- whose first column was indexed, hiding exactly the case that matters.
--
-- This version aggregates the FK column list (in KEY position order) and the
-- leading prefix of every candidate index on the same table, then flags any
-- FK whose full ordered column list is NOT a prefix of at least one index.
-- ---------------------------------------------------------------------------
WITH fk_cols AS (
    SELECT
        kcu.TABLE_SCHEMA,
        kcu.TABLE_NAME,
        kcu.CONSTRAINT_NAME,
        kcu.REFERENCED_TABLE_SCHEMA,
        kcu.REFERENCED_TABLE_NAME,
        GROUP_CONCAT(kcu.COLUMN_NAME
                     ORDER BY kcu.ORDINAL_POSITION
                     SEPARATOR ',')                          AS fk_col_list,
        GROUP_CONCAT(kcu.REFERENCED_COLUMN_NAME
                     ORDER BY kcu.ORDINAL_POSITION
                     SEPARATOR ',')                          AS ref_col_list,
        MAX(kcu.ORDINAL_POSITION)                            AS fk_col_count
    FROM information_schema.KEY_COLUMN_USAGE kcu
    WHERE kcu.REFERENCED_TABLE_NAME IS NOT NULL
      AND kcu.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                    'performance_schema', 'sys')
    GROUP BY kcu.TABLE_SCHEMA, kcu.TABLE_NAME, kcu.CONSTRAINT_NAME,
             kcu.REFERENCED_TABLE_SCHEMA, kcu.REFERENCED_TABLE_NAME
),
idx_prefixes AS (
    -- For every index, materialize the leading-column prefix (in order).
    -- We only need prefixes up to the largest FK width we'll check against.
    SELECT
        s.TABLE_SCHEMA,
        s.TABLE_NAME,
        s.INDEX_NAME,
        GROUP_CONCAT(s.COLUMN_NAME
                     ORDER BY s.SEQ_IN_INDEX
                     SEPARATOR ',')                          AS index_col_list
    FROM information_schema.STATISTICS s
    WHERE s.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                  'performance_schema', 'sys')
    GROUP BY s.TABLE_SCHEMA, s.TABLE_NAME, s.INDEX_NAME
)
SELECT
    f.TABLE_SCHEMA                                           AS schema_name,
    f.TABLE_NAME,
    f.CONSTRAINT_NAME                                        AS fk_name,
    f.fk_col_list                                            AS fk_columns,
    f.REFERENCED_TABLE_SCHEMA,
    f.REFERENCED_TABLE_NAME,
    f.ref_col_list                                           AS referenced_columns,
    COALESCE(
        (
            SELECT GROUP_CONCAT(ip.INDEX_NAME SEPARATOR ', ')
            FROM idx_prefixes ip
            WHERE ip.TABLE_SCHEMA = f.TABLE_SCHEMA
              AND ip.TABLE_NAME   = f.TABLE_NAME
              -- Require the index's leading column list to START WITH the
              -- FK column list in order. Appending a comma avoids matching
              -- "col1" when FK is "col1_extra".
              AND (ip.index_col_list = f.fk_col_list
                OR ip.index_col_list LIKE CONCAT(f.fk_col_list, ',%'))
        ),
        'NO FULL COVERING INDEX'
    )                                                         AS supporting_indexes
FROM fk_cols f
ORDER BY f.TABLE_SCHEMA, f.TABLE_NAME, f.CONSTRAINT_NAME;

-- ---------------------------------------------------------------------------
-- Index usage statistics (top by reads — most used indexes)
-- ---------------------------------------------------------------------------
SELECT
    object_schema                                           AS schema_name,
    object_name                                             AS table_name,
    index_name,
    count_star                                              AS total_io,
    count_read                                              AS `reads`,
    count_write                                             AS `writes`,
    count_fetch                                             AS fetches,
    ROUND(sum_timer_wait / 1e12, 2)                         AS total_wait_ms
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NOT NULL
  AND count_star > 0
  AND object_schema NOT IN ('mysql', 'information_schema',
                             'performance_schema', 'sys')
ORDER BY count_read DESC
LIMIT 30;
