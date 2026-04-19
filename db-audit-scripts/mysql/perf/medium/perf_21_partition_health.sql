-- =============================================================================
-- perf_21_partition_health.sql
-- Priority: MEDIUM
-- Purpose: Inventory partitioned tables, partition methods, per-partition
--          row/size distribution, sub-partitioning. MySQL partitioning
--          has strict constraints (every UNIQUE key must include the
--          partition expression) — mis-use shows up here.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Partitioned-table inventory — one row per *partition*, so the count
-- of partitions per table is a GROUP BY away.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    PARTITION_METHOD,
    SUBPARTITION_METHOD,
    PARTITION_EXPRESSION,
    SUBPARTITION_EXPRESSION,
    COUNT(*)                                              AS partition_count,
    SUM(TABLE_ROWS)                                       AS est_rows_total,
    ROUND(SUM(DATA_LENGTH)  / 1024 / 1024, 1)             AS data_mb,
    ROUND(SUM(INDEX_LENGTH) / 1024 / 1024, 1)             AS index_mb
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
GROUP BY TABLE_SCHEMA, TABLE_NAME, PARTITION_METHOD,
         SUBPARTITION_METHOD, PARTITION_EXPRESSION, SUBPARTITION_EXPRESSION
ORDER BY data_mb DESC;

-- ---------------------------------------------------------------------------
-- Per-partition detail — row skew across partitions signals a bad
-- partition key (hot partition hogs all the writes).
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    PARTITION_NAME,
    PARTITION_ORDINAL_POSITION                            AS ord,
    PARTITION_DESCRIPTION,
    TABLE_ROWS,
    ROUND(DATA_LENGTH  / 1024 / 1024, 1)                  AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 1)                  AS index_mb,
    CREATE_TIME,
    UPDATE_TIME
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
ORDER BY DATA_LENGTH DESC
LIMIT 300;

-- ---------------------------------------------------------------------------
-- Partition-count distribution per table — MySQL hard-limits at 8 192
-- partitions per table (including sub-partitions). Tables nearing
-- the limit can't grow.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    COUNT(*)                                              AS partition_count,
    CASE
        WHEN COUNT(*) > 4096 THEN 'critical — approaching 8192 hard limit'
        WHEN COUNT(*) > 1024 THEN 'high — review retention'
        WHEN COUNT(*) > 100  THEN 'moderate'
        ELSE 'ok'
    END                                                   AS assessment
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
GROUP BY TABLE_SCHEMA, TABLE_NAME
HAVING COUNT(*) > 10
ORDER BY partition_count DESC;

-- ---------------------------------------------------------------------------
-- Partitioning-method mix
-- ---------------------------------------------------------------------------
SELECT
    PARTITION_METHOD,
    COUNT(DISTINCT CONCAT(TABLE_SCHEMA, '.', TABLE_NAME)) AS tables_using
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
GROUP BY PARTITION_METHOD
ORDER BY tables_using DESC;

-- ---------------------------------------------------------------------------
-- Tables with MAXVALUE (range) / DEFAULT (list) catch-all partitions —
-- missing catch-all on RANGE causes INSERTs to fail on unmatched values.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    PARTITION_METHOD,
    SUM(CASE WHEN PARTITION_DESCRIPTION IN ('MAXVALUE','DEFAULT') THEN 1 ELSE 0 END) AS has_catchall,
    COUNT(*) AS partition_count
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND PARTITION_METHOD IN ('RANGE','RANGE COLUMNS','LIST','LIST COLUMNS')
GROUP BY TABLE_SCHEMA, TABLE_NAME, PARTITION_METHOD
ORDER BY has_catchall, TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Last UPDATE_TIME per partition — cold (never updated) partitions are
-- retention candidates; hot partitions reveal write pattern.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA, TABLE_NAME, PARTITION_NAME,
    UPDATE_TIME, CREATE_TIME, TABLE_ROWS
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND UPDATE_TIME IS NOT NULL
ORDER BY UPDATE_TIME DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    COUNT(DISTINCT CONCAT(TABLE_SCHEMA,'.',TABLE_NAME))   AS partitioned_tables,
    COUNT(*)                                              AS total_partitions,
    SUM(DATA_LENGTH + INDEX_LENGTH) DIV (1024*1024)       AS total_mb
FROM information_schema.PARTITIONS
WHERE PARTITION_NAME IS NOT NULL
  AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');
