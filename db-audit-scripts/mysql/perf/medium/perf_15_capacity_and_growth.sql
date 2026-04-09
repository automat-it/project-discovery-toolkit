-- =============================================================================
-- perf_15_capacity_and_growth.sql
-- Priority: MEDIUM
-- Purpose: Snapshot of storage usage, connection trends, and other
--          capacity indicators for resource planning.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have transaction ID wraparound (no XID age concept).
--       Tablespaces are not exposed as directly as pg_tablespace.
--       Sequence headroom maps to AUTO_INCREMENT columns.
--       Per-database transaction counts are not available as cumulative
--       per-schema counters (only global counters exist).

-- ---------------------------------------------------------------------------
-- Total storage usage across all user schemas
-- ---------------------------------------------------------------------------
SELECT
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024 / 1024, 3)
                                                            AS total_data_gb,
    ROUND(SUM(DATA_FREE) / 1024 / 1024 / 1024, 3)          AS total_free_gb,
    COUNT(DISTINCT TABLE_SCHEMA)                            AS user_schema_count,
    COUNT(*)                                                AS table_count
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys');

-- ---------------------------------------------------------------------------
-- Per-schema size and growth indicators
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    ROUND(SUM(DATA_LENGTH) / 1024 / 1024, 2)               AS data_mb,
    ROUND(SUM(INDEX_LENGTH) / 1024 / 1024, 2)              AS index_mb,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS total_mb,
    ROUND(SUM(DATA_FREE) / 1024 / 1024, 2)                 AS free_mb,
    SUM(TABLE_ROWS)                                         AS approx_total_rows,
    COUNT(*)                                                AS table_count
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
GROUP BY TABLE_SCHEMA
ORDER BY SUM(DATA_LENGTH + INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Largest tables with row counts
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    UPDATE_TIME                                             AS last_modified,
    AUTO_INCREMENT
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Connection limits and headroom
-- ---------------------------------------------------------------------------
SELECT
    @@max_connections                                       AS max_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Threads_connected') + 0        AS current_connections,
    @@max_connections
        - (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
           WHERE VARIABLE_NAME = 'Threads_connected')       AS available_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Max_used_connections')          AS peak_connections;

-- ---------------------------------------------------------------------------
-- AUTO_INCREMENT headroom (analogous to sequence headroom in PostgreSQL)
-- Identifies tables where AUTO_INCREMENT is approaching the column type limit.
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.AUTO_INCREMENT,
    c.DATA_TYPE                                             AS column_type,
    c.COLUMN_NAME,
    c.COLUMN_TYPE,
    CASE c.DATA_TYPE
        WHEN 'tinyint'   THEN 127
        WHEN 'smallint'  THEN 32767
        WHEN 'mediumint' THEN 8388607
        WHEN 'int'       THEN 2147483647
        WHEN 'bigint'    THEN 9223372036854775807
        ELSE NULL
    END                                                     AS max_value,
    CASE c.DATA_TYPE
        WHEN 'tinyint'   THEN ROUND(100.0 * t.AUTO_INCREMENT / 127, 4)
        WHEN 'smallint'  THEN ROUND(100.0 * t.AUTO_INCREMENT / 32767, 4)
        WHEN 'mediumint' THEN ROUND(100.0 * t.AUTO_INCREMENT / 8388607, 4)
        WHEN 'int'       THEN ROUND(100.0 * t.AUTO_INCREMENT / 2147483647, 4)
        WHEN 'bigint'    THEN ROUND(100.0 * t.AUTO_INCREMENT / 9223372036854775807, 8)
        ELSE NULL
    END                                                     AS pct_consumed
FROM information_schema.TABLES t
JOIN information_schema.COLUMNS c
  ON  c.TABLE_SCHEMA = t.TABLE_SCHEMA
  AND c.TABLE_NAME   = t.TABLE_NAME
  AND c.EXTRA LIKE '%auto_increment%'
WHERE t.AUTO_INCREMENT IS NOT NULL
  AND t.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
ORDER BY pct_consumed DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Global write activity counters (proxy for growth rate)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Com_insert',
    'Com_update',
    'Com_delete',
    'Com_replace',
    'Com_insert_select',
    'Com_update_multi',
    'Com_delete_multi',
    'Handler_write',
    'Handler_update',
    'Handler_delete'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB tablespace file sizes (approximate disk usage)
-- NOTE: MySQL 8.0 exposes tablespace info via information_schema.FILES
-- ---------------------------------------------------------------------------
SELECT
    FILE_NAME,
    FILE_TYPE,
    TABLESPACE_NAME,
    ROUND(TOTAL_EXTENTS * EXTENT_SIZE / 1024 / 1024, 2)    AS allocated_mb,
    ROUND(FREE_EXTENTS * EXTENT_SIZE / 1024 / 1024, 2)     AS free_mb,
    ROUND((TOTAL_EXTENTS - FREE_EXTENTS) * EXTENT_SIZE
          / 1024 / 1024, 2)                                 AS used_mb
FROM information_schema.FILES
WHERE FILE_TYPE IN ('TABLESPACE', 'TEMPORARY')
  AND TOTAL_EXTENTS IS NOT NULL
ORDER BY (TOTAL_EXTENTS - FREE_EXTENTS) * EXTENT_SIZE DESC;
