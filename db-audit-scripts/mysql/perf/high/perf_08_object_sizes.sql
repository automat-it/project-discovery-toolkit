-- =============================================================================
-- perf_08_object_sizes.sql
-- Priority: HIGH
-- Purpose: Largest tables and indexes, growth hotspots.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL exposes size data via information_schema.TABLES (DATA_LENGTH,
--       INDEX_LENGTH). There is no TOAST concept in MySQL; large values
--       are handled by InnoDB's off-page storage transparently.
--       Partition sizes are available via information_schema.PARTITIONS.
--       There is no direct equivalent of pg_database_size() per-schema
--       aggregation — we sum DATA_LENGTH + INDEX_LENGTH per schema.

-- ---------------------------------------------------------------------------
-- Database (schema) sizes
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA                                            AS schema_name,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)
                                                            AS total_mb,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024 / 1024, 3)
                                                            AS total_gb,
    SUM(TABLE_ROWS)                                         AS approx_total_rows,
    COUNT(*)                                                AS table_count
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('information_schema', 'performance_schema', 'sys')
GROUP BY TABLE_SCHEMA
ORDER BY SUM(DATA_LENGTH + INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Top 50 largest tables (data + indexes)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    -- NOTE: MySQL has no direct TOAST equivalent;
    --       InnoDB stores overflow pages transparently (ROW_FORMAT affects this)
    ROW_FORMAT,
    AUTO_INCREMENT,
    UPDATE_TIME                                             AS last_modified
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Top 50 largest indexes
-- NOTE: information_schema.STATISTICS does not expose individual index sizes.
--       Index sizes are aggregated per table in INDEX_LENGTH. For per-index
--       sizes use sys.schema_index_statistics or InnoDB internal pages.
--       The query below shows tables by INDEX_LENGTH as the best proxy.
-- ---------------------------------------------------------------------------
SELECT
    s.TABLE_SCHEMA,
    s.TABLE_NAME,
    s.INDEX_NAME,
    s.INDEX_TYPE,
    s.NON_UNIQUE,
    s.CARDINALITY,
    -- Index size is not available per-index; show table total as context
    ROUND(t.INDEX_LENGTH / 1024 / 1024, 2)                  AS table_index_mb,
    ROUND(t.DATA_LENGTH / 1024 / 1024, 2)                   AS table_data_mb
FROM information_schema.STATISTICS s
JOIN information_schema.TABLES t
  ON  t.TABLE_SCHEMA = s.TABLE_SCHEMA
  AND t.TABLE_NAME   = s.TABLE_NAME
WHERE s.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND s.SEQ_IN_INDEX = 1
ORDER BY t.INDEX_LENGTH DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Tables where index size EXCEEDS data size (write overhead candidates)
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
-- Views inventory
-- (MySQL does not have materialized views natively)
-- NOTE: MySQL 8.0 has no MATERIALIZED VIEW. Regular views are listed here.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME                                              AS view_name,
    VIEW_DEFINITION,
    IS_UPDATABLE,
    DEFINER,
    SECURITY_TYPE
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Partition sizes (for partitioned tables)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    PARTITION_NAME,
    SUBPARTITION_NAME,
    PARTITION_METHOD,
    PARTITION_EXPRESSION,
    PARTITION_DESCRIPTION,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb
FROM information_schema.PARTITIONS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND PARTITION_NAME IS NOT NULL
ORDER BY TABLE_SCHEMA, TABLE_NAME, PARTITION_ORDINAL_POSITION;

-- ---------------------------------------------------------------------------
-- Free space per schema (DATA_FREE = estimated reclaimable space)
-- This is approximate — InnoDB reports the free space in the tablespace,
-- not a precise "wasted" figure.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    ROUND(SUM(DATA_FREE) / 1024 / 1024, 2)                 AS free_mb,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS used_mb,
    ROUND(100.0 * SUM(DATA_FREE)
          / NULLIF(SUM(DATA_LENGTH + INDEX_LENGTH + DATA_FREE), 0), 2)
                                                            AS free_pct
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
GROUP BY TABLE_SCHEMA
ORDER BY SUM(DATA_FREE) DESC;
