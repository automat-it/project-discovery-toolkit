-- =============================================================================
-- perf_07_table_stats_health.sql
-- Priority: HIGH
-- Purpose: Check freshness of optimizer statistics and table health.
--          Stale stats produce bad plans.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have a direct equivalent of pg_stat_user_tables.
--       Table statistics are stored in information_schema.TABLES (which
--       reads InnoDB table stats). The UPDATE_TIME column tracks when
--       rows were last modified. There is no VACUUM/ANALYZE counter; MySQL
--       uses ANALYZE TABLE manually or innodb_stats_auto_recalc.
--       Dead tuples / bloat from MVCC are handled by InnoDB purge thread,
--       not exposed as row counts.

-- ---------------------------------------------------------------------------
-- Tables that have NEVER had statistics collected (no update time recorded)
-- These are tables with no data activity since creation.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    CREATE_TIME,
    UPDATE_TIME                                             AS last_modified,
    AUTO_INCREMENT
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND UPDATE_TIME IS NULL
  AND TABLE_ROWS > 0
ORDER BY TABLE_ROWS DESC;

-- ---------------------------------------------------------------------------
-- Tables with stale statistics (UPDATE_TIME older than 7 days for large tables)
-- NOTE: MySQL updates InnoDB stats automatically based on
--       innodb_stats_auto_recalc (default ON). This shows tables where
--       UPDATE_TIME is old relative to their size — useful review candidates.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    UPDATE_TIME                                             AS last_modified,
    DATEDIFF(NOW(), UPDATE_TIME)                            AS days_since_modified,
    CREATE_TIME
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND UPDATE_TIME IS NOT NULL
  AND UPDATE_TIME < DATE_SUB(NOW(), INTERVAL 7 DAY)
  AND TABLE_ROWS > 1000
ORDER BY TABLE_ROWS DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- InnoDB statistics settings (controls how stats are gathered)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_stats_persistent',
    'innodb_stats_auto_recalc',
    'innodb_stats_sample_pages',
    'innodb_stats_transient_sample_pages',
    'innodb_stats_method',
    'innodb_stats_on_metadata',
    'innodb_stats_include_delete_marked'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Tables with per-table statistics overrides (STATS_PERSISTENT, STATS_SAMPLE)
-- These are set via CREATE/ALTER TABLE ... STATS_PERSISTENT = ...
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    CREATE_OPTIONS
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND CREATE_OPTIONS LIKE '%STATS_%'
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Currently running ANALYZE TABLE or CHECK TABLE operations
-- (MySQL equivalent of autovacuum/analyze workers)
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    HOST,
    DB,
    COMMAND,
    TIME                                                    AS seconds,
    STATE,
    LEFT(INFO, 300)                                         AS query
FROM information_schema.PROCESSLIST
WHERE INFO LIKE '%ANALYZE%'
   OR INFO LIKE '%CHECK TABLE%'
   OR INFO LIKE '%OPTIMIZE%'
   OR STATE LIKE '%statistics%'
ORDER BY TIME DESC;

-- ---------------------------------------------------------------------------
-- Table sizes with row counts (data + index breakdown)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    UPDATE_TIME                                             AS last_modified
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- InnoDB persistent statistics per table (mysql.innodb_table_stats)
-- NOTE: mysql.innodb_table_stats contains the actual stats used by the
--       optimizer. last_update tells you when stats were last collected.
-- ---------------------------------------------------------------------------
SELECT
    database_name,
    table_name,
    last_update,
    n_rows,
    clustered_index_size,
    sum_of_other_index_sizes,
    DATEDIFF(NOW(), last_update)                            AS days_since_stats_update
FROM mysql.innodb_table_stats
ORDER BY days_since_stats_update DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- InnoDB persistent statistics per index (mysql.innodb_index_stats)
-- ---------------------------------------------------------------------------
SELECT
    database_name,
    table_name,
    index_name,
    last_update,
    stat_name,
    stat_value,
    sample_size,
    stat_description
FROM mysql.innodb_index_stats
WHERE stat_name IN ('n_diff_pfx01', 'size', 'n_leaf_pages')
ORDER BY database_name, table_name, index_name, stat_name
LIMIT 100;
