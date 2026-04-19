-- =============================================================================
-- perf_19_storage_topology.sql
-- Priority: MEDIUM
-- Purpose: Map MySQL storage: datadir, InnoDB system/undo/temp tablespaces,
--          file-per-table distribution, general & binlog paths, buffer
--          pool sizing vs on-disk footprint.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Server-level storage paths
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'datadir',
    'tmpdir',
    'innodb_data_home_dir',
    'innodb_data_file_path',
    'innodb_log_group_home_dir',
    'innodb_undo_directory',
    'innodb_undo_tablespaces',
    'innodb_temp_tablespaces_dir',
    'innodb_file_per_table',
    'innodb_page_size',
    'innodb_buffer_pool_size',
    'innodb_redo_log_capacity',
    'log_bin_basename',
    'log_error',
    'secure_file_priv',
    'relay_log_basename'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB tablespaces (system, per-table, general, undo, temp)
-- ---------------------------------------------------------------------------
-- NOTE: MySQL 8.0 dropped FILE_FORMAT from INNODB_TABLESPACES. The columns
-- below are the common-subset that exists on 5.7 and 8.0+.
SELECT
    NAME                          AS tablespace_name,
    SPACE_TYPE,
    ROW_FORMAT,
    PAGE_SIZE,
    ENCRYPTION,
    STATE
FROM information_schema.INNODB_TABLESPACES
ORDER BY SPACE_TYPE, NAME
LIMIT 100;

-- ---------------------------------------------------------------------------
-- On-disk file inventory for InnoDB tablespaces (.ibd files)
-- INNODB_DATAFILES links tablespace -> physical file path
-- ---------------------------------------------------------------------------
-- NOTE: INNODB_DATAFILES exposes (SPACE, PATH) only; there is no FILE_NAME.
SELECT
    t.NAME                        AS tablespace,
    t.SPACE_TYPE,
    f.PATH                        AS file_path,
    ROUND(t.FILE_SIZE/1024/1024, 2) AS file_size_mb,
    ROUND(t.ALLOCATED_SIZE/1024/1024, 2) AS allocated_mb
FROM information_schema.INNODB_TABLESPACES t
LEFT JOIN information_schema.INNODB_DATAFILES f
       ON f.SPACE = t.SPACE
ORDER BY t.FILE_SIZE DESC
LIMIT 100;

-- ---------------------------------------------------------------------------
-- Per-database size
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA                                         AS `database`,
    COUNT(*)                                             AS tables,
    ROUND(SUM(DATA_LENGTH)/1024/1024, 2)                 AS data_mb,
    ROUND(SUM(INDEX_LENGTH)/1024/1024, 2)                AS index_mb,
    ROUND(SUM(DATA_FREE)/1024/1024, 2)                   AS free_mb,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH)/1024/1024, 2)  AS total_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
GROUP BY TABLE_SCHEMA
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Top 30 largest tables (where the bytes actually live)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA                                         AS `database`,
    TABLE_NAME,
    ENGINE,
    ROW_FORMAT,
    TABLE_ROWS,
    ROUND(DATA_LENGTH/1024/1024, 2)                      AS data_mb,
    ROUND(INDEX_LENGTH/1024/1024, 2)                     AS index_mb,
    ROUND(DATA_FREE/1024/1024, 2)                        AS free_mb,
    ROUND((DATA_LENGTH+INDEX_LENGTH)/1024/1024, 2)       AS total_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY (DATA_LENGTH+INDEX_LENGTH) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Non-InnoDB tables (MyISAM/MEMORY/CSV/ARCHIVE — different backup rules)
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS,
    ROUND((DATA_LENGTH+INDEX_LENGTH)/1024/1024, 2) AS size_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND ENGINE IS NOT NULL
  AND ENGINE <> 'InnoDB'
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Binary log files on disk (master) — only populated when log_bin=ON
-- ---------------------------------------------------------------------------
-- Show the variable; actual SHOW BINARY LOGS requires REPLICATION CLIENT and
-- cannot be run from information_schema on most versions.
SELECT VARIABLE_VALUE AS log_bin_state
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'log_bin';

-- ---------------------------------------------------------------------------
-- Buffer pool vs data footprint (cache headroom indicator)
-- ---------------------------------------------------------------------------
SELECT
    ROUND(@@innodb_buffer_pool_size/1024/1024, 0)                           AS buffer_pool_mb,
    ROUND(SUM(DATA_LENGTH+INDEX_LENGTH)/1024/1024, 0)                       AS data_plus_idx_mb,
    ROUND(100.0 * @@innodb_buffer_pool_size
          / NULLIF(SUM(DATA_LENGTH+INDEX_LENGTH), 0), 1)                    AS pool_to_data_pct
FROM information_schema.TABLES
WHERE ENGINE = 'InnoDB';

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    @@datadir                                                               AS datadir,
    @@innodb_data_home_dir                                                  AS innodb_home,
    (SELECT COUNT(*) FROM information_schema.INNODB_TABLESPACES)            AS innodb_tablespaces,
    (SELECT COUNT(*) FROM information_schema.INNODB_TABLESPACES
       WHERE SPACE_TYPE = 'Single')                                         AS file_per_table_tablespaces,
    (SELECT COUNT(DISTINCT ENGINE) FROM information_schema.TABLES
       WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')) AS distinct_engines_used;
