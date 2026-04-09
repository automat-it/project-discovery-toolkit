-- =============================================================================
-- perf_18_forecast_inputs.sql
-- Priority: LOW
-- Purpose: Snapshot data points useful as inputs to capacity forecasting.
--          MySQL itself does not store time-series — these snapshots
--          should be collected periodically and stored externally
--          (Prometheus, CloudWatch, etc.) to build forecasts.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have per-database cumulative transaction/I/O counters
--       like pg_stat_database. All counters below are global.
--       There is no transaction ID wraparound concept in MySQL.
--       Collect these snapshots periodically; compare deltas for growth rates.

-- ---------------------------------------------------------------------------
-- Single-row snapshot of instance-wide usage indicators
-- ---------------------------------------------------------------------------
SELECT
    NOW()                                                   AS snapshot_at,
    (SELECT ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024 / 1024, 3)
     FROM information_schema.TABLES
     WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys')
       AND TABLE_TYPE = 'BASE TABLE')                       AS total_data_gb,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Threads_connected') + 0        AS client_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Threads_running') + 0          AS active_connections,
    @@max_connections                                       AS max_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Com_commit') + 0               AS total_commits,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Com_rollback') + 0             AS total_rollbacks,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_data_reads') + 0        AS total_disk_reads,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_data_writes') + 0       AS total_disk_writes,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests') + 0
                                                            AS total_buffer_pool_reads,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_write_requests') + 0
                                                            AS total_buffer_pool_writes;

-- ---------------------------------------------------------------------------
-- Per-schema snapshot
-- ---------------------------------------------------------------------------
SELECT
    NOW()                                                   AS snapshot_at,
    TABLE_SCHEMA,
    COUNT(*)                                                AS table_count,
    SUM(TABLE_ROWS)                                         AS approx_total_rows,
    ROUND(SUM(DATA_LENGTH) / 1024 / 1024, 2)               AS data_mb,
    ROUND(SUM(INDEX_LENGTH) / 1024 / 1024, 2)              AS index_mb,
    ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS total_mb,
    ROUND(SUM(DATA_FREE) / 1024 / 1024, 2)                 AS free_mb
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
GROUP BY TABLE_SCHEMA
ORDER BY SUM(DATA_LENGTH + INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Per-table snapshot for top 50 tables by size
-- ---------------------------------------------------------------------------
SELECT
    NOW()                                                   AS snapshot_at,
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS                                              AS approx_rows,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    ROUND(DATA_LENGTH / 1024 / 1024, 2)                     AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2)                    AS index_mb,
    ROUND(DATA_FREE / 1024 / 1024, 2)                       AS free_mb,
    UPDATE_TIME                                             AS last_modified,
    AUTO_INCREMENT
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Global status snapshot (key metrics for trending)
-- ---------------------------------------------------------------------------
SELECT
    NOW()                                                   AS snapshot_at,
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Threads_connected',
    'Threads_running',
    'Max_used_connections',
    'Com_select',
    'Com_insert',
    'Com_update',
    'Com_delete',
    'Com_commit',
    'Com_rollback',
    'Innodb_data_reads',
    'Innodb_data_writes',
    'Innodb_buffer_pool_reads',
    'Innodb_buffer_pool_read_requests',
    'Innodb_buffer_pool_write_requests',
    'Innodb_os_log_written',
    'Innodb_deadlocks',
    'Innodb_row_lock_waits',
    'Created_tmp_disk_tables',
    'Created_tmp_tables',
    'Sort_merge_passes',
    'Select_scan',
    'Bytes_received',
    'Bytes_sent',
    'Uptime'
)
ORDER BY VARIABLE_NAME;
