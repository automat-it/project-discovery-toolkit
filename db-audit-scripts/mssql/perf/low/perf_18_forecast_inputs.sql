-- =============================================================================
-- perf_18_forecast_inputs.sql
-- Priority: LOW
-- Purpose: Snapshot data points suitable as inputs to external capacity
--          forecasting (Prometheus / CloudWatch / Grafana / PowerBI).
--          SQL Server does not store time-series natively — run this
--          periodically and push the results to a time-series store.
-- Sources: sys.databases, sys.master_files, sys.dm_db_partition_stats,
--          sys.dm_os_performance_counters, sys.identity_columns.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Single-row snapshot of cluster-wide usage indicators
-- ---------------------------------------------------------------------------
SELECT
    SYSUTCDATETIME()                                  AS snapshot_at,
    (SELECT SUM(CAST(size AS BIGINT)) * 8 / 1024
       FROM sys.master_files
      WHERE database_id > 4)                          AS total_user_db_mb,
    (SELECT COUNT(*) FROM sys.databases
      WHERE database_id > 4)                          AS user_database_count,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions
      WHERE is_user_process = 1)                      AS current_user_sessions,
    (SELECT CAST(value_in_use AS INT) FROM sys.configurations
      WHERE name = 'user connections')                AS configured_max_connections,
    (SELECT TOP 1 cntr_value FROM sys.dm_os_performance_counters
      WHERE counter_name = 'Batch Requests/sec')      AS batch_requests_per_sec,
    (SELECT TOP 1 cntr_value FROM sys.dm_os_performance_counters
      WHERE counter_name = 'User Connections')        AS user_connection_counter;

-- ---------------------------------------------------------------------------
-- Per-database snapshot
-- ---------------------------------------------------------------------------
SELECT
    SYSUTCDATETIME()                                  AS snapshot_at,
    d.name                                            AS database_name,
    d.state_desc,
    d.recovery_model_desc,
    SUM(CASE WHEN mf.type = 0 THEN CAST(mf.size AS BIGINT) END) * 8 / 1024 AS data_mb,
    SUM(CASE WHEN mf.type = 1 THEN CAST(mf.size AS BIGINT) END) * 8 / 1024 AS log_mb,
    d.create_date,
    d.is_query_store_on,
    d.is_cdc_enabled
FROM sys.databases d
JOIN sys.master_files mf ON mf.database_id = d.database_id
WHERE d.database_id > 4
GROUP BY d.name, d.state_desc, d.recovery_model_desc, d.create_date,
         d.is_query_store_on, d.is_cdc_enabled
ORDER BY data_mb DESC;

-- ---------------------------------------------------------------------------
-- Per-table snapshot for the current database (top 50 by size)
-- ---------------------------------------------------------------------------
SELECT TOP 50
    SYSUTCDATETIME()                                  AS snapshot_at,
    DB_NAME()                                         AS database_name,
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    SUM(ps.row_count)                                 AS row_count,
    SUM(ps.reserved_page_count) * 8                   AS reserved_kb,
    SUM(ps.in_row_data_page_count) * 8                AS in_row_data_kb,
    SUM(ps.lob_reserved_page_count) * 8               AS lob_kb
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name
ORDER BY SUM(ps.reserved_page_count) DESC;

-- ---------------------------------------------------------------------------
-- Per-file I/O snapshot (cumulative, rate = diff between samples)
-- ---------------------------------------------------------------------------
SELECT
    SYSUTCDATETIME()                                  AS snapshot_at,
    DB_NAME(vfs.database_id)                          AS database_name,
    mf.name                                           AS logical_file,
    mf.type_desc,
    vfs.num_of_reads,
    vfs.num_of_writes,
    vfs.num_of_bytes_read,
    vfs.num_of_bytes_written,
    vfs.io_stall_read_ms,
    vfs.io_stall_write_ms
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
JOIN sys.master_files mf
      ON mf.database_id = vfs.database_id
     AND mf.file_id     = vfs.file_id
WHERE vfs.database_id > 4;

-- ---------------------------------------------------------------------------
-- Identity headroom for future-date alerting
-- ---------------------------------------------------------------------------
SELECT
    SYSUTCDATETIME()                                  AS snapshot_at,
    DB_NAME()                                         AS database_name,
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    ic.name                                           AS column_name,
    TYPE_NAME(ic.user_type_id)                        AS data_type,
    CAST(ic.last_value AS BIGINT)                     AS last_value,
    CASE TYPE_NAME(ic.user_type_id)
        WHEN 'int'    THEN CAST(100.0 * CAST(ic.last_value AS BIGINT) / 2147483647 AS DECIMAL(6,4))
        WHEN 'bigint' THEN CAST(100.0 * CAST(ic.last_value AS DECIMAL(38,0)) / 9223372036854775807 AS DECIMAL(8,6))
        ELSE NULL
    END                                               AS pct_consumed
FROM sys.identity_columns ic
JOIN sys.objects o ON o.object_id = ic.object_id
WHERE o.is_ms_shipped = 0
  AND ic.last_value IS NOT NULL
ORDER BY pct_consumed DESC;

-- ---------------------------------------------------------------------------
-- Global performance counters useful as forecasting inputs
-- ---------------------------------------------------------------------------
SELECT
    SYSUTCDATETIME()                                  AS snapshot_at,
    object_name,
    counter_name,
    instance_name,
    cntr_value
FROM sys.dm_os_performance_counters
WHERE counter_name IN (
    'Batch Requests/sec',
    'User Connections',
    'Active Transactions',
    'Log Flushes/sec',
    'Page reads/sec',
    'Page writes/sec',
    'Full Scans/sec',
    'Range Scans/sec',
    'Index Searches/sec',
    'Forwarded Records/sec',
    'Transactions/sec')
  AND (instance_name = '' OR instance_name = '_Total' OR instance_name = 'master');
