-- =============================================================================
-- perf_14_checkpoint_bgwriter.sql
-- Priority: MEDIUM
-- Purpose: Checkpoint behaviour, lazy writer activity, log flush
--          throughput. Forced / aggressive checkpoints cause latency
--          spikes; slow log flushes starve OLTP.
-- Sources: sys.dm_os_performance_counters,
--          sys.dm_io_virtual_file_stats, sys.dm_db_log_stats (2017+).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Checkpoint / lazy writer counters
-- ---------------------------------------------------------------------------
SELECT
    object_name,
    counter_name,
    instance_name,
    cntr_value                                        AS counter_value,
    cntr_type
FROM sys.dm_os_performance_counters
WHERE counter_name IN (
    'Checkpoint pages/sec',
    'Lazy writes/sec',
    'Background writer pages/sec',
    'Page reads/sec',
    'Page writes/sec',
    'Readahead pages/sec',
    'Free list stalls/sec',
    'Log Flushes/sec',
    'Log Flush Wait Time',
    'Log Flush Waits/sec',
    'Log Flushes/sec',
    'Page Splits/sec')
ORDER BY object_name, counter_name, instance_name;

-- ---------------------------------------------------------------------------
-- Checkpoint-related configuration
-- ---------------------------------------------------------------------------
SELECT
    name, value, value_in_use
FROM sys.configurations
WHERE name IN ('recovery interval (min)');

-- ---------------------------------------------------------------------------
-- Per-database log file statistics (2017+)
-- Works on Linux / recent builds; on older editions use DBCC LOGINFO.
-- ---------------------------------------------------------------------------
-- NOTE: the columns below use the SQL Server 2017+ naming
-- (total_log_size_mb / active_log_size_mb). Older builds exposed
-- total_log_size_in_bytes / active_log_size_in_bytes — those were renamed.
BEGIN TRY
    SELECT
        DB_NAME(ls.database_id)                       AS database_name,
        ls.total_log_size_mb,
        ls.active_log_size_mb,
        ls.log_backup_time,
        ls.log_backup_lsn,
        ls.log_since_last_log_backup_mb,
        ls.log_truncation_holdup_reason
    FROM sys.dm_db_log_stats(DB_ID()) ls;
END TRY
BEGIN CATCH
    PRINT '[note] sys.dm_db_log_stats unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Database log file size and log reuse wait cause
-- (why isn't the log shrinking?)
-- ---------------------------------------------------------------------------
SELECT
    d.name                                            AS database_name,
    d.log_reuse_wait_desc,
    d.recovery_model_desc,
    mf.name                                           AS logical_log_file,
    CAST(CAST(mf.size AS BIGINT) * 8.0 / 1024 AS DECIMAL(18,2))       AS log_size_mb,
    CASE WHEN mf.is_percent_growth = 1
         THEN CONCAT(mf.growth, '%')
         ELSE CONCAT(CAST(mf.growth AS BIGINT) * 8 / 1024, ' MB')
    END                                               AS log_growth_setting,
    CASE WHEN mf.max_size = -1 THEN 'unlimited'
         ELSE CAST(CAST(mf.max_size AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                               AS log_max_size
FROM sys.databases d
JOIN sys.master_files mf
      ON mf.database_id = d.database_id
     AND mf.type = 1                                   -- log files only
WHERE d.database_id > 4
ORDER BY d.name;

-- ---------------------------------------------------------------------------
-- Per-file I/O throughput (focus on log files — checkpoint / commit writes)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(vfs.database_id)                          AS database_name,
    mf.name                                           AS logical_file,
    mf.type_desc                                      AS file_type,
    vfs.num_of_writes,
    CAST(vfs.num_of_bytes_written / 1024.0 / 1024 AS DECIMAL(18,2)) AS mb_written,
    vfs.io_stall_write_ms                             AS total_write_stall_ms,
    CAST(vfs.io_stall_write_ms / NULLIF(vfs.num_of_writes, 0) AS DECIMAL(18,2)) AS avg_write_stall_ms
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
JOIN sys.master_files mf
      ON mf.database_id = vfs.database_id
     AND mf.file_id     = vfs.file_id
WHERE mf.type = 1                                      -- log files
ORDER BY vfs.num_of_writes DESC;

-- ---------------------------------------------------------------------------
-- WRITELOG waits (persistent log-flush pressure)
-- ---------------------------------------------------------------------------
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    CAST(wait_time_ms / NULLIF(waiting_tasks_count, 0) AS DECIMAL(18,2)) AS avg_wait_ms
FROM sys.dm_os_wait_stats
WHERE wait_type IN ('WRITELOG','LOGMGR','LOGMGR_QUEUE','LOGBUFFER',
                    'LOGMGR_FLUSH','LOG_RATE_GOVERNOR')
ORDER BY wait_time_ms DESC;

-- ---------------------------------------------------------------------------
-- Quick interpretation hints
-- ---------------------------------------------------------------------------
SELECT
    'avg_write_stall_ms for log file > 5ms = commit latency pressure'  AS hint_1,
    'Free list stalls/sec > 0 = lazy writer cannot keep up with buffer pool pressure' AS hint_2,
    'Checkpoint pages/sec spikes + high WRITELOG = consider checkpoint smoothing / faster disk' AS hint_3,
    'log_reuse_wait_desc <> NOTHING = log will keep growing until the blocker clears' AS hint_4;
