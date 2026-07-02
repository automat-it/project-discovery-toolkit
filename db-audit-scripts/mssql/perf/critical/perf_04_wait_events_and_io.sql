-- =============================================================================
-- perf_04_wait_events_and_io.sql
-- Priority: CRITICAL
-- Purpose: Identify the bottleneck — CPU, disk I/O, locks, network — via
--          wait statistics and I/O counters.
-- Sources: sys.dm_os_wait_stats, sys.dm_exec_requests,
--          sys.dm_io_virtual_file_stats, sys.dm_os_performance_counters.
-- Read-only.
-- =============================================================================

-- Portability: this script reads sys.master_files, which is NOT
-- supported on Azure SQL Database (single DB). It works on SQL
-- Server 2019+ on-prem, SQL Managed Instance, and Azure SQL DB
-- Hyperscale. Skip this script on Azure SQL DB.
SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Current wait breakdown (active sessions only — snapshot)
-- ---------------------------------------------------------------------------
SELECT
    COALESCE(r.wait_type, 'CPU/Running')              AS wait_type,
    COUNT(*)                                          AS sessions,
    CAST(100.0 * COUNT(*) / SUM(COUNT(*)) OVER () AS DECIMAL(5,2)) AS pct
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
WHERE s.is_user_process = 1
  AND r.session_id <> @@SPID
GROUP BY r.wait_type
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Top accumulated wait types (server lifetime)
-- Excludes the standard "benign" waits commonly filtered out (sleep,
-- broker, hadr idles, system tasks) so the signal is what actually
-- affected user workloads.
-- ---------------------------------------------------------------------------
SELECT TOP 30
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    CAST(wait_time_ms / 1000.0 / 60 AS DECIMAL(18,2))  AS wait_minutes,
    signal_wait_time_ms,
    CAST(100.0 * signal_wait_time_ms / NULLIF(wait_time_ms, 0) AS DECIMAL(5,2)) AS signal_pct,
    CAST(wait_time_ms / NULLIF(waiting_tasks_count, 0) AS DECIMAL(18,2)) AS avg_wait_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'BROKER_EVENTHANDLER','BROKER_RECEIVE_WAITFOR','BROKER_TASK_STOP',
    'BROKER_TO_FLUSH','BROKER_TRANSMITTER','CHECKPOINT_QUEUE',
    'CHKPT','CLR_AUTO_EVENT','CLR_MANUAL_EVENT','CLR_SEMAPHORE',
    'DBMIRROR_DBM_EVENT','DBMIRROR_EVENTS_QUEUE','DBMIRROR_WORKER_QUEUE',
    'DBMIRRORING_CMD','DIRTY_PAGE_POLL','DISPATCHER_QUEUE_SEMAPHORE',
    'EXECSYNC','FSAGENT','FT_IFTS_SCHEDULER_IDLE_WAIT','FT_IFTSHC_MUTEX',
    'HADR_CLUSAPI_CALL','HADR_FILESTREAM_IOMGR_IOCOMPLETION','HADR_LOGCAPTURE_WAIT',
    'HADR_NOTIFICATION_DEQUEUE','HADR_TIMER_TASK','HADR_WORK_QUEUE',
    'KSOURCE_WAKEUP','LAZYWRITER_SLEEP','LOGMGR_QUEUE',
    'ONDEMAND_TASK_QUEUE','PWAIT_ALL_COMPONENTS_INITIALIZED',
    'QDS_PERSIST_TASK_MAIN_LOOP_SLEEP','QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
    'REQUEST_FOR_DEADLOCK_SEARCH','RESOURCE_QUEUE','SERVER_IDLE_CHECK',
    'SLEEP_BPOOL_FLUSH','SLEEP_DBSTARTUP','SLEEP_DCOMSTARTUP',
    'SLEEP_MASTERDBREADY','SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED',
    'SLEEP_MSDBSTARTUP','SLEEP_SYSTEMTASK','SLEEP_TASK','SLEEP_TEMPDBSTARTUP',
    'SNI_HTTP_ACCEPT','SP_SERVER_DIAGNOSTICS_SLEEP','SQLTRACE_BUFFER_FLUSH',
    'SQLTRACE_INCREMENTAL_FLUSH_SLEEP','SQLTRACE_WAIT_ENTRIES',
    'WAIT_FOR_RESULTS','WAITFOR','WAITFOR_TASKSHUTDOWN',
    'WAIT_XTP_HOST_WAIT','WAIT_XTP_OFFLINE_CKPT_NEW_LOG','WAIT_XTP_CKPT_CLOSE',
    'XE_DISPATCHER_JOIN','XE_DISPATCHER_WAIT','XE_TIMER_EVENT')
  AND wait_time_ms > 0
ORDER BY wait_time_ms DESC;

-- ---------------------------------------------------------------------------
-- Wait categorization (CPU-proxy, I/O, Lock, Latch, Network, Compile)
-- ---------------------------------------------------------------------------
SELECT
    CASE
        WHEN wait_type LIKE 'PAGEIOLATCH%'            THEN 'I/O (data pages)'
        WHEN wait_type LIKE 'WRITELOG'                THEN 'I/O (log flush)'
        WHEN wait_type LIKE 'ASYNC_IO_COMPLETION%'    THEN 'I/O (async)'
        WHEN wait_type LIKE 'IO_COMPLETION%'          THEN 'I/O'
        WHEN wait_type LIKE 'LCK_%'                   THEN 'Lock'
        WHEN wait_type LIKE 'PAGELATCH%'              THEN 'Latch (in-memory)'
        WHEN wait_type LIKE 'LATCH_%'                 THEN 'Latch'
        WHEN wait_type LIKE 'CXPACKET'                THEN 'Parallelism'
        WHEN wait_type LIKE 'CXCONSUMER'              THEN 'Parallelism'
        WHEN wait_type LIKE 'SOS_SCHEDULER_YIELD'     THEN 'CPU pressure'
        WHEN wait_type LIKE 'ASYNC_NETWORK_IO'        THEN 'Network'
        WHEN wait_type LIKE 'RESOURCE_SEMAPHORE%'     THEN 'Memory grant'
        WHEN wait_type LIKE 'PREEMPTIVE_%'            THEN 'External call'
        WHEN wait_type LIKE 'BACKUP%'                 THEN 'Backup'
        WHEN wait_type LIKE 'CMEMTHREAD'              THEN 'Memory allocator'
        ELSE 'Other'
    END                                               AS category,
    COUNT(*)                                          AS distinct_wait_types,
    SUM(wait_time_ms)                                 AS total_wait_ms,
    CAST(SUM(wait_time_ms) / 1000.0 / 60 AS DECIMAL(18,2)) AS total_wait_minutes
FROM sys.dm_os_wait_stats
WHERE wait_time_ms > 0
GROUP BY
    CASE
        WHEN wait_type LIKE 'PAGEIOLATCH%'            THEN 'I/O (data pages)'
        WHEN wait_type LIKE 'WRITELOG'                THEN 'I/O (log flush)'
        WHEN wait_type LIKE 'ASYNC_IO_COMPLETION%'    THEN 'I/O (async)'
        WHEN wait_type LIKE 'IO_COMPLETION%'          THEN 'I/O'
        WHEN wait_type LIKE 'LCK_%'                   THEN 'Lock'
        WHEN wait_type LIKE 'PAGELATCH%'              THEN 'Latch (in-memory)'
        WHEN wait_type LIKE 'LATCH_%'                 THEN 'Latch'
        WHEN wait_type LIKE 'CXPACKET'                THEN 'Parallelism'
        WHEN wait_type LIKE 'CXCONSUMER'              THEN 'Parallelism'
        WHEN wait_type LIKE 'SOS_SCHEDULER_YIELD'     THEN 'CPU pressure'
        WHEN wait_type LIKE 'ASYNC_NETWORK_IO'        THEN 'Network'
        WHEN wait_type LIKE 'RESOURCE_SEMAPHORE%'     THEN 'Memory grant'
        WHEN wait_type LIKE 'PREEMPTIVE_%'            THEN 'External call'
        WHEN wait_type LIKE 'BACKUP%'                 THEN 'Backup'
        WHEN wait_type LIKE 'CMEMTHREAD'              THEN 'Memory allocator'
        ELSE 'Other'
    END
ORDER BY total_wait_ms DESC;

-- ---------------------------------------------------------------------------
-- Per-database file I/O totals. sys.master_files is unavailable on Azure
-- SQL Database; TRY/CATCH lets the block skip cleanly instead of aborting.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT TOP 50
        DB_NAME(vfs.database_id)                           AS database_name,
        mf.name                                            AS logical_file,
        mf.type_desc                                       AS file_type,
        mf.physical_name,
        vfs.num_of_reads,
        vfs.num_of_writes,
        CAST(vfs.num_of_bytes_read / 1024.0 / 1024 AS DECIMAL(18,2))  AS mb_read,
        CAST(vfs.num_of_bytes_written / 1024.0 / 1024 AS DECIMAL(18,2)) AS mb_written,
        CAST(vfs.io_stall_read_ms / NULLIF(vfs.num_of_reads, 0) AS DECIMAL(18,2))   AS avg_read_stall_ms,
        CAST(vfs.io_stall_write_ms / NULLIF(vfs.num_of_writes, 0) AS DECIMAL(18,2)) AS avg_write_stall_ms,
        -- The view exposes a generic `io_stall` column (read+write), not
        -- `io_stall_ms`. Rename for clarity.
        vfs.io_stall                                       AS total_stall_ms
    FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
    JOIN sys.master_files mf
          ON mf.database_id = vfs.database_id
         AND mf.file_id     = vfs.file_id
    ORDER BY vfs.io_stall DESC;
END TRY
BEGIN CATCH
    PRINT '[note] sys.master_files not accessible (likely Azure SQL DB): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Buffer cache hit ratio (target: > 99% on OLTP)
-- ---------------------------------------------------------------------------
SELECT
    obj.object_name,
    MAX(CASE WHEN obj.counter_name = 'Buffer cache hit ratio'       THEN obj.cntr_value END) AS hit_ratio,
    MAX(CASE WHEN obj.counter_name = 'Buffer cache hit ratio base'  THEN obj.cntr_value END) AS hit_ratio_base,
    CAST(100.0 *
        MAX(CASE WHEN obj.counter_name = 'Buffer cache hit ratio'      THEN obj.cntr_value END) /
        NULLIF(MAX(CASE WHEN obj.counter_name = 'Buffer cache hit ratio base' THEN obj.cntr_value END), 0)
        AS DECIMAL(5,2))                               AS hit_ratio_pct
FROM sys.dm_os_performance_counters obj
WHERE obj.counter_name IN ('Buffer cache hit ratio', 'Buffer cache hit ratio base')
GROUP BY obj.object_name;

-- ---------------------------------------------------------------------------
-- Page life expectancy per NUMA node (target: > 300 sec on OLTP)
-- ---------------------------------------------------------------------------
SELECT
    object_name,
    instance_name,
    cntr_value                                         AS page_life_expectancy_sec
FROM sys.dm_os_performance_counters
WHERE counter_name = 'Page life expectancy'
ORDER BY instance_name;
