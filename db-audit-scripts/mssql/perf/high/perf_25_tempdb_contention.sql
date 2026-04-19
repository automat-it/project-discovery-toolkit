-- =============================================================================
-- perf_25_tempdb_contention.sql
-- Priority: HIGH (MSSQL-only)
-- Purpose: Detect tempdb PFS / GAM / SGAM latch contention, uneven
--          data-file sizing, mis-matched CPU:file ratio, tempdb growth
--          / free-space state, active tempdb session consumption.
-- Read-only.
-- References:
--   https://learn.microsoft.com/en-us/sql/relational-databases/tempdb/tempdb-database
--   https://learn.microsoft.com/en-us/sql/relational-databases/databases/configure-tempdb
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- tempdb file layout — one row per data / log file. Equal initial size
-- and identical growth settings are best practice to avoid GAM allocation
-- hotspot.
-- ---------------------------------------------------------------------------
SELECT
    df.file_id,
    df.name                                               AS logical_name,
    df.physical_name,
    df.type_desc                                          AS file_type,
    df.state_desc,
    CAST(df.size          * 8 / 1024.0 AS DECIMAL(18,1))  AS current_mb,
    CASE df.is_percent_growth
        WHEN 1 THEN CAST(df.growth AS VARCHAR(10)) + ' %'
        ELSE CAST(CAST(df.growth AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                                   AS growth,
    CASE WHEN df.max_size = -1 THEN 'unlimited'
         WHEN df.max_size =  0 THEN 'no growth'
         ELSE CAST(CAST(df.max_size AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                                   AS max_size
FROM tempdb.sys.database_files df
ORDER BY df.type, df.file_id;

-- ---------------------------------------------------------------------------
-- CPU-count vs tempdb-data-file count — Microsoft guidance:
-- 1 data file per logical processor up to 8, then add files in groups
-- of 4 while monitoring PAGELATCH waits.
-- ---------------------------------------------------------------------------
SELECT
    (SELECT cpu_count FROM sys.dm_os_sys_info)                         AS logical_cpus,
    (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0)    AS tempdb_data_files,
    CASE
        WHEN (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0)
             < LEAST_VALUE
            THEN 'under-provisioned — file count below recommendation'
        WHEN (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0)
             > (SELECT cpu_count FROM sys.dm_os_sys_info)
            THEN 'over-provisioned — more files than CPUs'
        ELSE 'ok'
    END                                                                AS assessment
FROM (
    SELECT LEAST_VALUE = CASE WHEN (SELECT cpu_count FROM sys.dm_os_sys_info) < 8
                              THEN (SELECT cpu_count FROM sys.dm_os_sys_info)
                              ELSE 8 END
) x;

-- ---------------------------------------------------------------------------
-- Free space + usage per tempdb file right now
-- ---------------------------------------------------------------------------
SELECT
    df.file_id,
    df.name,
    CAST(df.size        * 8 / 1024.0 AS DECIMAL(18,1))    AS size_mb,
    CAST(FILEPROPERTY(df.name,'SpaceUsed') * 8 / 1024.0 AS DECIMAL(18,1)) AS used_mb,
    CAST((df.size - CAST(FILEPROPERTY(df.name,'SpaceUsed') AS INT))
                       * 8 / 1024.0 AS DECIMAL(18,1))     AS free_mb,
    CAST(FILEPROPERTY(df.name,'SpaceUsed') * 100.0 / NULLIF(df.size,0) AS DECIMAL(5,1)) AS pct_used
FROM tempdb.sys.database_files df
WHERE df.type = 0;      -- ROWS only; log file not meaningful here

-- Broader usage breakdown via sys.dm_db_file_space_usage — user objects,
-- internal objects, version store.
SELECT
    file_id,
    CAST(total_page_count         * 8 / 1024.0 AS DECIMAL(18,1)) AS total_mb,
    CAST(allocated_extent_page_count * 8 / 1024.0 AS DECIMAL(18,1)) AS allocated_mb,
    CAST(user_object_reserved_page_count     * 8 / 1024.0 AS DECIMAL(18,1)) AS user_obj_mb,
    CAST(internal_object_reserved_page_count * 8 / 1024.0 AS DECIMAL(18,1)) AS internal_obj_mb,
    CAST(version_store_reserved_page_count   * 8 / 1024.0 AS DECIMAL(18,1)) AS version_store_mb,
    CAST(mixed_extent_page_count             * 8 / 1024.0 AS DECIMAL(18,1)) AS mixed_extent_mb,
    CAST(unallocated_extent_page_count       * 8 / 1024.0 AS DECIMAL(18,1)) AS unallocated_mb
FROM tempdb.sys.dm_db_file_space_usage;

-- ---------------------------------------------------------------------------
-- Allocation-bitmap latch waits — PFS (pages 1 + 8088-page boundaries),
-- GAM (page 2), SGAM (page 3). Extract page number from wait resource.
-- ---------------------------------------------------------------------------
SELECT
    session_id,
    wait_duration_ms,
    wait_type,
    blocking_session_id,
    resource_description,
    CASE
        WHEN resource_description LIKE '2:%:1'      THEN 'PFS'
        WHEN resource_description LIKE '2:%:2'      THEN 'GAM'
        WHEN resource_description LIKE '2:%:3'      THEN 'SGAM'
        WHEN resource_description LIKE '2:%:%'      THEN 'tempdb page'
        ELSE 'other'
    END                                                   AS resource_kind
FROM sys.dm_os_waiting_tasks
WHERE wait_type LIKE 'PAGELATCH%'
  AND resource_description LIKE '2:%'
ORDER BY wait_duration_ms DESC;

-- Cumulative PAGELATCH wait breakdown since the last counter reset
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    max_wait_time_ms,
    signal_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_type LIKE 'PAGELATCH%'
ORDER BY wait_time_ms DESC;

-- ---------------------------------------------------------------------------
-- Per-session tempdb consumption — spots a runaway spill.
-- task_alloc = pages still allocated to running tasks; session_alloc =
-- all pages held by the session (including internal objects).
-- ---------------------------------------------------------------------------
SELECT TOP 30
    su.session_id,
    CAST(su.user_objects_alloc_page_count     * 8 / 1024.0 AS DECIMAL(18,1)) AS user_obj_mb,
    CAST(su.internal_objects_alloc_page_count * 8 / 1024.0 AS DECIMAL(18,1)) AS internal_obj_mb,
    CAST(su.user_objects_dealloc_page_count   * 8 / 1024.0 AS DECIMAL(18,1)) AS user_obj_released_mb,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status,
    r.command,
    r.wait_type,
    r.wait_time,
    SUBSTRING(t.text, r.statement_start_offset/2 + 1,
              (CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(t.text)
                    ELSE r.statement_end_offset END
                - r.statement_start_offset)/2 + 1)        AS current_statement
FROM sys.dm_db_session_space_usage su
JOIN sys.dm_exec_sessions s ON s.session_id = su.session_id
LEFT JOIN sys.dm_exec_requests r ON r.session_id = su.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE (su.user_objects_alloc_page_count + su.internal_objects_alloc_page_count) > 0
ORDER BY (su.user_objects_alloc_page_count + su.internal_objects_alloc_page_count) DESC;

-- ---------------------------------------------------------------------------
-- Version-store growth — long-running transactions keep version chains
-- alive, inflating tempdb.
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(database_id)                                  AS database_name,
    reserved_page_count,
    CAST(reserved_page_count * 8 / 1024.0 AS DECIMAL(18,1)) AS reserved_mb
FROM sys.dm_tran_version_store_space_usage
ORDER BY reserved_page_count DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT cpu_count FROM sys.dm_os_sys_info)                              AS logical_cpus,
    (SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type = 0)         AS tempdb_data_files,
    (SELECT SUM(wait_time_ms) FROM sys.dm_os_wait_stats
      WHERE wait_type LIKE 'PAGELATCH%')                                    AS pagelatch_wait_ms_total,
    (SELECT COUNT(*) FROM sys.dm_os_waiting_tasks
      WHERE wait_type LIKE 'PAGELATCH%' AND resource_description LIKE '2:%') AS pagelatch_waiters_now;
