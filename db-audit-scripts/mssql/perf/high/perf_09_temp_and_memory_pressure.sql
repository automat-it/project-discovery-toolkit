-- =============================================================================
-- perf_09_temp_and_memory_pressure.sql
-- Priority: HIGH
-- Purpose: Detect tempdb contention, memory grant pressure, and queries
--          spilling to disk.
-- Sources: sys.dm_db_file_space_usage, sys.dm_exec_query_memory_grants,
--          sys.dm_exec_query_resource_semaphores, sys.dm_os_memory_clerks,
--          Query Store wait stats.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- TempDB file usage breakdown (per file, per allocation type)
-- ---------------------------------------------------------------------------
SELECT
    mf.name                                           AS file_name,
    mf.physical_name,
    CAST(mf.size * 8.0 / 1024 AS DECIMAL(18,2))       AS size_mb,
    CAST((fsu.unallocated_extent_page_count * 8.0) / 1024 AS DECIMAL(18,2)) AS free_mb,
    CAST(fsu.user_object_reserved_page_count     * 8.0 / 1024 AS DECIMAL(18,2)) AS user_obj_mb,
    CAST(fsu.internal_object_reserved_page_count * 8.0 / 1024 AS DECIMAL(18,2)) AS internal_obj_mb,
    CAST(fsu.version_store_reserved_page_count   * 8.0 / 1024 AS DECIMAL(18,2)) AS version_store_mb,
    CAST(fsu.mixed_extent_page_count             * 8.0 / 1024 AS DECIMAL(18,2)) AS mixed_extent_mb
FROM tempdb.sys.dm_db_file_space_usage fsu
JOIN tempdb.sys.database_files mf ON mf.file_id = fsu.file_id
ORDER BY mf.file_id;

-- ---------------------------------------------------------------------------
-- Current memory grants (queries actively consuming or waiting for memory)
-- ---------------------------------------------------------------------------
SELECT
    mg.session_id,
    mg.request_id,
    mg.grant_time,
    mg.granted_memory_kb / 1024                       AS granted_mb,
    mg.requested_memory_kb / 1024                     AS requested_mb,
    mg.required_memory_kb / 1024                      AS required_mb,
    mg.used_memory_kb / 1024                          AS used_mb,
    mg.max_used_memory_kb / 1024                      AS max_used_mb,
    mg.wait_time_ms                                   AS wait_ms,
    mg.dop,
    LEFT(txt.text, 300)                               AS query_text
FROM sys.dm_exec_query_memory_grants mg
OUTER APPLY sys.dm_exec_sql_text(mg.sql_handle) txt
ORDER BY mg.granted_memory_kb DESC;

-- ---------------------------------------------------------------------------
-- Resource semaphores (memory grant queue backlog)
-- ---------------------------------------------------------------------------
SELECT
    resource_semaphore_id,
    target_memory_kb / 1024                           AS target_mb,
    max_target_memory_kb / 1024                       AS max_target_mb,
    total_memory_kb / 1024                            AS total_mb,
    available_memory_kb / 1024                        AS available_mb,
    granted_memory_kb / 1024                          AS granted_mb,
    used_memory_kb / 1024                             AS used_mb,
    grantee_count,
    waiter_count,
    timeout_error_count,
    forced_grant_count
FROM sys.dm_exec_query_resource_semaphores;

-- ---------------------------------------------------------------------------
-- Top memory clerks (where memory is going)
-- ---------------------------------------------------------------------------
SELECT TOP 20
    type                                              AS memory_clerk,
    COUNT(*)                                          AS instance_count,
    SUM(pages_kb) / 1024                              AS total_mb
FROM sys.dm_os_memory_clerks
WHERE pages_kb > 0
GROUP BY type
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Buffer-pool allocation per database (who owns the pages)
-- ---------------------------------------------------------------------------
SELECT TOP 20
    DB_NAME(database_id)                              AS database_name,
    COUNT(*)                                          AS cached_pages,
    CAST(COUNT(*) * 8.0 / 1024 AS DECIMAL(18,2))      AS cached_mb
FROM sys.dm_os_buffer_descriptors
WHERE database_id <> 32767                             -- exclude resource db
GROUP BY database_id
ORDER BY cached_pages DESC;

-- ---------------------------------------------------------------------------
-- Hash spill / sort spill hints from plan cache (sys.dm_exec_query_stats +
-- plan XML scan). Not every plan has spill warnings exposed, but when
-- they do the count here lights up.
-- ---------------------------------------------------------------------------
SELECT TOP 25
    qs.execution_count,
    qs.total_grant_kb / 1024                          AS total_granted_mb,
    qs.total_used_grant_kb / 1024                     AS total_used_mb,
    qs.total_ideal_grant_kb / 1024                    AS total_ideal_mb,
    qs.max_ideal_grant_kb / 1024                      AS max_ideal_mb,
    qs.max_used_grant_kb / 1024                       AS max_used_mb,
    qs.total_spills,
    qs.max_spills,
    SUBSTRING(st.text,
              (qs.statement_start_offset/2) + 1,
              ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                                             ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2) + 1)  AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.total_spills > 0
ORDER BY qs.total_spills DESC;

-- ---------------------------------------------------------------------------
-- Plan-cache queries with the biggest memory grants
-- ---------------------------------------------------------------------------
SELECT TOP 25
    qs.execution_count,
    qs.max_used_grant_kb / 1024                       AS max_used_grant_mb,
    qs.max_ideal_grant_kb / 1024                      AS max_ideal_grant_mb,
    qs.total_used_grant_kb / NULLIF(qs.execution_count, 0) / 1024 AS avg_used_grant_mb,
    SUBSTRING(st.text,
              (qs.statement_start_offset/2) + 1,
              ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                                             ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2) + 1)  AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.max_used_grant_kb > 0
ORDER BY qs.max_used_grant_kb DESC;

-- ---------------------------------------------------------------------------
-- TempDB contention waits: PAGELATCH on allocation bitmaps (GAM/SGAM/PFS)
-- ---------------------------------------------------------------------------
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    CAST(wait_time_ms / 1000.0 / 60 AS DECIMAL(18,2))  AS wait_minutes
FROM sys.dm_os_wait_stats
WHERE wait_type IN ('PAGELATCH_SH','PAGELATCH_EX','PAGELATCH_UP',
                    'PAGEIOLATCH_SH','PAGEIOLATCH_EX')
  AND waiting_tasks_count > 0
ORDER BY wait_time_ms DESC;
