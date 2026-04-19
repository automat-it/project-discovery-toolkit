-- =============================================================================
-- perf_01_top_sql.sql
-- Priority: CRITICAL
-- Purpose: Identify the most expensive SQL by total time, mean latency,
--          call frequency, CPU, and I/O. The single most useful query
--          for finding the real cause of database load.
-- Sources: Query Store (preferred, per-database) and sys.dm_exec_query_stats
--          (plan-cache fallback, server-wide).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Query Store availability for the current database
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                           AS database_name,
    actual_state_desc,
    desired_state_desc,
    readonly_reason,
    current_storage_size_mb,
    max_storage_size_mb,
    query_capture_mode_desc,
    size_based_cleanup_mode_desc
FROM sys.database_query_store_options;

-- ---------------------------------------------------------------------------
-- Top 25 queries by TOTAL execution time (Query Store, current database)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    rs.execution_type_desc              AS exec_type,
    qt.query_sql_text                   AS query_text,
    SUM(rs.count_executions)            AS total_executions,
    SUM(rs.avg_duration * rs.count_executions) / 1000.0 AS total_ms,
    CAST(SUM(rs.avg_duration * rs.count_executions) / NULLIF(SUM(rs.count_executions),0) / 1000.0 AS DECIMAL(18,2)) AS mean_ms,
    CAST(SUM(rs.avg_cpu_time * rs.count_executions) / NULLIF(SUM(rs.count_executions),0) / 1000.0 AS DECIMAL(18,2)) AS mean_cpu_ms,
    SUM(rs.avg_logical_io_reads * rs.count_executions) AS total_logical_reads,
    SUM(rs.avg_physical_io_reads * rs.count_executions) AS total_physical_reads,
    q.query_id,
    p.plan_id
FROM sys.query_store_runtime_stats rs
JOIN sys.query_store_plan p              ON p.plan_id = rs.plan_id
JOIN sys.query_store_query q             ON q.query_id = p.query_id
JOIN sys.query_store_query_text qt       ON qt.query_text_id = q.query_text_id
GROUP BY rs.execution_type_desc, qt.query_sql_text, q.query_id, p.plan_id
ORDER BY total_ms DESC;

-- ---------------------------------------------------------------------------
-- Top 25 queries by MEAN execution time (slow individual calls)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    CAST(rs.avg_duration / 1000.0 AS DECIMAL(18,2))   AS mean_ms,
    CAST(rs.min_duration / 1000.0 AS DECIMAL(18,2))   AS min_ms,
    CAST(rs.max_duration / 1000.0 AS DECIMAL(18,2))   AS max_ms,
    CAST(rs.stdev_duration / 1000.0 AS DECIMAL(18,2)) AS stdev_ms,
    rs.count_executions,
    CAST(rs.avg_cpu_time / 1000.0 AS DECIMAL(18,2))   AS mean_cpu_ms,
    rs.avg_logical_io_reads                           AS avg_logical_reads,
    LEFT(qt.query_sql_text, 300)                      AS query_preview,
    q.query_id
FROM sys.query_store_runtime_stats rs
JOIN sys.query_store_plan p        ON p.plan_id = rs.plan_id
JOIN sys.query_store_query q       ON q.query_id = p.query_id
JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id
WHERE rs.count_executions > 5
ORDER BY rs.avg_duration DESC;

-- ---------------------------------------------------------------------------
-- Top queries by CALL FREQUENCY (chatty clients / N+1)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    SUM(rs.count_executions)                                 AS total_calls,
    CAST(SUM(rs.avg_duration * rs.count_executions) / 1000.0 AS DECIMAL(18,2)) AS total_ms,
    CAST(AVG(rs.avg_duration) / 1000.0 AS DECIMAL(18,2))     AS mean_ms,
    LEFT(qt.query_sql_text, 300)                             AS query_preview,
    q.query_id
FROM sys.query_store_runtime_stats rs
JOIN sys.query_store_plan p        ON p.plan_id = rs.plan_id
JOIN sys.query_store_query q       ON q.query_id = p.query_id
JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id
GROUP BY qt.query_sql_text, q.query_id
ORDER BY total_calls DESC;

-- ---------------------------------------------------------------------------
-- Plan-cache fallback: top queries by CPU time (server-wide)
-- Useful when Query Store is off on some database.
-- ---------------------------------------------------------------------------
SELECT TOP 25
    qs.execution_count,
    CAST(qs.total_worker_time / 1000.0 / qs.execution_count AS DECIMAL(18,2))  AS mean_cpu_ms,
    CAST(qs.total_elapsed_time / 1000.0 / qs.execution_count AS DECIMAL(18,2)) AS mean_elapsed_ms,
    qs.total_logical_reads / NULLIF(qs.execution_count,0)                      AS mean_logical_reads,
    qs.total_physical_reads / NULLIF(qs.execution_count,0)                     AS mean_physical_reads,
    DB_NAME(st.dbid)                                                           AS database_name,
    SUBSTRING(st.text,
              (qs.statement_start_offset/2) + 1,
              ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                                             ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2) + 1)                           AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.execution_count > 1
ORDER BY qs.total_worker_time DESC;

-- ---------------------------------------------------------------------------
-- Plan-cache: top queries by physical I/O
-- ---------------------------------------------------------------------------
SELECT TOP 25
    qs.total_physical_reads                                                    AS total_physical_reads,
    qs.total_logical_reads                                                     AS total_logical_reads,
    qs.execution_count,
    CAST(qs.total_physical_reads * 8.0 / 1024 AS DECIMAL(18,2))                AS mb_read_from_disk,
    DB_NAME(st.dbid)                                                           AS database_name,
    SUBSTRING(st.text,
              (qs.statement_start_offset/2) + 1,
              ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                                             ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2) + 1)                           AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.total_physical_reads > 0
ORDER BY qs.total_physical_reads DESC;
