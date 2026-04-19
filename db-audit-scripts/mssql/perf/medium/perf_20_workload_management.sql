-- =============================================================================
-- perf_20_workload_management.sql
-- Priority: MEDIUM
-- Purpose: Surface Resource Governor configuration, concurrency limits,
--          MAXDOP / CTFP, in-flight long requests, and Query Store
--          wait-category breakdown — the SQL Server workload-
--          management surface.
-- Sources: sys.resource_governor_*, sys.dm_resource_governor_*,
--          sys.configurations, sys.dm_exec_requests,
--          sys.dm_exec_query_stats, sys.query_store_wait_stats.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Resource Governor: is it enabled? Configuration vs in-memory state.
-- ---------------------------------------------------------------------------
SELECT
    is_enabled,
    classifier_function_id,
    OBJECT_SCHEMA_NAME(classifier_function_id) + '.' +
    OBJECT_NAME(classifier_function_id) AS classifier_function,
    max_outstanding_io_per_volume
FROM sys.resource_governor_configuration;

-- Configured resource pools
SELECT
    pool_id,
    name                                                 AS pool_name,
    min_cpu_percent,
    max_cpu_percent,
    cap_cpu_percent,
    min_memory_percent,
    max_memory_percent,
    min_iops_per_volume,
    max_iops_per_volume
FROM sys.resource_governor_resource_pools
ORDER BY pool_id;

-- Runtime stats for resource pools (only populated when RG is enabled)
SELECT
    rp.name                                              AS pool_name,
    prp.statistics_start_time,
    prp.total_cpu_usage_ms,
    prp.cache_memory_kb,
    prp.compile_memory_kb,
    prp.used_memgrant_kb,
    prp.total_memgrant_count,
    prp.total_memgrant_timeout_count,
    prp.active_memgrant_count,
    prp.active_memgrant_kb
FROM sys.dm_resource_governor_resource_pools prp
JOIN sys.resource_governor_resource_pools rp ON rp.pool_id = prp.pool_id
ORDER BY rp.name;

-- Configured workload groups (request caps, DOP overrides)
SELECT
    g.group_id,
    g.name                                               AS group_name,
    p.name                                               AS pool_name,
    g.importance,
    g.request_max_memory_grant_percent,
    g.request_max_cpu_time_sec,
    g.request_memory_grant_timeout_sec,
    g.max_dop,
    g.group_max_requests
FROM sys.resource_governor_workload_groups g
JOIN sys.resource_governor_resource_pools p ON p.pool_id = g.pool_id
ORDER BY p.name, g.name;

-- Runtime stats for workload groups
SELECT
    g.name                                               AS group_name,
    wgs.statistics_start_time,
    wgs.total_request_count,
    wgs.total_queued_request_count,
    wgs.active_request_count,
    wgs.queued_request_count,
    wgs.total_cpu_limit_violation_count,
    wgs.total_cpu_usage_ms,
    wgs.total_lock_wait_count,
    wgs.total_lock_wait_time_ms
FROM sys.dm_resource_governor_workload_groups wgs
JOIN sys.resource_governor_workload_groups g ON g.group_id = wgs.group_id
ORDER BY g.name;

-- ---------------------------------------------------------------------------
-- Parallelism / memory knobs (instance-wide)
-- ---------------------------------------------------------------------------
SELECT
    name,
    value,
    value_in_use,
    minimum,
    maximum,
    description
FROM sys.configurations
WHERE name IN (
    'max degree of parallelism',
    'cost threshold for parallelism',
    'max worker threads',
    'max server memory (MB)',
    'min server memory (MB)',
    'user connections',
    'query governor cost limit',
    'remote query timeout (s)',
    'blocked process threshold (s)',
    'priority boost',
    'lightweight pooling'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Currently-connected sessions grouped by workload group + login
-- ---------------------------------------------------------------------------
SELECT
    wg.name                                              AS workload_group,
    s.login_name,
    s.program_name,
    COUNT(*)                                             AS sessions,
    SUM(CASE WHEN s.status = 'running'  THEN 1 ELSE 0 END) AS running,
    SUM(CASE WHEN s.status = 'sleeping' THEN 1 ELSE 0 END) AS sleeping
FROM sys.dm_exec_sessions s
LEFT JOIN sys.resource_governor_workload_groups wg ON wg.group_id = s.group_id
WHERE s.is_user_process = 1
GROUP BY wg.name, s.login_name, s.program_name
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Long-running user requests (>60s)
-- ---------------------------------------------------------------------------
SELECT TOP 50
    r.session_id,
    s.login_name,
    DB_NAME(r.database_id)                               AS database_name,
    r.status,
    r.command,
    r.wait_type,
    r.wait_time,
    DATEDIFF(second, r.start_time, SYSUTCDATETIME())     AS seconds_running,
    r.cpu_time,
    r.total_elapsed_time,
    r.percent_complete,
    LEFT(txt.text, 300)                                  AS current_statement
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) txt
WHERE s.is_user_process = 1
  AND DATEDIFF(second, r.start_time, SYSUTCDATETIME()) > 60
ORDER BY seconds_running DESC;

-- ---------------------------------------------------------------------------
-- Query Store wait-category summary (top contributors by wait time).
-- Only runs if Query Store is enabled in the current database.
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    SELECT TOP 25
        ws.wait_category_desc,
        SUM(ws.total_query_wait_time_ms) AS total_wait_ms,
        SUM(ws.execution_type_desc = 'Regular') AS regular_executions
    FROM sys.query_store_wait_stats ws
    GROUP BY ws.wait_category_desc
    ORDER BY total_wait_ms DESC;
END;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT is_enabled FROM sys.resource_governor_configuration)               AS rg_enabled,
    (SELECT COUNT(*) FROM sys.resource_governor_resource_pools
       WHERE name NOT IN ('internal','default'))                               AS custom_pools,
    (SELECT COUNT(*) FROM sys.resource_governor_workload_groups
       WHERE name NOT IN ('internal','default'))                               AS custom_workload_groups,
    (SELECT value_in_use FROM sys.configurations
       WHERE name = 'max degree of parallelism')                               AS maxdop,
    (SELECT value_in_use FROM sys.configurations
       WHERE name = 'cost threshold for parallelism')                          AS ctfp,
    (SELECT COUNT(*) FROM sys.dm_exec_requests r
      JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
      WHERE s.is_user_process = 1
        AND DATEDIFF(second, r.start_time, SYSUTCDATETIME()) > 60)             AS long_running_requests;
