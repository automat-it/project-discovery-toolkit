-- =============================================================================
-- perf_23_plan_regression.sql
-- Priority: MEDIUM
-- Purpose: Find queries whose plans regressed. Query Store exposes
--          first-class plan history per query; this script surfaces
--          (a) multi-plan queries, (b) current-vs-historical regressions,
--          (c) forced plans and force-failure count, (d) high-variance
--          plan-cache entries as a fallback when Query Store is off.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Query Store state for the current database
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                             AS database_name,
    actual_state_desc,
    desired_state_desc,
    readonly_reason,
    current_storage_size_mb,
    max_storage_size_mb,
    query_capture_mode_desc,
    size_based_cleanup_mode_desc,
    stale_query_threshold_days,
    interval_length_minutes,
    wait_stats_capture_mode_desc
FROM sys.database_query_store_options;

-- ---------------------------------------------------------------------------
-- Queries with > 1 plan in Query Store — candidates for regression.
-- Guarded with TRY/CATCH because Query Store tables error on DBs where
-- it is OFF.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        q.query_id,
        LEFT(qt.query_sql_text, 200)                      AS query_sample,
        COUNT(DISTINCT p.plan_id)                         AS plan_count,
        MIN(p.last_execution_time)                        AS first_plan_seen,
        MAX(p.last_execution_time)                        AS last_plan_seen,
        SUM(p.count_compiles)                             AS total_compiles
    FROM sys.query_store_query        q
    JOIN sys.query_store_query_text   qt ON qt.query_text_id = q.query_text_id
    JOIN sys.query_store_plan         p  ON p.query_id = q.query_id
    GROUP BY q.query_id, qt.query_sql_text
    HAVING COUNT(DISTINCT p.plan_id) > 1
    ORDER BY plan_count DESC, total_compiles DESC;
END TRY
BEGIN CATCH
    PRINT '[note] Query Store unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Regressed queries — current plan's avg duration > historical plan's
-- avg duration by 2× on the same query_id.
-- ---------------------------------------------------------------------------
BEGIN TRY
    ;WITH plan_stats AS (
        SELECT
            p.query_id,
            p.plan_id,
            p.is_forced_plan,
            MAX(p.last_execution_time)                    AS last_exec,
            SUM(rs.count_executions)                      AS executions,
            SUM(rs.avg_duration * rs.count_executions) / NULLIF(SUM(rs.count_executions),0) AS weighted_avg_us
        FROM sys.query_store_plan p
        JOIN sys.query_store_runtime_stats rs ON rs.plan_id = p.plan_id
        GROUP BY p.query_id, p.plan_id, p.is_forced_plan
    ), ranked AS (
        SELECT *,
            ROW_NUMBER() OVER (PARTITION BY query_id ORDER BY last_exec DESC)  AS rn_latest,
            ROW_NUMBER() OVER (PARTITION BY query_id ORDER BY weighted_avg_us) AS rn_fastest
        FROM plan_stats
    )
    SELECT
        l.query_id,
        l.plan_id                                         AS latest_plan_id,
        CAST(l.weighted_avg_us / 1000.0 AS DECIMAL(18,2)) AS latest_avg_ms,
        f.plan_id                                         AS fastest_plan_id,
        CAST(f.weighted_avg_us / 1000.0 AS DECIMAL(18,2)) AS fastest_avg_ms,
        CAST(l.weighted_avg_us / NULLIF(f.weighted_avg_us,0) AS DECIMAL(18,2)) AS regression_factor,
        l.is_forced_plan                                  AS latest_is_forced
    FROM ranked l
    JOIN ranked f ON f.query_id = l.query_id AND f.rn_fastest = 1
    WHERE l.rn_latest = 1
      AND l.plan_id <> f.plan_id
      AND l.weighted_avg_us > 2 * f.weighted_avg_us
    ORDER BY regression_factor DESC;
END TRY
BEGIN CATCH
    PRINT '[note] Query Store plan-regression query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Forced plans + whether the force is currently succeeding
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        query_id,
        plan_id,
        is_forced_plan,
        force_failure_count,
        last_force_failure_reason_desc,
        last_execution_time
    FROM sys.query_store_plan
    WHERE is_forced_plan = 1
    ORDER BY force_failure_count DESC, last_execution_time DESC;
END TRY
BEGIN CATCH
    PRINT '[note] forced-plan query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Plan-cache fallback — high max/min ratio from sys.dm_exec_query_stats.
-- Works on any build; useful when Query Store is off.
-- ---------------------------------------------------------------------------
SELECT TOP 50
    qs.sql_handle,
    qs.plan_handle,
    qs.execution_count,
    qs.total_elapsed_time / NULLIF(qs.execution_count,0) / 1000   AS avg_elapsed_ms,
    qs.min_elapsed_time / 1000                                    AS min_elapsed_ms,
    qs.max_elapsed_time / 1000                                    AS max_elapsed_ms,
    CASE WHEN qs.min_elapsed_time > 0
         THEN qs.max_elapsed_time / qs.min_elapsed_time END       AS max_over_min,
    qs.total_logical_reads,
    qs.total_worker_time,
    SUBSTRING(st.text, qs.statement_start_offset/2 + 1,
              (CASE qs.statement_end_offset
                  WHEN -1 THEN DATALENGTH(st.text)
                  ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2 + 1)                AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.execution_count >= 50
ORDER BY CASE WHEN qs.min_elapsed_time > 0
              THEN qs.max_elapsed_time / qs.min_elapsed_time END DESC;

-- ---------------------------------------------------------------------------
-- Parameter-sensitivity signals — same query_hash, many plans in cache
-- ---------------------------------------------------------------------------
SELECT TOP 30
    query_hash,
    COUNT(DISTINCT plan_handle)                           AS distinct_plans,
    SUM(execution_count)                                  AS total_executions,
    MAX(total_elapsed_time / NULLIF(execution_count,0)) / 1000 AS worst_avg_ms
FROM sys.dm_exec_query_stats
GROUP BY query_hash
HAVING COUNT(DISTINCT plan_handle) > 2
ORDER BY distinct_plans DESC, total_executions DESC;
