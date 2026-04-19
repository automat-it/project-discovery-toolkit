-- =============================================================================
-- perf_16_plan_instability.sql
-- Priority: LOW
-- Purpose: Detect query plan instability via execution-time variance
--          and multiple plans per query.
-- Sources: Query Store (preferred), sys.dm_exec_query_stats for plan-
--          cache outlier detection.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Queries with multiple plans over time (Query Store)
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    SELECT TOP 25
        q.query_id,
        COUNT(DISTINCT p.plan_id)                     AS plan_count,
        SUM(rs.count_executions)                      AS total_executions,
        CAST(AVG(rs.avg_duration) / 1000.0 AS DECIMAL(18,2)) AS mean_ms,
        CAST(AVG(rs.stdev_duration) / 1000.0 AS DECIMAL(18,2)) AS stdev_ms,
        CAST(MAX(rs.max_duration) / 1000.0 AS DECIMAL(18,2))   AS max_ms,
        CAST(MIN(rs.min_duration) / 1000.0 AS DECIMAL(18,2))   AS min_ms,
        LEFT(qt.query_sql_text, 300)                  AS query_preview
    FROM sys.query_store_query q
    JOIN sys.query_store_query_text qt   ON qt.query_text_id = q.query_text_id
    JOIN sys.query_store_plan p          ON p.query_id = q.query_id
    JOIN sys.query_store_runtime_stats rs ON rs.plan_id = p.plan_id
    GROUP BY q.query_id, qt.query_sql_text
    HAVING COUNT(DISTINCT p.plan_id) > 1
    ORDER BY plan_count DESC, total_executions DESC;
END;

-- ---------------------------------------------------------------------------
-- Queries whose duration variance is extremely high
-- (Query Store: stdev >= mean suggests parameter-sniffing / skew)
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    SELECT TOP 25
        q.query_id,
        SUM(rs.count_executions)                      AS executions,
        CAST(AVG(rs.avg_duration) / 1000.0 AS DECIMAL(18,2))    AS mean_ms,
        CAST(AVG(rs.stdev_duration) / 1000.0 AS DECIMAL(18,2))  AS stdev_ms,
        CAST(MAX(rs.max_duration) / NULLIF(MIN(rs.min_duration), 0) AS DECIMAL(10,2)) AS max_min_ratio,
        CAST(AVG(rs.stdev_duration) / NULLIF(AVG(rs.avg_duration), 0) AS DECIMAL(10,3)) AS cv,
        LEFT(qt.query_sql_text, 300)                  AS query_preview
    FROM sys.query_store_runtime_stats rs
    JOIN sys.query_store_plan p        ON p.plan_id = rs.plan_id
    JOIN sys.query_store_query q       ON q.query_id = p.query_id
    JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id
    GROUP BY q.query_id, qt.query_sql_text
    HAVING SUM(rs.count_executions) > 20
       AND AVG(rs.stdev_duration) > AVG(rs.avg_duration)
    ORDER BY cv DESC;
END;

-- ---------------------------------------------------------------------------
-- Queries with regressed plans (current plan slower than a prior plan).
-- Requires Query Store Plan Forcing hints / visible history.
-- The `;WITH plan_stats ...` CTE is nested inside the IF/BEGIN block — the
-- leading semicolon is required to terminate the preceding batch start
-- so the CTE parses correctly.
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    ;WITH plan_stats AS (
        SELECT
            q.query_id,
            p.plan_id,
            MIN(rsi.start_time)                       AS first_seen,
            MAX(rsi.end_time)                         AS last_seen,
            SUM(rs.count_executions)                  AS executions,
            AVG(rs.avg_duration)                      AS avg_duration
        FROM sys.query_store_runtime_stats rs
        JOIN sys.query_store_runtime_stats_interval rsi ON rsi.runtime_stats_interval_id = rs.runtime_stats_interval_id
        JOIN sys.query_store_plan p  ON p.plan_id = rs.plan_id
        JOIN sys.query_store_query q ON q.query_id = p.query_id
        GROUP BY q.query_id, p.plan_id
    )
    SELECT TOP 25
        ps1.query_id,
        ps1.plan_id                                   AS slower_plan,
        ps2.plan_id                                   AS faster_plan,
        CAST(ps1.avg_duration / 1000.0 AS DECIMAL(18,2)) AS slower_ms,
        CAST(ps2.avg_duration / 1000.0 AS DECIMAL(18,2)) AS faster_ms,
        ps1.executions                                AS slower_exec_count,
        ps2.executions                                AS faster_exec_count,
        ps1.last_seen
    FROM plan_stats ps1
    JOIN plan_stats ps2
          ON ps1.query_id = ps2.query_id
         AND ps1.plan_id  < ps2.plan_id
    WHERE ps1.avg_duration > ps2.avg_duration * 2
      AND ps1.executions > 10
      AND ps2.executions > 10
    ORDER BY (ps1.avg_duration - ps2.avg_duration) DESC;
END;

-- ---------------------------------------------------------------------------
-- Plan cache: queries with a large ratio of max / min elapsed time
-- (outlier detection when Query Store is not enabled)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    qs.execution_count,
    CAST(qs.min_elapsed_time / 1000.0 AS DECIMAL(18,2)) AS min_ms,
    CAST(qs.max_elapsed_time / 1000.0 AS DECIMAL(18,2)) AS max_ms,
    CAST(qs.total_elapsed_time / NULLIF(qs.execution_count, 0) / 1000.0 AS DECIMAL(18,2)) AS mean_ms,
    CAST(qs.max_elapsed_time / NULLIF(qs.min_elapsed_time, 0.0) AS DECIMAL(18,2)) AS max_min_ratio,
    SUBSTRING(st.text,
              (qs.statement_start_offset/2) + 1,
              ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
                                             ELSE qs.statement_end_offset END
                - qs.statement_start_offset)/2) + 1)  AS statement_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
WHERE qs.execution_count > 20
  AND qs.min_elapsed_time > 0
  AND qs.max_elapsed_time > qs.min_elapsed_time * 100
ORDER BY max_min_ratio DESC;

-- ---------------------------------------------------------------------------
-- Parameterization / plan cache settings
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('optimize for ad hoc workloads',
               'cost threshold for parallelism',
               'max degree of parallelism');

-- ---------------------------------------------------------------------------
-- Forced plans in Query Store (explicit plan guide equivalents)
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    SELECT
        q.query_id,
        p.plan_id,
        p.is_forced_plan,
        p.force_failure_count,
        p.last_force_failure_reason_desc,
        LEFT(qt.query_sql_text, 300)                  AS query_preview
    FROM sys.query_store_plan p
    JOIN sys.query_store_query q       ON q.query_id = p.query_id
    JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id
    WHERE p.is_forced_plan = 1;
END;
