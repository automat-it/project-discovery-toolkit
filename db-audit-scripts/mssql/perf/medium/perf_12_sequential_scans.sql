-- =============================================================================
-- perf_12_sequential_scans.sql
-- Priority: MEDIUM
-- Purpose: Tables with high table-scan ratio — typically missing index
--          indicators (or appropriate for very small / very hot tables).
-- Sources: sys.dm_db_index_usage_stats (scans vs seeks on clustered /
--          heap), sys.indexes, sys.dm_db_partition_stats,
--          sys.dm_db_missing_index_details.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Tables where SCANS dominate seeks on the clustered index / heap
-- (excludes tiny tables where a scan is cheaper than a seek anyway)
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.type_desc                                       AS index_type,
    i.name                                            AS index_name,
    us.user_seeks,
    us.user_scans,
    us.user_lookups,
    us.user_updates,
    CAST(100.0 * us.user_scans
         / NULLIF(us.user_seeks + us.user_scans + us.user_lookups, 0)
         AS DECIMAL(5,2))                             AS scan_pct,
    SUM(ps.row_count) OVER (PARTITION BY o.object_id) AS row_count,
    CAST(SUM(ps.reserved_page_count) OVER (PARTITION BY o.object_id) * 8.0 / 1024
         AS DECIMAL(18,2))                            AS size_mb
FROM sys.dm_db_index_usage_stats us
JOIN sys.indexes i
      ON i.object_id = us.object_id AND i.index_id = us.index_id
JOIN sys.objects o
      ON o.object_id = i.object_id
JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = i.object_id AND ps.index_id = i.index_id
WHERE us.database_id = DB_ID()
  AND i.index_id IN (0, 1)                             -- heap or clustered
  AND o.is_ms_shipped = 0
  AND us.user_scans > 100
  AND us.user_scans > us.user_seeks * 5
ORDER BY us.user_scans DESC;

-- ---------------------------------------------------------------------------
-- Tables with large size, many rows, and lots of scans
-- (classic missing-index candidates)
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    us.user_scans,
    us.user_seeks,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.dm_db_index_usage_stats us
JOIN sys.indexes i
      ON i.object_id = us.object_id AND i.index_id = us.index_id
JOIN sys.objects o
      ON o.object_id = i.object_id
JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = i.object_id AND ps.index_id = i.index_id
WHERE us.database_id = DB_ID()
  AND i.index_id IN (0, 1)
  AND o.is_ms_shipped = 0
  AND us.user_scans > 50
GROUP BY o.schema_id, o.name, us.user_scans, us.user_seeks
HAVING SUM(ps.row_count) > 10000
ORDER BY us.user_scans DESC;

-- ---------------------------------------------------------------------------
-- Tables with NO nonclustered indexes (heap or clustered only)
-- ---------------------------------------------------------------------------
-- Pre-compute the heap/clustered base-structure label in a derived table
-- so the outer SELECT does not force o.object_id into GROUP BY.
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    bs.base_structure,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.objects o
CROSS APPLY (
    SELECT TOP 1 type_desc AS base_structure
      FROM sys.indexes
     WHERE object_id = o.object_id AND index_id IN (0,1)
) bs
JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = o.object_id AND ps.index_id IN (0,1)
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND NOT EXISTS (
      SELECT 1 FROM sys.indexes i
       WHERE i.object_id = o.object_id
         AND i.index_id > 1                            -- any nonclustered
  )
GROUP BY o.schema_id, o.name, bs.base_structure
HAVING SUM(ps.reserved_page_count) * 8.0 / 1024 > 1
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Missing-index advisor suggestions for the current database (top 25)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    OBJECT_SCHEMA_NAME(mid.object_id, mid.database_id) AS schema_name,
    OBJECT_NAME(mid.object_id, mid.database_id)        AS table_name,
    migs.user_seeks,
    migs.user_scans,
    migs.avg_total_user_cost,
    migs.avg_user_impact,
    CAST(migs.avg_total_user_cost
         * (migs.avg_user_impact / 100.0)
         * (migs.user_seeks + migs.user_scans) AS DECIMAL(18,2)) AS improvement_score,
    mid.equality_columns,
    mid.inequality_columns,
    mid.included_columns
FROM sys.dm_db_missing_index_details mid
JOIN sys.dm_db_missing_index_groups mig   ON mig.index_handle   = mid.index_handle
JOIN sys.dm_db_missing_index_group_stats migs
      ON migs.group_handle = mig.index_group_handle
WHERE mid.database_id = DB_ID()
ORDER BY improvement_score DESC;

-- ---------------------------------------------------------------------------
-- Operator-level scan hints from Query Store (top queries whose plan XML
-- contains <TableScan>)
-- ---------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state <> 0)
BEGIN
    SELECT TOP 25
        q.query_id,
        SUM(rs.count_executions)                      AS executions,
        CAST(SUM(rs.avg_duration * rs.count_executions) / 1000.0 AS DECIMAL(18,2)) AS total_ms,
        LEFT(qt.query_sql_text, 300)                  AS query_preview
    FROM sys.query_store_runtime_stats rs
    JOIN sys.query_store_plan p        ON p.plan_id = rs.plan_id
    JOIN sys.query_store_query q       ON q.query_id = p.query_id
    JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id
    WHERE CAST(p.query_plan AS NVARCHAR(MAX)) LIKE '%<TableScan%'
       OR CAST(p.query_plan AS NVARCHAR(MAX)) LIKE '%<IndexScan %'
    GROUP BY q.query_id, qt.query_sql_text
    ORDER BY total_ms DESC;
END;
