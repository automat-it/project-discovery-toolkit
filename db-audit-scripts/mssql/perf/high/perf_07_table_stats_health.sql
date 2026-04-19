-- =============================================================================
-- perf_07_table_stats_health.sql
-- Priority: HIGH
-- Purpose: Check freshness of statistics and index fragmentation — stale
--          statistics produce bad plans.
-- Sources: sys.stats, sys.dm_db_stats_properties,
--          sys.dm_db_index_physical_stats, sys.dm_db_index_usage_stats.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Database-level auto-stats options
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS database_name,
    is_auto_create_stats_on,
    is_auto_update_stats_on,
    is_auto_update_stats_async_on,
    is_auto_create_stats_incremental_on
FROM sys.databases
WHERE database_id > 4
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Tables that have NEVER had statistics updated (no rows read-sampled)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    s.name                                            AS stat_name,
    s.auto_created,
    s.user_created,
    s.no_recompute                                    AS auto_update_disabled,
    sp.last_updated,
    sp.rows,
    sp.rows_sampled,
    sp.modification_counter
FROM sys.stats s
JOIN sys.objects o           ON o.object_id = s.object_id
OUTER APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND sp.last_updated IS NULL
ORDER BY schema_name, table_name;

-- ---------------------------------------------------------------------------
-- Stale statistics: high modification ratio since last update
-- ---------------------------------------------------------------------------
SELECT TOP 50
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    s.name                                            AS stat_name,
    sp.last_updated,
    sp.rows,
    sp.rows_sampled,
    sp.modification_counter,
    CAST(100.0 * sp.modification_counter
         / NULLIF(sp.rows, 0) AS DECIMAL(18,2))       AS mod_pct,
    DATEDIFF(day, sp.last_updated, SYSUTCDATETIME())  AS days_since_update,
    s.no_recompute                                    AS auto_update_disabled
FROM sys.stats s
JOIN sys.objects o ON o.object_id = s.object_id
OUTER APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND sp.modification_counter > 1000
ORDER BY mod_pct DESC;

-- ---------------------------------------------------------------------------
-- Statistics where AUTO-UPDATE is explicitly OFF (intentional or forgotten)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    s.name                                            AS stat_name,
    s.auto_created,
    s.user_created,
    sp.last_updated,
    sp.rows
FROM sys.stats s
JOIN sys.objects o ON o.object_id = s.object_id
OUTER APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
WHERE s.no_recompute = 1
  AND o.is_ms_shipped = 0
ORDER BY schema_name, table_name, stat_name;

-- ---------------------------------------------------------------------------
-- Index fragmentation (>30 % logical fragmentation on large objects)
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    ips.page_count,
    CAST(ips.page_count * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    CAST(ips.avg_fragmentation_in_percent AS DECIMAL(5,2)) AS fragmentation_pct,
    CAST(ips.avg_page_space_used_in_percent AS DECIMAL(5,2)) AS page_fullness_pct,
    ips.record_count
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
JOIN sys.indexes i
      ON i.object_id = ips.object_id AND i.index_id = ips.index_id
JOIN sys.objects o
      ON o.object_id = ips.object_id
WHERE ips.page_count > 128                              -- ignore tiny objects
  AND ips.avg_fragmentation_in_percent > 30
  AND o.is_ms_shipped = 0
ORDER BY ips.avg_fragmentation_in_percent DESC;

-- ---------------------------------------------------------------------------
-- Row count + sizing per user table (quick stats health overview)
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    MAX(us.last_user_seek)                            AS last_seek,
    MAX(us.last_user_scan)                            AS last_scan,
    MAX(us.last_user_update)                          AS last_update
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
LEFT JOIN sys.dm_db_index_usage_stats us
      ON us.object_id = o.object_id AND us.database_id = DB_ID()
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND ps.index_id IN (0, 1)                             -- heap or clustered only
GROUP BY o.schema_id, o.name
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Statistics targets (sample percentage) per index/stat
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    s.name                                            AS stat_name,
    sp.rows,
    sp.rows_sampled,
    CAST(100.0 * sp.rows_sampled / NULLIF(sp.rows, 0) AS DECIMAL(5,2)) AS sample_pct
FROM sys.stats s
JOIN sys.objects o ON o.object_id = s.object_id
OUTER APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
WHERE o.is_ms_shipped = 0
  AND sp.rows IS NOT NULL
ORDER BY sp.rows DESC;
