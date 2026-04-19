-- =============================================================================
-- perf_11_bloat_estimation.sql
-- Priority: MEDIUM
-- Purpose: Estimate index and heap bloat / fragmentation. Bloat wastes
--          I/O and cache space.
-- Sources: sys.dm_db_index_physical_stats, sys.dm_db_partition_stats,
--          sys.allocation_units.
-- Note: SQL Server does not have PostgreSQL's pg_stat_user_tables dead
--       tuple concept (MVCC works differently). Bloat is approximated via
--       page fullness percent and forwarded-record counts on heaps.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Indexes with low page fullness (a lot of air in each 8 KB page)
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    ips.page_count,
    CAST(ips.page_count * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    CAST(ips.avg_page_space_used_in_percent AS DECIMAL(5,2)) AS page_fullness_pct,
    CAST(100.0 - ips.avg_page_space_used_in_percent AS DECIMAL(5,2)) AS wasted_pct,
    CAST(ips.page_count * 8.0 * (100.0 - ips.avg_page_space_used_in_percent) / 100.0 / 1024
         AS DECIMAL(18,2))                            AS wasted_mb,
    CAST(ips.avg_fragmentation_in_percent AS DECIMAL(5,2)) AS fragmentation_pct,
    -- fill_factor is a property of the index itself, not of the
    -- dm_db_index_physical_stats result — take it from sys.indexes.
    i.fill_factor,
    ips.record_count
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'SAMPLED') ips
JOIN sys.indexes i
      ON i.object_id = ips.object_id AND i.index_id = ips.index_id
JOIN sys.objects o
      ON o.object_id = ips.object_id
WHERE ips.page_count > 256                              -- > 2 MB
  AND ips.avg_page_space_used_in_percent < 75
  AND o.is_ms_shipped = 0
ORDER BY wasted_mb DESC;

-- ---------------------------------------------------------------------------
-- Heap tables with forwarded records (update-moved rows, hurts scans)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    ips.forwarded_record_count,
    ips.page_count,
    CAST(ips.page_count * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    CAST(100.0 * ips.forwarded_record_count
         / NULLIF(ips.record_count, 0) AS DECIMAL(5,2)) AS forwarded_pct,
    ips.record_count
-- object_id / index_id / partition_number must all be NULL together;
-- if one is NULL so must the others. Filter heaps via ips.index_id = 0
-- in the WHERE clause instead.
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'DETAILED') ips
JOIN sys.objects o ON o.object_id = ips.object_id
WHERE ips.index_id = 0                                -- heap only
  AND ips.forwarded_record_count > 0
  AND o.is_ms_shipped = 0
ORDER BY ips.forwarded_record_count DESC;

-- ---------------------------------------------------------------------------
-- Large tables without a clustered index (heaps accumulate forwarded
-- records and fragmentation more aggressively than B-trees)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.objects o
JOIN sys.indexes i            ON i.object_id = o.object_id AND i.index_id = 0
JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = o.object_id AND ps.index_id = 0
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name
HAVING SUM(ps.reserved_page_count) * 8.0 / 1024 > 1
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Ghost records (soft-deleted rows awaiting cleanup by the ghost cleanup
-- task) — many ghost records indicate heavy DELETE activity
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    ips.ghost_record_count,
    ips.version_ghost_record_count,
    ips.record_count,
    CAST(100.0 * (ips.ghost_record_count + ips.version_ghost_record_count)
         / NULLIF(ips.record_count, 0) AS DECIMAL(5,2)) AS ghost_pct,
    ips.page_count
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'DETAILED') ips
JOIN sys.indexes i ON i.object_id = ips.object_id AND i.index_id = ips.index_id
JOIN sys.objects o ON o.object_id = ips.object_id
WHERE ips.ghost_record_count + ips.version_ghost_record_count > 100
  AND o.is_ms_shipped = 0
ORDER BY ghost_pct DESC;

-- ---------------------------------------------------------------------------
-- LOB allocation vs in-row allocation per table — outsized LOB space
-- often signals oversized NVARCHAR(MAX) / VARBINARY(MAX) columns
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    CAST(SUM(ps.in_row_data_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS in_row_mb,
    CAST(SUM(ps.lob_reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS lob_mb,
    CAST(SUM(ps.row_overflow_reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS row_overflow_mb,
    CAST(SUM(ps.lob_reserved_page_count) * 1.0
         / NULLIF(SUM(ps.in_row_data_page_count), 0) AS DECIMAL(8,2)) AS lob_to_inrow_ratio
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name
HAVING SUM(ps.lob_reserved_page_count) > 0
ORDER BY lob_mb DESC;
