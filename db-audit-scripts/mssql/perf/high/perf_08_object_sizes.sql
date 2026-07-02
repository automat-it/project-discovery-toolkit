-- =============================================================================
-- perf_08_object_sizes.sql
-- Priority: HIGH
-- Purpose: Largest databases, tables, indexes, and partitions — identify
--          hot spots and growth candidates.
-- Sources: sys.databases, sys.master_files, sys.dm_db_partition_stats,
--          sys.partitions, sys.partition_schemes.
-- Read-only.
-- =============================================================================

-- Portability: this script reads sys.master_files, which is NOT
-- supported on Azure SQL Database (single DB). It works on SQL
-- Server 2019+ on-prem, SQL Managed Instance, and Azure SQL DB
-- Hyperscale. Skip this script on Azure SQL DB.
SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Database sizes (data + log files). sys.master_files is unavailable on
-- Azure SQL Database; TRY/CATCH lets the block skip cleanly instead of
-- aborting the whole script.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        d.name                                            AS database_name,
        d.state_desc,
        d.recovery_model_desc,
        CAST(SUM(CASE WHEN mf.type = 0 THEN mf.size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS data_mb,
        CAST(SUM(CASE WHEN mf.type = 1 THEN mf.size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS log_mb,
        CAST(SUM(mf.size) * 8.0 / 1024 AS DECIMAL(18,2))   AS total_mb,
        COUNT(CASE WHEN mf.type = 0 THEN 1 END)           AS data_file_count,
        COUNT(CASE WHEN mf.type = 1 THEN 1 END)           AS log_file_count
    FROM sys.databases d
    JOIN sys.master_files mf ON mf.database_id = d.database_id
    WHERE d.database_id > 4
    GROUP BY d.name, d.state_desc, d.recovery_model_desc
    ORDER BY total_mb DESC;
END TRY
BEGIN CATCH
    PRINT '[note] sys.master_files not accessible (likely Azure SQL DB): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Schema sizes in the current database
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    COUNT(DISTINCT o.object_id)                       AS table_count,
    SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.row_count ELSE 0 END) AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS total_mb
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Top 50 largest tables (heap + clustered + nonclustered reserved space)
-- ---------------------------------------------------------------------------
SELECT TOP 50
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.row_count ELSE 0 END) AS row_count,
    CAST(SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.in_row_data_page_count ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS heap_or_clustered_mb,
    CAST(SUM(CASE WHEN ps.index_id >  1 THEN ps.in_row_data_page_count ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS nonclustered_mb,
    CAST(SUM(ps.lob_reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS lob_mb,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS total_mb
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Top 50 largest indexes (excluding heap / clustered PK)
-- ---------------------------------------------------------------------------
SELECT TOP 50
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.dm_db_partition_stats ps
JOIN sys.indexes i ON i.object_id = ps.object_id AND i.index_id = ps.index_id
JOIN sys.objects o ON o.object_id = i.object_id
WHERE i.index_id > 1                                  -- nonclustered only
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name, i.name, i.type_desc
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Tables where indexes are LARGER than the heap/clustered data
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    CAST(SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.reserved_page_count ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS data_mb,
    CAST(SUM(CASE WHEN ps.index_id >  1 THEN ps.reserved_page_count ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS indexes_mb,
    -- DECIMAL(18,2) -- index size can be many multiples of data size on
    -- tables with lots of covering / wide non-clustered indexes, so the
    -- ratio routinely exceeds 999.99 and overflows DECIMAL(5,2).
    CAST(SUM(CASE WHEN ps.index_id >  1 THEN ps.reserved_page_count ELSE 0 END)
         * 1.0
         / NULLIF(SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.reserved_page_count ELSE 0 END), 0)
         AS DECIMAL(18,2))                             AS index_to_data_ratio
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name
HAVING SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.reserved_page_count ELSE 0 END) > 1280  -- > 10 MB data
   AND SUM(CASE WHEN ps.index_id >  1 THEN ps.reserved_page_count ELSE 0 END)
       > SUM(CASE WHEN ps.index_id IN (0,1) THEN ps.reserved_page_count ELSE 0 END)
ORDER BY indexes_mb DESC;

-- ---------------------------------------------------------------------------
-- Partitioned tables — row count + size per partition
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    p.partition_number,
    p.rows                                            AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    pf.name                                           AS partition_function,
    ps2.name                                          AS partition_scheme
FROM sys.partitions p
JOIN sys.indexes i             ON i.object_id = p.object_id AND i.index_id = p.index_id
JOIN sys.objects o             ON o.object_id = p.object_id
LEFT JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = p.object_id
     AND ps.index_id  = p.index_id
     AND ps.partition_number = p.partition_number
LEFT JOIN sys.partition_schemes   ps2 ON ps2.data_space_id = i.data_space_id
LEFT JOIN sys.partition_functions pf  ON pf.function_id    = ps2.function_id
WHERE o.is_ms_shipped = 0
  AND i.index_id IN (0,1)                              -- partitions for heap / clustered
  AND EXISTS (SELECT 1 FROM sys.partitions p2
               WHERE p2.object_id = p.object_id
                 AND p2.index_id  = p.index_id
                 AND p2.partition_number > 1)
GROUP BY o.schema_id, o.name, i.name, p.partition_number, p.rows, pf.name, ps2.name
ORDER BY schema_name, table_name, p.partition_number;

-- ---------------------------------------------------------------------------
-- Columnstore indexes (segment count + row groups)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    SUM(rg.total_rows)                                AS total_rows,
    SUM(rg.deleted_rows)                              AS deleted_rows,
    COUNT(*)                                          AS row_groups,
    SUM(CAST(rg.size_in_bytes AS BIGINT)) / 1024 / 1024 AS size_mb
FROM sys.dm_db_column_store_row_group_physical_stats rg
JOIN sys.indexes i ON i.object_id = rg.object_id AND i.index_id = rg.index_id
JOIN sys.objects o ON o.object_id = i.object_id
WHERE o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name, i.name, i.type_desc
ORDER BY size_mb DESC;
