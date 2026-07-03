-- =============================================================================
-- perf_19_storage_topology.sql
-- Priority: MEDIUM
-- Purpose: Map SQL Server storage: data/log file locations, filegroups,
--          tempdb layout, and per-filegroup size distribution. Critical
--          for DR planning and I/O balancing.
-- Sources: sys.master_files, sys.database_files, sys.filegroups,
--          sys.dm_io_virtual_file_stats, sys.dm_db_file_space_usage.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Instance-wide file inventory (all databases)
-- NOTE: sys.master_files does not exist on Azure SQL Database; a direct
-- reference there is a batch-aborting compile error, so the query runs via
-- OBJECT_ID-guarded dynamic SQL (TRY/CATCH alone cannot catch that).
-- ---------------------------------------------------------------------------
IF OBJECT_ID('sys.master_files') IS NOT NULL
BEGIN
    BEGIN TRY
        EXEC sp_executesql N'
    SELECT
        DB_NAME(mf.database_id)                          AS database_name,
        mf.file_id,
        mf.name                                          AS logical_name,
        mf.type_desc,
        mf.physical_name,
        mf.state_desc,
        CAST(mf.size * 8.0 / 1024 AS DECIMAL(18,2))      AS size_mb,
        mf.max_size,
        mf.growth,
        mf.is_percent_growth,
        mf.is_read_only
    FROM sys.master_files mf
    ORDER BY database_name, mf.file_id;';
    END TRY
    BEGIN CATCH
        PRINT '[note] sys.master_files not accessible: ' + ERROR_MESSAGE();
    END CATCH;
END
ELSE
    PRINT '[note] sys.master_files not available - skipped';

-- ---------------------------------------------------------------------------
-- Current-database file layout
-- ---------------------------------------------------------------------------
SELECT
    df.file_id,
    df.name                                              AS logical_name,
    df.type_desc,
    df.physical_name,
    fg.name                                              AS filegroup_name,
    fg.is_default                                        AS is_default_fg,
    fg.type_desc                                         AS filegroup_type,
    CAST(df.size * 8.0 / 1024 AS DECIMAL(18,2))          AS size_mb,
    CASE df.max_size
        WHEN -1 THEN 'UNLIMITED'
        WHEN 0  THEN 'NO GROWTH'
        -- Cast to BIGINT before multiplying; max_size is INT pages and
        -- max_size * 8 overflows INT for any file larger than ~2 TB.
        ELSE CAST(CAST(df.max_size AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                                  AS max_size,
    CASE WHEN df.is_percent_growth = 1
         THEN CAST(df.growth AS VARCHAR(10)) + '%'
         ELSE CAST(CAST(df.growth AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                                  AS growth
FROM sys.database_files df
LEFT JOIN sys.filegroups fg ON fg.data_space_id = df.data_space_id
ORDER BY df.type_desc, df.file_id;

-- ---------------------------------------------------------------------------
-- Per-filegroup size in the current database
-- ---------------------------------------------------------------------------
SELECT
    fg.name                                              AS filegroup_name,
    fg.type_desc,
    fg.is_default,
    COUNT(df.file_id)                                    AS file_count,
    CAST(SUM(df.size) * 8.0 / 1024 AS DECIMAL(18,2))     AS total_size_mb
FROM sys.filegroups fg
LEFT JOIN sys.database_files df ON df.data_space_id = fg.data_space_id
GROUP BY fg.name, fg.type_desc, fg.is_default
ORDER BY total_size_mb DESC;

-- ---------------------------------------------------------------------------
-- Per-table filegroup placement — which table lives in which FG
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                             AS schema_name,
    o.name                                               AS table_name,
    ds.name                                              AS placed_on,
    ds.type_desc                                         AS placement_type,
    CAST(SUM(a.total_pages) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.objects o
JOIN sys.indexes i    ON i.object_id = o.object_id AND i.index_id IN (0,1)
JOIN sys.data_spaces ds ON ds.data_space_id = i.data_space_id
JOIN sys.partitions p ON p.object_id = o.object_id AND p.index_id = i.index_id
JOIN sys.allocation_units a ON a.container_id = p.hobt_id
WHERE o.is_ms_shipped = 0
  AND o.type = 'U'
GROUP BY o.schema_id, o.name, ds.name, ds.type_desc
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- I/O latency per file (top offenders)
-- ---------------------------------------------------------------------------
IF OBJECT_ID('sys.master_files') IS NOT NULL
BEGIN
    BEGIN TRY
        EXEC sp_executesql N'
    SELECT TOP 30
        DB_NAME(vfs.database_id)                         AS database_name,
        mf.name                                          AS logical_name,
        mf.type_desc,
        vfs.num_of_reads,
        vfs.num_of_writes,
        CAST(vfs.io_stall_read_ms * 1.0 / NULLIF(vfs.num_of_reads,0) AS DECIMAL(18,2))  AS avg_read_ms,
        CAST(vfs.io_stall_write_ms * 1.0 / NULLIF(vfs.num_of_writes,0) AS DECIMAL(18,2)) AS avg_write_ms,
        CAST(vfs.size_on_disk_bytes / 1024.0 / 1024 AS DECIMAL(18,2)) AS size_on_disk_mb,
        mf.physical_name
    FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
    JOIN sys.master_files mf
          ON mf.database_id = vfs.database_id AND mf.file_id = vfs.file_id
    ORDER BY (vfs.io_stall_read_ms + vfs.io_stall_write_ms) DESC;';
    END TRY
    BEGIN CATCH
        PRINT '[note] per-file I/O latency unavailable: ' + ERROR_MESSAGE();
    END CATCH;
END
ELSE
    PRINT '[note] sys.master_files not available - per-file I/O latency skipped';

-- ---------------------------------------------------------------------------
-- tempdb file layout (multi-file tempdb is a best practice)
-- ---------------------------------------------------------------------------
IF OBJECT_ID('sys.master_files') IS NOT NULL
BEGIN
    BEGIN TRY
        EXEC sp_executesql N'
    SELECT
        mf.name                                          AS logical_name,
        mf.physical_name,
        mf.type_desc,
        CAST(mf.size * 8.0 / 1024 AS DECIMAL(18,2))      AS size_mb,
        mf.growth,
        mf.is_percent_growth
    FROM sys.master_files mf
    WHERE mf.database_id = DB_ID(''tempdb'')
    ORDER BY mf.type_desc, mf.file_id;';
    END TRY
    BEGIN CATCH
        PRINT '[note] tempdb file layout unavailable: ' + ERROR_MESSAGE();
    END CATCH;
END
ELSE
    PRINT '[note] sys.master_files not available - tempdb layout skipped';

-- ---------------------------------------------------------------------------
-- Distinct physical drives in use (quick view of I/O spread)
-- ---------------------------------------------------------------------------
IF OBJECT_ID('sys.master_files') IS NOT NULL
BEGIN
    BEGIN TRY
        EXEC sp_executesql N'
    SELECT
        UPPER(LEFT(physical_name, 3))                    AS drive_letter,
        COUNT(*)                                         AS files_on_drive,
        CAST(SUM(size) * 8.0 / 1024 AS DECIMAL(18,2))    AS total_size_mb
    FROM sys.master_files
    GROUP BY UPPER(LEFT(physical_name, 3))
    ORDER BY total_size_mb DESC;';
    END TRY
    BEGIN CATCH
        PRINT '[note] drive rollup unavailable: ' + ERROR_MESSAGE();
    END CATCH;
END
ELSE
    PRINT '[note] sys.master_files not available - drive rollup skipped';

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.database_files WHERE type_desc = 'ROWS')      AS data_files,
    (SELECT COUNT(*) FROM sys.database_files WHERE type_desc = 'LOG')       AS log_files,
    (SELECT COUNT(*) FROM sys.filegroups)                                    AS filegroups,
    (SELECT COUNT(*) FROM sys.filegroups WHERE type_desc = 'MEMORY_OPTIMIZED_DATA_FILEGROUP') AS in_memory_filegroups,
    CAST((SELECT SUM(size) * 8.0 / 1024 FROM sys.database_files
          WHERE type_desc = 'ROWS') AS DECIMAL(18,2))                       AS data_size_mb,
    CAST((SELECT SUM(size) * 8.0 / 1024 FROM sys.database_files
          WHERE type_desc = 'LOG') AS DECIMAL(18,2))                        AS log_size_mb;
