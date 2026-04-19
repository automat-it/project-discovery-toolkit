-- =============================================================================
-- sec_23_data_retention_audit.sql
-- Priority: MEDIUM
-- Purpose: Identify large tables with no retention signal — no
--          partitioning, no scheduled Agent job that prunes, and a
--          time-like column that would be the natural retention key.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Top 100 tables by reserved pages across all databases the login can see
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                             AS database_name,
    s.name                                                AS schema_name,
    o.name                                                AS table_name,
    p.rows                                                AS row_count,
    CAST(SUM(au.total_pages) * 8.0 / 1024 AS DECIMAL(18,1)) AS total_mb,
    CAST(SUM(au.used_pages)  * 8.0 / 1024 AS DECIMAL(18,1)) AS used_mb,
    o.create_date,
    o.modify_date,
    MAX(CASE WHEN i.index_id IN (0,1) THEN i.data_space_id END) AS data_space_id
FROM sys.objects o
JOIN sys.schemas  s  ON s.schema_id = o.schema_id
JOIN sys.partitions p ON p.object_id = o.object_id AND p.index_id IN (0,1)
JOIN sys.allocation_units au ON au.container_id = p.partition_id
JOIN sys.indexes  i  ON i.object_id = o.object_id
WHERE o.type = 'U'
GROUP BY s.name, o.name, p.rows, o.create_date, o.modify_date
ORDER BY SUM(au.total_pages) DESC
OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY;

-- ---------------------------------------------------------------------------
-- Large tables WITHOUT partitioning — default data_space_id in
-- sys.indexes corresponds to a filegroup (> 0) for non-partitioned
-- objects; partition_scheme_id lives in sys.partition_schemes.
-- A non-partitioned > 1 GB table is a retention candidate.
-- ---------------------------------------------------------------------------
;WITH tbl AS (
    SELECT
        s.name   AS schema_name,
        o.name   AS table_name,
        o.object_id,
        SUM(au.total_pages) * 8 / 1024 AS total_mb,
        MAX(p.rows) AS rows
    FROM sys.objects o
    JOIN sys.schemas s ON s.schema_id = o.schema_id
    JOIN sys.partitions p ON p.object_id = o.object_id AND p.index_id IN (0,1)
    JOIN sys.allocation_units au ON au.container_id = p.partition_id
    WHERE o.type = 'U'
    GROUP BY s.name, o.name, o.object_id
), part_status AS (
    SELECT object_id,
           MAX(CASE WHEN ps.data_space_id IS NOT NULL THEN 1 ELSE 0 END) AS is_partitioned
    FROM sys.indexes i
    LEFT JOIN sys.partition_schemes ps ON ps.data_space_id = i.data_space_id
    WHERE i.index_id IN (0,1)
    GROUP BY object_id
)
SELECT
    t.schema_name, t.table_name, t.total_mb, t.rows,
    CASE ps.is_partitioned WHEN 1 THEN 'partitioned' ELSE 'not partitioned' END AS partitioning
FROM tbl t
LEFT JOIN part_status ps ON ps.object_id = t.object_id
WHERE t.total_mb > 1024
  AND COALESCE(ps.is_partitioned, 0) = 0
ORDER BY t.total_mb DESC;

-- ---------------------------------------------------------------------------
-- Tables with time-like columns — candidate retention keys
-- ---------------------------------------------------------------------------
SELECT
    s.name                                                AS schema_name,
    o.name                                                AS table_name,
    c.name                                                AS column_name,
    t.name                                                AS type_name,
    c.is_nullable
FROM sys.columns c
JOIN sys.objects o ON o.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = o.schema_id
JOIN sys.types   t ON t.user_type_id = c.user_type_id
WHERE o.type = 'U'
  AND (t.name IN ('date','datetime','datetime2','datetimeoffset','smalldatetime')
       OR c.name LIKE '%created%'
       OR c.name LIKE '%modified%'
       OR c.name LIKE '%updated%'
       OR c.name LIKE '%inserted%'
       OR c.name LIKE '%_date'
       OR c.name LIKE '%_timestamp'
       OR c.name LIKE 'event_%')
ORDER BY s.name, o.name, c.column_id;

-- ---------------------------------------------------------------------------
-- SQL Agent jobs — scheduled retention lives here. Wrapped in TRY/CATCH
-- because Agent is absent on Azure SQL DB and SQL Express.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        j.job_id,
        j.name                                            AS job_name,
        j.enabled,
        j.date_created,
        j.date_modified,
        j.description,
        (SELECT COUNT(*) FROM msdb.dbo.sysjobschedules js WHERE js.job_id = j.job_id) AS schedule_count,
        (SELECT TOP 1 step.command
           FROM msdb.dbo.sysjobsteps step
          WHERE step.job_id = j.job_id
            AND (step.command LIKE '%DELETE%' OR step.command LIKE '%TRUNCATE%'
                 OR step.command LIKE '%purge%' OR step.command LIKE '%retention%')
          ORDER BY step.step_id)                           AS sample_retention_step
    FROM msdb.dbo.sysjobs j
    WHERE EXISTS (
        SELECT 1 FROM msdb.dbo.sysjobsteps step
         WHERE step.job_id = j.job_id
           AND (step.command LIKE '%DELETE%' OR step.command LIKE '%TRUNCATE%'
                OR step.command LIKE '%purge%' OR step.command LIKE '%retention%')
    )
    ORDER BY j.name;
END TRY
BEGIN CATCH
    PRINT '[note] SQL Agent / msdb not accessible: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Temporal tables — built-in retention via HISTORY_RETENTION_PERIOD.
-- A temporal table with retention NULL keeps history forever.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        SCHEMA_NAME(t.schema_id)                          AS schema_name,
        t.name                                            AS table_name,
        t.temporal_type_desc,
        OBJECT_NAME(t.history_table_id)                   AS history_table,
        t.history_retention_period,
        t.history_retention_period_unit_desc,
        CASE WHEN t.temporal_type = 2 AND t.history_retention_period IS NULL
             THEN 'history retained forever — review policy' END AS assessment
    FROM sys.tables t
    WHERE t.temporal_type_desc IS NOT NULL
      AND t.temporal_type_desc <> 'NON_TEMPORAL_TABLE';
END TRY
BEGIN CATCH
    PRINT '[note] temporal-table metadata unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.objects WHERE type = 'U')                     AS user_tables,
    (SELECT COUNT(DISTINCT object_id) FROM sys.partitions
      WHERE partition_number > 1 AND index_id IN (0,1))                     AS partitioned_tables,
    (SELECT COUNT(*) FROM sys.tables WHERE temporal_type = 2)               AS temporal_tables;
