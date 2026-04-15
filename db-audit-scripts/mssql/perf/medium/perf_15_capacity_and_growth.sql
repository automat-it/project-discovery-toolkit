-- =============================================================================
-- perf_15_capacity_and_growth.sql
-- Priority: MEDIUM
-- Purpose: Snapshot of storage usage, identity headroom, connection
--          pressure, and other capacity indicators for resource planning.
-- Sources: sys.databases, sys.master_files, sys.identity_columns,
--          sys.sequences, sys.dm_db_partition_stats, sys.dm_os_sys_info.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Cluster-wide storage usage (single-statement, T-SQL compatible)
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.databases WHERE database_id > 4)  AS user_databases,
    (SELECT SUM(CAST(size AS BIGINT)) * 8 / 1024 FROM sys.master_files) AS total_mb,
    (SELECT SUM(CAST(size AS BIGINT)) * 8 / 1024 FROM sys.master_files WHERE type = 0) AS total_data_mb,
    (SELECT SUM(CAST(size AS BIGINT)) * 8 / 1024 FROM sys.master_files WHERE type = 1) AS total_log_mb;

-- ---------------------------------------------------------------------------
-- Per-database size and growth indicators
-- ---------------------------------------------------------------------------
SELECT
    d.name                                            AS database_name,
    d.state_desc,
    d.recovery_model_desc,
    CAST(SUM(CASE WHEN mf.type = 0 THEN mf.size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS data_mb,
    CAST(SUM(CASE WHEN mf.type = 1 THEN mf.size END) * 8.0 / 1024 AS DECIMAL(18,2)) AS log_mb,
    COUNT(CASE WHEN mf.type = 0 THEN 1 END)           AS data_files,
    COUNT(CASE WHEN mf.type = 1 THEN 1 END)           AS log_files,
    d.create_date,
    d.log_reuse_wait_desc
FROM sys.databases d
JOIN sys.master_files mf ON mf.database_id = d.database_id
WHERE d.database_id > 4
GROUP BY d.name, d.state_desc, d.recovery_model_desc,
         d.create_date, d.log_reuse_wait_desc
ORDER BY data_mb DESC;

-- ---------------------------------------------------------------------------
-- Top tables by rows / size in the current database
-- ---------------------------------------------------------------------------
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    SUM(ps.row_count)                                 AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.dm_db_partition_stats ps
JOIN sys.objects o ON o.object_id = ps.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND ps.index_id IN (0, 1)
GROUP BY o.schema_id, o.name
ORDER BY row_count DESC;

-- ---------------------------------------------------------------------------
-- Connection limit and current usage
-- ---------------------------------------------------------------------------
SELECT
    (SELECT CAST(value_in_use AS INT) FROM sys.configurations WHERE name = 'user connections') AS configured_max_connections,
    @@MAX_CONNECTIONS                                 AS server_max_connections,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1) AS current_user_sessions,
    (SELECT COUNT(*) FROM sys.dm_exec_connections)    AS current_connections;

-- ---------------------------------------------------------------------------
-- IDENTITY column headroom (approaching INT / BIGINT overflow)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    ic.name                                           AS column_name,
    TYPE_NAME(ic.user_type_id)                        AS data_type,
    ic.seed_value,
    ic.increment_value,
    ic.last_value,
    CASE TYPE_NAME(ic.user_type_id)
        WHEN 'tinyint'  THEN 255
        WHEN 'smallint' THEN 32767
        WHEN 'int'      THEN 2147483647
        WHEN 'bigint'   THEN 9223372036854775807
        ELSE NULL
    END                                               AS max_value,
    CASE TYPE_NAME(ic.user_type_id)
        WHEN 'tinyint'  THEN CAST(100.0 * CAST(ic.last_value AS BIGINT) / 255 AS DECIMAL(6,3))
        WHEN 'smallint' THEN CAST(100.0 * CAST(ic.last_value AS BIGINT) / 32767 AS DECIMAL(6,3))
        WHEN 'int'      THEN CAST(100.0 * CAST(ic.last_value AS BIGINT) / 2147483647 AS DECIMAL(6,4))
        WHEN 'bigint'   THEN CAST(100.0 * CAST(ic.last_value AS DECIMAL(38,0)) / 9223372036854775807 AS DECIMAL(8,6))
        ELSE NULL
    END                                               AS pct_consumed
FROM sys.identity_columns ic
JOIN sys.objects o ON o.object_id = ic.object_id
WHERE o.is_ms_shipped = 0
  AND ic.last_value IS NOT NULL
ORDER BY pct_consumed DESC;

-- ---------------------------------------------------------------------------
-- SEQUENCE objects (explicit sequences — not auto-identity)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(s.schema_id)                          AS schema_name,
    s.name                                            AS sequence_name,
    TYPE_NAME(s.user_type_id)                         AS data_type,
    s.current_value,
    s.maximum_value,
    s.minimum_value,
    s.increment,
    s.is_cycling,
    s.is_exhausted,
    CAST(100.0 * CAST(s.current_value AS DECIMAL(38,0))
              / NULLIF(CAST(s.maximum_value AS DECIMAL(38,0)), 0)
              AS DECIMAL(8,4))                        AS pct_consumed
FROM sys.sequences s
ORDER BY pct_consumed DESC;

-- ---------------------------------------------------------------------------
-- Filegroup usage per database (data space allocation breakdown)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(database_id)                              AS database_name,
    data_space_id,
    name                                              AS filegroup_or_logical_file,
    type_desc,
    state_desc,
    CAST(size * 8.0 / 1024 AS DECIMAL(18,2))          AS size_mb,
    is_read_only
FROM sys.master_files
WHERE database_id > 4
ORDER BY DB_NAME(database_id), type_desc, name;
