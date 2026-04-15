-- =============================================================================
-- perf_05_configuration_snapshot.sql
-- Priority: CRITICAL
-- Purpose: Snapshot of tunable parameters. Spot gross misconfiguration
--          (parallelism defaults, min/max memory unset, autogrow mismatches).
-- Sources: sys.configurations, sys.databases, sys.master_files,
--          sys.dm_os_sys_info, sys.dm_exec_query_optimizer_info.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- SQL Server edition, version, and instance-level sys info
-- ---------------------------------------------------------------------------
SELECT
    SERVERPROPERTY('Edition')                         AS edition,
    SERVERPROPERTY('ProductVersion')                  AS version,
    SERVERPROPERTY('ProductLevel')                    AS patch_level,
    SERVERPROPERTY('EngineEdition')                   AS engine_edition,
    SERVERPROPERTY('Collation')                       AS server_collation,
    SERVERPROPERTY('IsClustered')                     AS is_clustered,
    SERVERPROPERTY('IsHadrEnabled')                   AS is_hadr_enabled,
    SERVERPROPERTY('IsFullTextInstalled')             AS full_text_installed,
    SERVERPROPERTY('MachineName')                     AS machine_name,
    SERVERPROPERTY('ServerName')                      AS server_name;

-- ---------------------------------------------------------------------------
-- OS / hardware snapshot
-- ---------------------------------------------------------------------------
SELECT
    cpu_count,
    hyperthread_ratio,
    physical_memory_kb / 1024 / 1024                  AS physical_memory_gb,
    committed_kb / 1024 / 1024                        AS committed_gb,
    committed_target_kb / 1024 / 1024                 AS committed_target_gb,
    max_workers_count,
    scheduler_count,
    sqlserver_start_time
FROM sys.dm_os_sys_info;

-- ---------------------------------------------------------------------------
-- Every sp_configure / sys.configurations setting (non-default highlighted)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS setting,
    value                                             AS value_set,
    value_in_use                                      AS current_value,
    minimum,
    maximum,
    description,
    is_advanced,
    is_dynamic,
    CASE WHEN value <> value_in_use THEN 'PENDING RESTART' ELSE '' END AS pending_restart
FROM sys.configurations
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Memory configuration (min/max server memory, grants, large pages)
-- ---------------------------------------------------------------------------
SELECT
    name, value, value_in_use, minimum, maximum
FROM sys.configurations
WHERE name IN (
    'min server memory (MB)',
    'max server memory (MB)',
    'index create memory (KB)',
    'min memory per query (KB)',
    'query wait (s)',
    'locks',
    'max worker threads',
    'priority boost',
    'fill factor (%)')
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Parallelism configuration
-- ---------------------------------------------------------------------------
SELECT
    name, value, value_in_use
FROM sys.configurations
WHERE name IN (
    'cost threshold for parallelism',
    'max degree of parallelism',
    'parallelism worker threads')
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Database-level options that often drift from defaults
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS database_name,
    state_desc,
    recovery_model_desc,
    compatibility_level,
    page_verify_option_desc,
    is_auto_close_on,
    is_auto_shrink_on,
    is_auto_create_stats_on,
    is_auto_update_stats_on,
    is_auto_update_stats_async_on,
    snapshot_isolation_state_desc,
    is_read_committed_snapshot_on,
    is_broker_enabled,
    is_cdc_enabled,
    is_query_store_on,
    is_parameterization_forced,
    collation_name
FROM sys.databases
WHERE database_id > 4
ORDER BY name;

-- ---------------------------------------------------------------------------
-- File auto-growth settings (look for 1 MB / 10% defaults)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(database_id)                              AS database_name,
    name                                              AS logical_file,
    type_desc                                         AS file_type,
    physical_name,
    CAST(size AS BIGINT) * 8 / 1024                   AS size_mb,
    CASE WHEN is_percent_growth = 1
         THEN CONCAT(growth, '%')
         ELSE CONCAT(CAST(growth AS BIGINT) * 8 / 1024, ' MB')
    END                                               AS growth_setting,
    CASE WHEN max_size = -1 THEN 'unlimited'
         WHEN max_size =  0 THEN 'no growth'
         ELSE CAST(CAST(max_size AS BIGINT) * 8 / 1024 AS VARCHAR(20)) + ' MB'
    END                                               AS max_size,
    state_desc
FROM sys.master_files
WHERE database_id > 4
ORDER BY DB_NAME(database_id), type_desc, name;

-- ---------------------------------------------------------------------------
-- Trace flags currently on
-- ---------------------------------------------------------------------------
DBCC TRACESTATUS(-1) WITH NO_INFOMSGS;

-- ---------------------------------------------------------------------------
-- TempDB configuration (file count, sizes — important for contention)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS logical_file,
    type_desc,
    physical_name,
    CAST(size AS BIGINT) * 8 / 1024                   AS size_mb,
    CASE WHEN is_percent_growth = 1
         THEN CONCAT(growth, '%')
         ELSE CONCAT(CAST(growth AS BIGINT) * 8 / 1024, ' MB')
    END                                               AS growth_setting,
    state_desc
FROM sys.master_files
WHERE database_id = 2
ORDER BY type_desc, file_id;
