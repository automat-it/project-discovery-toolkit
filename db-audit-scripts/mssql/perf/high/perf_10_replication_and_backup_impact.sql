-- =============================================================================
-- perf_10_replication_and_backup_impact.sql
-- Priority: HIGH
-- Purpose: Replication state (AlwaysOn / CDC / Change Tracking / Log
--          Shipping), active backups, and recent backup history — all
--          things that can push write latency up.
-- Sources: sys.dm_hadr_*, sys.databases, cdc.*, MSdb backup history,
--          sys.dm_exec_requests for in-flight backups.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Is this an AlwaysOn AG member? (NULL = standalone)
-- ---------------------------------------------------------------------------
SELECT
    SERVERPROPERTY('IsHadrEnabled')                   AS is_hadr_enabled,
    SERVERPROPERTY('HadrManagerStatus')               AS hadr_manager_status;

-- AG replica state
SELECT
    ag.name                                           AS ag_name,
    ar.replica_server_name,
    ars.role_desc                                     AS current_role,
    ars.operational_state_desc,
    ars.connected_state_desc,
    ars.synchronization_health_desc,
    ar.availability_mode_desc,
    ar.failover_mode_desc,
    ar.primary_role_allow_connections_desc,
    ar.secondary_role_allow_connections_desc
FROM sys.availability_groups ag
JOIN sys.availability_replicas  ar ON ar.group_id = ag.group_id
LEFT JOIN sys.dm_hadr_availability_replica_states ars ON ars.replica_id = ar.replica_id;

-- Per-database AG state (lag, redo queue, log send queue)
SELECT
    DB_NAME(drs.database_id)                          AS database_name,
    ar.replica_server_name,
    drs.synchronization_state_desc,
    drs.synchronization_health_desc,
    drs.log_send_queue_size,
    drs.log_send_rate,
    drs.redo_queue_size,
    drs.redo_rate,
    drs.last_sent_time,
    drs.last_received_time,
    drs.last_hardened_time,
    drs.last_redone_time
FROM sys.dm_hadr_database_replica_states drs
LEFT JOIN sys.availability_replicas ar ON ar.replica_id = drs.replica_id
ORDER BY DB_NAME(drs.database_id);

-- ---------------------------------------------------------------------------
-- CDC state per database
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS database_name,
    is_cdc_enabled,
    is_change_feed_enabled
FROM sys.databases
WHERE database_id > 4
ORDER BY name;

-- CDC capture / cleanup jobs (if exposed at instance level)
SELECT
    j.name                                            AS job_name,
    j.enabled,
    j.description,
    js.last_run_outcome,
    js.last_run_date,
    js.last_run_time
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobservers js ON js.job_id = j.job_id
WHERE j.name LIKE 'cdc.%'
ORDER BY j.name;

-- CDC enabled tables in this database + last LSN seen
-- Run this script with USE <db> for each database you care about.
IF EXISTS (SELECT 1 FROM sys.schemas WHERE name = 'cdc')
BEGIN
    SELECT
        ct.capture_instance,
        OBJECT_SCHEMA_NAME(ct.source_object_id)       AS source_schema,
        OBJECT_NAME(ct.source_object_id)              AS source_table,
        ct.start_lsn,
        ct.create_date,
        ct.supports_net_changes
    FROM cdc.change_tables ct
    ORDER BY source_schema, source_table;
END;

-- ---------------------------------------------------------------------------
-- Change Tracking (lightweight alternative to CDC)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(database_id)                              AS database_name,
    retention_period,
    retention_period_units_desc,
    is_auto_cleanup_on
FROM sys.change_tracking_databases;

SELECT
    OBJECT_SCHEMA_NAME(object_id)                     AS schema_name,
    OBJECT_NAME(object_id)                            AS table_name,
    is_track_columns_updated_on,
    begin_version,
    min_valid_version,
    cleanup_version
FROM sys.change_tracking_tables
ORDER BY OBJECT_SCHEMA_NAME(object_id), OBJECT_NAME(object_id);

-- ---------------------------------------------------------------------------
-- Replication distribution (if transactional replication is configured)
-- ---------------------------------------------------------------------------
IF DB_ID('distribution') IS NOT NULL
BEGIN
    SELECT
        name                                          AS replication_db
    FROM sys.databases
    WHERE name = 'distribution';
END;

-- ---------------------------------------------------------------------------
-- Currently running base backups / restores
-- ---------------------------------------------------------------------------
SELECT
    r.session_id,
    s.login_name,
    DB_NAME(r.database_id)                            AS database_name,
    r.command,
    r.start_time,
    r.percent_complete,
    DATEADD(second, r.estimated_completion_time / 1000, SYSUTCDATETIME())
                                                      AS estimated_completion,
    r.wait_type,
    r.wait_time,
    LEFT(txt.text, 300)                               AS statement_text
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) txt
WHERE r.command IN ('BACKUP DATABASE','BACKUP LOG','BACKUP DIFFERENTIAL',
                    'RESTORE DATABASE','RESTORE LOG',
                    'DbccFilesCompact','DbccSpaceReclaim')
ORDER BY r.start_time;

-- ---------------------------------------------------------------------------
-- Last successful backup per database (from msdb backup history)
-- ---------------------------------------------------------------------------
SELECT
    d.name                                            AS database_name,
    d.recovery_model_desc,
    MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END) AS last_full,
    MAX(CASE WHEN bs.type = 'I' THEN bs.backup_finish_date END) AS last_differential,
    MAX(CASE WHEN bs.type = 'L' THEN bs.backup_finish_date END) AS last_log,
    DATEDIFF(hour,
             ISNULL(MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END),
                    '1900-01-01'),
             SYSUTCDATETIME())                        AS hours_since_full
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset bs
      ON bs.database_name = d.name
WHERE d.database_id > 4
GROUP BY d.name, d.recovery_model_desc
ORDER BY d.name;

-- ---------------------------------------------------------------------------
-- Log-shipping status (if configured)
-- ---------------------------------------------------------------------------
IF OBJECT_ID('msdb.dbo.log_shipping_monitor_primary') IS NOT NULL
    SELECT * FROM msdb.dbo.log_shipping_monitor_primary;
IF OBJECT_ID('msdb.dbo.log_shipping_monitor_secondary') IS NOT NULL
    SELECT * FROM msdb.dbo.log_shipping_monitor_secondary;
