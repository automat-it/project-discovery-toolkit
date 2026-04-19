-- =============================================================================
-- perf_22_replication_deepdive.sql
-- Priority: HIGH
-- Purpose: Surface Always On AG state, database-replica synchronisation
--          state, send / redo queue sizes, log-shipping status, and
--          classic transactional replication agents. AG secondaries
--          falling behind on redo is a silent failover risk.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Feature flags
-- ---------------------------------------------------------------------------
SELECT
    SERVERPROPERTY('IsHadrEnabled')                       AS hadr_enabled,
    SERVERPROPERTY('HadrManagerStatus')                   AS hadr_manager_status,
    SERVERPROPERTY('IsClustered')                         AS is_clustered;

-- ---------------------------------------------------------------------------
-- Availability groups + replica state
-- Guarded with TRY/CATCH — these DMVs return an error if HADR is off.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        ar.replica_server_name,
        ar.availability_mode_desc,
        ar.failover_mode_desc,
        ars.role_desc,
        ars.operational_state_desc,
        ars.connected_state_desc,
        ars.synchronization_health_desc,
        ars.last_connect_error_description,
        ars.last_connect_error_timestamp
    FROM sys.availability_groups          ag
    JOIN sys.availability_replicas        ar  ON ar.group_id = ag.group_id
    LEFT JOIN sys.dm_hadr_availability_replica_states ars
           ON ars.replica_id = ar.replica_id
    ORDER BY ag.name, ar.replica_server_name;
END TRY
BEGIN CATCH
    PRINT '[note] Always On DMVs unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Per-database replica state — redo / send queue in KB
-- log_send_queue_size / redo_queue_size in KB; log_send_rate /
-- redo_rate in KB/sec. Division by rate gives "seconds behind".
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        ar.replica_server_name,
        DB_NAME(drs.database_id)                          AS database_name,
        drs.synchronization_state_desc,
        drs.synchronization_health_desc,
        drs.database_state_desc,
        drs.is_suspended,
        drs.suspend_reason_desc,
        drs.log_send_queue_size                           AS log_send_queue_kb,
        drs.log_send_rate                                 AS log_send_rate_kb_s,
        drs.redo_queue_size                               AS redo_queue_kb,
        drs.redo_rate                                     AS redo_rate_kb_s,
        CASE WHEN ISNULL(drs.redo_rate,0) > 0
             THEN drs.redo_queue_size * 1.0 / drs.redo_rate
        END                                               AS est_redo_seconds_behind,
        drs.last_sent_time,
        drs.last_received_time,
        drs.last_hardened_time,
        drs.last_redone_time
    FROM sys.dm_hadr_database_replica_states drs
    JOIN sys.availability_replicas ar ON ar.replica_id = drs.replica_id
    JOIN sys.availability_groups   ag ON ag.group_id   = ar.group_id
    ORDER BY drs.redo_queue_size DESC, ag_name, database_name;
END TRY
BEGIN CATCH
    PRINT '[note] sys.dm_hadr_database_replica_states unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- AG listener configuration
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        agl.dns_name,
        agl.port,
        agl.is_conformant,
        ip.ip_address,
        ip.network_subnet_ip,
        ip.state_desc
    FROM sys.availability_groups                ag
    JOIN sys.availability_group_listeners       agl ON agl.group_id = ag.group_id
    LEFT JOIN sys.availability_group_listener_ip_addresses ip
           ON ip.listener_id = agl.listener_id
    ORDER BY ag.name, ip.ip_address;
END TRY
BEGIN CATCH
    PRINT '[note] AG listener DMVs unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Database mirroring (legacy, pre-AG) — still deployed on 2012/2014 farms
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        DB_NAME(database_id)                              AS database_name,
        mirroring_state_desc,
        mirroring_role_desc,
        mirroring_safety_level_desc,
        mirroring_partner_name,
        mirroring_partner_instance,
        mirroring_witness_name,
        mirroring_witness_state_desc,
        mirroring_failover_lsn,
        mirroring_connection_timeout,
        mirroring_redo_queue
    FROM sys.database_mirroring
    WHERE mirroring_state IS NOT NULL;
END TRY
BEGIN CATCH
    PRINT '[note] sys.database_mirroring query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Log shipping monitor (if configured in msdb)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        primary_server,
        primary_database,
        backup_threshold,
        threshold_alert_enabled,
        last_backup_file,
        last_backup_date,
        last_backup_date_utc,
        DATEDIFF(minute, last_backup_date_utc, SYSUTCDATETIME()) AS minutes_since_last_backup
    FROM msdb.dbo.log_shipping_monitor_primary;
END TRY
BEGIN CATCH
    PRINT '[note] log_shipping_monitor_primary not accessible: ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    SELECT
        primary_server,
        primary_database,
        secondary_server,
        secondary_database,
        restore_threshold,
        last_copied_file,
        last_copied_date_utc,
        last_restored_file,
        last_restored_date_utc,
        last_restored_latency,
        DATEDIFF(minute, last_restored_date_utc, SYSUTCDATETIME()) AS minutes_since_last_restore
    FROM msdb.dbo.log_shipping_monitor_secondary;
END TRY
BEGIN CATCH
    PRINT '[note] log_shipping_monitor_secondary not accessible: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Transactional replication — publisher side
-- ---------------------------------------------------------------------------
BEGIN TRY
    EXEC sp_replcounters;
END TRY
BEGIN CATCH
    PRINT '[note] sp_replcounters failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        (SELECT COUNT(*) FROM sys.availability_groups)                               AS ag_count,
        (SELECT COUNT(*) FROM sys.dm_hadr_database_replica_states
                          WHERE synchronization_health <> 2)                         AS unhealthy_db_replicas,
        (SELECT COUNT(*) FROM sys.dm_hadr_database_replica_states
                          WHERE is_suspended = 1)                                    AS suspended_db_replicas,
        (SELECT COUNT(*) FROM sys.database_mirroring WHERE mirroring_state IS NOT NULL) AS mirrored_dbs;
END TRY
BEGIN CATCH
    PRINT '[note] summary query failed: ' + ERROR_MESSAGE();
END CATCH;
