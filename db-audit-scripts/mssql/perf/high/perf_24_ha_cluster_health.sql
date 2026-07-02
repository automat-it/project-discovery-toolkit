-- =============================================================================
-- perf_24_ha_cluster_health.sql
-- Priority: HIGH
-- Purpose: Always On cluster-posture signals: quorum, automatic-failover
--          readiness, WSFC / cluster node count, backup preferences,
--          endpoints, seeding mode, listener IPs across subnets,
--          long-running transactions. Complements perf_22
--          (per-database redo / send lag) with cluster-level posture.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Quick role signal
-- ---------------------------------------------------------------------------
SELECT
    @@SERVERNAME                                          AS server_name,
    SERVERPROPERTY('IsHadrEnabled')                       AS hadr_enabled,
    SERVERPROPERTY('HadrManagerStatus')                   AS hadr_manager_status,
    SERVERPROPERTY('ServerName')                          AS virtual_name;

-- ---------------------------------------------------------------------------
-- WSFC cluster node inventory
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        NodeName,
        status,
        status_description,
        is_current_owner
    FROM sys.dm_os_cluster_nodes;
END TRY
BEGIN CATCH
    PRINT '[note] dm_os_cluster_nodes unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- AG-level settings — automatic seeding, required synchronised secondaries
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        ag.automated_backup_preference_desc,
        ag.failure_condition_level,
        ag.health_check_timeout,
        ag.db_failover,
        ag.dtc_support,
        ag.required_synchronized_secondaries_to_commit,
        ag.cluster_type_desc,
        ag.sequence_number
    FROM sys.availability_groups ag
    ORDER BY ag.name;
END TRY
BEGIN CATCH
    PRINT '[note] availability_groups unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Replica-level settings — availability/failover mode, seeding, endpoint
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        ar.replica_server_name,
        ar.availability_mode_desc,
        ar.failover_mode_desc,
        ar.seeding_mode_desc,
        ar.backup_priority,
        ar.read_only_routing_url,
        ar.primary_role_allow_connections_desc,
        ar.secondary_role_allow_connections_desc,
        ar.endpoint_url,
        ar.session_timeout
    FROM sys.availability_groups    ag
    JOIN sys.availability_replicas  ar ON ar.group_id = ag.group_id
    ORDER BY ag.name, ar.replica_server_name;
END TRY
BEGIN CATCH
    PRINT '[note] availability_replicas unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Quorum-readiness view: synchronised secondaries per AG — required for
-- automatic failover. A synchronous_commit replica in SYNCHRONIZING
-- (not SYNCHRONIZED) state blocks failover.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        SUM(CASE WHEN ar.availability_mode = 1
                      AND drs.synchronization_state = 2 THEN 1 ELSE 0 END) AS sync_committed_and_synced,
        SUM(CASE WHEN ar.availability_mode = 1
                      AND drs.synchronization_state <> 2 THEN 1 ELSE 0 END) AS sync_committed_not_synced,
        ag.required_synchronized_secondaries_to_commit    AS required_sync,
        CASE
            WHEN SUM(CASE WHEN ar.availability_mode = 1
                               AND drs.synchronization_state = 2 THEN 1 ELSE 0 END)
                 < ag.required_synchronized_secondaries_to_commit
            THEN 'FAILOVER DEGRADED — insufficient synchronised secondaries'
            ELSE 'ok'
        END                                               AS failover_readiness
    FROM sys.availability_groups              ag
    JOIN sys.availability_replicas            ar  ON ar.group_id = ag.group_id
    LEFT JOIN sys.dm_hadr_database_replica_states drs
           ON drs.replica_id = ar.replica_id
    GROUP BY ag.name, ag.required_synchronized_secondaries_to_commit;
END TRY
BEGIN CATCH
    PRINT '[note] failover-readiness query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- AG listener IPs (multi-subnet setups require IPs in every subnet)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        ag.name                                           AS ag_name,
        agl.dns_name,
        agl.port,
        ip.ip_address,
        ip.ip_subnet_mask,
        ip.network_subnet_ip,
        ip.state_desc,
        ip.is_dhcp
    FROM sys.availability_groups                 ag
    JOIN sys.availability_group_listeners        agl ON agl.group_id = ag.group_id
    LEFT JOIN sys.availability_group_listener_ip_addresses ip
           ON ip.listener_id = agl.listener_id
    ORDER BY ag.name, ip.ip_address;
END TRY
BEGIN CATCH
    PRINT '[note] AG listener IPs unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- HADR endpoint state
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        e.name,
        e.type_desc,
        e.state_desc,
        e.is_admin_endpoint,
        te.connection_auth_desc,
        te.is_encryption_enabled,
        te.encryption_algorithm_desc
    FROM sys.endpoints e
    LEFT JOIN sys.database_mirroring_endpoints te ON te.endpoint_id = e.endpoint_id
    WHERE e.type_desc = 'DATABASE_MIRRORING';
END TRY
BEGIN CATCH
    PRINT '[note] endpoints unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Long-running transactions — block log truncation, stall log backups,
-- halt secondary redo
-- ---------------------------------------------------------------------------
SELECT
    s.session_id,
    s.login_name,
    s.host_name,
    t.transaction_id,
    t.name                                                AS tran_name,
    t.transaction_begin_time,
    DATEDIFF(second, t.transaction_begin_time, SYSDATETIME()) AS age_seconds,
    t.transaction_type,
    t.transaction_state,
    s.status                                              AS session_status,
    r.status                                              AS request_status,
    r.wait_type,
    r.wait_time,
    r.blocking_session_id
FROM sys.dm_tran_active_transactions t
JOIN sys.dm_tran_session_transactions st ON st.transaction_id = t.transaction_id
JOIN sys.dm_exec_sessions s              ON s.session_id = st.session_id
LEFT JOIN sys.dm_exec_requests r         ON r.session_id = st.session_id
WHERE t.transaction_begin_time < DATEADD(minute, -5, SYSDATETIME())
ORDER BY t.transaction_begin_time;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        SERVERPROPERTY('IsHadrEnabled')                                         AS hadr_enabled,
        (SELECT COUNT(*) FROM sys.availability_groups)                          AS ag_count,
        (SELECT COUNT(*) FROM sys.availability_replicas)                        AS replica_count,
        (SELECT COUNT(*) FROM sys.dm_hadr_database_replica_states
          WHERE synchronization_state = 2)                                      AS synced_db_replicas,
        (SELECT COUNT(*) FROM sys.dm_hadr_database_replica_states
          WHERE synchronization_state <> 2)                                     AS unsynced_db_replicas,
        (SELECT COUNT(*) FROM sys.dm_tran_active_transactions
          WHERE transaction_begin_time < DATEADD(minute, -5, SYSDATETIME())) AS long_running_txns;
END TRY
BEGIN CATCH
    PRINT '[note] HA summary failed: ' + ERROR_MESSAGE();
END CATCH;
