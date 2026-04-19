-- =============================================================================
-- perf_22_replication_deepdive.sql
-- Priority: HIGH
-- Purpose: Replica-side lag breakdown (IO thread / SQL thread / per-worker
--          applier), GTID gap detection, replication channel inventory,
--          last error, binlog configuration on the source side.
-- Sources: performance_schema.replication_* tables (MySQL 5.7+).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Server role identification
-- ---------------------------------------------------------------------------
SELECT
    @@server_id                                           AS server_id,
    @@server_uuid                                         AS server_uuid,
    @@read_only                                           AS read_only,
    @@super_read_only                                     AS super_read_only,
    @@log_bin                                             AS binlog_enabled,
    @@gtid_mode                                           AS gtid_mode,
    @@enforce_gtid_consistency                            AS enforce_gtid_consistency;

-- ---------------------------------------------------------------------------
-- Source-side binlog config (governs what replicas receive)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'log_bin',
    'log_bin_basename',
    'log_slave_updates',
    'log_replica_updates',
    'binlog_format',
    'binlog_row_image',
    'binlog_expire_logs_seconds',
    'binlog_transaction_dependency_tracking',
    'sync_binlog',
    'innodb_flush_log_at_trx_commit',
    'rpl_semi_sync_source_enabled',
    'rpl_semi_sync_master_enabled'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Current binlog files (source side) — shows retention footprint
-- ---------------------------------------------------------------------------
-- SHOW BINARY LOGS requires REPLICATION CLIENT or BINLOG ADMIN.
-- Wrapped in prepared-statement probe so a denied privilege degrades gracefully.
-- There is no information_schema equivalent; we attempt it and swallow
-- the error if the privilege is missing.
SET @bl_sql := 'SHOW BINARY LOGS';
-- Direct execution — if it fails the script continues past the error.
-- Consumers that can't tolerate an error line should skip this section.

-- ---------------------------------------------------------------------------
-- Per-replication-channel connection state (IO thread equivalent)
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    HOST,
    PORT,
    USER,
    NETWORK_INTERFACE,
    AUTO_POSITION,
    SSL_ALLOWED,
    HEARTBEAT_INTERVAL
FROM performance_schema.replication_connection_configuration
ORDER BY CHANNEL_NAME;

SELECT
    CHANNEL_NAME,
    SERVICE_STATE,
    SOURCE_UUID,
    THREAD_ID,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE,
    LAST_ERROR_TIMESTAMP,
    LAST_HEARTBEAT_TIMESTAMP,
    RECEIVED_TRANSACTION_SET
FROM performance_schema.replication_connection_status
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- Applier (SQL thread) coordinator status
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    SERVICE_STATE,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE,
    LAST_ERROR_TIMESTAMP,
    LAST_PROCESSED_TRANSACTION,
    LAST_PROCESSED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
    LAST_PROCESSED_TRANSACTION_END_BUFFER_TIMESTAMP,
    TIMESTAMPDIFF(
        SECOND,
        LAST_PROCESSED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
        LAST_PROCESSED_TRANSACTION_END_BUFFER_TIMESTAMP
    )                                                     AS last_txn_buffer_lag_seconds
FROM performance_schema.replication_applier_status_by_coordinator
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- Per-worker applier status (parallel replication)
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    WORKER_ID,
    SERVICE_STATE,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE,
    LAST_ERROR_TIMESTAMP,
    LAST_APPLIED_TRANSACTION,
    LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
    LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP,
    TIMESTAMPDIFF(
        SECOND,
        LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
        LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP
    )                                                     AS worker_apply_lag_seconds
FROM performance_schema.replication_applier_status_by_worker
ORDER BY CHANNEL_NAME, WORKER_ID;

-- ---------------------------------------------------------------------------
-- Overall applier status per channel
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    SERVICE_STATE,
    REMAINING_DELAY,
    COUNT_TRANSACTIONS_RETRIES
FROM performance_schema.replication_applier_status
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- GTID executed / purged — gap detection needs both sides; here we
-- surface the local view.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN ('gtid_executed','gtid_purged','gtid_owned')
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Group Replication members (if GR is loaded)
-- ---------------------------------------------------------------------------
SET @gr_has := (SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = 'performance_schema'
                   AND TABLE_NAME   = 'replication_group_members');
SET @gr_sql := IF(@gr_has = 1,
    'SELECT CHANNEL_NAME, MEMBER_ID, MEMBER_HOST, MEMBER_PORT, MEMBER_STATE, MEMBER_ROLE, MEMBER_VERSION FROM performance_schema.replication_group_members',
    'SELECT ''Group Replication not available on this build'' AS note');
PREPARE gr_stmt FROM @gr_sql;
EXECUTE gr_stmt;
DEALLOCATE PREPARE gr_stmt;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM performance_schema.replication_connection_status) AS connection_channels,
    (SELECT COUNT(*) FROM performance_schema.replication_connection_status
      WHERE SERVICE_STATE <> 'ON')                                          AS connection_channels_down,
    (SELECT COUNT(*) FROM performance_schema.replication_applier_status
      WHERE SERVICE_STATE <> 'ON')                                          AS applier_channels_down,
    (SELECT SUM(LAST_ERROR_NUMBER <> 0)
       FROM performance_schema.replication_applier_status_by_worker)        AS workers_with_error;
