-- =============================================================================
-- perf_10_replication_and_backup_impact.sql
-- Priority: HIGH
-- Purpose: Replication lag, binary log pressure, and ongoing backup
--          activity that may impact write latency.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL replication is fundamentally different from PostgreSQL
--       streaming replication. MySQL uses binary logs (binlog) rather than
--       WAL. Replication state is exposed via performance_schema.replication_*
--       tables (MySQL 8.0) and SHOW REPLICA STATUS.
--       There are no LSN-based lag metrics; lag is in seconds (Seconds_Behind_Source).
--       Replication slots have no direct equivalent; GTID position is used.

-- ---------------------------------------------------------------------------
-- Is this instance a replica? (check replication connection status)
-- ---------------------------------------------------------------------------
SELECT
    COUNT(*)                                                AS replica_channel_count,
    CASE WHEN COUNT(*) > 0 THEN 'YES' ELSE 'NO (primary or standalone)' END
                                                            AS is_replica
FROM performance_schema.replication_connection_status;

-- ---------------------------------------------------------------------------
-- PRIMARY: Binary log status and position
-- ---------------------------------------------------------------------------
SHOW MASTER STATUS;

-- ---------------------------------------------------------------------------
-- PRIMARY: Connected replicas
-- NOTE: SHOW REPLICAS requires MySQL 8.0.22+. On 5.7 and 8.0.0–8.0.21 use
--       SHOW SLAVE HOSTS instead (same output shape, deprecated alias).
-- ---------------------------------------------------------------------------
SHOW REPLICAS;

-- ---------------------------------------------------------------------------
-- REPLICA: Connection status per channel (lag and I/O thread state)
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    SOURCE_UUID,
    SERVICE_STATE                                           AS io_thread_state,
    RECEIVED_TRANSACTION_SET,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE,
    LAST_ERROR_TIMESTAMP,
    COUNT_RECEIVED_HEARTBEATS,
    LAST_HEARTBEAT_TIMESTAMP,
    -- NOTE: Seconds_Behind_Source is in replication_applier_status_by_worker
    --       for parallel replication; single-threaded lag is below.
    LAST_QUEUED_TRANSACTION,
    LAST_QUEUED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
    LAST_QUEUED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP,
    LAST_QUEUED_TRANSACTION_START_QUEUE_TIMESTAMP
FROM performance_schema.replication_connection_status
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- REPLICA: Applier (SQL thread) status per channel
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    SERVICE_STATE                                           AS sql_thread_state,
    REMAINING_DELAY                                         AS delay_remaining_sec,
    COUNT_TRANSACTIONS_RETRIES,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE,
    LAST_ERROR_TIMESTAMP
FROM performance_schema.replication_applier_status
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- REPLICA: Per-worker applier status (parallel replication)
-- Includes transaction lag per worker.
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    WORKER_ID,
    THREAD_ID,
    SERVICE_STATE,
    LAST_APPLIED_TRANSACTION,
    LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
    LAST_APPLIED_TRANSACTION_IMMEDIATE_COMMIT_TIMESTAMP,
    LAST_APPLIED_TRANSACTION_END_APPLY_TIMESTAMP,
    TIMESTAMPDIFF(SECOND,
        LAST_APPLIED_TRANSACTION_ORIGINAL_COMMIT_TIMESTAMP,
        NOW())                                              AS lag_seconds,
    APPLYING_TRANSACTION,
    LAST_ERROR_NUMBER,
    LAST_ERROR_MESSAGE
FROM performance_schema.replication_applier_status_by_worker
ORDER BY CHANNEL_NAME, WORKER_ID;

-- ---------------------------------------------------------------------------
-- REPLICA: Connection configuration (source host, port, SSL settings)
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    HOST                                                    AS source_host,
    PORT                                                    AS source_port,
    USER                                                    AS replication_user,
    USING_GTID,
    GTID_ONLY,
    SSL_ALLOWED,
    SSL_CA_FILE,
    SSL_CERT_FILE,
    AUTO_POSITION,
    CONNECT_RETRY,
    HEARTBEAT_INTERVAL
FROM performance_schema.replication_connection_configuration
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- Binary log settings and status
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'log_bin',
    'binlog_format',
    'gtid_mode',
    'enforce_gtid_consistency',
    'binlog_expire_logs_seconds',
    'expire_logs_days',
    'max_binlog_size',
    'sync_binlog',
    'binlog_row_image',
    'binlog_transaction_compression',
    'replica_parallel_workers',
    'slave_parallel_workers',
    'replica_parallel_type',
    'replica_preserve_commit_order',
    'rpl_semi_sync_source_enabled',
    'rpl_semi_sync_master_enabled',
    'rpl_semi_sync_replica_enabled',
    'rpl_semi_sync_slave_enabled'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Binary log file list (approximate WAL equivalent)
-- ---------------------------------------------------------------------------
SHOW BINARY LOGS;

-- ---------------------------------------------------------------------------
-- Currently running backup-related processes
-- (mysqldump, mysqlbackup, xtrabackup appear as queries in the processlist)
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    HOST,
    DB,
    COMMAND,
    TIME                                                    AS seconds,
    STATE,
    LEFT(INFO, 200)                                         AS query
FROM information_schema.PROCESSLIST
WHERE INFO LIKE '%FLUSH TABLES%'
   OR INFO LIKE '%LOCK TABLES%'
   OR INFO LIKE '%mysqldump%'
   OR INFO LIKE '%xtrabackup%'
   OR STATE LIKE '%backup%'
ORDER BY TIME DESC;

-- ---------------------------------------------------------------------------
-- Replication lag via global status (quick single value)
-- NOTE: Seconds_Behind_Source = 0 on primary or when not replicating.
--       Use SHOW REPLICA STATUS for the full detail per channel.
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Replica_running',
    'Slave_running',
    'Rpl_semi_sync_source_status',
    'Rpl_semi_sync_master_status',
    'Rpl_semi_sync_replica_status',
    'Rpl_semi_sync_slave_status',
    'Binlog_cache_use',
    'Binlog_cache_disk_use',
    'Binlog_stmt_cache_use',
    'Binlog_stmt_cache_disk_use'
)
ORDER BY VARIABLE_NAME;
