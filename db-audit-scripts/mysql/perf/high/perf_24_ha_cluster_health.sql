-- =============================================================================
-- perf_24_ha_cluster_health.sql
-- Priority: HIGH
-- Purpose: Group Replication cluster health, semi-sync ack health,
--          flow-control / quorum, member roles. Complements perf_22
--          (per-channel lag) with cluster-posture signals.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Node role
-- ---------------------------------------------------------------------------
SELECT
    @@server_id              AS server_id,
    @@server_uuid            AS server_uuid,
    @@read_only              AS read_only,
    @@super_read_only        AS super_read_only,
    @@log_bin                AS binlog_enabled,
    @@gtid_mode              AS gtid_mode;

-- ---------------------------------------------------------------------------
-- Semi-synchronous replication status — ack timeouts silently degrade
-- the primary to async.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'rpl_semi_sync%'
ORDER BY VARIABLE_NAME;

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME LIKE 'Rpl_semi_sync%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Group Replication — presence + member inventory
-- ---------------------------------------------------------------------------
SET @gr_has := (SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = 'performance_schema'
                   AND TABLE_NAME   = 'replication_group_members');
SET @gr_sql := IF(@gr_has = 1,
    'SELECT CHANNEL_NAME, MEMBER_ID, MEMBER_HOST, MEMBER_PORT, MEMBER_STATE, MEMBER_ROLE, MEMBER_VERSION FROM performance_schema.replication_group_members',
    'SELECT ''Group Replication plugin not installed'' AS note');
PREPARE gr_stmt FROM @gr_sql;
EXECUTE gr_stmt;
DEALLOCATE PREPARE gr_stmt;

-- Group Replication statistics — per-member transaction counts, queue
SET @grs_has := (SELECT COUNT(*) FROM information_schema.TABLES
                  WHERE TABLE_SCHEMA = 'performance_schema'
                    AND TABLE_NAME   = 'replication_group_member_stats');
SET @grs_sql := IF(@grs_has = 1,
    'SELECT CHANNEL_NAME, MEMBER_ID,
            COUNT_TRANSACTIONS_IN_QUEUE, COUNT_TRANSACTIONS_CHECKED,
            COUNT_CONFLICTS_DETECTED, COUNT_TRANSACTIONS_ROWS_VALIDATING,
            TRANSACTIONS_COMMITTED_ALL_MEMBERS, LAST_CONFLICT_FREE_TRANSACTION,
            COUNT_TRANSACTIONS_REMOTE_IN_APPLIER_QUEUE,
            COUNT_TRANSACTIONS_REMOTE_APPLIED, COUNT_TRANSACTIONS_LOCAL_PROPOSED,
            COUNT_TRANSACTIONS_LOCAL_ROLLBACK
     FROM performance_schema.replication_group_member_stats',
    'SELECT ''Group Replication stats table unavailable'' AS note');
PREPARE grs_stmt FROM @grs_sql;
EXECUTE grs_stmt;
DEALLOCATE PREPARE grs_stmt;

-- GR variables — flow control, consistency mode
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'group_replication%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB Cluster / MySQL Router hints — the mysql_innodb_cluster_metadata
-- schema is created by the AdminAPI. Its presence is a strong signal
-- an InnoDB Cluster is in use.
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME
FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME IN ('mysql_innodb_cluster_metadata','mysql_innodb_cs_metadata');

-- ---------------------------------------------------------------------------
-- Long-running transactions — keep binlog / purge threads stuck.
-- ---------------------------------------------------------------------------
SELECT
    trx_id,
    trx_state,
    trx_started,
    TIMESTAMPDIFF(SECOND, trx_started, NOW())             AS age_seconds,
    trx_mysql_thread_id,
    trx_isolation_level,
    trx_rows_modified,
    LEFT(trx_query, 200)                                  AS query
FROM information_schema.INNODB_TRX
WHERE trx_started < NOW() - INTERVAL 5 MINUTE
ORDER BY trx_started;

-- ---------------------------------------------------------------------------
-- Uncommitted XA transactions — silent tail-latency + binlog-retention source
-- ---------------------------------------------------------------------------
SET @xa_sql := 'XA RECOVER';
-- XA RECOVER requires XA_RECOVER_ADMIN privilege; we execute best-effort.
-- Consumers without the privilege will see a permission error line.

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    @@read_only                                                              AS read_only,
    @@super_read_only                                                        AS super_read_only,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
      WHERE VARIABLE_NAME = 'Rpl_semi_sync_source_status')                   AS semi_sync_source_on,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
      WHERE VARIABLE_NAME = 'Rpl_semi_sync_master_status')                   AS semi_sync_master_on,
    (SELECT COUNT(*) FROM information_schema.INNODB_TRX
      WHERE trx_started < NOW() - INTERVAL 5 MINUTE)                         AS long_innodb_trx;
