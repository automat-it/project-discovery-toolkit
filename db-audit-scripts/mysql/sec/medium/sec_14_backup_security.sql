-- =============================================================================
-- sec_14_backup_security.sql
-- Priority: MEDIUM
-- Purpose: Verify backup-related access and ongoing backup activity.
-- Note: Most backup security (encryption, S3/disk access, retention) lives
--       outside MySQL — at the cloud provider or filesystem layer. This
--       script covers only what is visible from inside the DB.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL backup mechanisms differ from PostgreSQL:
--       - mysqldump: logical backup via SQL export — appears in PROCESSLIST
--       - MySQL Enterprise Backup (mysqlbackup): hot backup tool
--       - Percona XtraBackup: open-source hot backup
--       - Binary log: enables point-in-time recovery
--       - REPLICATION SLAVE privilege is required for binary log access
--         (analogous to PostgreSQL's REPLICATION privilege)
--       - There are no replication slots in MySQL; GTID positions serve
--         a similar purpose for change tracking.
--       - pg_stat_archiver has no MySQL equivalent; binlog retention is
--         controlled by binlog_expire_logs_seconds.

-- ---------------------------------------------------------------------------
-- Accounts with REPLICATION SLAVE privilege
-- (can read all binary log data — backup-equivalent access)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv,
    password_expired,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE Repl_slave_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Accounts with SUPER privilege (can perform administrative backup ops)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Repl_slave_priv,
    password_expired
FROM mysql.user
WHERE Super_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Dynamic privileges relevant to backup operations (MySQL 8.0+)
-- BACKUP_ADMIN: required for LOCK INSTANCE FOR BACKUP
-- BINLOG_ADMIN: required to manage binary logs
-- REPLICATION_SLAVE_ADMIN: required for CHANGE REPLICATION SOURCE
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    PRIV                                                    AS dynamic_privilege,
    WITH_GRANT_OPTION
FROM mysql.global_grants
WHERE PRIV IN ('BACKUP_ADMIN', 'BINLOG_ADMIN', 'REPLICATION_SLAVE_ADMIN',
               'REPLICATION_APPLIER', 'CLONE_ADMIN', 'INNODB_REDO_LOG_ARCHIVE')
ORDER BY USER, HOST, PRIV;

-- ---------------------------------------------------------------------------
-- Currently running backup-related processes
-- (mysqldump, mysqlbackup, xtrabackup appear as PROCESSLIST entries)
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    DB,
    COMMAND,
    TIME                                                     AS seconds,
    STATE,
    LEFT(INFO, 200)                                         AS query
FROM information_schema.PROCESSLIST
WHERE INFO LIKE '%FLUSH TABLES%'
   OR INFO LIKE '%LOCK TABLES%'
   OR INFO LIKE '%LOCK INSTANCE%'
   OR INFO LIKE '%mysqldump%'
   OR INFO LIKE '%mysqlpump%'
   OR INFO LIKE '%xtrabackup%'
   OR STATE LIKE '%backup%'
   OR STATE LIKE '%flush%'
ORDER BY TIME DESC;

-- ---------------------------------------------------------------------------
-- Binary log settings and status (equivalent to WAL/archiving in PostgreSQL)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'log_bin',
    'binlog_format',
    'binlog_expire_logs_seconds',
    'expire_logs_days',
    'max_binlog_size',
    'sync_binlog',
    'binlog_row_image',
    'binlog_transaction_compression',
    'gtid_mode',
    'enforce_gtid_consistency',
    'innodb_flush_log_at_trx_commit'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Binary log files (equivalent to WAL segment list)
-- ---------------------------------------------------------------------------
SHOW BINARY LOGS;

-- ---------------------------------------------------------------------------
-- Active replication channels (reading binary logs for replication/CDC)
-- Equivalent to PostgreSQL replication slots — channels consuming binlogs
-- ---------------------------------------------------------------------------
SELECT
    CHANNEL_NAME,
    SOURCE_UUID,
    SERVICE_STATE                                           AS io_thread_state,
    LAST_ERROR_MESSAGE,
    LAST_HEARTBEAT_TIMESTAMP
FROM performance_schema.replication_connection_status
ORDER BY CHANNEL_NAME;

-- ---------------------------------------------------------------------------
-- Possible data export activity (SELECT INTO OUTFILE, mysqldump)
-- NOTE: SELECT INTO OUTFILE writes directly to the filesystem and
--       requires FILE privilege or secure_file_priv directory access.
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    DB,
    COMMAND,
    TIME                                                     AS seconds,
    STATE,
    LEFT(INFO, 300)                                         AS query
FROM information_schema.PROCESSLIST
WHERE STATE <> 'Sleep'
  AND INFO LIKE '%INTO OUTFILE%'
  AND COMMAND = 'Query';

-- ---------------------------------------------------------------------------
-- FILE privilege holders (can LOAD DATA INFILE / SELECT INTO OUTFILE)
-- This is a potential data exfiltration vector.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    File_priv                                               AS has_file_priv
FROM mysql.user
WHERE File_priv = 'Y'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- secure_file_priv setting (restricts LOAD DATA / SELECT INTO OUTFILE paths)
-- Empty string = no restriction (dangerous), NULL = feature disabled
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'secure_file_priv';
