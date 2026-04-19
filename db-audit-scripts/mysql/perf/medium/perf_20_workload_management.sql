-- =============================================================================
-- perf_20_workload_management.sql
-- Priority: MEDIUM
-- Purpose: Surface workload-management signals — Resource Groups (MySQL
--          8.0+), concurrency limits, per-user caps, and long-running
--          statements. MySQL's workload-management surface is thinner
--          than MSSQL Resource Governor but richer than PG's.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Resource Groups (MySQL 8.0+) — bind threads to CPU sets and priorities
-- information_schema.RESOURCE_GROUPS exists on 8.0+; guarded via a
-- prepared statement so it doesn't error on 5.7.
-- ---------------------------------------------------------------------------
SET @rg_has := (SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = 'information_schema'
                   AND TABLE_NAME   = 'RESOURCE_GROUPS');
SET @rg_sql := IF(@rg_has = 1,
    'SELECT RESOURCE_GROUP_NAME,
            RESOURCE_GROUP_TYPE,
            RESOURCE_GROUP_ENABLED,
            VCPU_IDS,
            THREAD_PRIORITY
       FROM information_schema.RESOURCE_GROUPS
      ORDER BY RESOURCE_GROUP_TYPE, RESOURCE_GROUP_NAME',
    'SELECT ''RESOURCE_GROUPS not available on this MySQL version'' AS note');
PREPARE rg_stmt FROM @rg_sql;
EXECUTE rg_stmt;
DEALLOCATE PREPARE rg_stmt;

-- ---------------------------------------------------------------------------
-- Concurrency / worker limits
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'max_connections',
    'max_user_connections',
    'thread_handling',
    'thread_pool_size',
    'thread_pool_max_active_query_threads',
    'innodb_thread_concurrency',
    'innodb_read_io_threads',
    'innodb_write_io_threads',
    'innodb_purge_threads',
    'innodb_parallel_read_threads',
    'innodb_buffer_pool_instances',
    'slave_parallel_workers',
    'replica_parallel_workers',
    'binlog_group_commit_sync_delay'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Per-account limits (mysql.user resource caps — MAX_QUERIES_PER_HOUR,
-- MAX_UPDATES_PER_HOUR, MAX_CONNECTIONS_PER_HOUR, MAX_USER_CONNECTIONS)
-- ---------------------------------------------------------------------------
SELECT
    User, Host,
    max_questions           AS max_queries_per_hour,
    max_updates             AS max_updates_per_hour,
    max_connections         AS max_connections_per_hour,
    max_user_connections
FROM mysql.user
WHERE (max_questions + max_updates + max_connections + max_user_connections) > 0
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Statement timeout defaults / current session limits
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'max_execution_time',
    'lock_wait_timeout',
    'innodb_lock_wait_timeout',
    'wait_timeout',
    'interactive_timeout',
    'connect_timeout',
    'net_read_timeout',
    'net_write_timeout'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Current activity snapshot by state
-- ---------------------------------------------------------------------------
SELECT
    COALESCE(STATE, '(null)')                             AS state,
    COUNT(*)                                              AS threads,
    SUM(CASE WHEN TIME > 60 THEN 1 ELSE 0 END)            AS over_60s
FROM information_schema.PROCESSLIST
WHERE COMMAND <> 'Sleep'
GROUP BY STATE
ORDER BY threads DESC;

-- ---------------------------------------------------------------------------
-- Long-running statements currently executing (> 60s, non-Sleep)
-- ---------------------------------------------------------------------------
SELECT
    ID                         AS thread_id,
    USER,
    HOST,
    DB                         AS `database`,
    COMMAND,
    TIME                       AS seconds_running,
    STATE,
    LEFT(INFO, 300)            AS current_sql
FROM information_schema.PROCESSLIST
WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump', 'Binlog Dump GTID')
  AND TIME > 60
ORDER BY TIME DESC;

-- ---------------------------------------------------------------------------
-- In-flight Stage events (ALTER / CREATE INDEX / dump / import progress)
-- Requires stage/sql/% instruments enabled.
-- ---------------------------------------------------------------------------
SELECT
    THREAD_ID,
    EVENT_NAME,
    WORK_COMPLETED,
    WORK_ESTIMATED,
    CASE WHEN WORK_ESTIMATED > 0
         THEN ROUND(100.0 * WORK_COMPLETED / WORK_ESTIMATED, 2)
         ELSE NULL END           AS pct_done,
    ROUND(TIMER_WAIT/1000000000000, 2) AS seconds_elapsed
FROM performance_schema.events_stages_current
WHERE WORK_ESTIMATED IS NOT NULL
ORDER BY pct_done;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    @@max_connections                                               AS max_conn,
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST
       WHERE COMMAND <> 'Sleep')                                    AS active_threads,
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST
       WHERE COMMAND NOT IN ('Sleep','Daemon','Binlog Dump','Binlog Dump GTID')
         AND TIME > 60)                                             AS long_running,
    @@max_execution_time                                            AS stmt_timeout_ms,
    @@innodb_lock_wait_timeout                                      AS innodb_lock_wait_s;
