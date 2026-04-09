-- =============================================================================
-- perf_13_deadlock_history.sql
-- Priority: MEDIUM
-- Purpose: Surface deadlock counters and conflict statistics. MySQL stores
--          the last deadlock detail in SHOW ENGINE INNODB STATUS; older
--          deadlocks are only in the error log when
--          innodb_print_all_deadlocks = ON.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL stores deadlock history differently from PostgreSQL.
--       pg_stat_database.deadlocks has a per-database counter;
--       MySQL has a single global Innodb_deadlocks counter.
--       The last deadlock detail is in SHOW ENGINE INNODB STATUS
--       (not a structured table — parse manually).
--       Full deadlock history requires innodb_print_all_deadlocks = ON
--       (writes each deadlock to the error log).
--       There is no pg_stat_database_conflicts equivalent in MySQL.

-- ---------------------------------------------------------------------------
-- Global deadlock counter (cumulative since server start)
-- ---------------------------------------------------------------------------
SHOW GLOBAL STATUS LIKE 'Innodb_deadlocks';

-- ---------------------------------------------------------------------------
-- Transaction-related global counters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Innodb_deadlocks',
    'Innodb_row_lock_waits',
    'Innodb_row_lock_time',
    'Innodb_row_lock_time_avg',
    'Innodb_row_lock_time_max',
    'Innodb_row_lock_current_waits',
    'Com_rollback',
    'Com_commit',
    'Handler_rollback',
    'Handler_savepoint_rollback'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Rollback ratio (transactions rolled back vs committed)
-- NOTE: MySQL does not expose per-database transaction counts like
--       pg_stat_database. These are global counters.
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Com_commit') + 0               AS commits,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Com_rollback') + 0             AS rollbacks,
    ROUND(
        100.0
        * (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
           WHERE VARIABLE_NAME = 'Com_rollback')
        / NULLIF(
            (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
             WHERE VARIABLE_NAME = 'Com_commit')
            + (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
               WHERE VARIABLE_NAME = 'Com_rollback'),
            0),
        2)                                                  AS rollback_pct;

-- ---------------------------------------------------------------------------
-- Logging settings relevant to deadlock investigation
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_lock_wait_timeout',
    'lock_wait_timeout',
    'innodb_deadlock_detect',
    'innodb_print_all_deadlocks',
    'log_error',
    'log_error_verbosity',
    'general_log',
    'slow_query_log',
    'long_query_time'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Current waiters on locks (live snapshot)
-- ---------------------------------------------------------------------------
SELECT
    r.PROCESSLIST_ID                                        AS waiting_pid,
    r.PROCESSLIST_USER                                      AS waiting_user,
    r.PROCESSLIST_HOST                                      AS waiting_host,
    r.PROCESSLIST_TIME                                      AS waiting_seconds,
    LEFT(r.PROCESSLIST_INFO, 200)                           AS waiting_query,
    b.PROCESSLIST_ID                                        AS blocking_pid,
    b.PROCESSLIST_USER                                      AS blocking_user,
    b.PROCESSLIST_HOST                                      AS blocking_host,
    LEFT(b.PROCESSLIST_INFO, 200)                           AS blocking_query
FROM performance_schema.data_lock_waits dlw
JOIN performance_schema.threads r
  ON r.THREAD_ID = dlw.REQUESTING_THREAD_ID
JOIN performance_schema.threads b
  ON b.THREAD_ID = dlw.BLOCKING_THREAD_ID
ORDER BY r.PROCESSLIST_TIME DESC;

-- ---------------------------------------------------------------------------
-- Top queries by rollback count (often the same as deadlock victims)
-- NOTE: MySQL does not expose per-digest rollback counts directly.
--       SUM_ERRORS in events_statements_summary_by_digest captures
--       statement errors which includes lock timeout errors.
-- ---------------------------------------------------------------------------
SELECT
    SUM_ERRORS                                              AS errors,
    COUNT_STAR                                              AS calls,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    SUM_ROWS_AFFECTED                                       AS rows_affected,
    DIGEST,
    LEFT(DIGEST_TEXT, 300)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ERRORS > 0
  AND DIGEST_TEXT IS NOT NULL
  AND (DIGEST_TEXT LIKE '%UPDATE%'
    OR DIGEST_TEXT LIKE '%DELETE%'
    OR DIGEST_TEXT LIKE '%INSERT%')
ORDER BY SUM_ERRORS DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- InnoDB status (contains last deadlock detail — parse the output manually)
-- NOTE: SHOW ENGINE INNODB STATUS returns unstructured text with a
--       "LATEST DETECTED DEADLOCK" section when a deadlock has occurred.
--       There is no SQL-queryable deadlock history table in MySQL.
-- ---------------------------------------------------------------------------
-- SHOW ENGINE INNODB STATUS;
-- (Commented out as it returns unstructured BLOB text; run interactively
--  and search for "LATEST DETECTED DEADLOCK" in the output.)

-- ---------------------------------------------------------------------------
-- Current open transactions (potential deadlock contributors)
-- ---------------------------------------------------------------------------
SELECT
    trx_id,
    trx_state,
    trx_started,
    TIMESTAMPDIFF(SECOND, trx_started, NOW())               AS age_seconds,
    trx_mysql_thread_id                                     AS pid,
    trx_query,
    trx_rows_locked,
    trx_lock_structs,
    trx_tables_locked,
    trx_isolation_level
FROM information_schema.INNODB_TRX
ORDER BY trx_started;
