-- =============================================================================
-- perf_02_blocking_and_locks.sql
-- Priority: CRITICAL
-- Purpose: Find blocking sessions, long-running transactions, idle-in-tx
--          sessions. The most common cause of latency spikes and timeouts.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL uses performance_schema.data_locks and data_lock_waits
--       instead of pg_locks. The processlist is available via
--       information_schema.processlist or performance_schema.threads.
--       There is no pg_blocking_pids() equivalent — blocking is derived
--       from data_lock_waits.

-- ---------------------------------------------------------------------------
-- Direct blocking pairs (who is blocking whom right now)
-- ---------------------------------------------------------------------------
SELECT
    r.THREAD_ID                                             AS blocked_thread_id,
    r.PROCESSLIST_ID                                        AS blocked_pid,
    r.PROCESSLIST_USER                                      AS blocked_user,
    r.PROCESSLIST_HOST                                      AS blocked_host,
    r.PROCESSLIST_DB                                        AS blocked_db,
    -- REQUESTING_ENGINE_LOCK_ID is VARCHAR (e.g. "140013:1:3:2"); wrapping
    -- it in ROUND() silently truncated the value to the leading digits and
    -- lost the full lock-space coordinates. Pass the string through as-is.
    dlw.REQUESTING_ENGINE_LOCK_ID                          AS blocked_lock_id,
    b.THREAD_ID                                             AS blocking_thread_id,
    b.PROCESSLIST_ID                                        AS blocking_pid,
    b.PROCESSLIST_USER                                      AS blocking_user,
    b.PROCESSLIST_HOST                                      AS blocking_host,
    r.PROCESSLIST_TIME                                      AS blocked_seconds,
    LEFT(r.PROCESSLIST_INFO, 200)                           AS blocked_query,
    LEFT(b.PROCESSLIST_INFO, 200)                           AS blocking_query
FROM performance_schema.data_lock_waits dlw
JOIN performance_schema.threads r
  ON r.THREAD_ID = dlw.REQUESTING_THREAD_ID
JOIN performance_schema.threads b
  ON b.THREAD_ID = dlw.BLOCKING_THREAD_ID
ORDER BY r.PROCESSLIST_TIME DESC;

-- ---------------------------------------------------------------------------
-- All current data lock waits (full detail from performance_schema)
-- ---------------------------------------------------------------------------
SELECT
    dlw.REQUESTING_THREAD_ID                                AS waiting_thread,
    dlw.REQUESTING_ENGINE_LOCK_ID                           AS waiting_lock_id,
    dlw.BLOCKING_THREAD_ID                                  AS holding_thread,
    dlw.BLOCKING_ENGINE_LOCK_ID                             AS holding_lock_id,
    dl_r.OBJECT_SCHEMA                                      AS schema_name,
    dl_r.OBJECT_NAME                                        AS table_name,
    dl_r.LOCK_TYPE                                          AS lock_type,
    dl_r.LOCK_MODE                                          AS lock_mode,
    dl_r.LOCK_STATUS                                        AS lock_status
FROM performance_schema.data_lock_waits dlw
JOIN performance_schema.data_locks dl_r
  ON dl_r.ENGINE_LOCK_ID = dlw.REQUESTING_ENGINE_LOCK_ID
ORDER BY dlw.REQUESTING_THREAD_ID;

-- ---------------------------------------------------------------------------
-- Long-running transactions (> 60 seconds)
-- These hold row/gap locks, block DDL, and may indicate runaway queries.
-- ---------------------------------------------------------------------------
SELECT
    p.ID                                                    AS pid,
    p.USER                                                  AS user,
    p.HOST                                                  AS host,
    p.DB                                                    AS database_name,
    p.COMMAND                                               AS command,
    p.TIME                                                  AS seconds,
    p.STATE                                                 AS state,
    LEFT(p.INFO, 300)                                       AS query,
    -- NOTE: trx_started from InnoDB status gives true transaction age
    it.trx_started                                          AS trx_started,
    it.trx_state                                            AS trx_state,
    it.trx_rows_locked                                      AS rows_locked,
    it.trx_rows_modified                                    AS rows_modified
FROM information_schema.PROCESSLIST p
LEFT JOIN information_schema.INNODB_TRX it
  ON it.trx_mysql_thread_id = p.ID
WHERE p.TIME > 60
  AND p.COMMAND <> 'Sleep'
ORDER BY p.TIME DESC;

-- ---------------------------------------------------------------------------
-- Idle (sleeping) connections with an open transaction
-- (MySQL equivalent of "idle in transaction")
-- ---------------------------------------------------------------------------
SELECT
    p.ID                                                    AS pid,
    p.USER                                                  AS user,
    p.HOST                                                  AS host,
    p.DB                                                    AS database_name,
    p.TIME                                                  AS idle_seconds,
    LEFT(p.INFO, 300)                                       AS last_query,
    it.trx_started                                          AS trx_started,
    it.trx_state,
    it.trx_rows_locked                                      AS rows_locked
FROM information_schema.PROCESSLIST p
JOIN information_schema.INNODB_TRX it
  ON it.trx_mysql_thread_id = p.ID
WHERE p.COMMAND = 'Sleep'
ORDER BY p.TIME DESC;

-- ---------------------------------------------------------------------------
-- Lock summary by mode (InnoDB data locks)
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA                                           AS schema_name,
    OBJECT_NAME                                             AS table_name,
    LOCK_TYPE,
    LOCK_MODE,
    LOCK_STATUS,
    COUNT(*)                                                AS lock_count
FROM performance_schema.data_locks
GROUP BY OBJECT_SCHEMA, OBJECT_NAME, LOCK_TYPE, LOCK_MODE, LOCK_STATUS
ORDER BY lock_count DESC;

-- ---------------------------------------------------------------------------
-- Tables with the most lock contention right now
-- ---------------------------------------------------------------------------
SELECT
    dl.OBJECT_SCHEMA                                        AS schema_name,
    dl.OBJECT_NAME                                          AS table_name,
    COUNT(*)                                                AS total_locks,
    SUM(CASE WHEN dl.LOCK_STATUS = 'WAITING' THEN 1 ELSE 0 END)
                                                            AS waiting_locks,
    COUNT(DISTINCT dl.THREAD_ID)                            AS distinct_threads,
    GROUP_CONCAT(DISTINCT dl.LOCK_MODE ORDER BY dl.LOCK_MODE SEPARATOR ', ')
                                                            AS lock_modes
FROM performance_schema.data_locks dl
WHERE dl.OBJECT_SCHEMA IS NOT NULL
GROUP BY dl.OBJECT_SCHEMA, dl.OBJECT_NAME
HAVING COUNT(*) > 1
ORDER BY waiting_locks DESC, total_locks DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Deadlock counters (global)
-- NOTE: MySQL exposes a global deadlock counter; per-database counters
--       like pg_stat_database.deadlocks do not exist.
-- ---------------------------------------------------------------------------
SHOW GLOBAL STATUS LIKE 'Innodb_deadlocks';

-- ---------------------------------------------------------------------------
-- InnoDB transaction list (all open transactions)
-- ---------------------------------------------------------------------------
SELECT
    trx_id,
    trx_state,
    trx_started,
    TIMESTAMPDIFF(SECOND, trx_started, NOW())               AS trx_age_seconds,
    trx_mysql_thread_id                                     AS pid,
    trx_query,
    trx_rows_locked,
    trx_rows_modified,
    trx_lock_structs,
    trx_tables_in_use,
    trx_tables_locked,
    trx_isolation_level
FROM information_schema.INNODB_TRX
ORDER BY trx_started;
