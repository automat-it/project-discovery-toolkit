-- =============================================================================
-- perf_02_blocking_and_locks.sql
-- Priority: CRITICAL
-- Purpose: Find blocking sessions, long-running transactions, idle sessions
--          holding locks — the most common cause of latency spikes.
-- Sources: sys.dm_exec_requests, sys.dm_exec_sessions, sys.dm_tran_locks,
--          sys.dm_os_waiting_tasks, sys.dm_tran_active_transactions.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects
SET QUOTED_IDENTIFIER ON;                          -- required for FOR XML PATH / XML type methods used below

-- ---------------------------------------------------------------------------
-- Direct blocking pairs (who is blocking whom right now)
-- ---------------------------------------------------------------------------
-- login_name / host_name / program_name live on sys.dm_exec_sessions,
-- not sys.dm_exec_requests. JOIN through sessions for both sides.
SELECT
    blocked.session_id                       AS blocked_spid,
    blocked_sess.login_name                  AS blocked_user,
    blocked_sess.host_name                   AS blocked_host,
    blocked_sess.program_name                AS blocked_app,
    DB_NAME(blocked.database_id)             AS blocked_db,
    blocked.wait_type                        AS wait_type,
    blocked.wait_time                        AS wait_ms,
    blocked.wait_resource                    AS wait_resource,
    blocking.session_id                      AS blocking_spid,
    blocking_sess.login_name                 AS blocking_user,
    blocking_sess.host_name                  AS blocking_host,
    blocking_sess.program_name               AS blocking_app,
    DATEDIFF(second, blocking_sess.last_request_start_time, SYSDATETIME())
                                             AS blocker_last_request_age_sec,
    LEFT(blocked_txt.text, 300)              AS blocked_statement,
    LEFT(blocking_txt.text, 300)             AS blocking_statement
FROM sys.dm_exec_requests blocked
JOIN sys.dm_exec_requests blocking
      ON blocked.blocking_session_id = blocking.session_id
JOIN sys.dm_exec_sessions blocked_sess
      ON blocked_sess.session_id = blocked.session_id
JOIN sys.dm_exec_sessions blocking_sess
      ON blocking_sess.session_id = blocking.session_id
OUTER APPLY sys.dm_exec_sql_text(blocked.sql_handle)   blocked_txt
OUTER APPLY sys.dm_exec_sql_text(blocking.sql_handle)  blocking_txt
WHERE blocked.blocking_session_id <> 0
ORDER BY blocked.wait_time DESC;

-- ---------------------------------------------------------------------------
-- Full blocking chain (recursive — includes head blocker)
-- ---------------------------------------------------------------------------
WITH blocking_chain AS (
    SELECT
        r.session_id,
        r.blocking_session_id,
        r.wait_type,
        r.wait_time,
        r.wait_resource,
        CAST(r.session_id AS VARCHAR(MAX))                 AS path,
        0                                                  AS level
    FROM sys.dm_exec_requests r
    WHERE r.blocking_session_id = 0
      AND EXISTS (SELECT 1 FROM sys.dm_exec_requests r2
                   WHERE r2.blocking_session_id = r.session_id)
    UNION ALL
    SELECT
        r.session_id,
        r.blocking_session_id,
        r.wait_type,
        r.wait_time,
        r.wait_resource,
        bc.path + ' -> ' + CAST(r.session_id AS VARCHAR(20)),
        bc.level + 1
    FROM sys.dm_exec_requests r
    JOIN blocking_chain bc ON r.blocking_session_id = bc.session_id
    WHERE bc.level < 10
)
SELECT
    level,
    session_id,
    blocking_session_id,
    wait_type,
    wait_time,
    wait_resource,
    path
FROM blocking_chain
ORDER BY path, level;

-- ---------------------------------------------------------------------------
-- Long-running transactions (> 60 seconds)
-- These hold locks, prevent log truncation, accumulate pressure.
-- ---------------------------------------------------------------------------
SELECT
    s.session_id                                           AS spid,
    s.login_name,
    s.host_name,
    s.program_name,
    DB_NAME(r.database_id)                                 AS database_name,
    at.transaction_id,
    at.name                                                AS transaction_name,
    at.transaction_begin_time,
    DATEDIFF(second, at.transaction_begin_time, SYSDATETIME()) AS txn_age_sec,
    at.transaction_state,
    r.status                                               AS request_status,
    r.wait_type,
    LEFT(txt.text, 300)                                    AS current_statement
FROM sys.dm_tran_active_transactions at
JOIN sys.dm_tran_session_transactions st ON st.transaction_id = at.transaction_id
JOIN sys.dm_exec_sessions s               ON s.session_id = st.session_id
LEFT JOIN sys.dm_exec_requests r          ON r.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) txt
WHERE at.transaction_begin_time < DATEADD(second, -60, SYSDATETIME())
  AND s.is_user_process = 1
ORDER BY at.transaction_begin_time;

-- ---------------------------------------------------------------------------
-- Sleeping sessions with an open transaction (SQL Server analog of
-- "idle in transaction"). These silently hold locks.
-- ---------------------------------------------------------------------------
SELECT
    s.session_id                                           AS spid,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status                                               AS session_status,
    DATEDIFF(second, s.last_request_end_time, SYSDATETIME()) AS idle_sec,
    s.open_transaction_count,
    DB_NAME(s.database_id)                                 AS database_name,
    LEFT(txt.text, 300)                                    AS last_statement
-- most_recent_sql_handle lives on sys.dm_exec_connections, not on
-- sys.dm_exec_sessions. Join through connections to resolve the text.
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) txt
WHERE s.is_user_process   = 1
  AND s.status            = 'sleeping'
  AND s.open_transaction_count > 0
ORDER BY s.last_request_end_time;

-- ---------------------------------------------------------------------------
-- Lock summary by mode and resource type
-- ---------------------------------------------------------------------------
SELECT
    resource_type,
    request_mode,
    request_status,
    COUNT(*)                                               AS lock_count
FROM sys.dm_tran_locks
GROUP BY resource_type, request_mode, request_status
ORDER BY lock_count DESC;

-- ---------------------------------------------------------------------------
-- Tables with the most current lock contention.
-- Edge case: when l.resource_database_id points at a database other than
-- the one this script is running from, OBJECT_SCHEMA_NAME / OBJECT_NAME
-- return NULL because the resolver cannot cross databases from the
-- current context. This is fine for a per-database audit; for server-
-- wide lock investigation run the script once per impacted database.
-- ---------------------------------------------------------------------------
SELECT TOP 30
    DB_NAME(l.resource_database_id)                        AS database_name,
    OBJECT_SCHEMA_NAME(l.resource_associated_entity_id, l.resource_database_id) AS schema_name,
    OBJECT_NAME(l.resource_associated_entity_id, l.resource_database_id)        AS object_name,
    COUNT(*)                                               AS total_locks,
    SUM(CASE WHEN l.request_status = 'WAIT' THEN 1 ELSE 0 END) AS waiting_locks,
    COUNT(DISTINCT l.request_session_id)                   AS distinct_sessions,
    -- SQL Server's STRING_AGG does not accept DISTINCT; fold distinct
    -- values with a correlated APPLY before aggregation.
    STUFF((
        SELECT ', ' + request_mode
          FROM (SELECT DISTINCT request_mode
                  FROM sys.dm_tran_locks l2
                 WHERE l2.resource_database_id = l.resource_database_id
                   AND l2.resource_associated_entity_id = l.resource_associated_entity_id
                   AND l2.resource_type = 'OBJECT') d
         FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, '') AS lock_modes
FROM sys.dm_tran_locks l
WHERE l.resource_type = 'OBJECT'
  AND l.resource_associated_entity_id > 0
GROUP BY l.resource_database_id, l.resource_associated_entity_id
HAVING COUNT(*) > 1
ORDER BY waiting_locks DESC, total_locks DESC;

-- ---------------------------------------------------------------------------
-- Deadlock count (instance-wide, since SQL Server start)
-- ---------------------------------------------------------------------------
SELECT
    instance_name                                          AS database_name,
    cntr_value                                             AS deadlock_count
FROM sys.dm_os_performance_counters
WHERE counter_name = 'Number of Deadlocks/sec'
ORDER BY instance_name;
