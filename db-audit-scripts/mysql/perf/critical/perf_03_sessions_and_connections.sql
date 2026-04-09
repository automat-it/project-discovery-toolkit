-- =============================================================================
-- perf_03_sessions_and_connections.sql
-- Priority: CRITICAL
-- Purpose: Connection inventory by user / app / state, find connection
--          storms and pool misconfigurations.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL exposes connections via information_schema.PROCESSLIST and
--       performance_schema.threads. There is no direct equivalent of
--       pg_stat_activity.backend_type; COMMAND covers similar territory.
--       Per-user and per-host connection limits come from mysql.user and
--       information_schema.USER_ATTRIBUTES (MySQL 8.0).

-- ---------------------------------------------------------------------------
-- Connection limit vs current usage
-- ---------------------------------------------------------------------------
SELECT
    @@max_connections                                       AS max_connections,
    -- NOTE: MySQL has no superuser_reserved_connections concept;
    --       @@max_connections includes all users.
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST)   AS total_connections,
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST
     WHERE COMMAND <> 'Sleep')                              AS active_connections,
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST
     WHERE COMMAND = 'Sleep')                               AS idle_connections,
    (SELECT COUNT(*) FROM information_schema.PROCESSLIST
     WHERE STATE LIKE '%lock%')                             AS waiting_for_lock,
    ROUND(100.0 *
        (SELECT COUNT(*) FROM information_schema.PROCESSLIST)
        / NULLIF(@@max_connections, 0), 2)                  AS pct_used;

-- ---------------------------------------------------------------------------
-- Global connection status counters
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Threads_connected',
    'Threads_running',
    'Threads_cached',
    'Max_used_connections',
    'Max_used_connections_time',
    'Connection_errors_max_connections',
    'Aborted_connects',
    'Aborted_clients'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Connections by state (COMMAND column)
-- ---------------------------------------------------------------------------
SELECT
    COMMAND                                                 AS state,
    COUNT(*)                                                AS connections
FROM information_schema.PROCESSLIST
GROUP BY COMMAND
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Connections by database / user / command
-- ---------------------------------------------------------------------------
SELECT
    DB                                                      AS database_name,
    USER                                                    AS user,
    COMMAND                                                 AS command,
    COUNT(*)                                                AS connections
FROM information_schema.PROCESSLIST
GROUP BY DB, USER, COMMAND
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Connections by client host (find a single host hammering the DB)
-- ---------------------------------------------------------------------------
SELECT
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    USER,
    COUNT(*)                                                AS connections,
    SUM(CASE WHEN COMMAND <> 'Sleep' THEN 1 ELSE 0 END)    AS active,
    SUM(CASE WHEN COMMAND = 'Sleep' THEN 1 ELSE 0 END)      AS idle
FROM information_schema.PROCESSLIST
GROUP BY SUBSTRING_INDEX(HOST, ':', 1), USER
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Per-user connection limits vs current usage
-- NOTE: MySQL connection limits per user are stored in mysql.user.
--       max_user_connections = 0 means no per-user limit (global limit applies).
-- ---------------------------------------------------------------------------
SELECT
    u.User                                                  AS user,
    u.max_user_connections                                  AS limit_per_user,
    COUNT(p.ID)                                             AS current_connections,
    CASE WHEN u.max_user_connections > 0
         THEN ROUND(100.0 * COUNT(p.ID) / u.max_user_connections, 2)
         ELSE NULL
    END                                                     AS pct_used
FROM mysql.user u
LEFT JOIN information_schema.PROCESSLIST p
  ON p.USER = u.User
GROUP BY u.User, u.max_user_connections
HAVING COUNT(p.ID) > 0
ORDER BY current_connections DESC;

-- ---------------------------------------------------------------------------
-- Per-host connection limits vs current usage
-- ---------------------------------------------------------------------------
SELECT
    u.Host,
    COUNT(p.ID)                                             AS current_connections
FROM mysql.user u
LEFT JOIN information_schema.PROCESSLIST p
  ON SUBSTRING_INDEX(p.HOST, ':', 1) = u.Host
GROUP BY u.Host
HAVING COUNT(p.ID) > 0
ORDER BY current_connections DESC;

-- ---------------------------------------------------------------------------
-- Oldest / longest-running connections (potential pool leak)
-- ---------------------------------------------------------------------------
SELECT
    ID                                                      AS pid,
    USER,
    SUBSTRING_INDEX(HOST, ':', 1)                           AS host,
    DB                                                      AS database_name,
    COMMAND,
    TIME                                                    AS seconds,
    STATE,
    LEFT(INFO, 200)                                         AS query
FROM information_schema.PROCESSLIST
ORDER BY TIME DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Thread detail from performance_schema (richer than PROCESSLIST)
-- ---------------------------------------------------------------------------
SELECT
    t.THREAD_ID,
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_HOST                                      AS host,
    t.PROCESSLIST_DB                                        AS database_name,
    t.PROCESSLIST_COMMAND                                   AS command,
    t.PROCESSLIST_TIME                                      AS seconds,
    t.PROCESSLIST_STATE                                     AS state,
    t.TYPE                                                  AS thread_type,
    LEFT(t.PROCESSLIST_INFO, 200)                           AS query
FROM performance_schema.threads t
WHERE t.TYPE = 'FOREGROUND'
ORDER BY t.PROCESSLIST_TIME DESC
LIMIT 25;
