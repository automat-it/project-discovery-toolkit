-- =============================================================================
-- perf_02_blocking_and_locks.sql
-- Priority: CRITICAL
-- Purpose: Find blocking sessions, long-running transactions, idle-in-tx
--          sessions. The most common cause of latency spikes and timeouts.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Direct blocking pairs (who is blocking whom right now)
-- ---------------------------------------------------------------------------
SELECT
    blocked.pid                                          AS blocked_pid,
    blocked.usename                                      AS blocked_user,
    blocked.application_name                             AS blocked_app,
    blocked.client_addr                                  AS blocked_client,
    blocking.pid                                         AS blocking_pid,
    blocking.usename                                     AS blocking_user,
    blocking.application_name                            AS blocking_app,
    blocking.client_addr                                 AS blocking_client,
    blocked.wait_event_type,
    blocked.wait_event,
    now() - blocked.query_start                          AS blocked_duration,
    now() - blocking.xact_start                          AS blocker_xact_age,
    blocking.state                                       AS blocker_state,
    left(blocked.query, 200)                             AS blocked_query,
    left(blocking.query, 200)                            AS blocking_query
FROM pg_stat_activity blocked
JOIN pg_stat_activity blocking
  ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
WHERE blocked.wait_event_type = 'Lock'
ORDER BY blocked_duration DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- Full blocking tree (recursive — handles chained blockers)
-- ---------------------------------------------------------------------------
WITH RECURSIVE blocking_tree AS (
    SELECT
        pid,
        usename,
        application_name,
        wait_event_type,
        wait_event,
        state,
        query,
        pg_blocking_pids(pid)                            AS blockers,
        1                                                AS level,
        pid::text                                        AS path
    FROM pg_stat_activity
    WHERE cardinality(pg_blocking_pids(pid)) > 0
    UNION ALL
    SELECT
        a.pid,
        a.usename,
        a.application_name,
        a.wait_event_type,
        a.wait_event,
        a.state,
        a.query,
        pg_blocking_pids(a.pid),
        bt.level + 1,
        bt.path || ' -> ' || a.pid::text
    FROM pg_stat_activity a
    JOIN blocking_tree bt ON a.pid = ANY(bt.blockers)
    WHERE bt.level < 10
)
SELECT
    level,
    path,
    pid,
    usename,
    application_name                                     AS app,
    wait_event_type,
    wait_event,
    state,
    left(query, 200)                                     AS query
FROM blocking_tree
ORDER BY path, level;

-- ---------------------------------------------------------------------------
-- Long-running transactions (> 1 minute)
-- These hold XID horizon back, block VACUUM, and accumulate locks.
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    state,
    now() - xact_start                                   AS xact_age,
    now() - query_start                                  AS query_age,
    now() - state_change                                 AS state_age,
    wait_event_type,
    wait_event,
    backend_xid,
    backend_xmin,
    left(query, 300)                                     AS query
FROM pg_stat_activity
WHERE xact_start IS NOT NULL
  AND now() - xact_start > interval '1 minute'
  AND pid <> pg_backend_pid()
ORDER BY xact_start;

-- ---------------------------------------------------------------------------
-- Idle in transaction sessions (silent killers — hold locks, bloat tables)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    state,
    now() - state_change                                 AS idle_duration,
    now() - xact_start                                   AS xact_age,
    backend_xid,
    backend_xmin,
    left(query, 300)                                     AS last_query
FROM pg_stat_activity
WHERE state IN ('idle in transaction', 'idle in transaction (aborted)')
ORDER BY state_change;

-- ---------------------------------------------------------------------------
-- Lock summary by mode
-- ---------------------------------------------------------------------------
SELECT
    mode,
    locktype,
    granted,
    count(*)                                             AS lock_count
FROM pg_locks
GROUP BY mode, locktype, granted
ORDER BY lock_count DESC;

-- ---------------------------------------------------------------------------
-- Tables with the most lock contention right now
-- ---------------------------------------------------------------------------
SELECT
    l.relation::regclass                                 AS relation,
    count(*)                                             AS total_locks,
    count(*) FILTER (WHERE NOT l.granted)                AS waiting_locks,
    count(DISTINCT l.pid)                                AS distinct_pids,
    string_agg(DISTINCT l.mode, ', ' ORDER BY l.mode)    AS lock_modes
FROM pg_locks l
WHERE l.relation IS NOT NULL
GROUP BY l.relation
HAVING count(*) > 1
ORDER BY waiting_locks DESC, total_locks DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Deadlock counters per database (cumulative since stats reset)
-- ---------------------------------------------------------------------------
SELECT
    datname,
    deadlocks,
    conflicts,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY deadlocks DESC;
