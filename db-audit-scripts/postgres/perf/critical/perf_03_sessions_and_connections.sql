-- =============================================================================
-- perf_03_sessions_and_connections.sql
-- Priority: CRITICAL
-- Purpose: Connection inventory by user / app / state, find connection
--          storms and pool misconfigurations.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Connection limit vs current usage
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections')                AS max_connections,
    (SELECT setting::int FROM pg_settings WHERE name = 'superuser_reserved_connections') AS superuser_reserved,
    (SELECT count(*) FROM pg_stat_activity)                                              AS total,
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'active')                       AS active,
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle')                         AS idle,
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction')          AS idle_in_tx,
    (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction (aborted)') AS idle_in_tx_aborted,
    (SELECT count(*) FROM pg_stat_activity WHERE wait_event IS NOT NULL)                 AS waiting,
    round(100.0 * (SELECT count(*) FROM pg_stat_activity)
                / NULLIF((SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), 0), 2)
                                                                                         AS pct_used;

-- ---------------------------------------------------------------------------
-- Connections by state
-- ---------------------------------------------------------------------------
SELECT
    coalesce(state, 'background')                        AS state,
    count(*)                                             AS connections
FROM pg_stat_activity
GROUP BY state
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Connections by database / user / application
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    usename                                              AS user,
    application_name                                     AS application,
    state,
    count(*)                                             AS connections
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY datname, usename, application_name, state
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Connections by client address (find a single host hammering the DB)
-- ---------------------------------------------------------------------------
SELECT
    coalesce(host(client_addr), 'local')                 AS client_host,
    usename,
    application_name,
    count(*)                                             AS connections,
    count(*) FILTER (WHERE state = 'active')             AS active,
    count(*) FILTER (WHERE state = 'idle')               AS idle
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY client_addr, usename, application_name
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Backend type breakdown (client vs background workers, autovacuum, etc.)
-- ---------------------------------------------------------------------------
SELECT
    backend_type,
    count(*)                                             AS count
FROM pg_stat_activity
GROUP BY backend_type
ORDER BY count DESC;

-- ---------------------------------------------------------------------------
-- Per-role connection limits vs current usage
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolconnlimit                                       AS limit,
    count(a.pid)                                         AS current,
    CASE WHEN r.rolconnlimit > 0
         THEN round(100.0 * count(a.pid) / r.rolconnlimit, 2)
         ELSE NULL
    END                                                  AS pct_used
FROM pg_roles r
LEFT JOIN pg_stat_activity a ON a.usename = r.rolname
WHERE r.rolcanlogin
GROUP BY r.rolname, r.rolconnlimit
HAVING count(a.pid) > 0
ORDER BY current DESC;

-- ---------------------------------------------------------------------------
-- Per-database connection limits vs current usage
-- ---------------------------------------------------------------------------
SELECT
    d.datname                                            AS database,
    d.datconnlimit                                       AS limit,
    count(a.pid)                                         AS current,
    CASE WHEN d.datconnlimit > 0
         THEN round(100.0 * count(a.pid) / d.datconnlimit, 2)
         ELSE NULL
    END                                                  AS pct_used
FROM pg_database d
LEFT JOIN pg_stat_activity a ON a.datname = d.datname
WHERE NOT d.datistemplate
GROUP BY d.datname, d.datconnlimit
ORDER BY current DESC;

-- ---------------------------------------------------------------------------
-- Oldest connections (potential pool leak)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    backend_start,
    now() - backend_start                                AS connection_age,
    state,
    now() - state_change                                 AS state_age
FROM pg_stat_activity
WHERE backend_type = 'client backend'
ORDER BY backend_start
LIMIT 25;
