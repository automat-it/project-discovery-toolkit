-- =============================================================================
-- perf_03_sessions_and_connections.sql
-- Priority: CRITICAL
-- Purpose: Connection inventory by user / app / state — find connection
--          storms, pool misconfigurations, and oldest sessions.
-- Sources: sys.dm_exec_sessions, sys.dm_exec_connections,
--          sys.dm_exec_requests, sys.configurations.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Connection limit vs current usage
-- ---------------------------------------------------------------------------
SELECT
    (SELECT CAST(value_in_use AS INT) FROM sys.configurations
      WHERE name = 'user connections')                 AS max_connections_config,
    @@MAX_CONNECTIONS                                  AS server_max_connections,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions)        AS total_sessions,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions
      WHERE is_user_process = 1)                       AS user_sessions,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions
      WHERE is_user_process = 1 AND status = 'running') AS running,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions
      WHERE is_user_process = 1 AND status = 'sleeping') AS sleeping,
    (SELECT COUNT(*) FROM sys.dm_exec_requests
      WHERE blocking_session_id <> 0)                  AS waiting_on_locks,
    (SELECT COUNT(*) FROM sys.dm_exec_sessions
      WHERE is_user_process = 1 AND open_transaction_count > 0) AS with_open_txn;

-- ---------------------------------------------------------------------------
-- Sessions by status
-- ---------------------------------------------------------------------------
SELECT
    status,
    COUNT(*)                                           AS sessions,
    SUM(CASE WHEN is_user_process = 1 THEN 1 ELSE 0 END) AS user_sessions,
    SUM(CASE WHEN is_user_process = 0 THEN 1 ELSE 0 END) AS system_sessions
FROM sys.dm_exec_sessions
GROUP BY status
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Sessions by login / application / host
-- ---------------------------------------------------------------------------
SELECT
    login_name,
    program_name,
    host_name,
    DB_NAME(database_id)                               AS database_name,
    status,
    COUNT(*)                                           AS sessions,
    SUM(open_transaction_count)                        AS open_txns
FROM sys.dm_exec_sessions
WHERE is_user_process = 1
GROUP BY login_name, program_name, host_name, database_id, status
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Sessions by client IP (find a single host hammering the server)
-- ---------------------------------------------------------------------------
SELECT
    c.client_net_address                               AS client_ip,
    s.login_name,
    s.program_name,
    COUNT(*)                                           AS connections,
    SUM(CASE WHEN s.status = 'running' THEN 1 ELSE 0 END)  AS running,
    SUM(CASE WHEN s.status = 'sleeping' THEN 1 ELSE 0 END) AS sleeping
FROM sys.dm_exec_sessions s
JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
WHERE s.is_user_process = 1
GROUP BY c.client_net_address, s.login_name, s.program_name
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Per-login connection limits vs current usage
-- ---------------------------------------------------------------------------
SELECT
    p.name                                             AS login,
    p.type_desc                                        AS login_type,
    p.is_disabled,
    COUNT(s.session_id)                                AS current_connections
FROM sys.server_principals p
LEFT JOIN sys.dm_exec_sessions s ON s.login_name = p.name AND s.is_user_process = 1
WHERE p.type IN ('S','U','G')
GROUP BY p.name, p.type_desc, p.is_disabled
HAVING COUNT(s.session_id) > 0
ORDER BY current_connections DESC;

-- ---------------------------------------------------------------------------
-- Oldest connections (pool leak candidates)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    DB_NAME(s.database_id)                             AS database_name,
    c.client_net_address,
    s.login_time,
    DATEDIFF(second, s.login_time, SYSUTCDATETIME())   AS connection_age_sec,
    s.status,
    s.last_request_start_time,
    DATEDIFF(second, s.last_request_end_time, SYSUTCDATETIME()) AS idle_sec,
    s.open_transaction_count
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
WHERE s.is_user_process = 1
ORDER BY s.login_time;

-- ---------------------------------------------------------------------------
-- Endpoints / network protocols currently accepting connections
-- ---------------------------------------------------------------------------
SELECT
    protocol_desc,
    type_desc,
    state_desc,
    name,
    is_admin_endpoint
FROM sys.endpoints
WHERE type > 0
ORDER BY protocol_desc, name;

-- ---------------------------------------------------------------------------
-- Connection protocol breakdown (TCP vs shared memory vs named pipe)
-- ---------------------------------------------------------------------------
SELECT
    protocol_type,
    net_transport,
    encrypt_option,
    auth_scheme,
    COUNT(*)                                           AS connection_count
FROM sys.dm_exec_connections
GROUP BY protocol_type, net_transport, encrypt_option, auth_scheme
ORDER BY connection_count DESC;
