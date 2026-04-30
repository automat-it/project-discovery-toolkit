-- =============================================================================
-- sec_08_network_exposure.sql
-- Priority: HIGH
-- Purpose: Attack surface — listener IPs / port, endpoints, connected
--          clients, firewall-relevant metadata.
-- Sources: sys.dm_exec_connections, sys.tcp_endpoints,
--          sys.endpoints, sys.server_network_protocols_config (optional).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects
-- FOR XML PATH + .value() in the connected-IPs query below requires
-- QUOTED_IDENTIFIER ON. sqlcmd defaults to OFF (unlike SSMS), which
-- raises Msg 1934 on the SELECT. Set it explicitly here.
SET QUOTED_IDENTIFIER ON;

-- ---------------------------------------------------------------------------
-- Endpoints (TCP listeners, dedicated admin, service broker, etc.)
-- ---------------------------------------------------------------------------
SELECT
    e.name                                            AS endpoint_name,
    e.type_desc                                       AS endpoint_type,
    e.protocol_desc,
    e.state_desc,
    e.is_admin_endpoint,
    e.principal_id,
    SUSER_NAME(e.principal_id)                        AS owner
FROM sys.endpoints e
ORDER BY e.type_desc, e.name;

-- TCP endpoint detail (port + IP bindings). sys.tcp_endpoints does not
-- exist on Azure SQL Database — guard so those audits keep going.
BEGIN TRY
    SELECT
        e.name                                        AS endpoint_name,
        te.port,
        te.is_dynamic_port,
        te.ip_address
    FROM sys.endpoints e
    JOIN sys.tcp_endpoints te ON te.endpoint_id = e.endpoint_id;
END TRY
BEGIN CATCH
    PRINT '[note] sys.tcp_endpoints unavailable (Azure SQL DB or restricted): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Remote (non-loopback) current connections
-- ---------------------------------------------------------------------------
SELECT
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    c.client_net_address,
    c.local_net_address                               AS server_listener_ip,
    c.local_tcp_port                                  AS server_listener_port,
    c.encrypt_option,
    c.auth_scheme,
    c.protocol_type,
    c.net_transport,
    s.login_time
FROM sys.dm_exec_connections c
JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id
WHERE s.is_user_process = 1
  AND c.client_net_address IS NOT NULL
  AND c.client_net_address NOT IN ('<local machine>', '127.0.0.1', '::1')
ORDER BY s.login_time;

-- ---------------------------------------------------------------------------
-- Distinct client IPs currently connected
-- ---------------------------------------------------------------------------
-- STRING_AGG ... WITHIN GROUP requires database compatibility level 130+
-- (SQL Server 2017+). On databases left at older compat levels (still
-- common after upgrades) the parser raises 'Incorrect syntax near (' on
-- the WITHIN GROUP clause. Use the FOR XML PATH idiom which works on
-- every supported version regardless of compat level.
SELECT
    c.client_net_address                              AS client_ip,
    COUNT(*)                                          AS sessions,
    STUFF((SELECT N', ' + CAST(s2.login_name AS NVARCHAR(256))
             FROM sys.dm_exec_sessions s2
             JOIN sys.dm_exec_connections c2
                  ON c2.session_id = s2.session_id
            WHERE c2.client_net_address = c.client_net_address
              AND s2.is_user_process = 1
            ORDER BY s2.login_name
            FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'),
          1, 2, '')                                   AS logins_used
FROM sys.dm_exec_connections c
JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id
WHERE s.is_user_process = 1
GROUP BY c.client_net_address
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Public / authenticated permissions on endpoints — anyone with access
-- can CONNECT to the endpoint. Check for over-broad grants.
-- ---------------------------------------------------------------------------
SELECT
    e.name                                            AS endpoint_name,
    e.type_desc                                       AS endpoint_type,
    gp.name                                           AS grantee,
    p.permission_name,
    p.state_desc
FROM sys.server_permissions p
JOIN sys.endpoints e          ON e.endpoint_id = p.major_id
JOIN sys.server_principals gp ON gp.principal_id = p.grantee_principal_id
WHERE p.class = 105                                    -- endpoint class
ORDER BY e.name, gp.name;

-- ---------------------------------------------------------------------------
-- Linked servers (outbound network surface)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS linked_server,
    product,
    provider,
    data_source,
    modify_date,
    is_linked,
    is_remote_login_enabled,
    is_rpc_out_enabled,
    is_data_access_enabled
FROM sys.servers
WHERE is_linked = 1
ORDER BY name;

-- Remote logins mapped to linked servers (may carry plaintext credentials)
SELECT
    s.name                                            AS linked_server,
    rl.local_principal_id,
    SUSER_NAME(rl.local_principal_id)                 AS local_login,
    rl.remote_name                                    AS remote_login,
    rl.modify_date
FROM sys.linked_logins rl
JOIN sys.servers s ON s.server_id = rl.server_id
ORDER BY s.name, rl.local_principal_id;

-- ---------------------------------------------------------------------------
-- SQL Server Browser / Agent status (if accessible)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT servicename, status_desc, startup_type_desc, last_startup_time
    FROM   sys.dm_server_services;
END TRY
BEGIN CATCH
    PRINT '[note] sys.dm_server_services requires elevated perms or is unavailable: '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.endpoints WHERE type > 0)  AS custom_endpoints,
    (SELECT COUNT(*) FROM sys.endpoints WHERE is_admin_endpoint = 1) AS admin_endpoints,
    (SELECT COUNT(*) FROM sys.servers WHERE is_linked = 1) AS linked_servers,
    (SELECT COUNT(DISTINCT c.client_net_address)
       FROM sys.dm_exec_connections c
       JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id
      WHERE s.is_user_process = 1)                   AS distinct_client_ips_right_now;
