-- =============================================================================
-- sec_08_network_exposure.sql
-- Priority: HIGH
-- Purpose: Determine attack surface — listen addresses, allowed networks,
--          remote access patterns.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Listen addresses and port
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'listen_addresses',
    'port',
    'unix_socket_directories',
    'unix_socket_group',
    'unix_socket_permissions',
    'bonjour'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- pg_hba.conf — all host-based rules with risk classification
-- ---------------------------------------------------------------------------
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    netmask,
    auth_method,
    CASE
        WHEN address IN ('0.0.0.0/0', '::/0')      THEN 'CRITICAL: open to internet'
        WHEN address LIKE '0.0.0.0/_'              THEN 'HIGH: very broad'
        WHEN address LIKE '0.0.0.0/__'
             AND substring(address from '/(\d+)')::int < 16
                                                   THEN 'HIGH: broad CIDR'
        WHEN type IN ('local')                     THEN 'LOW: unix socket'
        WHEN address IN ('127.0.0.1/32', '::1/128') THEN 'LOW: loopback'
        ELSE 'review'
    END                                                  AS risk
FROM pg_hba_file_rules
WHERE type IN ('host', 'hostssl', 'hostnossl', 'local')
ORDER BY line_number;

-- ---------------------------------------------------------------------------
-- Distinct client networks currently connected
-- ---------------------------------------------------------------------------
SELECT
    coalesce(host(client_addr), 'local socket')          AS client_host,
    count(*)                                             AS sessions,
    array_agg(DISTINCT usename)                          AS users,
    array_agg(DISTINCT application_name)                 AS apps
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY client_addr
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Remote (non-localhost) connections right now
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    client_hostname,
    client_port,
    backend_start,
    state
FROM pg_stat_activity
WHERE backend_type = 'client backend'
  AND client_addr IS NOT NULL
  AND client_addr <> '127.0.0.1'::inet
  AND client_addr <> '::1'::inet
ORDER BY client_addr;

-- ---------------------------------------------------------------------------
-- pg_ident.conf mappings (user name mapping for external auth)
-- ---------------------------------------------------------------------------
SELECT
    line_number,
    map_name,
    sys_name                                             AS system_user,
    pg_user                                              AS db_user,
    error
FROM pg_ident_file_mappings
ORDER BY line_number;
