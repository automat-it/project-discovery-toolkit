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
-- pg_hba.conf — all host-based rules with risk classification.
-- pg_hba_file_rules is restricted to elevated roles on most deployments;
-- guard so a limited-privilege audit user gets a clear skip message instead
-- of a permission-denied error that aborts the rest of the file.
--
-- Also switched the CIDR comparison to numeric extraction so any /0..//15
-- (class-A-ish and broader) lands in the "broad CIDR" bucket, regardless of
-- the number of digits in the netmask.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_hba_file_rules', 'SELECT') AS can_read_pg_hba
\gset
\if :can_read_pg_hba
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
        WHEN address ~ '^0\.0\.0\.0/\d+$'
             AND substring(address from '/(\d+)')::int < 16
                                                   THEN 'HIGH: broad CIDR'
        WHEN type IN ('local')                     THEN 'LOW: unix socket'
        WHEN address IN ('127.0.0.1/32', '::1/128') THEN 'LOW: loopback'
        ELSE 'review'
    END                                                  AS risk
FROM pg_hba_file_rules
WHERE type IN ('host', 'hostssl', 'hostnossl', 'local')
ORDER BY line_number;
\else
SELECT 'Skipped: pg_hba_file_rules is not readable by ' || current_user
       || ' — re-run as superuser / pg_read_server_files to inspect HBA rules.' AS note;
\endif

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
-- pg_ident.conf mappings (user name mapping for external auth).
-- Same privilege model as pg_hba_file_rules — guard access so non-privileged
-- runs skip cleanly instead of erroring.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege(current_user, 'pg_ident_file_mappings', 'SELECT') AS can_read_pg_ident
\gset
\if :can_read_pg_ident
SELECT
    line_number,
    map_name,
    sys_name      AS system_user,
    pg_username   AS db_user,
    error
FROM pg_ident_file_mappings
ORDER BY line_number;
\else
SELECT 'Skipped: pg_ident_file_mappings is not readable by ' || current_user
       || ' — re-run as superuser / pg_read_server_files to inspect ident mappings.' AS note;
\endif
