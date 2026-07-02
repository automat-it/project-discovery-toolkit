-- =============================================================================
-- sec_20_failed_login_patterns.sql
-- Priority: HIGH
-- Purpose: Detect brute-force / credential-stuffing patterns by inspecting
--          authentication configuration, active connections, and any
--          installed auth-failure tracking extension. PostgreSQL does not
--          surface failed logins via SQL by default — failed attempts go
--          only to the server log. This script reports what *is* visible
--          and calls out gaps.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Authentication logging config — are failed logins even being recorded?
-- ---------------------------------------------------------------------------
SELECT name, setting, source, short_desc
FROM pg_settings
WHERE name IN (
    'log_connections',
    'log_disconnections',
    'log_hostname',
    'log_line_prefix',
    'logging_collector',
    'log_destination',
    'log_directory',
    'log_filename'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- pg_hba rules — any host lines still using trust / password (cleartext)?
-- Privileged: pg_hba_file_rules is restricted to superusers (and to roles
-- with pg_read_server_files in 14+). Guard behind a privilege check so the
-- script does not fail for ordinary audit roles.
-- ---------------------------------------------------------------------------
SELECT has_table_privilege('pg_catalog.pg_hba_file_rules', 'SELECT') AS can_read_hba
\gset
\if :can_read_hba
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    netmask,
    auth_method,
    options,
    error
FROM pg_hba_file_rules
ORDER BY line_number;
\else
SELECT 'pg_hba_file_rules NOT accessible for this role - skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Roles with LOGIN and no password expiry window
-- ---------------------------------------------------------------------------
SELECT
    rolname,
    rolcanlogin,
    rolvaliduntil,
    rolconnlimit,
    CASE WHEN rolvaliduntil IS NULL THEN 'no expiry'
         WHEN rolvaliduntil < now() THEN 'expired'
         ELSE 'valid' END                    AS password_state
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Currently connected clients — cluster of many connections from one IP
-- with short-lived sessions is a brute-force indicator.
-- ---------------------------------------------------------------------------
SELECT
    client_addr,
    COUNT(*)                                  AS sessions,
    COUNT(DISTINCT usename)                   AS distinct_users,
    MIN(backend_start)                        AS first_seen,
    MAX(backend_start)                        AS last_seen
FROM pg_stat_activity
WHERE client_addr IS NOT NULL
GROUP BY client_addr
ORDER BY sessions DESC, distinct_users DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Role-level connection limit usage — exhausting a role's rolconnlimit is
-- a classic DoS / brute-force signature.
-- ---------------------------------------------------------------------------
SELECT
    r.rolname,
    r.rolconnlimit,
    COALESCE(a.sessions, 0)                   AS current_sessions,
    CASE WHEN r.rolconnlimit > 0
         THEN round(100.0 * COALESCE(a.sessions,0) / r.rolconnlimit, 1)
         ELSE NULL END                         AS pct_used
FROM pg_roles r
LEFT JOIN (
    SELECT usename, COUNT(*) AS sessions
      FROM pg_stat_activity
     WHERE backend_type = 'client backend'
     GROUP BY usename
) a ON a.usename = r.rolname
WHERE r.rolcanlogin = true
ORDER BY pct_used DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- Check for log-parser style extensions (pg_failed_login counter if any;
-- community extensions such as credcheck / pg_auth_failure) — they are
-- the only way to see failed-login aggregates via SQL.
-- ---------------------------------------------------------------------------
SELECT extname, extversion
FROM pg_extension
WHERE extname IN ('credcheck', 'passwordcheck', 'pg_auth_failure',
                  'pgaudit', 'pg_stat_kcache')
ORDER BY extname;

-- ---------------------------------------------------------------------------
-- Summary + operator guidance
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting FROM pg_settings WHERE name = 'log_connections')    AS log_connections,
    (SELECT setting FROM pg_settings WHERE name = 'log_hostname')       AS log_hostname,
    (SELECT COUNT(*) FROM pg_stat_activity WHERE client_addr IS NOT NULL) AS active_remote_sessions,
    CASE
      WHEN (SELECT setting FROM pg_settings WHERE name='log_connections') = 'on'
        THEN 'Failed logins captured in server log — grep "authentication failed" / "password authentication failed"'
      ELSE 'log_connections is OFF — failed logins are NOT being recorded anywhere'
    END                                                                  AS assessment;
