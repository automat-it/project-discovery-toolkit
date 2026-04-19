-- =============================================================================
-- sec_13_service_accounts.sql
-- Priority: MEDIUM
-- Purpose: Identify technical / service accounts. These tend to accumulate
--          excess privilege over time. SQL Server has no explicit
--          service-account flag, so we use naming heuristics and
--          behaviour (CHECK_EXPIRATION off, high connection counts,
--          generic application_name).
-- Sources: sys.server_principals, sys.sql_logins,
--          sys.dm_exec_sessions.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Likely service accounts by naming pattern
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.type_desc,
    sp.is_disabled,
    sp.create_date,
    sl.is_policy_checked,
    sl.is_expiration_checked,
    -- password_last_set_time is exposed via LOGINPROPERTY, not as a column.
    CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2) AS password_last_set_time
FROM sys.server_principals sp
LEFT JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type IN ('S','U','G')
  AND (
      sp.name LIKE '%svc%' OR sp.name LIKE '%service%' OR sp.name LIKE '%_sys%'
   OR sp.name LIKE '%_app%' OR sp.name LIKE '%_etl%' OR sp.name LIKE '%_bot%'
   OR sp.name LIKE '%_daemon%' OR sp.name LIKE '%_backup%' OR sp.name LIKE '%_monitor%'
   OR sp.name LIKE '%_worker%' OR sp.name LIKE '%_job%' OR sp.name LIKE '%_cron%'
   OR sp.name LIKE '%_ci' OR sp.name LIKE '%_cd' OR sp.name LIKE '%_deploy%'
   OR sp.name LIKE '%_migration%'
  )
ORDER BY sp.name;

-- ---------------------------------------------------------------------------
-- Service-like logins with elevated privileges (sysadmin / CONTROL SERVER
-- or any database db_owner)
-- ---------------------------------------------------------------------------
SELECT
    m.name                                            AS service_login,
    r.name                                            AS role
FROM sys.server_role_members srm
JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
WHERE m.type IN ('S','U','G')
  AND r.name IN ('sysadmin','securityadmin','serveradmin','setupadmin','dbcreator')
  AND (m.name LIKE '%svc%' OR m.name LIKE '%service%'
    OR m.name LIKE '%_app%' OR m.name LIKE '%_sys%'
    OR m.name LIKE '%_etl%' OR m.name LIKE '%_bot%')
ORDER BY m.name;

-- ---------------------------------------------------------------------------
-- Currently connected sessions whose program_name looks like an app /
-- service (batch jobs, .NET apps, pooled connections)
-- ---------------------------------------------------------------------------
SELECT
    s.login_name,
    s.program_name,
    s.host_name,
    COUNT(*)                                          AS sessions,
    MIN(s.login_time)                                 AS oldest_session,
    MAX(s.login_time)                                 AS newest_session
FROM sys.dm_exec_sessions s
WHERE s.is_user_process = 1
  AND s.program_name <> ''
GROUP BY s.login_name, s.program_name, s.host_name
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Logins with unusually high session counts (pooled / daemon logins)
-- ---------------------------------------------------------------------------
SELECT
    s.login_name,
    COUNT(*)                                          AS current_connections,
    COUNT(DISTINCT s.program_name)                    AS distinct_apps,
    COUNT(DISTINCT s.host_name)                       AS distinct_hosts,
    COUNT(DISTINCT c.client_net_address)              AS distinct_client_ips,
    MIN(s.login_time)                                 AS oldest_session
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
WHERE s.is_user_process = 1
GROUP BY s.login_name
HAVING COUNT(*) > 5
ORDER BY current_connections DESC;

-- ---------------------------------------------------------------------------
-- Service accounts with CHECK_EXPIRATION off (password never expires)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.is_disabled,
    sl.is_policy_checked,
    sl.is_expiration_checked,
    CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2) AS password_last_set_time,
    DATEDIFF(day,
             CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2),
             SYSUTCDATETIME())                        AS days_since_change
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND sl.is_expiration_checked = 0
  AND (sp.name LIKE '%svc%' OR sp.name LIKE '%service%'
    OR sp.name LIKE '%_app%' OR sp.name LIKE '%_bot%'
    OR sp.name LIKE '%_etl%' OR sp.name LIKE '%_monitor%'
    OR sp.name LIKE '%_backup%')
ORDER BY password_last_set_time;

-- ---------------------------------------------------------------------------
-- Object ownership by likely service accounts.
--
-- NOTE: sys.objects.principal_id is NULL for objects that inherit
-- ownership from their schema (the default when CREATE omits AUTHORIZATION).
-- Join through sys.schemas.principal_id to pick up the effective owner;
-- COALESCE(o.principal_id, s.principal_id) gives the correct value in
-- both cases.
-- ---------------------------------------------------------------------------
SELECT
    pr.name                                           AS owner,
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    COUNT(*)                                          AS owned_objects
FROM sys.objects o
JOIN sys.schemas s              ON s.schema_id = o.schema_id
JOIN sys.database_principals pr ON pr.principal_id = COALESCE(o.principal_id, s.principal_id)
WHERE (pr.name LIKE '%svc%' OR pr.name LIKE '%service%'
    OR pr.name LIKE '%_app%' OR pr.name LIKE '%_bot%')
  AND o.is_ms_shipped = 0
GROUP BY pr.name, SCHEMA_NAME(o.schema_id)
ORDER BY owned_objects DESC;
