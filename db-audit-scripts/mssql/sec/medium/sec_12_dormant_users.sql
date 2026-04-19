-- =============================================================================
-- sec_12_dormant_users.sql
-- Priority: MEDIUM
-- Purpose: Find inactive accounts that should be reviewed or disabled.
-- Note: SQL Server tracks login_time per session and modify_date per
--       login; the Server Audit "SUCCESSFUL_LOGIN_GROUP" records every
--       login for long-term dormancy tracking. Without the audit trail
--       this script uses proxies (last_modify_date, session absence,
--       disabled flag).
-- Sources: sys.server_principals, sys.sql_logins,
--          sys.dm_exec_sessions, sys.database_principals.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Disabled logins (explicitly inactive)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.type_desc,
    sp.create_date,
    sp.modify_date,
    sp.default_database_name
FROM sys.server_principals sp
WHERE sp.is_disabled = 1
  AND sp.type IN ('S','U','G')
ORDER BY sp.modify_date DESC;

-- ---------------------------------------------------------------------------
-- Logins with no active session right now and not modified in > 90 days
-- (approximate dormancy — absence ≠ dormant; treat as a starting point)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.type_desc,
    sp.create_date,
    sp.modify_date,
    DATEDIFF(day, sp.modify_date, SYSUTCDATETIME())   AS days_since_modify,
    sp.is_disabled
FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G')
  AND sp.modify_date < DATEADD(day, -90, SYSUTCDATETIME())
  AND NOT EXISTS (
      SELECT 1 FROM sys.dm_exec_sessions s
       WHERE s.is_user_process = 1
         AND s.login_name = sp.name
  )
ORDER BY sp.modify_date;

-- ---------------------------------------------------------------------------
-- Expired SQL logins still enabled (should be disabled or rotated)
-- ---------------------------------------------------------------------------
-- NOTE: is_expired / password_last_set_time are NOT columns of
-- sys.sql_logins; use LOGINPROPERTY().
SELECT
    sp.name                                           AS login_name,
    LOGINPROPERTY(sp.name, 'IsExpired')               AS password_expired,
    CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2) AS password_last_set_time,
    DATEDIFF(day,
             CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2),
             SYSUTCDATETIME())                        AS days_since_change,
    sp.is_disabled
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND CAST(LOGINPROPERTY(sp.name, 'IsExpired') AS INT) = 1
  AND sp.is_disabled = 0
ORDER BY password_last_set_time;

-- ---------------------------------------------------------------------------
-- Database users whose mapped login does not exist (orphans — candidates
-- for removal or re-mapping)
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    dp.name                                           AS database_user,
    dp.type_desc,
    dp.sid,
    dp.create_date,
    dp.modify_date
FROM sys.database_principals dp
WHERE dp.type IN ('S','U','G')
  AND dp.sid IS NOT NULL
  AND dp.authentication_type_desc = 'INSTANCE'
  AND NOT EXISTS (
      SELECT 1 FROM sys.server_principals sp
       WHERE sp.sid = dp.sid
  )
  AND dp.name NOT IN ('dbo','guest','sys','INFORMATION_SCHEMA');

-- ---------------------------------------------------------------------------
-- Logins with no database mappings (exist on the server, mapped nowhere)
-- ---------------------------------------------------------------------------
;WITH db_users AS (
    SELECT sid
      FROM sys.database_principals
     WHERE sid IS NOT NULL
)
SELECT
    sp.name                                           AS login_name,
    sp.type_desc,
    sp.create_date,
    sp.modify_date,
    sp.default_database_name,
    sp.is_disabled
FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G')
  AND sp.name NOT IN ('sa','##MS_PolicyEventProcessingLogin##',
                      '##MS_PolicyTsqlExecutionLogin##',
                      'NT SERVICE\SQLWriter', 'NT SERVICE\Winmgmt')
  AND sp.sid NOT IN (SELECT sid FROM db_users WHERE sid IS NOT NULL)
ORDER BY sp.create_date;

-- ---------------------------------------------------------------------------
-- Logins that own nothing (no database, no job, no endpoint)
-- ---------------------------------------------------------------------------
-- msdb is not present on Azure SQL Database; the Agent-job ownership
-- predicate is wrapped so the query degrades gracefully there.
BEGIN TRY
    SELECT
        sp.name                                       AS login_name,
        sp.type_desc,
        sp.is_disabled
    FROM sys.server_principals sp
    WHERE sp.type IN ('S','U','G')
      AND sp.name NOT IN ('sa')
      AND NOT EXISTS (SELECT 1 FROM sys.databases WHERE owner_sid = sp.sid)
      AND NOT EXISTS (SELECT 1 FROM sys.endpoints WHERE principal_id = sp.principal_id)
      AND NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE owner_sid = sp.sid)
    ORDER BY sp.name;
END TRY
BEGIN CATCH
    PRINT '[note] logins-owning-nothing query failed (msdb may be absent): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_principals
      WHERE is_disabled = 1 AND type IN ('S','U','G'))    AS disabled_logins,
    (SELECT COUNT(*) FROM sys.server_principals
      WHERE type IN ('S','U','G')
        AND modify_date < DATEADD(day, -180, SYSUTCDATETIME())) AS logins_unmodified_180d,
    (SELECT COUNT(*) FROM sys.server_principals sp
      WHERE sp.type = 'S'
        AND CAST(LOGINPROPERTY(sp.name, 'IsExpired') AS INT) = 1) AS expired_passwords;
