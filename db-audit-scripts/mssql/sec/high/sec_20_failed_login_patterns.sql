-- =============================================================================
-- sec_20_failed_login_patterns.sql
-- Priority: HIGH
-- Purpose: Detect brute-force / credential-stuffing patterns. SQL Server
--          records failed logins in the ERRORLOG (parseable via
--          xp_readerrorlog) and in Server Audit if configured.
-- Sources: xp_readerrorlog, sys.server_audits, sys.dm_server_audit_status,
--          sys.sql_logins (LOGINPROPERTY), sys.dm_exec_sessions.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Login-audit configuration — is SQL Server set to log failed / successful
-- logins at all?
-- Registry read requires VIEW SERVER STATE + xp_instance_regread; wrapped
-- in TRY/CATCH so restricted audit roles still get the rest of the script.
-- ---------------------------------------------------------------------------
BEGIN TRY
    DECLARE @AuditLevel INT;
    EXEC xp_instance_regread
        N'HKEY_LOCAL_MACHINE',
        N'Software\Microsoft\MSSQLServer\MSSQLServer',
        N'AuditLevel',
        @AuditLevel OUTPUT;

    SELECT
        @AuditLevel AS audit_level_raw,
        CASE @AuditLevel
            WHEN 0 THEN 'None'
            WHEN 1 THEN 'Successful logins only'
            WHEN 2 THEN 'Failed logins only'
            WHEN 3 THEN 'Both successful and failed'
            ELSE 'Unknown'
        END        AS login_audit_setting;
END TRY
BEGIN CATCH
    PRINT '[note] AuditLevel registry read failed (Azure SQL DB or restricted account): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Server audits currently capturing FAILED_LOGIN_GROUP / LOGIN_CHANGE events
-- ---------------------------------------------------------------------------
SELECT
    sa.name                               AS audit_name,
    sa.type_desc,
    sas.status_desc,
    sa.create_date
FROM sys.server_audits sa
LEFT JOIN sys.dm_server_audit_status sas ON sas.audit_id = sa.audit_id
ORDER BY sa.name;

SELECT
    sas.name                              AS spec_name,
    sasd.audit_action_name,
    sas.is_state_enabled
FROM sys.server_audit_specifications sas
JOIN sys.server_audit_specification_details sasd
      ON sasd.server_specification_id = sas.server_specification_id
WHERE sasd.audit_action_name LIKE '%LOGIN%'
   OR sasd.audit_action_name LIKE '%PRINCIPAL%'
ORDER BY sas.name, sasd.audit_action_name;

-- ---------------------------------------------------------------------------
-- Parse current ERRORLOG for "Login failed" entries
-- xp_readerrorlog signature:
--   log#, log_type(1=errorlog 2=SQLAgent), search1, search2, datetime_start,
--   datetime_end, order ('DESC'/'ASC')  -- order arg only on 2012 SP1+/2017+.
-- We fall back to the 6-arg form for older builds.
-- ---------------------------------------------------------------------------
DECLARE @el TABLE (LogDate DATETIME, ProcessInfo NVARCHAR(100), Text NVARCHAR(MAX));

BEGIN TRY
    INSERT INTO @el
    EXEC sys.xp_readerrorlog 0, 1, N'Login failed', NULL, NULL, NULL, N'DESC';
END TRY
BEGIN CATCH
    BEGIN TRY
        INSERT INTO @el
        EXEC sys.xp_readerrorlog 0, 1, N'Login failed';
    END TRY
    BEGIN CATCH
        PRINT '[note] xp_readerrorlog failed: ' + ERROR_MESSAGE();
    END CATCH
END CATCH;

-- Most recent 100 raw failed-login lines
SELECT TOP 100
    LogDate, ProcessInfo, Text
FROM @el
ORDER BY LogDate DESC;

-- Aggregate: count per (login, client IP, reason)
SELECT
    attempts,
    login_name,
    client_ip,
    reason,
    first_seen,
    last_seen
FROM (
    SELECT
        COUNT(*)           AS attempts,
        MIN(LogDate)       AS first_seen,
        MAX(LogDate)       AS last_seen,
        -- Extract user between "for user '" and next "'"
        LTRIM(RTRIM(SUBSTRING(
            Text,
            CHARINDEX('for user ''', Text) + 10,
            CASE
              WHEN CHARINDEX('for user ''', Text) = 0 THEN 0
              ELSE CHARINDEX('''', Text, CHARINDEX('for user ''', Text) + 10)
                   - (CHARINDEX('for user ''', Text) + 10)
            END
        )))                 AS login_name,
        -- Extract IP after "CLIENT: "
        LTRIM(RTRIM(SUBSTRING(
            Text,
            CHARINDEX('CLIENT: ', Text) + 8,
            CASE WHEN CHARINDEX('CLIENT: ', Text) = 0 THEN 0 ELSE 64 END
        )))                 AS client_ip,
        -- Extract reason fragment
        LEFT(
            SUBSTRING(Text,
                      CHARINDEX('Reason:', Text),
                      CASE WHEN CHARINDEX('Reason:', Text) = 0 THEN 0 ELSE 120 END),
            120)            AS reason
    FROM @el
    GROUP BY
        LTRIM(RTRIM(SUBSTRING(
            Text,
            CHARINDEX('for user ''', Text) + 10,
            CASE
              WHEN CHARINDEX('for user ''', Text) = 0 THEN 0
              ELSE CHARINDEX('''', Text, CHARINDEX('for user ''', Text) + 10)
                   - (CHARINDEX('for user ''', Text) + 10)
            END))),
        LTRIM(RTRIM(SUBSTRING(
            Text,
            CHARINDEX('CLIENT: ', Text) + 8,
            CASE WHEN CHARINDEX('CLIENT: ', Text) = 0 THEN 0 ELSE 64 END))),
        LEFT(
            SUBSTRING(Text,
                      CHARINDEX('Reason:', Text),
                      CASE WHEN CHARINDEX('Reason:', Text) = 0 THEN 0 ELSE 120 END),
            120)
) agg
WHERE attempts > 1
ORDER BY attempts DESC;

-- ---------------------------------------------------------------------------
-- Account lockout state per SQL login (LOGINPROPERTY surfaces
-- IsLocked / BadPasswordCount / BadPasswordTime / HistoryLength).
-- Only meaningful for SQL logins on Windows-aware SQL Server; Azure SQL
-- returns NULL for most of these properties — still safe to call.
-- ---------------------------------------------------------------------------
SELECT
    sl.name                                   AS login_name,
    sl.is_disabled,
    CAST(LOGINPROPERTY(sl.name, 'IsLocked')           AS INT) AS is_locked,
    CAST(LOGINPROPERTY(sl.name, 'IsExpired')          AS INT) AS is_expired,
    CAST(LOGINPROPERTY(sl.name, 'IsMustChange')       AS INT) AS must_change,
    CAST(LOGINPROPERTY(sl.name, 'BadPasswordCount')   AS INT) AS bad_password_count,
    CAST(LOGINPROPERTY(sl.name, 'BadPasswordTime')    AS DATETIME) AS bad_password_time,
    CAST(LOGINPROPERTY(sl.name, 'LockoutTime')        AS DATETIME) AS lockout_time,
    sl.is_policy_checked,
    sl.is_expiration_checked
FROM sys.sql_logins sl
ORDER BY bad_password_count DESC, login_name;

-- ---------------------------------------------------------------------------
-- Currently-connected sessions grouped by client IP
-- ---------------------------------------------------------------------------
SELECT
    c.client_net_address                       AS client_ip,
    COUNT(*)                                   AS active_sessions,
    COUNT(DISTINCT s.login_name)               AS distinct_logins
FROM sys.dm_exec_sessions s
JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
WHERE s.is_user_process = 1
GROUP BY c.client_net_address
ORDER BY active_sessions DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM @el)                                 AS failed_login_lines_in_errorlog,
    (SELECT COUNT(*) FROM sys.server_audits)                   AS server_audits_configured,
    (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status = 1) AS server_audits_running,
    (SELECT COUNT(*) FROM sys.sql_logins
      WHERE CAST(LOGINPROPERTY(name,'IsLocked') AS INT) = 1)   AS currently_locked_logins;
