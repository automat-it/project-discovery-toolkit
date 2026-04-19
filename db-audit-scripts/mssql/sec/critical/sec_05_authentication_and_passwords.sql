-- =============================================================================
-- sec_05_authentication_and_passwords.sql
-- Priority: CRITICAL
-- Purpose: Inspect authentication configuration, password policy, and
--          accounts with weak / missing / expired credentials.
-- Sources: sys.sql_logins, sys.server_principals, sys.configurations,
--          SERVERPROPERTY('IsIntegratedSecurityOnly').
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Authentication mode (Mixed vs Windows-only)
-- ---------------------------------------------------------------------------
SELECT
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows Authentication only'
        WHEN 0 THEN 'Mixed Mode (Windows + SQL)'
        ELSE 'Unknown'
    END                                               AS authentication_mode,
    SERVERPROPERTY('Edition')                         AS edition,
    SERVERPROPERTY('ProductVersion')                  AS version;

-- ---------------------------------------------------------------------------
-- Password-policy configuration (server-level)
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('common criteria compliance enabled',
               'default language',
               'default full-text language',
               'remote login timeout (s)',
               'login audit level');

-- ---------------------------------------------------------------------------
-- SQL logins that do NOT enforce CHECK_POLICY / CHECK_EXPIRATION
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.is_disabled,
    sl.is_policy_checked                              AS check_policy,
    sl.is_expiration_checked                          AS check_expiration,
    sp.create_date,
    sp.modify_date
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND (sl.is_policy_checked = 0 OR sl.is_expiration_checked = 0)
ORDER BY sp.name;

-- ---------------------------------------------------------------------------
-- Accounts with expired passwords
-- ---------------------------------------------------------------------------
-- NOTE: is_expired and password_last_set_time are NOT columns of
-- sys.sql_logins — they are returned by LOGINPROPERTY().
SELECT
    sp.name                                           AS login_name,
    sp.is_disabled,
    LOGINPROPERTY(sp.name, 'IsExpired')               AS password_expired,
    sl.is_policy_checked,
    sl.is_expiration_checked,
    LOGINPROPERTY(sp.name, 'PasswordLastSetTime')     AS password_last_set_time,
    CASE WHEN sl.password_hash IS NULL THEN 1 ELSE 0 END AS password_hash_null
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND CAST(LOGINPROPERTY(sp.name, 'IsExpired') AS INT) = 1
ORDER BY sp.name;

-- ---------------------------------------------------------------------------
-- Accounts whose password has never been set or is older than 180 days
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.is_disabled,
    CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2) AS password_last_set_time,
    DATEDIFF(day,
             CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2),
             SYSUTCDATETIME())                        AS days_since_change,
    sl.is_policy_checked,
    sl.is_expiration_checked
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND (LOGINPROPERTY(sp.name, 'PasswordLastSetTime') IS NULL
       OR CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2)
          < DATEADD(day, -180, SYSUTCDATETIME()))
ORDER BY password_last_set_time;

-- ---------------------------------------------------------------------------
-- Accounts whose password equals the login name
-- (PWDCOMPARE requires VIEW ANY DEFINITION)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    'Password equals login name' AS finding
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND PWDCOMPARE(sp.name, sl.password_hash) = 1;

-- Common weak passwords (extend as needed)
DECLARE @weak TABLE (p NVARCHAR(128));
INSERT INTO @weak VALUES ('password'),('Password123!'),('admin'),('Admin123!'),
                         ('12345'),('abc123'),('letmein'),('welcome'),('changeme');

SELECT
    sp.name                                           AS login_name,
    w.p                                               AS weak_password_matched
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
CROSS JOIN @weak w
WHERE sp.type = 'S'
  AND PWDCOMPARE(w.p, sl.password_hash) = 1;

-- ---------------------------------------------------------------------------
-- Logins with password hash of length 0 (blank password — hash is still
-- set, but it hashes an empty string)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND PWDCOMPARE('', sl.password_hash) = 1;

-- ---------------------------------------------------------------------------
-- Disabled logins (not a finding, but useful inventory)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sp.type_desc,
    sp.create_date,
    sp.modify_date
FROM sys.server_principals sp
WHERE sp.is_disabled = 1
  AND sp.type IN ('S','U','G')
ORDER BY sp.name;

-- ---------------------------------------------------------------------------
-- Login audit level (must be 2 = failed and successful, or 3 = both w/ pwd)
-- for best forensic coverage. xp_instance_regread is sysadmin-only on
-- Windows and not available on SQL Server on Linux or Azure SQL — wrap
-- so the script keeps going with a [note] line on those platforms.
-- ---------------------------------------------------------------------------
BEGIN TRY
    EXEC xp_instance_regread
        N'HKEY_LOCAL_MACHINE',
        N'Software\Microsoft\MSSQLServer\MSSQLServer',
        N'AuditLevel';
END TRY
BEGIN CATCH
    PRINT '[note] xp_instance_regread unavailable or not permitted: '
          + ERROR_MESSAGE();
END CATCH;
