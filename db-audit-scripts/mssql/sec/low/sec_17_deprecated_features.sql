-- =============================================================================
-- sec_17_deprecated_features.sql
-- Priority: LOW
-- Purpose: Surface deprecated authentication mechanisms, legacy server
--          options, old compatibility levels, and any active use of
--          deprecated features.
-- Sources: sys.configurations, sys.databases, sys.sql_logins,
--          sys.dm_os_performance_counters (deprecated feature counters).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Databases still on an old compatibility level
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS database_name,
    compatibility_level,
    CASE
        WHEN compatibility_level < 130 THEN 'OLD (pre-SQL 2016)'
        WHEN compatibility_level < 140 THEN 'SQL 2016'
        WHEN compatibility_level < 150 THEN 'SQL 2017'
        WHEN compatibility_level < 160 THEN 'SQL 2019'
        ELSE 'SQL 2022+'
    END                                               AS compat_band,
    create_date,
    recovery_model_desc
FROM sys.databases
WHERE database_id > 4
ORDER BY compatibility_level, name;

-- ---------------------------------------------------------------------------
-- Use of deprecated features (since last restart)
-- ---------------------------------------------------------------------------
SELECT
    instance_name                                     AS feature_name,
    cntr_value                                        AS usage_count
FROM sys.dm_os_performance_counters
WHERE object_name LIKE '%:Deprecated Features'
  AND cntr_value > 0
ORDER BY cntr_value DESC;

-- ---------------------------------------------------------------------------
-- Mixed Mode authentication status (if Windows-only, disregard SQL login
-- findings — they cannot connect anyway)
-- ---------------------------------------------------------------------------
SELECT
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'Windows only'
        WHEN 0 THEN 'Mixed Mode'
        ELSE 'Unknown'
    END                                               AS authentication_mode;

-- ---------------------------------------------------------------------------
-- SQL logins with CHECK_POLICY OFF or CHECK_EXPIRATION OFF
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS login_name,
    sl.is_policy_checked                              AS check_policy,
    sl.is_expiration_checked                          AS check_expiration,
    CAST(LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS DATETIME2) AS password_last_set_time,
    sp.is_disabled
FROM sys.server_principals sp
JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id
WHERE sp.type = 'S'
  AND (sl.is_policy_checked = 0 OR sl.is_expiration_checked = 0)
ORDER BY sp.name;

-- ---------------------------------------------------------------------------
-- Legacy server options (should be OFF on modern installations)
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN (
    'cross db ownership chaining',
    'remote access',
    'server trigger recursion',
    'xp_cmdshell',
    'Ole Automation Procedures',
    'Ad Hoc Distributed Queries',
    'allow updates',                                   -- removed in 2005+; kept for audit
    'SQL Mail XPs',
    'Web Assistant Procedures',
    'remote proc trans');

-- ---------------------------------------------------------------------------
-- TDS / TLS version configuration (cipher surface)
-- ---------------------------------------------------------------------------
BEGIN TRY
    EXEC xp_instance_regread
        N'HKEY_LOCAL_MACHINE',
        N'SOFTWARE\Microsoft\MSSQLServer\SuperSocketNetLib',
        N'ExtendedProtection';
END TRY
BEGIN CATCH
    PRINT '[note] TLS registry read unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Deprecated data types in use
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(c.object_id)                   AS schema_name,
    OBJECT_NAME(c.object_id)                          AS object_name,
    c.name                                            AS column_name,
    TYPE_NAME(c.user_type_id)                         AS data_type,
    c.max_length
FROM sys.columns c
JOIN sys.objects o ON o.object_id = c.object_id
WHERE o.type IN ('U','V')
  AND o.is_ms_shipped = 0
  AND TYPE_NAME(c.user_type_id) IN ('text','ntext','image','timestamp')
ORDER BY schema_name, object_name, column_name;

-- ---------------------------------------------------------------------------
-- Database Mail / SQL Mail — legacy alerting stack
-- ---------------------------------------------------------------------------
BEGIN TRY
    IF DB_ID('msdb') IS NOT NULL
    BEGIN
        SELECT
            profile_id, name, description
        FROM msdb.dbo.sysmail_profile;
    END;
END TRY
BEGIN CATCH
    PRINT '[note] msdb.dbo.sysmail_profile unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.databases WHERE compatibility_level < 150
       AND database_id > 4)                           AS databases_pre_2017,
    (SELECT COUNT(*) FROM sys.sql_logins
      WHERE is_policy_checked = 0)                    AS logins_policy_off,
    (SELECT COUNT(*) FROM sys.sql_logins
      WHERE is_expiration_checked = 0)                AS logins_expiration_off,
    (SELECT COUNT(*) FROM sys.columns c
       JOIN sys.objects o ON o.object_id = c.object_id
      WHERE TYPE_NAME(c.user_type_id) IN ('text','ntext','image')
        AND o.is_ms_shipped = 0)                      AS legacy_typed_columns;
