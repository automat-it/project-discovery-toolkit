-- =============================================================================
-- sec_18_audit_gaps.sql
-- Priority: LOW
-- Purpose: Identify gaps in audit coverage — what is NOT being logged
--          that probably should be.
-- Sources: sys.server_audits, sys.server_audit_specifications,
--          sys.database_audit_specifications, sys.configurations,
--          sys.databases (Query Store).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Is a Server Audit running at all?
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_audits)          AS audits_defined,
    (SELECT COUNT(*) FROM sys.dm_server_audit_status
      WHERE status_desc = 'STARTED')                  AS audits_running,
    CASE
        WHEN (SELECT COUNT(*) FROM sys.dm_server_audit_status
               WHERE status_desc = 'STARTED') > 0 THEN 'OK'
        ELSE 'GAP: no server audit is capturing events'
    END                                               AS finding;

-- ---------------------------------------------------------------------------
-- Which of the standard, high-value audit action groups are covered?
-- ---------------------------------------------------------------------------
;WITH expected AS (
    SELECT 'FAILED_LOGIN_GROUP'                 AS group_name UNION ALL
    SELECT 'SUCCESSFUL_LOGIN_GROUP'             UNION ALL
    SELECT 'SERVER_ROLE_MEMBER_CHANGE_GROUP'    UNION ALL
    SELECT 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'  UNION ALL
    SELECT 'SERVER_PERMISSION_CHANGE_GROUP'     UNION ALL
    SELECT 'DATABASE_PERMISSION_CHANGE_GROUP'   UNION ALL
    SELECT 'SERVER_PRINCIPAL_CHANGE_GROUP'      UNION ALL
    SELECT 'DATABASE_PRINCIPAL_CHANGE_GROUP'    UNION ALL
    SELECT 'SCHEMA_OBJECT_CHANGE_GROUP'         UNION ALL
    SELECT 'DATABASE_OBJECT_CHANGE_GROUP'       UNION ALL
    SELECT 'AUDIT_CHANGE_GROUP'
)
SELECT
    e.group_name                                      AS audit_group,
    CASE
        WHEN EXISTS (
            SELECT 1 FROM sys.server_audit_specification_details sasd
             WHERE sasd.audit_action_name = e.group_name
               AND sasd.is_group = 1
        )
        OR EXISTS (
            SELECT 1 FROM sys.database_audit_specification_details dasd
             WHERE dasd.audit_action_name = e.group_name
               AND dasd.is_group = 1
        )
        THEN 'covered'
        ELSE 'GAP'
    END                                               AS status
FROM expected e
ORDER BY e.group_name;

-- ---------------------------------------------------------------------------
-- Query Store coverage per database (needed for perf_01, perf_16 forensics)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS database_name,
    is_query_store_on,
    CASE WHEN is_query_store_on = 0 AND database_id > 4
         THEN 'GAP: Query Store disabled'
         ELSE 'OK'
    END                                               AS finding
FROM sys.databases
WHERE database_id > 4
ORDER BY name;

-- ---------------------------------------------------------------------------
-- CDC / Change Tracking coverage — for databases that should have it
-- ---------------------------------------------------------------------------
SELECT
    d.name                                            AS database_name,
    d.is_cdc_enabled,
    CASE WHEN ct.database_id IS NOT NULL
         THEN 1 ELSE 0 END                             AS has_change_tracking,
    ct.retention_period,
    ct.retention_period_units_desc
FROM sys.databases d
LEFT JOIN sys.change_tracking_databases ct ON ct.database_id = d.database_id
WHERE d.database_id > 4
ORDER BY d.name;

-- ---------------------------------------------------------------------------
-- Logging-related configuration switches
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('default trace enabled',
               'blocked process threshold (s)',
               'common criteria compliance enabled',
               'login audit level');

-- ---------------------------------------------------------------------------
-- Extended Events session coverage
-- ---------------------------------------------------------------------------
SELECT
    xs.name                                           AS session_name,
    xs.create_time,
    xs.pending_buffers,
    COUNT(DISTINCT xe.event_name)                     AS events_captured
FROM sys.dm_xe_sessions xs
LEFT JOIN sys.dm_xe_session_events xe ON xe.event_session_address = xs.address
GROUP BY xs.name, xs.create_time, xs.pending_buffers
ORDER BY session_name;

-- ---------------------------------------------------------------------------
-- Agent job-outcome logging — failing jobs unnoticed?
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT TOP 25
        j.name                                        AS job_name,
        j.enabled,
        jh.run_date,
        jh.run_time,
        jh.run_duration,
        CASE jh.run_status
            WHEN 0 THEN 'Failed'
            WHEN 1 THEN 'Succeeded'
            WHEN 2 THEN 'Retry'
            WHEN 3 THEN 'Canceled'
            WHEN 4 THEN 'In progress'
        END                                           AS outcome,
        jh.message
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobhistory jh ON jh.job_id = j.job_id AND jh.step_id = 0
    WHERE j.enabled = 1
      AND jh.run_status = 0
    ORDER BY jh.run_date DESC, jh.run_time DESC;
END TRY
BEGIN CATCH
    PRINT '[note] msdb job history unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.dm_server_audit_status WHERE status_desc = 'STARTED') AS audits_running,
    (SELECT COUNT(*) FROM sys.database_audit_specifications WHERE is_state_enabled = 1) AS db_audit_specs_enabled,
    (SELECT COUNT(*) FROM sys.databases WHERE is_query_store_on = 1 AND database_id > 4) AS databases_with_query_store,
    (SELECT COUNT(*) FROM sys.dm_xe_sessions) AS xe_sessions_running;
