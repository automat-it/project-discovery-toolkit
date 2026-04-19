-- =============================================================================
-- sec_06_audit_logging.sql
-- Priority: HIGH
-- Purpose: Verify audit logging is enabled and configured. Without
--          traceability there is no incident response.
-- Sources: sys.server_audits, sys.server_audit_specifications,
--          sys.database_audit_specifications, sys.traces,
--          sys.dm_server_audit_status.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Server Audits defined on the instance
-- ---------------------------------------------------------------------------
-- max_rollover_files / max_size live on sys.server_file_audits, not
-- sys.server_audits — LEFT JOIN so non-file destinations (application log,
-- security log) still appear with NULL rollover / size.
SELECT
    sa.name                                           AS audit_name,
    sa.audit_guid,
    sa.create_date,
    sa.modify_date,
    sa.type_desc                                      AS destination,
    sa.on_failure_desc                                AS on_failure,
    sa.queue_delay,
    sfa.max_rollover_files,
    sfa.max_files,
    sfa.max_file_size,
    sfa.log_file_path
FROM sys.server_audits sa
LEFT JOIN sys.server_file_audits sfa ON sfa.audit_guid = sa.audit_guid
ORDER BY sa.name;

-- ---------------------------------------------------------------------------
-- Current runtime status of each Server Audit
-- ---------------------------------------------------------------------------
-- dm_server_audit_status surfaces runtime status; queue_delay is a
-- static configuration property on sys.server_audits (joined here).
SELECT
    s.audit_id,
    s.name                                            AS audit_name,
    s.status_desc,
    s.status_time,
    sa.queue_delay,
    s.audit_file_path,
    s.audit_file_size,
    CASE WHEN s.event_session_address IS NOT NULL
         THEN 1 ELSE 0 END                             AS is_event_session_bound
FROM sys.dm_server_audit_status s
LEFT JOIN sys.server_audits sa ON sa.audit_id = s.audit_id;

-- ---------------------------------------------------------------------------
-- Server Audit Specifications (what events are captured server-wide)
-- ---------------------------------------------------------------------------
SELECT
    sas.name                                          AS spec_name,
    sa.name                                           AS target_audit,
    sas.is_state_enabled,
    sasd.audit_action_name,
    sasd.is_group
FROM sys.server_audit_specifications sas
JOIN sys.server_audits sa
      ON sa.audit_guid = sas.audit_guid
LEFT JOIN sys.server_audit_specification_details sasd
      ON sasd.server_specification_id = sas.server_specification_id
ORDER BY sas.name, sasd.audit_action_name;

-- ---------------------------------------------------------------------------
-- Database Audit Specifications (current database)
-- ---------------------------------------------------------------------------
SELECT
    das.name                                          AS spec_name,
    sa.name                                           AS target_audit,
    das.is_state_enabled,
    dasd.audit_action_name,
    dasd.is_group,
    dasd.class_desc,
    CASE dasd.class
        WHEN 0 THEN DB_NAME()
        WHEN 1 THEN OBJECT_SCHEMA_NAME(dasd.major_id) + '.' + OBJECT_NAME(dasd.major_id)
        WHEN 3 THEN SCHEMA_NAME(dasd.major_id)
        ELSE CAST(dasd.class_desc AS NVARCHAR(50))
    END                                               AS object_name,
    USER_NAME(dasd.audited_principal_id)              AS audited_principal
FROM sys.database_audit_specifications das
JOIN sys.server_audits sa
      ON sa.audit_guid = das.audit_guid
LEFT JOIN sys.database_audit_specification_details dasd
      ON dasd.database_specification_id = das.database_specification_id
ORDER BY das.name, dasd.audit_action_name;

-- ---------------------------------------------------------------------------
-- Default trace status (a lightweight built-in audit for key events)
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'default trace enabled';

SELECT
    id                                                AS trace_id,
    status,
    path,
    max_size,
    max_files,
    start_time,
    last_event_time,
    event_count,
    dropped_event_count
FROM sys.traces;

-- ---------------------------------------------------------------------------
-- Extended Events sessions currently running
-- ---------------------------------------------------------------------------
SELECT
    xs.name                                           AS session_name,
    xs.create_time,
    COUNT(DISTINCT xe.event_name)                     AS event_count
FROM sys.dm_xe_sessions xs
LEFT JOIN sys.dm_xe_session_events xe ON xe.event_session_address = xs.address
GROUP BY xs.name, xs.create_time
ORDER BY session_name;

-- ---------------------------------------------------------------------------
-- SQL Server error log (last 24h, error-level entries only).
-- NOTE: the 7th parameter (sortOrder 'DESC') requires SQL Server
-- 2017 CU10+ or 2019+. On older builds we fall back to the 6-parameter
-- form via a second TRY. xp_readerrorlog is sysadmin-only in every
-- release and is not available on Azure SQL Database.
-- ---------------------------------------------------------------------------
BEGIN TRY
    EXEC xp_readerrorlog 0, 1, NULL, NULL,
                         NULL, NULL, 'DESC';
END TRY
BEGIN CATCH
    BEGIN TRY
        EXEC xp_readerrorlog 0, 1, NULL, NULL, NULL, NULL;
    END TRY
    BEGIN CATCH
        PRINT '[note] xp_readerrorlog unavailable or not permitted: '
              + ERROR_MESSAGE();
    END CATCH;
END CATCH;

-- ---------------------------------------------------------------------------
-- Audit readiness summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_audits)          AS server_audits_defined,
    (SELECT COUNT(*) FROM sys.dm_server_audit_status
      WHERE status_desc = 'STARTED')                  AS server_audits_running,
    (SELECT COUNT(*) FROM sys.server_audit_specifications
      WHERE is_state_enabled = 1)                     AS server_specs_enabled,
    (SELECT COUNT(*) FROM sys.database_audit_specifications
      WHERE is_state_enabled = 1)                     AS db_specs_enabled,
    (SELECT COUNT(*) FROM sys.dm_xe_sessions)         AS xe_sessions_running,
    (SELECT value_in_use FROM sys.configurations
      WHERE name = 'default trace enabled')           AS default_trace_enabled;
