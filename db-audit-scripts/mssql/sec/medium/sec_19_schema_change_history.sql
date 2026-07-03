-- =============================================================================
-- sec_19_schema_change_history.sql
-- Priority: MEDIUM
-- Purpose: Surface evidence of DDL / schema-change activity. SQL Server
--          exposes object modify_date directly, and records DDL events
--          in the default trace (short-term) plus any configured Server
--          Audit / Extended Event sessions.
-- Sources: sys.objects, sys.triggers (DDL triggers), sys.traces,
--          sys.server_audits, sys.database_audit_specifications,
--          sys.dm_xe_sessions, sys.fn_trace_gettable.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Server- and database-scoped DDL triggers
-- ---------------------------------------------------------------------------
-- COLLATE DATABASE_DEFAULT on every string column so the UNION ALL works
-- when the server collation differs from the database collation (common
-- on databases created with a non-default collation, e.g. Hebrew_CI_AS).
SELECT
    CAST('server' AS NVARCHAR(20)) COLLATE DATABASE_DEFAULT AS scope,
    CAST(name      AS NVARCHAR(128)) COLLATE DATABASE_DEFAULT AS trigger_name,
    CAST(type_desc AS NVARCHAR(60))  COLLATE DATABASE_DEFAULT AS type_desc,
    is_disabled,
    create_date,
    modify_date
FROM sys.server_triggers
UNION ALL
SELECT
    CAST('database' AS NVARCHAR(20)) COLLATE DATABASE_DEFAULT AS scope,
    CAST(name       AS NVARCHAR(128)) COLLATE DATABASE_DEFAULT AS trigger_name,
    CAST(type_desc  AS NVARCHAR(60))  COLLATE DATABASE_DEFAULT AS type_desc,
    is_disabled,
    create_date,
    modify_date
FROM sys.triggers
WHERE parent_class_desc = 'DATABASE'
ORDER BY scope, trigger_name;

-- ---------------------------------------------------------------------------
-- Server audit status (persistent DDL trail when configured to capture
-- SCHEMA_OBJECT_CHANGE_GROUP / DATABASE_OBJECT_CHANGE_GROUP)
-- ---------------------------------------------------------------------------
SELECT
    sa.name                                  AS audit_name,
    sa.type_desc                             AS audit_type,
    sas.status_desc                          AS status,
    sas.audit_file_path
FROM sys.server_audits sa
LEFT JOIN sys.dm_server_audit_status sas ON sas.audit_id = sa.audit_id
ORDER BY sa.name;

SELECT
    sasd.audit_action_id,
    sasd.audit_action_name,
    sas.name                                 AS specification,
    sas.is_state_enabled
FROM sys.server_audit_specifications sas
JOIN sys.server_audit_specification_details sasd
      ON sasd.server_specification_id = sas.server_specification_id
WHERE sasd.audit_action_name LIKE '%OBJECT_CHANGE%'
   OR sasd.audit_action_name LIKE '%SCHEMA%'
   OR sasd.audit_action_name LIKE '%DDL%'
ORDER BY sas.name, sasd.audit_action_name;

SELECT
    das.name                                 AS db_audit_spec,
    dasd.audit_action_name,
    das.is_state_enabled
FROM sys.database_audit_specifications das
JOIN sys.database_audit_specification_details dasd
      ON dasd.database_specification_id = das.database_specification_id
WHERE dasd.audit_action_name LIKE '%OBJECT_CHANGE%'
   OR dasd.audit_action_name LIKE '%SCHEMA%'
ORDER BY das.name, dasd.audit_action_name;

-- ---------------------------------------------------------------------------
-- Default trace — SQL Server keeps a rolling 5-file trace of DDL by default
-- (trace id 1). Read the latest file when available.
-- ---------------------------------------------------------------------------
BEGIN TRY
    DECLARE @trace_path NVARCHAR(400);
    SELECT @trace_path = CAST(value AS NVARCHAR(400))
      FROM sys.fn_trace_getinfo(1)
     WHERE property = 2;

    IF @trace_path IS NOT NULL
    BEGIN
        SELECT TOP 100
            t.EventClass,
            te.name                          AS event_name,
            t.StartTime,
            t.LoginName,
            t.HostName,
            t.ApplicationName,
            t.DatabaseName,
            t.ObjectName,
            t.TextData
        FROM sys.fn_trace_gettable(@trace_path, DEFAULT) t
        JOIN sys.trace_events te ON te.trace_event_id = t.EventClass
        WHERE te.name IN ('Object:Created','Object:Deleted','Object:Altered',
                          'Audit Schema Object Management Event',
                          'Audit Database Management Event',
                          'Audit Server Alter Trace Event')
        ORDER BY t.StartTime DESC;
    END
END TRY
BEGIN CATCH
    PRINT '[note] default trace inspection failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Recently created / modified objects in the current database
-- ---------------------------------------------------------------------------
SELECT TOP 100
    SCHEMA_NAME(o.schema_id)                  AS schema_name,
    o.name                                    AS object_name,
    o.type_desc                               AS object_type,
    o.create_date,
    o.modify_date,
    CASE WHEN o.modify_date > o.create_date THEN 'altered' ELSE 'created' END AS last_change
FROM sys.objects o
WHERE o.is_ms_shipped = 0
  AND (o.create_date > DATEADD(day, -90, SYSDATETIME())
    OR o.modify_date > DATEADD(day, -90, SYSDATETIME()))
ORDER BY o.modify_date DESC;

-- ---------------------------------------------------------------------------
-- Recently created logins / users (DDL on principals)
-- ---------------------------------------------------------------------------
-- COLLATE DATABASE_DEFAULT on the sysname columns so the UNION ALL is
-- collation-safe across server vs database collation differences.
SELECT
    CAST('server_principal' AS NVARCHAR(20)) COLLATE DATABASE_DEFAULT AS scope,
    CAST(name      AS NVARCHAR(128)) COLLATE DATABASE_DEFAULT AS name,
    CAST(type_desc AS NVARCHAR(60))  COLLATE DATABASE_DEFAULT AS type_desc,
    create_date, modify_date, is_disabled
FROM sys.server_principals
WHERE create_date > DATEADD(day, -90, SYSDATETIME())
   OR modify_date > DATEADD(day, -90, SYSDATETIME())
UNION ALL
SELECT
    CAST('database_principal' AS NVARCHAR(20)) COLLATE DATABASE_DEFAULT AS scope,
    CAST(name      AS NVARCHAR(128)) COLLATE DATABASE_DEFAULT AS name,
    CAST(type_desc AS NVARCHAR(60))  COLLATE DATABASE_DEFAULT AS type_desc,
    create_date, modify_date, CAST(NULL AS BIT)
FROM sys.database_principals
WHERE create_date > DATEADD(day, -90, SYSDATETIME())
   OR modify_date > DATEADD(day, -90, SYSDATETIME())
ORDER BY scope, modify_date DESC;

-- ---------------------------------------------------------------------------
-- Extended Event sessions that could capture DDL (object_altered,
-- object_created, object_deleted)
-- ---------------------------------------------------------------------------
SELECT
    s.name                   AS session_name,
    s.startup_state,
    CASE WHEN xs.name IS NOT NULL THEN 'running' ELSE 'stopped' END AS runtime_status,
    e.name                   AS event_captured
FROM sys.server_event_sessions s
JOIN sys.server_event_session_events e ON e.event_session_id = s.event_session_id
LEFT JOIN sys.dm_xe_sessions xs ON xs.name = s.name
WHERE e.name IN ('object_altered','object_created','object_deleted',
                 'sql_statement_completed','ddl_phase')
ORDER BY s.name, e.name;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.server_triggers)                         AS server_ddl_triggers,
    (SELECT COUNT(*) FROM sys.triggers WHERE parent_class_desc='DATABASE') AS db_ddl_triggers,
    (SELECT COUNT(*) FROM sys.server_audits)                           AS server_audits_configured,
    (SELECT COUNT(*) FROM sys.server_audit_specifications
       WHERE is_state_enabled = 1)                                     AS server_audit_specs_enabled,
    (SELECT COUNT(*) FROM sys.dm_xe_sessions)                          AS xe_sessions_running,
    CASE
      WHEN EXISTS(SELECT 1 FROM sys.dm_server_audit_status WHERE status = 1)
        THEN 'Server Audit active — DDL trail present'
      WHEN EXISTS(SELECT 1 FROM sys.server_triggers)
        THEN 'DDL triggers only — coverage limited to trigger definitions'
      ELSE 'Default trace only (short retention) — consider Server Audit or XE'
    END                                                                 AS assessment;
