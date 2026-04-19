-- =============================================================================
-- sec_10_dangerous_objects.sql
-- Priority: HIGH
-- Purpose: Find code paths that can enable privilege escalation —
--          EXECUTE AS routines, CLR assemblies, DDL triggers, linked
--          server objects, Service Broker activation procedures.
-- Sources: sys.sql_modules, sys.procedures, sys.triggers,
--          sys.server_triggers, sys.assemblies, sys.servers,
--          sys.service_queues.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Stored procedures / functions declared WITH EXECUTE AS OWNER / SELF /
-- 'user' (runs with elevated context — classic escalation surface)
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(sm.object_id)                  AS schema_name,
    OBJECT_NAME(sm.object_id)                         AS object_name,
    o.type_desc                                       AS object_type,
    CASE sm.execute_as_principal_id
        WHEN -2 THEN 'CALLER'                          -- default
        WHEN -1 THEN 'OWNER'
        WHEN  0 THEN 'SELF'
        ELSE USER_NAME(sm.execute_as_principal_id)
    END                                               AS execute_as,
    sm.is_schema_bound,
    sm.uses_database_collation
FROM sys.sql_modules sm
JOIN sys.objects o ON o.object_id = sm.object_id
WHERE sm.execute_as_principal_id IS NOT NULL
  AND o.is_ms_shipped = 0
  AND sm.execute_as_principal_id <> -2                  -- exclude default CALLER
ORDER BY schema_name, object_name;

-- ---------------------------------------------------------------------------
-- CLR assemblies — particularly UNSAFE / EXTERNAL_ACCESS (can execute
-- OS code, read files, open sockets)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS assembly_name,
    permission_set_desc,
    is_visible,
    is_user_defined,
    create_date,
    modify_date
FROM sys.assemblies
WHERE is_user_defined = 1
ORDER BY permission_set_desc, name;

-- CLR enabled at the server level?
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name = 'clr enabled';

-- ---------------------------------------------------------------------------
-- DML triggers in the current database
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(t.parent_id)                   AS target_schema,
    OBJECT_NAME(t.parent_id)                          AS target_table,
    t.name                                            AS trigger_name,
    t.type_desc                                       AS trigger_class,
    t.is_disabled,
    t.is_instead_of_trigger,
    t.create_date,
    t.modify_date
FROM sys.triggers t
JOIN sys.objects o ON o.object_id = t.parent_id
WHERE o.is_ms_shipped = 0
  AND t.parent_class = 1                               -- object-level triggers
ORDER BY target_schema, target_table, trigger_name;

-- DDL triggers on the database (fires on CREATE / ALTER / DROP)
SELECT
    t.name                                            AS trigger_name,
    t.parent_class_desc,
    t.type_desc,
    t.is_disabled,
    t.create_date,
    t.modify_date
FROM sys.triggers t
WHERE t.parent_class = 0;

-- Server-level triggers
SELECT
    st.name                                           AS trigger_name,
    st.type_desc,
    st.is_disabled,
    st.create_date,
    st.modify_date
FROM sys.server_triggers st;

-- ---------------------------------------------------------------------------
-- xp_cmdshell / OLE Automation Procedures / Ad Hoc Distributed Queries
-- state — if any of these is ON, it should be a deliberate decision
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('xp_cmdshell',
               'Ole Automation Procedures',
               'Ad Hoc Distributed Queries',
               'cross db ownership chaining',
               'remote access',
               'external scripts enabled',
               'allow polybase export');

-- ---------------------------------------------------------------------------
-- Service Broker: queue activation procedures (run under privileged
-- context when queue messages arrive)
-- ---------------------------------------------------------------------------
SELECT
    q.name                                            AS queue_name,
    q.is_activation_enabled,
    q.activation_procedure                            AS activation_procedure_id,
    OBJECT_SCHEMA_NAME(q.activation_procedure)        AS proc_schema,
    OBJECT_NAME(q.activation_procedure)               AS proc_name,
    q.max_readers,
    q.execute_as_principal_id,
    USER_NAME(q.execute_as_principal_id)              AS execute_as,
    q.is_receive_enabled
FROM sys.service_queues q
WHERE q.is_ms_shipped = 0
  AND q.activation_procedure IS NOT NULL
ORDER BY q.name;

-- ---------------------------------------------------------------------------
-- Linked servers with data-access / RPC enabled (outbound arbitrary query)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS linked_server,
    provider,
    data_source,
    is_data_access_enabled,
    is_rpc_out_enabled,
    is_remote_login_enabled,
    modify_date
FROM sys.servers
WHERE is_linked = 1
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Functions and procedures that reference xp_ / sp_OA / xp_regread
-- (quick text scan — heuristic, may miss dynamic SQL).
--
-- LIMITATION: sys.sql_modules.definition is NULL for objects created
-- WITH ENCRYPTION. Encrypted procedures will not match these LIKE
-- patterns; inventory them separately via
--   SELECT OBJECT_SCHEMA_NAME(object_id), OBJECT_NAME(object_id)
--     FROM sys.sql_modules WHERE definition IS NULL;
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(sm.object_id)                  AS schema_name,
    OBJECT_NAME(sm.object_id)                         AS object_name,
    o.type_desc,
    CASE
        WHEN sm.definition LIKE '%xp_cmdshell%'     THEN 'xp_cmdshell'
        WHEN sm.definition LIKE '%sp_OACreate%'     THEN 'sp_OACreate'
        WHEN sm.definition LIKE '%xp_regread%'      THEN 'xp_regread'
        WHEN sm.definition LIKE '%OPENROWSET%'      THEN 'OPENROWSET'
        WHEN sm.definition LIKE '%OPENDATASOURCE%'  THEN 'OPENDATASOURCE'
        ELSE 'other'
    END                                               AS suspicious_pattern
FROM sys.sql_modules sm
JOIN sys.objects o ON o.object_id = sm.object_id
WHERE o.is_ms_shipped = 0
  AND (sm.definition LIKE '%xp_cmdshell%'
    OR sm.definition LIKE '%sp_OACreate%'
    OR sm.definition LIKE '%xp_regread%'
    OR sm.definition LIKE '%OPENROWSET%'
    OR sm.definition LIKE '%OPENDATASOURCE%')
ORDER BY schema_name, object_name;

-- ---------------------------------------------------------------------------
-- Credentials visible at the server (used by SQLAgent / CLR / linked srv)
-- ---------------------------------------------------------------------------
SELECT
    c.name                                            AS credential_name,
    c.credential_identity,
    c.create_date,
    c.modify_date
FROM sys.credentials c
ORDER BY c.name;
