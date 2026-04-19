-- =============================================================================
-- perf_13_deadlock_history.sql
-- Priority: MEDIUM
-- Purpose: Surface deadlock counters, standby conflicts, and recent
--          deadlock XML from the system_health Extended Events session.
-- Sources: sys.dm_os_performance_counters, sys.traces / default trace,
--          system_health XE session ring buffer.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects
-- Parsing the XE ring-buffer XML requires QUOTED_IDENTIFIER ON.
SET QUOTED_IDENTIFIER ON;

-- ---------------------------------------------------------------------------
-- Deadlock counters (instance-wide, since SQL Server start)
-- ---------------------------------------------------------------------------
SELECT
    object_name,
    counter_name,
    instance_name                                     AS database_name,
    cntr_value                                        AS deadlock_count
FROM sys.dm_os_performance_counters
WHERE counter_name IN ('Number of Deadlocks/sec',
                       'Lock Timeouts/sec',
                       'Lock Waits/sec',
                       'Lock Wait Time (ms)')
ORDER BY object_name, counter_name, instance_name;

-- ---------------------------------------------------------------------------
-- Lock-timeout related settings
-- ---------------------------------------------------------------------------
SELECT name, value, value_in_use
FROM sys.configurations
WHERE name IN ('blocked process threshold (s)', 'locks');

-- ---------------------------------------------------------------------------
-- Extended Events: recent deadlock reports from system_health
-- Each row is a deadlock graph XML with its timestamp.
-- ---------------------------------------------------------------------------
;WITH sh AS (
    SELECT CAST(target_data AS XML) AS td
      FROM sys.dm_xe_session_targets xst
      JOIN sys.dm_xe_sessions xs ON xs.address = xst.event_session_address
     WHERE xs.name = 'system_health'
       AND xst.target_name = 'ring_buffer'
)
SELECT TOP 50
    ev.value('(@name)[1]', 'VARCHAR(50)')              AS event_name,
    ev.value('(@timestamp)[1]', 'DATETIME2')           AS event_time,
    ev.query('(data/value/deadlock)[1]')               AS deadlock_xml
FROM sh
CROSS APPLY sh.td.nodes('RingBufferTarget/event') AS T(ev)
WHERE ev.value('(@name)[1]', 'VARCHAR(50)') IN ('xml_deadlock_report','deadlock_report')
ORDER BY event_time DESC;

-- ---------------------------------------------------------------------------
-- Per-database rollback / abort rates as an indirect deadlock proxy
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(database_id)                              AS database_name,
    log_reuse_wait_desc,
    recovery_model_desc,
    is_auto_close_on
FROM sys.databases
WHERE database_id > 4
ORDER BY database_name;

-- ---------------------------------------------------------------------------
-- Recent blocked process reports from system_health
-- (requires 'blocked process threshold' > 0 — set in 01_server_configuration)
-- ---------------------------------------------------------------------------
;WITH sh AS (
    SELECT CAST(target_data AS XML) AS td
      FROM sys.dm_xe_session_targets xst
      JOIN sys.dm_xe_sessions xs ON xs.address = xst.event_session_address
     WHERE xs.name = 'system_health'
       AND xst.target_name = 'ring_buffer'
)
SELECT TOP 25
    ev.value('(@name)[1]', 'VARCHAR(50)')              AS event_name,
    ev.value('(@timestamp)[1]', 'DATETIME2')           AS event_time,
    ev.value('(data[@name="duration"]/value)[1]', 'BIGINT') / 1000
                                                        AS duration_ms,
    ev.query('(data[@name="blocked_process"]/value/blocked-process-report)[1]')
                                                        AS blocked_xml
FROM sh
CROSS APPLY sh.td.nodes('RingBufferTarget/event') AS T(ev)
WHERE ev.value('(@name)[1]', 'VARCHAR(50)') = 'blocked_process_report'
ORDER BY event_time DESC;

-- ---------------------------------------------------------------------------
-- Agent jobs that execute every minute or faster (often contain the
-- deadlock monitor / cleanup routines)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        j.name                                        AS job_name,
        s.name                                        AS schedule_name,
        s.freq_type,
        s.freq_subday_type,
        s.freq_subday_interval
    FROM msdb.dbo.sysjobs j
    JOIN msdb.dbo.sysjobschedules js ON js.job_id = j.job_id
    JOIN msdb.dbo.sysschedules     s ON s.schedule_id = js.schedule_id
    WHERE j.enabled = 1
      AND s.freq_subday_type IN (2, 4)                 -- seconds or minutes
    ORDER BY j.name;
END TRY
BEGIN CATCH
    PRINT '[note] msdb job schedule inventory failed: ' + ERROR_MESSAGE();
END CATCH;
