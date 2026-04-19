-- =============================================================================
-- sec_19_schema_change_history.sql
-- Priority: MEDIUM
-- Purpose: Surface evidence of DDL / schema-change activity. MySQL has no
--          built-in persistent DDL audit log, so we combine
--          information_schema CREATE_TIME / UPDATE_TIME, binlog config,
--          general log config, audit plugin presence, and recent DDL from
--          performance_schema statement history.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Audit / change-tracking plugins installed
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    PLUGIN_DESCRIPTION
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE '%audit%'
   OR PLUGIN_NAME LIKE '%AUDIT%'
   OR PLUGIN_NAME IN ('server_audit', 'audit_log', 'MARIADB_AUDIT_PLUGIN')
ORDER BY PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Binary log status — binlog carries every DDL statement and is the
-- closest thing to a DDL audit trail most MySQL deployments have.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'log_bin',
    'log_bin_basename',
    'binlog_format',
    'binlog_row_image',
    'binlog_expire_logs_seconds',
    'expire_logs_days',
    'sync_binlog',
    'log_bin_trust_function_creators'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- General query log / slow query log — also captures DDL if enabled
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'general_log',
    'general_log_file',
    'log_output',
    'slow_query_log',
    'slow_query_log_file',
    'log_queries_not_using_indexes'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Audit plugin runtime variables (MySQL Enterprise Audit / MariaDB Audit)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'audit_log_%'
   OR VARIABLE_NAME LIKE 'server_audit%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Recently-created / recently-modified tables (information_schema tracks
-- CREATE_TIME and UPDATE_TIME; UPDATE_TIME on InnoDB is approximate).
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS,
    CREATE_TIME,
    UPDATE_TIME
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND (CREATE_TIME > NOW() - INTERVAL 30 DAY
    OR UPDATE_TIME > NOW() - INTERVAL 30 DAY)
ORDER BY GREATEST(
    COALESCE(CREATE_TIME, '1970-01-01'),
    COALESCE(UPDATE_TIME, '1970-01-01')
) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Recently-modified routines / views / triggers / events
-- ---------------------------------------------------------------------------
SELECT
    ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE,
    CREATED, LAST_ALTERED, DEFINER, SECURITY_TYPE
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND (CREATED      > NOW() - INTERVAL 90 DAY
    OR LAST_ALTERED > NOW() - INTERVAL 90 DAY)
ORDER BY LAST_ALTERED DESC
LIMIT 50;

SELECT
    TRIGGER_SCHEMA, TRIGGER_NAME, EVENT_MANIPULATION,
    EVENT_OBJECT_SCHEMA, EVENT_OBJECT_TABLE, ACTION_TIMING,
    CREATED, DEFINER
FROM information_schema.TRIGGERS
WHERE TRIGGER_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
ORDER BY CREATED DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- DDL statements currently still visible in performance_schema short-term
-- history (limited buffer; not a long-term audit trail).
-- ---------------------------------------------------------------------------
SELECT
    EVENT_ID,
    THREAD_ID,
    CURRENT_SCHEMA,
    SQL_TEXT,
    EVENT_NAME,
    TIMER_WAIT/1000000000  AS elapsed_ms
FROM performance_schema.events_statements_history_long
WHERE SQL_TEXT IS NOT NULL
  AND (
      SQL_TEXT LIKE 'CREATE %'
   OR SQL_TEXT LIKE 'ALTER %'
   OR SQL_TEXT LIKE 'DROP %'
   OR SQL_TEXT LIKE 'RENAME %'
   OR SQL_TEXT LIKE 'TRUNCATE %'
   OR SQL_TEXT LIKE 'GRANT %'
   OR SQL_TEXT LIKE 'REVOKE %'
  )
ORDER BY EVENT_ID DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Summary: does this MySQL keep a DDL trail?
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
       WHERE VARIABLE_NAME = 'log_bin')       AS binlog_enabled,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
       WHERE VARIABLE_NAME = 'general_log')   AS general_log_enabled,
    (SELECT COUNT(*) FROM information_schema.PLUGINS
       WHERE PLUGIN_STATUS = 'ACTIVE'
         AND (PLUGIN_NAME LIKE '%audit%' OR PLUGIN_NAME LIKE '%AUDIT%')) AS audit_plugins_active,
    CASE
      WHEN EXISTS(
        SELECT 1 FROM information_schema.PLUGINS
         WHERE PLUGIN_STATUS='ACTIVE'
           AND (PLUGIN_NAME LIKE '%audit%' OR PLUGIN_NAME LIKE '%AUDIT%')
      ) THEN 'Audit plugin active'
      WHEN (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
             WHERE VARIABLE_NAME='log_bin') = 'ON'
        THEN 'binlog present — coarse DDL trail only'
      ELSE 'NO persistent DDL trail — recommend enabling audit plugin or binlog'
    END AS assessment;
