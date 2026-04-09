-- =============================================================================
-- sec_06_audit_logging.sql
-- Priority: HIGH
-- Purpose: Verify audit logging is enabled and configured properly.
--          Without traceability there is no incident response.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL has several audit options:
--       1. General query log (general_log) — logs all statements, high overhead
--       2. Slow query log (slow_query_log) — logs slow statements
--       3. Binary log (log_bin) — logs all changes (primarily for replication/recovery)
--       4. MySQL Enterprise Audit plugin (audit_log) — full audit trail,
--          requires MySQL Enterprise Edition
--       5. MariaDB has its own audit plugin (server_audit)
--       6. Community alternatives: audit_log_filter plugin (MySQL 8.0 EE)
--       There is no pgaudit equivalent in MySQL Community Edition.
--       For compliance-grade auditing, use MySQL Enterprise Audit or a
--       proxy-layer audit solution.

-- ---------------------------------------------------------------------------
-- Core logging configuration
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'general_log',
    'general_log_file',
    'slow_query_log',
    'slow_query_log_file',
    'long_query_time',
    'log_queries_not_using_indexes',
    'log_slow_admin_statements',
    'log_slow_replica_statements',
    'log_slow_slave_statements',
    'min_examined_row_limit',
    'log_output',
    'log_error',
    'log_error_verbosity',
    'log_timestamps'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- What DML/DDL activity gets logged
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'log_bin',
    'binlog_format',
    'binlog_row_event_max_size',
    'binlog_rows_query_log_events',
    'binlog_stmt_cache_size',
    'sql_log_bin',                -- per-session binary logging (can be disabled)
    'log_replica_updates',
    'log_slave_updates'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Audit plugin status (MySQL Enterprise Audit or community alternatives)
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    PLUGIN_DESCRIPTION
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE '%audit%'
   OR PLUGIN_NAME LIKE '%server_audit%'
ORDER BY PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Audit plugin configuration variables (if audit_log plugin is loaded)
-- NOTE: These variables only exist if MySQL Enterprise Audit is installed.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'audit_log%'
   OR VARIABLE_NAME LIKE 'server_audit%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Performance schema event consumers (controls what is tracked)
-- Enabling these creates an audit trail within the performance_schema.
-- ---------------------------------------------------------------------------
SELECT
    NAME                                                    AS consumer,
    ENABLED
FROM performance_schema.setup_consumers
ORDER BY NAME;

-- ---------------------------------------------------------------------------
-- Performance schema instrumented actors (per-user tracking)
-- ---------------------------------------------------------------------------
SELECT
    HOST,
    USER,
    ENABLED,
    HISTORY
FROM performance_schema.setup_actors
ORDER BY HOST, USER;

-- ---------------------------------------------------------------------------
-- Slow query log status
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'slow_query_log')                AS slow_query_log,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'long_query_time')               AS long_query_time_sec,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'log_queries_not_using_indexes') AS log_full_scans,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'general_log')                   AS general_log,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'log_bin')                       AS binary_log;

-- ---------------------------------------------------------------------------
-- Quick audit-readiness checklist
-- ---------------------------------------------------------------------------
SELECT
    CASE WHEN (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
               WHERE VARIABLE_NAME = 'slow_query_log') = 'ON'
         THEN 'ok' ELSE 'GAP: slow query log disabled' END  AS slow_log,
    CASE WHEN (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
               WHERE VARIABLE_NAME = 'general_log') = 'ON'
         THEN 'ok (high overhead)' ELSE 'GAP: general log disabled' END AS general_log,
    CASE WHEN (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
               WHERE VARIABLE_NAME = 'log_bin') = 'ON'
         THEN 'ok' ELSE 'GAP: binary log disabled' END      AS binary_log,
    (SELECT COUNT(*) FROM information_schema.PLUGINS
     WHERE PLUGIN_NAME LIKE '%audit%'
       AND PLUGIN_STATUS = 'ACTIVE')                        AS audit_plugins_active;
