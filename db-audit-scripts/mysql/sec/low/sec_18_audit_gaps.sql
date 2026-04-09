-- =============================================================================
-- sec_18_audit_gaps.sql
-- Priority: LOW
-- Purpose: Identify gaps in audit coverage — what is NOT being logged
--          that probably should be.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL audit coverage is more limited than PostgreSQL in Community Edition:
--       - No pgaudit equivalent (statement-level audit) without Enterprise Edition
--       - general_log logs all statements but is too expensive for production
--       - slow_query_log captures long-running queries
--       - binary log records all data changes (for replication/recovery)
--       - performance_schema.events_statements_* captures recent queries
--       - MySQL Enterprise Audit (audit_log plugin) provides full audit trail
--       Key gap: MySQL CE has no built-in way to log ALL DDL or privileged
--       operations without enabling general_log.

-- ---------------------------------------------------------------------------
-- Logging completeness checklist
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE,
    CASE VARIABLE_NAME
        WHEN 'slow_query_log' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok'
                ELSE 'GAP: slow query log disabled'
            END
        WHEN 'long_query_time' THEN
            CASE WHEN VARIABLE_VALUE + 0 <= 1
                 THEN 'ok (threshold <= 1 sec)'
                 ELSE CONCAT('GAP: slow query threshold too high (', VARIABLE_VALUE, 's)')
            END
        WHEN 'general_log' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok (high overhead — review for production)'
                ELSE 'GAP: general log disabled (all statements not logged)'
            END
        WHEN 'log_bin' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok (DML changes logged via binlog)'
                ELSE 'GAP: binary log disabled (no change history)'
            END
        WHEN 'log_queries_not_using_indexes' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok'
                ELSE 'partial: full scans not logged'
            END
        WHEN 'log_slow_admin_statements' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok'
                ELSE 'GAP: slow admin statements not logged'
            END
        WHEN 'binlog_rows_query_log_events' THEN
            CASE VARIABLE_VALUE
                WHEN 'ON' THEN 'ok (original SQL preserved in binlog)'
                ELSE 'partial: row-format binlog without original SQL'
            END
        ELSE 'check'
    END                                                     AS finding
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'slow_query_log',
    'long_query_time',
    'general_log',
    'log_bin',
    'log_queries_not_using_indexes',
    'log_slow_admin_statements',
    'binlog_rows_query_log_events'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Binary log format check (ROW preferred for exact change tracking)
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE,
    CASE VARIABLE_NAME
        WHEN 'binlog_format' THEN
            CASE VARIABLE_VALUE
                WHEN 'ROW'   THEN 'ok (exact row changes recorded)'
                WHEN 'MIXED' THEN 'partial — some statements use statement format'
                ELSE 'STATEMENT format: exact data changes not captured in binlog'
            END
        WHEN 'binlog_row_image' THEN
            CASE VARIABLE_VALUE
                WHEN 'FULL'    THEN 'ok (before and after images)'
                WHEN 'NOBLOB'  THEN 'partial — BLOBs excluded'
                WHEN 'MINIMAL' THEN 'minimal — only changed columns recorded'
                ELSE VARIABLE_VALUE
            END
    END                                                     AS finding
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN ('binlog_format', 'binlog_row_image')
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Audit plugin coverage check
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    CASE PLUGIN_STATUS
        WHEN 'ACTIVE' THEN 'ok — audit plugin active'
        ELSE 'GAP: audit plugin not active'
    END                                                     AS finding
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE '%audit%'
   OR PLUGIN_NAME LIKE '%server_audit%';

-- ---------------------------------------------------------------------------
-- Performance schema consumer coverage (statement-level tracking)
-- ---------------------------------------------------------------------------
SELECT
    NAME                                                    AS consumer,
    ENABLED,
    CASE
        WHEN NAME = 'events_statements_history_long' AND ENABLED = 'YES'
            THEN 'ok — long history of statements available'
        WHEN NAME = 'events_statements_history' AND ENABLED = 'YES'
            THEN 'ok — per-thread statement history available'
        WHEN NAME = 'events_statements_current' AND ENABLED = 'YES'
            THEN 'ok — current statement per thread tracked'
        WHEN ENABLED = 'NO'
            THEN 'GAP: consumer disabled, statements not tracked'
        ELSE 'check'
    END                                                     AS finding
FROM performance_schema.setup_consumers
WHERE NAME LIKE 'events_statements%'
ORDER BY NAME;

-- ---------------------------------------------------------------------------
-- Tables NOT covered by any explicit privilege audit
-- (equivalent to pg_18 tables not covered by pgaudit.role)
-- In MySQL CE, there is no way to audit per-table SELECT without general_log.
-- This lists all user tables as potential audit gaps.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_ROWS                                              AS approx_rows,
    ENGINE
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Statistics tracking parameters (MySQL performance_schema equivalent)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'performance_schema',
    'performance_schema_max_digest_length',
    'performance_schema_max_sql_text_length',
    'performance_schema_events_statements_history_long_size',
    'performance_schema_events_statements_history_size',
    'performance_schema_digests_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Quick gap summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'slow_query_log')               AS slow_log,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'general_log')                  AS general_log,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'log_bin')                      AS binlog,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'binlog_format')                AS binlog_format,
    (SELECT COUNT(*) FROM information_schema.PLUGINS
     WHERE PLUGIN_NAME LIKE '%audit%'
       AND PLUGIN_STATUS = 'ACTIVE')                       AS audit_plugins_active,
    (SELECT COUNT(*) FROM performance_schema.setup_consumers
     WHERE NAME = 'events_statements_history_long'
       AND ENABLED = 'YES')                                AS stmt_history_enabled;
