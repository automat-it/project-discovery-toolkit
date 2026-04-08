-- =============================================================================
-- sec_18_audit_gaps.sql
-- Priority: LOW
-- Purpose: Identify gaps in audit coverage — what is NOT being logged
--          that probably should be.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Logging completeness checklist
-- ---------------------------------------------------------------------------
SELECT
    name,
    setting,
    CASE name
        WHEN 'log_connections' THEN
            CASE setting WHEN 'on' THEN 'ok' ELSE 'GAP: connections not logged' END
        WHEN 'log_disconnections' THEN
            CASE setting WHEN 'on' THEN 'ok' ELSE 'GAP: disconnections not logged' END
        WHEN 'log_statement' THEN
            CASE setting
                WHEN 'all' THEN 'ok (verbose)'
                WHEN 'mod' THEN 'partial — only DML/DDL logged'
                WHEN 'ddl' THEN 'partial — only DDL logged'
                ELSE 'GAP: no statements logged'
            END
        WHEN 'log_min_duration_statement' THEN
            CASE WHEN setting::int >= 0 AND setting::int <= 1000
                 THEN 'ok'
                 ELSE 'GAP: slow query threshold too high or off' END
        WHEN 'log_lock_waits' THEN
            CASE setting WHEN 'on' THEN 'ok' ELSE 'GAP: lock waits not logged' END
        WHEN 'log_checkpoints' THEN
            CASE setting WHEN 'on' THEN 'ok' ELSE 'GAP: checkpoints not logged' END
        WHEN 'log_temp_files' THEN
            CASE WHEN setting::int >= 0 THEN 'ok' ELSE 'GAP: temp files not logged' END
        WHEN 'log_autovacuum_min_duration' THEN
            CASE WHEN setting::int >= 0 THEN 'ok' ELSE 'GAP: autovacuum not logged' END
        WHEN 'log_replication_commands' THEN
            CASE setting WHEN 'on' THEN 'ok' ELSE 'GAP: replication commands not logged' END
        WHEN 'log_error_verbosity' THEN
            CASE setting WHEN 'verbose' THEN 'ok'
                         WHEN 'default' THEN 'partial'
                         ELSE 'GAP: terse error logging' END
    END                                                  AS finding
FROM pg_settings
WHERE name IN (
    'log_connections',
    'log_disconnections',
    'log_statement',
    'log_min_duration_statement',
    'log_lock_waits',
    'log_checkpoints',
    'log_temp_files',
    'log_autovacuum_min_duration',
    'log_replication_commands',
    'log_error_verbosity'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- log_line_prefix coverage check (should include user, db, app, host, time)
-- ---------------------------------------------------------------------------
SELECT
    setting                                              AS log_line_prefix,
    setting LIKE '%%t%' OR setting LIKE '%%m%'           AS has_timestamp,
    setting LIKE '%%u%'                                  AS has_user,
    setting LIKE '%%d%'                                  AS has_database,
    setting LIKE '%%a%'                                  AS has_application,
    setting LIKE '%%h%' OR setting LIKE '%%r%'           AS has_host,
    setting LIKE '%%p%'                                  AS has_pid,
    setting LIKE '%%l%'                                  AS has_session_line
FROM pg_settings
WHERE name = 'log_line_prefix';

-- ---------------------------------------------------------------------------
-- pgaudit class coverage (which classes of statements are audited)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'pgaudit.log',
    'pgaudit.log_catalog',
    'pgaudit.log_client',
    'pgaudit.log_level',
    'pgaudit.log_parameter',
    'pgaudit.log_relation',
    'pgaudit.log_statement_once',
    'pgaudit.role'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Tables NOT covered by pgaudit object-level audit (if pgaudit.role is set)
-- This requires examining grants to the pgaudit role — placeholder query.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    pg_get_userbyid(c.relowner)                          AS owner
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Statistics tracking parameters (must be on for audit-related introspection)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'track_activities',
    'track_counts',
    'track_io_timing',
    'track_functions',
    'track_wal_io_timing',
    'track_commit_timestamp'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Quick gap summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting FROM pg_settings WHERE name = 'log_connections')             AS log_conn,
    (SELECT setting FROM pg_settings WHERE name = 'log_disconnections')          AS log_disconn,
    (SELECT setting FROM pg_settings WHERE name = 'log_statement')               AS log_stmt,
    (SELECT setting FROM pg_settings WHERE name = 'log_min_duration_statement')  AS slow_ms,
    (SELECT setting FROM pg_settings WHERE name = 'log_lock_waits')              AS log_locks,
    (SELECT count(*)::text FROM pg_extension WHERE extname = 'pgaudit')          AS pgaudit;
