-- =============================================================================
-- sec_06_audit_logging.sql
-- Priority: HIGH
-- Purpose: Verify audit logging is enabled and configured properly.
--          Without traceability there is no incident response.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Core logging parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit
FROM pg_settings
WHERE name IN (
    'logging_collector',
    'log_destination',
    'log_directory',
    'log_filename',
    'log_file_mode',
    'log_rotation_age',
    'log_rotation_size',
    'log_truncate_on_rotation',
    'log_min_messages',
    'log_min_error_statement',
    'log_min_duration_statement',
    'log_line_prefix'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- What gets logged
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'log_connections',
    'log_disconnections',
    'log_statement',
    'log_duration',
    'log_lock_waits',
    'log_temp_files',
    'log_autovacuum_min_duration',
    'log_checkpoints',
    'log_hostname',
    'log_error_verbosity',
    'log_replication_commands',
    'log_parameter_max_length',
    'log_parameter_max_length_on_error'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- pgaudit extension status (if installed)
-- ---------------------------------------------------------------------------
SELECT extname, extversion
FROM pg_extension
WHERE extname = 'pgaudit';

-- ---------------------------------------------------------------------------
-- pgaudit configuration (NULL if extension not loaded)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name LIKE 'pgaudit.%'
ORDER BY name;

-- ---------------------------------------------------------------------------
-- shared_preload_libraries (pgaudit must be there to function)
-- ---------------------------------------------------------------------------
SHOW shared_preload_libraries;

-- ---------------------------------------------------------------------------
-- Per-role / per-database logging overrides
-- ---------------------------------------------------------------------------
SELECT
    coalesce(r.rolname, 'ALL ROLES')                     AS role,
    coalesce(d.datname, 'ALL DBS')                       AS database,
    s.setconfig                                          AS settings
FROM pg_db_role_setting s
LEFT JOIN pg_roles r    ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
WHERE array_to_string(s.setconfig, ' ') ILIKE '%log_%'
   OR array_to_string(s.setconfig, ' ') ILIKE '%pgaudit%';

-- ---------------------------------------------------------------------------
-- Quick audit-readiness checklist
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting FROM pg_settings WHERE name = 'log_connections')      AS log_connections,
    (SELECT setting FROM pg_settings WHERE name = 'log_disconnections')   AS log_disconnections,
    (SELECT setting FROM pg_settings WHERE name = 'log_statement')        AS log_statement,
    (SELECT setting FROM pg_settings WHERE name = 'log_min_duration_statement') AS log_slow_ms,
    (SELECT setting FROM pg_settings WHERE name = 'log_line_prefix')      AS log_prefix,
    (SELECT count(*) FROM pg_extension WHERE extname = 'pgaudit')         AS pgaudit_installed;
