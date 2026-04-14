-- =============================================================================
-- sec_10_dangerous_objects.sql
-- Priority: HIGH
-- Purpose: Find code paths that could enable privilege escalation:
--          SECURITY DEFINER routines, dangerous plugins, triggers,
--          events with elevated access.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL equivalents for PostgreSQL dangerous objects:
--       - SECURITY DEFINER functions/procedures → same concept in MySQL
--       - Untrusted languages (plperlu, plpythonu) → no equivalent;
--         MySQL stored routines are SQL-only by default; UDFs (shared libs)
--         loaded via CREATE FUNCTION ... SONAME are the closest analog.
--       - Event triggers → MySQL Events (scheduled tasks) are the analog
--       - Foreign Data Wrappers → no direct MySQL equivalent; FEDERATED
--         engine is similar; external connectivity is via UDFs or
--         application-level connections.

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER routines (execute with definer's privileges)
-- These bypass caller's privilege checks — same risk as in PostgreSQL.
-- ---------------------------------------------------------------------------
SELECT
    ROUTINE_SCHEMA,
    ROUTINE_NAME,
    ROUTINE_TYPE,
    DEFINER,
    SECURITY_TYPE,
    CREATED,
    LAST_ALTERED,
    SQL_MODE,
    ROUTINE_COMMENT
FROM information_schema.ROUTINES
WHERE SECURITY_TYPE = 'DEFINER'
  AND ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER routines where the definer has SUPER or admin privileges
-- (highest risk — callable by users who wouldn't otherwise have those privs)
-- ---------------------------------------------------------------------------
SELECT
    r.ROUTINE_SCHEMA,
    r.ROUTINE_NAME,
    r.ROUTINE_TYPE,
    r.DEFINER,
    r.SECURITY_TYPE,
    u.Super_priv                                            AS definer_has_super,
    u.Grant_priv                                            AS definer_can_grant
FROM information_schema.ROUTINES r
LEFT JOIN mysql.user u
  -- DEFINER in information_schema is stored as 'user@host' (no quotes).
  -- We must match BOTH user and host; matching on User alone produces
  -- false positives whenever any account with the same username (on a
  -- different host) has SUPER, falsely flagging routines whose actual
  -- definer does not.
  ON u.User = SUBSTRING_INDEX(r.DEFINER, '@', 1)
 AND u.Host = SUBSTRING_INDEX(r.DEFINER, '@', -1)
WHERE r.SECURITY_TYPE = 'DEFINER'
  AND r.ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema',
                                'performance_schema', 'sys')
  AND u.Super_priv = 'Y'
ORDER BY r.ROUTINE_SCHEMA, r.ROUTINE_NAME;

-- ---------------------------------------------------------------------------
-- User-defined functions (UDFs) loaded from shared libraries
-- These can execute arbitrary OS code — the highest privilege escalation risk.
-- (Analogous to PostgreSQL plperlu / plpythonu / C language functions)
-- ---------------------------------------------------------------------------
-- NOTE: in MySQL 8.0+ mysql.func has only (name, ret, dl, type). The
-- User / Host / Aggregate columns existed on MySQL 5.x and were removed
-- as part of the data-dictionary rework, so the previous SELECT failed
-- with "Unknown column 'User'". UDFs in MySQL are installed globally
-- (not per-user), so User/Host were never meaningful here.
SELECT
    name                                                    AS udf_name,
    dl                                                      AS library,
    ret                                                     AS return_type,
    type                                                    AS udf_type
FROM mysql.func
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Installed plugins (can affect server behavior at a deep level)
-- Malicious or misconfigured plugins can bypass security controls.
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    PLUGIN_LIBRARY,
    PLUGIN_LIBRARY_VERSION,
    PLUGIN_AUTHOR,
    PLUGIN_DESCRIPTION,
    PLUGIN_LICENSE
FROM information_schema.PLUGINS
ORDER BY PLUGIN_TYPE, PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Scheduled events (MySQL EVENT = closest analog to PostgreSQL event triggers
-- for background tasks; can execute DDL/DML on a schedule)
-- ---------------------------------------------------------------------------
SELECT
    EVENT_SCHEMA,
    EVENT_NAME,
    DEFINER,
    EVENT_TYPE,
    EXECUTE_AT,
    INTERVAL_VALUE,
    INTERVAL_FIELD,
    STATUS,
    ON_COMPLETION,
    CREATED,
    LAST_ALTERED,
    LAST_EXECUTED,
    EVENT_COMMENT,
    ORIGINATOR,
    CHARACTER_SET_CLIENT
FROM information_schema.EVENTS
WHERE EVENT_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY EVENT_SCHEMA, EVENT_NAME;

-- ---------------------------------------------------------------------------
-- DML triggers on user tables
-- Triggers run silently as part of DML — can escalate privileges if
-- written carelessly or maliciously.
-- ---------------------------------------------------------------------------
SELECT
    TRIGGER_SCHEMA,
    TRIGGER_NAME,
    EVENT_MANIPULATION                                      AS trigger_event,
    EVENT_OBJECT_SCHEMA,
    EVENT_OBJECT_TABLE,
    ACTION_TIMING,
    DEFINER,
    CREATED,
    ACTION_STATEMENT
FROM information_schema.TRIGGERS
WHERE TRIGGER_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
ORDER BY TRIGGER_SCHEMA, EVENT_OBJECT_TABLE, TRIGGER_NAME;

-- ---------------------------------------------------------------------------
-- Triggers owned by users with SUPER privilege
-- ---------------------------------------------------------------------------
SELECT
    tr.TRIGGER_SCHEMA,
    tr.TRIGGER_NAME,
    tr.EVENT_OBJECT_TABLE,
    tr.DEFINER,
    tr.ACTION_TIMING,
    tr.EVENT_MANIPULATION
FROM information_schema.TRIGGERS tr
LEFT JOIN mysql.user u
  -- Match both user and host parts of DEFINER ('user@host'); matching
  -- on User alone falsely flags any trigger whose definer username
  -- happens to equal a SUPER user's username on a different host.
  ON u.User = SUBSTRING_INDEX(tr.DEFINER, '@', 1)
 AND u.Host = SUBSTRING_INDEX(tr.DEFINER, '@', -1)
WHERE tr.TRIGGER_SCHEMA NOT IN ('mysql', 'information_schema',
                                 'performance_schema', 'sys')
  AND u.Super_priv = 'Y'
ORDER BY tr.TRIGGER_SCHEMA, tr.EVENT_OBJECT_TABLE;

-- ---------------------------------------------------------------------------
-- FEDERATED engine tables (external connection points — like PostgreSQL FDW)
-- These tables map to remote MySQL servers; credentials stored in MySQL.
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.ENGINE,
    t.TABLE_COMMENT                                         AS connection_string
FROM information_schema.TABLES t
WHERE t.ENGINE = 'FEDERATED'
ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Linked server / external connections via metadata
-- (CHECK if linked_server or similar plugins are active)
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_STATUS,
    PLUGIN_TYPE
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME IN ('FEDERATED', 'federated', 'CONNECT', 'connect',
                      'Spider', 'spider')
ORDER BY PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Routines executable by any user (GRANT EXECUTE TO '%'@'%' or similar)
-- These allow privilege escalation via SECURITY DEFINER.
-- ---------------------------------------------------------------------------
-- NOTE: information_schema.ROUTINE_PRIVILEGES was dropped in MySQL 8.0
-- and is not populated on current MySQL / Aurora. Read routine grants
-- from mysql.procs_priv — the authoritative source in the data dictionary.
-- Flag grants whose host is the global wildcard '%' and whose routine is
-- SECURITY DEFINER (same escalation surface we were probing before).
SELECT
    CONCAT('''', pp.User, '''@''', pp.Host, '''')           AS GRANTEE,
    pp.Db                                                   AS ROUTINE_SCHEMA,
    pp.Routine_name                                         AS ROUTINE_NAME,
    pp.Routine_type                                         AS ROUTINE_TYPE,
    pp.Proc_priv                                            AS PRIVILEGE_TYPES,
    r.SECURITY_TYPE
FROM mysql.procs_priv pp
JOIN information_schema.ROUTINES r
  ON  r.ROUTINE_SCHEMA = pp.Db
  AND r.ROUTINE_NAME   = pp.Routine_name
  AND r.ROUTINE_TYPE   = pp.Routine_type
WHERE pp.Db NOT IN ('mysql', 'information_schema',
                    'performance_schema', 'sys')
  AND r.SECURITY_TYPE = 'DEFINER'
  AND (pp.Host = '%' OR pp.User = '')
ORDER BY pp.Db, pp.Routine_name;
