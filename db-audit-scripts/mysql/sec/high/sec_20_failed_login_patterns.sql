-- =============================================================================
-- sec_20_failed_login_patterns.sql
-- Priority: HIGH
-- Purpose: Detect brute-force / credential-stuffing patterns. MySQL 5.7+
--          exposes per-account and per-host authentication-error counters
--          in performance_schema (connection_control plugin adds more).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Connection-control plugin (adds delay after N failed logins)
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    PLUGIN_DESCRIPTION
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME LIKE 'CONNECTION_CONTROL%'
ORDER BY PLUGIN_NAME;

-- Runtime variables for connection_control
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'connection_control%'
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Accounts currently tracked by connection_control_failed_login_attempts
-- (each row is a user@host that has accumulated failed-login delays)
-- Table only exists when the CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS
-- plugin is installed — probe first and use a prepared statement so the
-- script does not abort on vanilla MySQL builds.
-- ---------------------------------------------------------------------------
SET @cc_has := (SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = 'information_schema'
                   AND TABLE_NAME   = 'CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS');
SET @cc_sql := IF(@cc_has = 1,
    'SELECT USERHOST, FAILED_ATTEMPTS
       FROM information_schema.CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS
      ORDER BY FAILED_ATTEMPTS DESC',
    'SELECT ''connection_control_failed_login_attempts plugin not installed'' AS note');
PREPARE cc_stmt FROM @cc_sql;
EXECUTE cc_stmt;
DEALLOCATE PREPARE cc_stmt;

-- ---------------------------------------------------------------------------
-- Authentication errors aggregated by account (ER_ACCESS_DENIED_ERROR=1045,
-- ER_ACCESS_DENIED_NO_PASSWORD_ERROR=1698, ER_HOST_NOT_PRIVILEGED=1130).
-- Requires performance_schema enabled and event_errors_summary instruments.
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    ERROR_NUMBER,
    ERROR_NAME,
    SUM_ERROR_RAISED,
    FIRST_SEEN,
    LAST_SEEN
FROM performance_schema.events_errors_summary_by_account_by_error
WHERE ERROR_NAME IN (
        'ER_ACCESS_DENIED_ERROR',
        'ER_ACCESS_DENIED_NO_PASSWORD_ERROR',
        'ER_HOST_NOT_PRIVILEGED',
        'ER_HOST_IS_BLOCKED',
        'ER_NOT_SUPPORTED_AUTH_MODE',
        'ER_PASSWORD_EXPIRE_ANONYMOUS_USER'
      )
  AND SUM_ERROR_RAISED > 0
ORDER BY SUM_ERROR_RAISED DESC;

-- ---------------------------------------------------------------------------
-- Auth errors aggregated by host (any user) — identifies a single attacker
-- cycling through usernames.
-- ---------------------------------------------------------------------------
SELECT
    HOST,
    ERROR_NAME,
    SUM_ERROR_RAISED,
    FIRST_SEEN,
    LAST_SEEN
FROM performance_schema.events_errors_summary_by_host_by_error
WHERE ERROR_NAME IN ('ER_ACCESS_DENIED_ERROR',
                     'ER_ACCESS_DENIED_NO_PASSWORD_ERROR',
                     'ER_HOST_IS_BLOCKED')
  AND SUM_ERROR_RAISED > 0
ORDER BY SUM_ERROR_RAISED DESC;

-- ---------------------------------------------------------------------------
-- Aborted connections / aborted clients counters (historical brute-force
-- indicator independent of performance_schema retention).
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Aborted_clients',
    'Aborted_connects',
    'Connection_errors_accept',
    'Connection_errors_internal',
    'Connection_errors_max_connections',
    'Connection_errors_peer_address',
    'Connection_errors_select',
    'Connection_errors_tcpwrap'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Per-host error counters from host_cache (shows blocked hosts due to
-- max_connect_errors)
-- ---------------------------------------------------------------------------
SELECT
    IP, HOST, HOST_VALIDATED,
    SUM_CONNECT_ERRORS,
    COUNT_HOST_BLOCKED_ERRORS,
    COUNT_AUTHENTICATION_ERRORS,
    COUNT_HANDSHAKE_ERRORS,
    COUNT_FORMAT_ERRORS,
    FIRST_ERROR_SEEN, LAST_ERROR_SEEN
FROM performance_schema.host_cache
ORDER BY SUM_CONNECT_ERRORS DESC, COUNT_AUTHENTICATION_ERRORS DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Password / lock related account attributes (MySQL 8.0)
-- ---------------------------------------------------------------------------
SELECT
    User, Host,
    account_locked,
    password_expired,
    password_last_changed,
    password_lifetime,
    password_reuse_history,
    password_reuse_time,
    password_require_current
FROM mysql.user
ORDER BY account_locked DESC, password_expired DESC, User, Host;

-- ---------------------------------------------------------------------------
-- max_connect_errors — how many handshake errors from a host before it is
-- blocked (too-high = easier brute force)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN ('max_connect_errors','max_user_connections','max_connections')
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM information_schema.PLUGINS
      WHERE PLUGIN_NAME LIKE 'CONNECTION_CONTROL%' AND PLUGIN_STATUS='ACTIVE') AS connection_control_active,
    (SELECT SUM(SUM_ERROR_RAISED) FROM performance_schema.events_errors_summary_by_account_by_error
      WHERE ERROR_NAME IN ('ER_ACCESS_DENIED_ERROR','ER_ACCESS_DENIED_NO_PASSWORD_ERROR')) AS total_access_denied,
    (SELECT SUM(COUNT_AUTHENTICATION_ERRORS) FROM performance_schema.host_cache) AS host_cache_auth_errors,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
      WHERE VARIABLE_NAME='Aborted_connects') AS aborted_connects;
