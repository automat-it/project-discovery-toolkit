-- =============================================================================
-- sec_12_dormant_users.sql
-- Priority: MEDIUM
-- Purpose: Find inactive accounts that should be reviewed and disabled.
-- Note: MySQL 8.0 tracks the last password change and connection count but
--       does not natively track "last login timestamp" without the Enterprise
--       Audit plugin or general_log parsing. The best proxies are:
--         - performance_schema.accounts (connections per account since reset)
--         - Current connection state from PROCESSLIST
--         - password_last_changed in mysql.user
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Login accounts vs current connections (who is NOT connected right now)
-- This is a snapshot — not actual dormancy. Use it as a starting point.
-- ---------------------------------------------------------------------------
SELECT
    u.User,
    u.Host,
    u.account_locked,
    u.Super_priv,
    u.plugin,
    u.password_last_changed,
    CASE WHEN p.USER IS NULL THEN 'no active session' ELSE 'connected' END
                                                            AS current_state
FROM mysql.user u
LEFT JOIN (
    SELECT DISTINCT USER
    FROM information_schema.PROCESSLIST
) p ON p.USER = u.User
WHERE u.account_locked = 'N'
  AND u.User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
ORDER BY current_state, u.User, u.Host;

-- ---------------------------------------------------------------------------
-- Accounts that have NEVER connected (zero total_connections in p_s.accounts)
-- NOTE: performance_schema.accounts is reset on server restart.
--       Zero here means no connections since last restart or stats reset.
-- ---------------------------------------------------------------------------
SELECT
    u.User,
    u.Host,
    u.account_locked,
    u.plugin,
    u.password_last_changed,
    COALESCE(a.TOTAL_CONNECTIONS, 0)                        AS total_connections_since_reset
FROM mysql.user u
LEFT JOIN performance_schema.accounts a
  ON  a.USER = u.User
  AND a.HOST LIKE REPLACE(u.Host, '%', '%')
WHERE u.account_locked = 'N'
  AND u.User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
  AND COALESCE(a.TOTAL_CONNECTIONS, 0) = 0
ORDER BY u.User, u.Host;

-- ---------------------------------------------------------------------------
-- Accounts with expired passwords (dormant — must change password or locked out)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    password_expired,
    password_last_changed,
    plugin,
    Super_priv
FROM mysql.user
WHERE password_expired = 'Y'
ORDER BY password_last_changed;

-- ---------------------------------------------------------------------------
-- Accounts with very old password_last_changed (> 180 days)
-- These are potentially dormant or forgotten service accounts.
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    plugin,
    password_last_changed,
    DATEDIFF(NOW(), password_last_changed)                  AS days_since_password_change,
    Super_priv
FROM mysql.user
WHERE password_last_changed IS NOT NULL
  AND password_last_changed < DATE_SUB(NOW(), INTERVAL 180 DAY)
  AND account_locked = 'N'
  AND User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
ORDER BY password_last_changed;

-- ---------------------------------------------------------------------------
-- Accounts with no password (cannot authenticate via password)
-- They may use socket auth, external plugin, or are truly dormant.
-- ---------------------------------------------------------------------------
SELECT
    u.User,
    u.Host,
    u.plugin,
    u.account_locked,
    CASE
        WHEN u.plugin IN ('auth_socket', 'unix_socket')
            THEN 'socket auth (OS-level only)'
        WHEN u.plugin = 'mysql_no_login'
            THEN 'no login allowed'
        WHEN u.authentication_string = '' OR u.authentication_string IS NULL
            THEN 'no password set'
        ELSE 'other'
    END                                                     AS auth_state
FROM mysql.user u
WHERE (u.authentication_string = '' OR u.authentication_string IS NULL)
  AND u.plugin NOT IN ('mysql_no_login')
  AND u.User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
ORDER BY u.User, u.Host;

-- ---------------------------------------------------------------------------
-- Accounts that own no objects (no tables, views, routines defined as DEFINER)
-- NOTE: MySQL does not have ownership like PostgreSQL; we approximate by
--       looking for accounts that appear as DEFINER on any object.
-- ---------------------------------------------------------------------------
SELECT
    u.User,
    u.Host,
    u.account_locked,
    u.plugin
FROM mysql.user u
WHERE u.account_locked = 'N'
  AND u.User NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
  AND NOT EXISTS (
      SELECT 1 FROM information_schema.ROUTINES r
      WHERE SUBSTRING_INDEX(r.DEFINER, '@', 1) = u.User
  )
  AND NOT EXISTS (
      SELECT 1 FROM information_schema.VIEWS v
      WHERE SUBSTRING_INDEX(v.DEFINER, '@', 1) = u.User
  )
  AND NOT EXISTS (
      SELECT 1 FROM information_schema.TRIGGERS t
      WHERE SUBSTRING_INDEX(t.DEFINER, '@', 1) = u.User
  )
  AND NOT EXISTS (
      SELECT 1 FROM information_schema.EVENTS e
      WHERE SUBSTRING_INDEX(e.DEFINER, '@', 1) = u.User
  )
ORDER BY u.User, u.Host;

-- ---------------------------------------------------------------------------
-- Connection counts per account since last stats reset (performance_schema)
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    CURRENT_CONNECTIONS,
    TOTAL_CONNECTIONS
FROM performance_schema.accounts
WHERE USER IS NOT NULL
  AND USER NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
ORDER BY TOTAL_CONNECTIONS DESC;
