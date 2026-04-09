-- =============================================================================
-- sec_13_service_accounts.sql
-- Priority: MEDIUM
-- Purpose: Identify and review technical / service accounts. These often
--          accumulate excess privilege over time.
-- Note: MySQL has no formal "service account" flag — this script uses
--       naming heuristics and behavioral indicators (no expiration, high
--       connection count, generic application-like usernames, etc.).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Likely service accounts by name pattern
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv,
    Grant_priv,
    Create_user_priv,
    Repl_slave_priv,
    max_connections,
    max_user_connections,
    password_expired,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE account_locked = 'N'
  AND (User REGEXP '(svc|service|app|application|system|sys|daemon|bot|worker|job|cron|etl|backup|monitor|metric|migration|deploy|ci|cd)'
    OR User REGEXP '_(user|account|role)$')
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Currently connected sessions showing service-like behavior
-- (many connections from the same user — likely a connection pool)
-- ---------------------------------------------------------------------------
SELECT
    USER,
    SUBSTRING_INDEX(HOST, ':', 1)                           AS client_host,
    COUNT(*)                                                AS sessions,
    COUNT(DISTINCT SUBSTRING_INDEX(HOST, ':', 1))           AS distinct_clients,
    SUM(CASE WHEN COMMAND <> 'Sleep' THEN 1 ELSE 0 END)    AS active_sessions
FROM information_schema.PROCESSLIST
WHERE USER NOT IN ('mysql.sys', 'mysql.session', 'mysql.infoschema')
GROUP BY USER, SUBSTRING_INDEX(HOST, ':', 1)
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Users with high connection counts (likely connection pool service users)
-- ---------------------------------------------------------------------------
SELECT
    USER,
    COUNT(*)                                                AS connections,
    COUNT(DISTINCT SUBSTRING_INDEX(HOST, ':', 1))           AS distinct_clients,
    MIN(TIME)                                               AS shortest_session_sec,
    MAX(TIME)                                               AS longest_session_sec
FROM information_schema.PROCESSLIST
GROUP BY USER
HAVING COUNT(*) > 5
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Service-like accounts with elevated privileges
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    account_locked,
    Super_priv,
    Grant_priv,
    Create_user_priv,
    Repl_slave_priv
FROM mysql.user
WHERE account_locked = 'N'
  AND (Super_priv = 'Y' OR Grant_priv = 'Y'
    OR Create_user_priv = 'Y' OR Repl_slave_priv = 'Y')
  AND User REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Service accounts with no password expiry policy
-- (password_lifetime = 0 means never expires; NULL inherits default)
-- ---------------------------------------------------------------------------
SELECT
    User,
    Host,
    max_connections,
    max_user_connections,
    password_lifetime,
    password_last_changed
FROM mysql.user
WHERE account_locked = 'N'
  AND (password_lifetime = 0 OR password_lifetime IS NULL)
  AND User REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
ORDER BY User, Host;

-- ---------------------------------------------------------------------------
-- Object "ownership" by likely service accounts
-- (accounts that appear as DEFINER on routines, views, triggers, events)
-- ---------------------------------------------------------------------------
SELECT
    SUBSTRING_INDEX(DEFINER, '@', 1)                        AS account,
    'ROUTINE'                                               AS object_type,
    ROUTINE_SCHEMA,
    ROUTINE_NAME,
    ROUTINE_TYPE,
    SECURITY_TYPE
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND SUBSTRING_INDEX(DEFINER, '@', 1)
      REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'

UNION ALL

SELECT
    SUBSTRING_INDEX(DEFINER, '@', 1),
    'VIEW',
    TABLE_SCHEMA,
    TABLE_NAME,
    NULL,
    SECURITY_TYPE
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND SUBSTRING_INDEX(DEFINER, '@', 1)
      REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'

UNION ALL

SELECT
    SUBSTRING_INDEX(DEFINER, '@', 1),
    'TRIGGER',
    TRIGGER_SCHEMA,
    TRIGGER_NAME,
    NULL,
    NULL
FROM information_schema.TRIGGERS
WHERE TRIGGER_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND SUBSTRING_INDEX(DEFINER, '@', 1)
      REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'

ORDER BY account, object_type, ROUTINE_SCHEMA, ROUTINE_NAME;

-- ---------------------------------------------------------------------------
-- Total connections per account since last stats reset
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    CURRENT_CONNECTIONS,
    TOTAL_CONNECTIONS
FROM performance_schema.accounts
WHERE USER REGEXP '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
ORDER BY TOTAL_CONNECTIONS DESC;
