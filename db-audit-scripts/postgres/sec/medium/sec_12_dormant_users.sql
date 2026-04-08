-- =============================================================================
-- sec_12_dormant_users.sql
-- Priority: MEDIUM
-- Purpose: Find inactive accounts that should be reviewed and disabled.
-- Note: PostgreSQL does not natively track last successful login. The best
--       proxies are: current connection state, valid_until in the past, or
--       absence in pg_stat_activity over time. For real "last login"
--       tracking you need pgaudit / log analysis.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Login users vs current connections (who is NOT connected right now)
-- This is a snapshot — not actual dormancy. Use it as a starting point.
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS user,
    r.rolsuper,
    r.rolvaliduntil                                      AS valid_until,
    CASE WHEN a.usename IS NULL THEN 'no active session' ELSE 'connected' END
                                                         AS current_state
FROM pg_roles r
LEFT JOIN (
    SELECT DISTINCT usename
    FROM pg_stat_activity
    WHERE backend_type = 'client backend'
) a ON a.usename = r.rolname
WHERE r.rolcanlogin
  AND r.rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY current_state, r.rolname;

-- ---------------------------------------------------------------------------
-- Login accounts that have been EXPIRED for > 30 days
-- (clearly dormant — should be removed)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS user,
    rolvaliduntil                                        AS expired_at,
    now() - rolvaliduntil                                AS expired_for,
    rolsuper
FROM pg_roles
WHERE rolcanlogin
  AND rolvaliduntil IS NOT NULL
  AND rolvaliduntil < now() - interval '30 days'
ORDER BY rolvaliduntil;

-- ---------------------------------------------------------------------------
-- Login accounts with no password and no IAM-style auth indicator
-- (cannot actually authenticate via password — possibly dormant or external)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS user,
    r.rolsuper,
    r.rolvaliduntil
FROM pg_roles r
LEFT JOIN pg_authid a USING (rolname)
WHERE r.rolcanlogin
  AND a.rolpassword IS NULL
  AND r.rolname NOT LIKE 'pg\_%' ESCAPE '\'
  AND NOT EXISTS (
      SELECT 1
      FROM pg_auth_members am
      JOIN pg_roles g ON g.oid = am.roleid
      WHERE am.member = r.oid
        AND g.rolname IN ('rds_iam', 'azure_ad_admin')
  )
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- Roles never granted any membership (orphans)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolcanlogin,
    r.rolsuper
FROM pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%' ESCAPE '\'
  AND NOT EXISTS (
      SELECT 1 FROM pg_auth_members WHERE member = r.oid
  )
  AND NOT EXISTS (
      SELECT 1 FROM pg_auth_members WHERE roleid = r.oid
  )
  AND NOT r.rolsuper
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- Roles that own no objects (potentially safe to drop)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS role,
    r.rolcanlogin
FROM pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%' ESCAPE '\'
  AND NOT r.rolsuper
  AND NOT EXISTS (SELECT 1 FROM pg_class     WHERE relowner   = r.oid)
  AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner   = r.oid)
  AND NOT EXISTS (SELECT 1 FROM pg_proc      WHERE proowner   = r.oid)
  AND NOT EXISTS (SELECT 1 FROM pg_database  WHERE datdba     = r.oid)
ORDER BY r.rolname;
