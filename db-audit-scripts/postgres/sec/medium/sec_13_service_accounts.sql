-- =============================================================================
-- sec_13_service_accounts.sql
-- Priority: MEDIUM
-- Purpose: Identify and review technical / service accounts. These often
--          accumulate excess privilege over time.
-- Note: PostgreSQL has no formal "service account" flag — this script uses
--       naming heuristics and behavioral indicators (no expiration, high
--       connection count, generic application_name, etc.).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Likely service accounts by name pattern
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolreplication,
    rolbypassrls,
    rolconnlimit,
    rolvaliduntil
FROM pg_roles
WHERE rolcanlogin
  AND (
      rolname ~* '(svc|service|app|application|system|sys|daemon|bot|worker|job|cron|etl|backup|monitor|metric|migration|deploy|ci|cd)'
      OR rolname ~* '_(user|account|role)$'
  )
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Currently connected sessions whose application_name suggests a service
-- ---------------------------------------------------------------------------
SELECT
    usename                                              AS user,
    application_name                                     AS app,
    count(*)                                             AS sessions,
    array_agg(DISTINCT host(client_addr))                AS client_hosts
FROM pg_stat_activity
WHERE backend_type = 'client backend'
  AND application_name <> ''
GROUP BY usename, application_name
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Users with high connection counts (often indicates pooled service users)
-- ---------------------------------------------------------------------------
SELECT
    usename                                              AS user,
    count(*)                                             AS connections,
    count(DISTINCT application_name)                     AS distinct_apps,
    count(DISTINCT client_addr)                          AS distinct_clients,
    min(backend_start)                                   AS oldest_session
FROM pg_stat_activity
WHERE backend_type = 'client backend'
GROUP BY usename
HAVING count(*) > 5
ORDER BY connections DESC;

-- ---------------------------------------------------------------------------
-- Service-like accounts with elevated privileges
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolreplication,
    rolbypassrls
FROM pg_roles
WHERE rolcanlogin
  AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
  AND rolname ~* '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Service accounts with no expiration date (long-lived credential risk)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolconnlimit,
    rolvaliduntil
FROM pg_roles
WHERE rolcanlogin
  AND rolvaliduntil IS NULL
  AND rolname ~* '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Object ownership by likely service accounts
-- ---------------------------------------------------------------------------
SELECT
    pg_get_userbyid(c.relowner)                          AS owner,
    n.nspname                                            AS schema,
    count(*) FILTER (WHERE c.relkind = 'r')              AS tables,
    count(*) FILTER (WHERE c.relkind = 'i')              AS indexes,
    count(*) FILTER (WHERE c.relkind = 'v')              AS views,
    count(*) FILTER (WHERE c.relkind = 'S')              AS sequences
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_roles r     ON r.oid = c.relowner
WHERE r.rolname ~* '(svc|service|app|system|sys|bot|worker|etl|backup|monitor|deploy|ci)'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
GROUP BY pg_get_userbyid(c.relowner), n.nspname
ORDER BY tables DESC;
