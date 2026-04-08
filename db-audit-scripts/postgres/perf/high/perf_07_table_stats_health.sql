-- =============================================================================
-- perf_07_table_stats_health.sql
-- Priority: HIGH
-- Purpose: Check freshness of statistics, autovacuum/analyze status,
--          dead tuples accumulation. Stale stats produce bad plans.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Tables NEVER analyzed (planner has no statistics)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    n_live_tup                                           AS rows,
    pg_size_pretty(pg_total_relation_size(relid))        AS size,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
WHERE last_analyze IS NULL
  AND last_autoanalyze IS NULL
  AND n_live_tup > 0
ORDER BY n_live_tup DESC;

-- ---------------------------------------------------------------------------
-- Tables with stale statistics (high modification ratio since last analyze)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    n_live_tup                                           AS live,
    n_mod_since_analyze                                  AS modified_since_analyze,
    n_ins_since_vacuum                                   AS inserted_since_vacuum,
    CASE WHEN n_live_tup > 0
         THEN round(100.0 * n_mod_since_analyze / n_live_tup, 2)
         ELSE 0
    END                                                  AS mod_pct,
    last_analyze,
    last_autoanalyze,
    now() - greatest(last_analyze, last_autoanalyze)     AS analyze_age
FROM pg_stat_user_tables
WHERE n_mod_since_analyze > 1000
ORDER BY mod_pct DESC NULLS LAST
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Tables with high dead tuple ratio (vacuum candidates)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    n_live_tup                                           AS live,
    n_dead_tup                                           AS dead,
    CASE WHEN n_live_tup > 0
         THEN round(100.0 * n_dead_tup / n_live_tup, 2)
         ELSE 0
    END                                                  AS dead_pct,
    pg_size_pretty(pg_total_relation_size(relid))        AS size,
    last_vacuum,
    last_autovacuum,
    now() - greatest(last_vacuum, last_autovacuum)       AS vacuum_age
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY dead_pct DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Vacuum / analyze activity counters per table
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    vacuum_count,
    autovacuum_count,
    analyze_count,
    autoanalyze_count,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
ORDER BY coalesce(last_autovacuum, '1970-01-01'::timestamptz)
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Currently running autovacuum / vacuum / analyze processes
-- ---------------------------------------------------------------------------
SELECT
    pid,
    datname,
    usename,
    backend_type,
    now() - query_start                                  AS duration,
    state,
    wait_event_type,
    wait_event,
    query
FROM pg_stat_activity
WHERE (query ILIKE '%vacuum%' OR query ILIKE '%analyze%' OR backend_type = 'autovacuum worker')
  AND state <> 'idle'
  AND pid <> pg_backend_pid()
ORDER BY query_start;

-- ---------------------------------------------------------------------------
-- Per-table autovacuum overrides (storage parameters)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    c.reloptions
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'm')
  AND c.reloptions IS NOT NULL
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Statistics target overrides per column (default is 100)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    a.attname                                            AS column,
    a.attstattarget                                      AS stats_target
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attstattarget > -1
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY a.attstattarget DESC;

-- ---------------------------------------------------------------------------
-- Low-information columns in pg_stats (suspicious or degenerate statistics)
-- These are columns where the planner has very little to work with:
--   * n_distinct = 0    -- analyzer could not determine distinct values
--   * null_frac > 0.95  -- almost entirely NULL, may mislead selectivity
-- A real "most modified" view requires pg_stat_user_tables.n_tup_upd, which
-- is exposed by the dead-tuple block above.
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    tablename                                            AS table,
    attname                                              AS column,
    null_frac,
    avg_width,
    n_distinct,
    correlation
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND (n_distinct = 0 OR null_frac > 0.95)
ORDER BY schemaname, tablename, attname
LIMIT 50;
