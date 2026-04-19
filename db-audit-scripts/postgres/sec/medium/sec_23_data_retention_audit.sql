-- =============================================================================
-- sec_23_data_retention_audit.sql
-- Priority: MEDIUM
-- Purpose: Identify tables that have grown large and show no sign of
--          scheduled deletion — a retention-policy gap raises GDPR /
--          HIPAA risk and wastes storage. Signals: tuple-delete count,
--          oldest-row age heuristics, partitioning presence, retention-
--          comment presence on the object.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Top 100 tables by size with activity signals.
--   n_tup_del / n_tup_upd / n_tup_ins counters reset whenever pg_stat is
--   reset; absolute values matter less than the *ratio* of deletes to
--   inserts. pure append-only tables (delete ratio = 0) are retention
--   candidates.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    c.relname                                             AS table_name,
    pg_size_pretty(pg_total_relation_size(c.oid))         AS total_size,
    c.reltuples::bigint                                   AS est_rows,
    s.n_tup_ins                                           AS inserts,
    s.n_tup_upd                                           AS updates,
    s.n_tup_del                                           AS deletes,
    CASE WHEN s.n_tup_ins > 0
         THEN ROUND((s.n_tup_del * 100.0) / s.n_tup_ins, 2)
    END                                                   AS delete_pct_of_insert,
    s.last_vacuum,
    s.last_autovacuum,
    c.relispartition                                      AS is_partition,
    (c.relkind = 'p')                                     AS is_partitioned_parent,
    obj_description(c.oid, 'pg_class')                    AS comment
FROM pg_class c
JOIN pg_namespace n      ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  AND pg_total_relation_size(c.oid) > 100 * 1024 * 1024    -- > 100 MB
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 100;

-- ---------------------------------------------------------------------------
-- Append-only-looking tables (zero deletes, substantial size) — each is
-- a retention-policy candidate. Threshold > 1 GB keeps noise down.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    c.relname                                             AS table_name,
    pg_size_pretty(pg_total_relation_size(c.oid))         AS total_size,
    s.n_tup_ins                                           AS inserts,
    s.n_tup_del                                           AS deletes,
    CASE WHEN c.relkind = 'p' THEN 'partitioned — check child retention'
         WHEN c.relispartition THEN 'partition — parent-level policy'
         ELSE 'no partitioning — retention needs DELETE / DROP logic'
    END                                                   AS retention_shape
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  AND pg_total_relation_size(c.oid) > 1024 * 1024 * 1024    -- > 1 GB
  AND COALESCE(s.n_tup_del, 0) = 0
  AND COALESCE(s.n_tup_ins, 0) > 0
ORDER BY pg_total_relation_size(c.oid) DESC;

-- ---------------------------------------------------------------------------
-- Tables with time-like columns — the operator can spot candidates for
-- a WHERE-clause retention DELETE / partition-pruning key.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    c.relname                                             AS table_name,
    a.attname                                             AS time_column,
    t.typname                                             AS type,
    pg_size_pretty(pg_total_relation_size(c.oid))         AS total_size
FROM pg_class c
JOIN pg_namespace n   ON n.oid = c.relnamespace
JOIN pg_attribute a   ON a.attrelid = c.oid
JOIN pg_type t        ON t.oid = a.atttypid
WHERE c.relkind = 'r'
  AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
  AND pg_total_relation_size(c.oid) > 100 * 1024 * 1024
  AND (t.typname IN ('timestamp','timestamptz','date')
       OR a.attname ~* '(created_at|updated_at|inserted_at|event_time|log_time|occurred_at|timestamp|_date)$')
ORDER BY pg_total_relation_size(c.oid) DESC, n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Retention-policy extensions visible in pg_extension
--   pg_partman, timescaledb, pgagent — surface them so the operator
--   knows a mechanism is present before recommending a new one.
-- ---------------------------------------------------------------------------
SELECT
    e.extname, e.extversion,
    CASE e.extname
        WHEN 'pg_partman'  THEN 'partition manager — check partman.part_config retention settings'
        WHEN 'timescaledb' THEN 'hypertables — check timescaledb retention policies (add_retention_policy)'
        WHEN 'pgagent'     THEN 'job scheduler — jobs may perform deletes'
        ELSE 'extension — unknown retention role'
    END                                                   AS role
FROM pg_extension e
WHERE e.extname IN ('pg_partman','timescaledb','pgagent','pg_cron');

-- ---------------------------------------------------------------------------
-- pg_cron jobs — if installed, the schedule likely encodes retention
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        RAISE NOTICE 'pg_cron installed — query cron.job for scheduled retention tasks';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind = 'r'
        AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
        AND pg_total_relation_size(c.oid) > 1024 * 1024 * 1024)              AS tables_over_1gb,
    (SELECT COUNT(*) FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
      WHERE c.relkind = 'r'
        AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
        AND pg_total_relation_size(c.oid) > 1024 * 1024 * 1024
        AND COALESCE(s.n_tup_del,0) = 0
        AND COALESCE(s.n_tup_ins,0) > 0)                                     AS large_append_only,
    (SELECT COUNT(*) FROM pg_partitioned_table)                              AS partitioned_parents;
