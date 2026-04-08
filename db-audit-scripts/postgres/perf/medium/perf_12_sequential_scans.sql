-- =============================================================================
-- perf_12_sequential_scans.sql
-- Priority: MEDIUM
-- Purpose: Tables with high sequential scan ratio — typically a missing
--          index indicator (or appropriate for very small / very hot tables).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Tables with high seq scan to index scan ratio (large tables only)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    seq_scan                                             AS seq_scans,
    seq_tup_read                                         AS seq_rows_read,
    idx_scan                                             AS idx_scans,
    idx_tup_fetch                                        AS idx_rows_fetched,
    n_live_tup                                           AS rows,
    pg_size_pretty(pg_relation_size(relid))              AS size,
    CASE WHEN seq_scan + idx_scan > 0
         THEN round(100.0 * seq_scan / (seq_scan + idx_scan), 2)
         ELSE 0
    END                                                  AS seq_pct,
    CASE WHEN seq_scan > 0
         THEN round(seq_tup_read::numeric / seq_scan, 0)
         ELSE 0
    END                                                  AS avg_rows_per_seq_scan
FROM pg_stat_user_tables
WHERE n_live_tup > 1000
  AND seq_scan > 0
ORDER BY seq_tup_read DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Tables where seq scans dominate over index scans
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    seq_scan,
    idx_scan,
    n_live_tup                                           AS rows,
    pg_size_pretty(pg_relation_size(relid))              AS size
FROM pg_stat_user_tables
WHERE seq_scan > coalesce(idx_scan, 0) * 5
  AND seq_scan > 100
  AND n_live_tup > 10000
ORDER BY seq_scan DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Tables with no indexes at all (excluding small tables)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    pg_size_pretty(pg_relation_size(c.oid))              AS size,
    s.n_live_tup                                         AS rows,
    s.seq_scan                                           AS seq_scans
FROM pg_class c
JOIN pg_namespace n         ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND NOT EXISTS (
      SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid
  )
  AND pg_relation_size(c.oid) > 1024 * 1024
ORDER BY pg_relation_size(c.oid) DESC;
