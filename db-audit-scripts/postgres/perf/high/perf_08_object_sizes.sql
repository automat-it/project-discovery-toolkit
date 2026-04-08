-- =============================================================================
-- perf_08_object_sizes.sql
-- Priority: HIGH
-- Purpose: Largest tables and indexes, growth hotspots, TOAST size.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database sizes
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    pg_size_pretty(pg_database_size(datname))            AS size,
    pg_database_size(datname)                            AS size_bytes
FROM pg_database
WHERE NOT datistemplate
ORDER BY pg_database_size(datname) DESC;

-- ---------------------------------------------------------------------------
-- Schema sizes in current database
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    pg_size_pretty(sum(pg_total_relation_size(c.oid)))   AS total_size,
    sum(pg_total_relation_size(c.oid))                   AS total_bytes,
    count(*) FILTER (WHERE c.relkind = 'r')              AS tables,
    count(*) FILTER (WHERE c.relkind = 'i')              AS indexes,
    count(*) FILTER (WHERE c.relkind = 'm')              AS matviews
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
GROUP BY n.nspname
ORDER BY total_bytes DESC;

-- ---------------------------------------------------------------------------
-- Top 50 largest tables (heap + indexes + toast)
-- ---------------------------------------------------------------------------
SELECT
    schemaname                                           AS schema,
    relname                                              AS table,
    pg_size_pretty(pg_total_relation_size(relid))        AS total_size,
    pg_size_pretty(pg_relation_size(relid))              AS heap_size,
    pg_size_pretty(pg_indexes_size(relid))               AS indexes_size,
    pg_size_pretty(pg_total_relation_size(relid)
                   - pg_relation_size(relid)
                   - pg_indexes_size(relid))             AS toast_size,
    n_live_tup                                           AS live_rows,
    n_dead_tup                                           AS dead_rows,
    pg_total_relation_size(relid)                        AS total_bytes
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Top 50 largest indexes
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    indexrelname                                         AS index,
    pg_size_pretty(pg_relation_size(indexrelid))         AS index_size,
    pg_size_pretty(pg_relation_size(relid))              AS table_size,
    idx_scan                                             AS scans,
    idx_tup_read                                         AS tuples_read
FROM pg_stat_user_indexes
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Tables where indexes are LARGER than the heap (write overhead candidates)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    pg_size_pretty(pg_relation_size(relid))              AS heap_size,
    pg_size_pretty(pg_indexes_size(relid))               AS indexes_size,
    round(pg_indexes_size(relid)::numeric
          / NULLIF(pg_relation_size(relid), 0), 2)       AS index_to_heap_ratio
FROM pg_stat_user_tables
WHERE pg_relation_size(relid) > 10 * 1024 * 1024
  AND pg_indexes_size(relid) > pg_relation_size(relid)
ORDER BY pg_indexes_size(relid) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Top TOAST tables (out-of-line storage for large values)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS toast_table,
    pg_size_pretty(pg_relation_size(c.oid))              AS size,
    parent.relname                                       AS parent_table,
    pg_size_pretty(pg_relation_size(parent.oid))         AS parent_heap_size
FROM pg_class c
JOIN pg_namespace n  ON n.oid = c.relnamespace
JOIN pg_class parent ON parent.reltoastrelid = c.oid
WHERE c.relkind = 't'
ORDER BY pg_relation_size(c.oid) DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Materialized views
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    matviewname                                          AS matview,
    ispopulated,
    hasindexes,
    pg_size_pretty(pg_total_relation_size(
        (schemaname || '.' || quote_ident(matviewname))::regclass
    ))                                                   AS size
FROM pg_matviews
ORDER BY pg_total_relation_size(
    (schemaname || '.' || quote_ident(matviewname))::regclass
) DESC;

-- ---------------------------------------------------------------------------
-- Partition sizes (for partitioned parents)
-- ---------------------------------------------------------------------------
SELECT
    parent.relnamespace::regnamespace                    AS schema,
    parent.relname                                       AS parent_table,
    child.relname                                        AS partition,
    pg_get_expr(child.relpartbound, child.oid)           AS bounds,
    pg_size_pretty(pg_total_relation_size(child.oid))    AS size,
    pg_total_relation_size(child.oid)                    AS size_bytes
FROM pg_inherits i
JOIN pg_class parent ON parent.oid = i.inhparent
JOIN pg_class child  ON child.oid  = i.inhrelid
WHERE parent.relkind = 'p'
ORDER BY parent.relname, pg_total_relation_size(child.oid) DESC;
