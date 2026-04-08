-- =============================================================================
-- perf_17_skewed_data.sql
-- Priority: LOW
-- Purpose: Detect uneven data distribution (skew) which leads to bad plans,
--          uneven parallel work, and partition hot spots.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Columns with very low cardinality (< 1% distinct values)
-- These often correlate with skew when used in WHERE / JOIN.
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    tablename                                            AS table,
    attname                                              AS column,
    n_distinct,
    null_frac,
    correlation,
    avg_width
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND n_distinct BETWEEN 1 AND 100
  AND n_distinct > 0
ORDER BY schemaname, tablename, n_distinct;

-- ---------------------------------------------------------------------------
-- Columns with negative n_distinct (a fraction of total rows)
-- close to 0 indicates many duplicates / skew.
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    tablename                                            AS table,
    attname                                              AS column,
    n_distinct,
    null_frac,
    correlation
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND n_distinct < 0
  AND n_distinct > -0.01
ORDER BY n_distinct;

-- ---------------------------------------------------------------------------
-- Columns where most_common_freqs has very high values (heavy hitters)
-- A value > 0.5 means one MCV dominates the column.
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    tablename                                            AS table,
    attname                                              AS column,
    null_frac,
    n_distinct,
    most_common_vals[1:5]                                AS top_values,
    most_common_freqs[1:5]                               AS top_freqs
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND most_common_freqs IS NOT NULL
  AND most_common_freqs[1] > 0.5
ORDER BY most_common_freqs[1] DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Highly null columns (> 90% NULL)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    tablename                                            AS table,
    attname                                              AS column,
    null_frac,
    n_distinct,
    avg_width
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND null_frac > 0.9
ORDER BY null_frac DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Partitioned tables: partition row count skew
-- ---------------------------------------------------------------------------
SELECT
    parent.relnamespace::regnamespace                    AS schema,
    parent.relname                                       AS parent_table,
    child.relname                                        AS partition,
    s.n_live_tup                                         AS rows,
    pg_size_pretty(pg_total_relation_size(child.oid))    AS size
FROM pg_inherits i
JOIN pg_class parent     ON parent.oid = i.inhparent
JOIN pg_class child      ON child.oid  = i.inhrelid
LEFT JOIN pg_stat_user_tables s ON s.relid = child.oid
WHERE parent.relkind = 'p'
ORDER BY parent.relname, s.n_live_tup DESC NULLS LAST;
