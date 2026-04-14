-- =============================================================================
-- perf_11_bloat_estimation.sql
-- Priority: MEDIUM
-- Purpose: Estimate table and index bloat. Affects I/O and cache efficiency.
-- Note: This uses a heuristic estimate based on pg_class statistics. For
--       precise numbers use pgstattuple (which requires the extension).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Quick dead-tuple based bloat indicator (no external functions)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    n_live_tup,
    n_dead_tup,
    CASE WHEN n_live_tup + n_dead_tup > 0
         THEN round(100.0 * n_dead_tup / (n_live_tup + n_dead_tup), 2)
         ELSE 0
    END                                                  AS dead_pct,
    pg_size_pretty(pg_relation_size(relid))              AS heap_size,
    pg_size_pretty(pg_total_relation_size(relid))        AS total_size,
    last_autovacuum,
    last_vacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Heuristic table bloat estimate (ioguix/check_postgres style)
-- Estimates expected size from row width and tuple count, then compares
-- against actual size. Approximate only.
-- ---------------------------------------------------------------------------
WITH constants AS (
    SELECT
        current_setting('block_size')::numeric           AS bs,
        23                                               AS hdr,
        8                                                AS ma
),
no_stats AS (
    SELECT table_schema, table_name,
           n_live_tup::numeric AS est_rows,
           pg_table_size(c.oid) AS table_size
    FROM information_schema.columns
    JOIN pg_stat_user_tables psut
        ON table_schema = psut.schemaname
       AND table_name   = psut.relname
    LEFT JOIN pg_stats
        ON table_schema = pg_stats.schemaname
       AND table_name   = pg_stats.tablename
       AND column_name  = attname
    JOIN pg_class c
        ON c.relname = table_name
    WHERE attname IS NULL
      AND table_schema NOT IN ('pg_catalog', 'information_schema')
    GROUP BY table_schema, table_name, n_live_tup, c.oid
),
null_headers AS (
    SELECT
        hdr + 1
            + (sum(case when null_frac <> 0 then 1 else 0 end) / 8)  AS nullhdr,
        sum((1 - null_frac) * avg_width)                 AS datawidth,
        max(null_frac)                                   AS maxfracsum,
        schemaname,
        tablename,
        hdr, ma, bs
    FROM pg_stats
    CROSS JOIN constants
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
    GROUP BY schemaname, tablename, hdr, ma, bs
),
data_headers AS (
    SELECT
        ma, bs, hdr, schemaname, tablename,
        (datawidth + (hdr + ma
                     - case when hdr % ma = 0 then ma else hdr % ma end))::numeric
                                                         AS datahdr,
        (maxfracsum * (nullhdr + ma
                     - case when nullhdr % ma = 0 then ma else nullhdr % ma end))
                                                         AS nullhdr2
    FROM null_headers
),
table_estimates AS (
    SELECT
        schemaname,
        tablename,
        bs,
        reltuples::numeric                               AS est_rows,
        relpages * bs                                    AS table_bytes,
        ceil((reltuples *
            (datahdr + nullhdr2 + 4 + ma
             - case when datahdr % ma = 0
                    then ma else datahdr % ma end)
            ) / (bs - 20::float)) * bs                   AS expected_bytes
    FROM data_headers
    JOIN pg_namespace
        ON schemaname = pg_namespace.nspname
    JOIN pg_class
        ON pg_class.relname      = tablename
       AND pg_class.relnamespace = pg_namespace.oid
    WHERE pg_class.relkind = 'r'
)
SELECT
    schemaname,
    tablename                                            AS table,
    pg_size_pretty(table_bytes::bigint)                  AS actual_size,
    pg_size_pretty(expected_bytes::bigint)               AS expected_size,
    pg_size_pretty((table_bytes - expected_bytes)::bigint)
                                                         AS bloat_size,
    CASE WHEN table_bytes > 0
         THEN round((100.0 * (table_bytes - expected_bytes)
                          / table_bytes)::numeric, 2)
         ELSE 0
    END                                                  AS bloat_pct
FROM table_estimates
WHERE table_bytes > 10 * 1024 * 1024
  AND table_bytes > expected_bytes
ORDER BY (table_bytes - expected_bytes) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Index size vs table size (very large index relative to small table = bloat)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    indexrelname                                         AS index,
    pg_size_pretty(pg_relation_size(indexrelid))         AS index_size,
    pg_size_pretty(pg_relation_size(relid))              AS table_size,
    round(pg_relation_size(indexrelid)::numeric
          / NULLIF(pg_relation_size(relid), 0), 2)       AS index_table_ratio,
    idx_scan
FROM pg_stat_user_indexes
WHERE pg_relation_size(indexrelid) > 10 * 1024 * 1024
  AND pg_relation_size(indexrelid) > pg_relation_size(relid)
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 30;
