-- =============================================================================
-- perf_17_skewed_data.sql
-- Priority: LOW
-- Purpose: Detect uneven data distribution (skew) that leads to bad plans,
--          uneven parallel work, and partition hot spots.
-- Sources: sys.dm_db_stats_histogram, sys.stats, sys.partitions,
--          sys.dm_db_partition_stats.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Columns with very low cardinality (n_distinct approx) — read from the
-- histogram unique-value count.
-- ---------------------------------------------------------------------------
;WITH hist AS (
    SELECT
        s.object_id,
        s.stats_id,
        s.name                                        AS stat_name,
        MAX(dh.range_high_key)                        AS max_key,
        COUNT(DISTINCT dh.range_high_key)             AS distinct_ranges,
        SUM(dh.equal_rows)                            AS rows_equal,
        SUM(dh.range_rows)                            AS rows_range,
        MAX(dh.equal_rows)                            AS top_equal_rows
    FROM sys.stats s
    CROSS APPLY sys.dm_db_stats_histogram(s.object_id, s.stats_id) dh
    JOIN sys.objects o ON o.object_id = s.object_id
    WHERE o.is_ms_shipped = 0
    GROUP BY s.object_id, s.stats_id, s.name
)
SELECT TOP 50
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    h.stat_name,
    h.distinct_ranges,
    CAST(100.0 * h.top_equal_rows
         / NULLIF(h.rows_equal + h.rows_range, 0) AS DECIMAL(5,2)) AS top_value_pct,
    h.top_equal_rows                                  AS top_value_rows,
    h.rows_equal + h.rows_range                       AS total_stats_rows
FROM hist h
JOIN sys.objects o ON o.object_id = h.object_id
WHERE h.rows_equal + h.rows_range > 100
  AND CAST(100.0 * h.top_equal_rows
           / NULLIF(h.rows_equal + h.rows_range, 0) AS DECIMAL(5,2)) > 30
ORDER BY top_value_pct DESC;

-- ---------------------------------------------------------------------------
-- Histograms with very few steps (likely skewed / low-cardinality columns)
-- ---------------------------------------------------------------------------
;WITH step_count AS (
    SELECT
        s.object_id,
        s.stats_id,
        s.name                                        AS stat_name,
        COUNT(*)                                      AS step_count
    FROM sys.stats s
    CROSS APPLY sys.dm_db_stats_histogram(s.object_id, s.stats_id) dh
    JOIN sys.objects o ON o.object_id = s.object_id
    WHERE o.is_ms_shipped = 0
    GROUP BY s.object_id, s.stats_id, s.name
)
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    sc.stat_name,
    sc.step_count,
    sp.rows,
    sp.rows_sampled
FROM step_count sc
JOIN sys.objects o ON o.object_id = sc.object_id
OUTER APPLY sys.dm_db_stats_properties(sc.object_id, sc.stats_id) sp
WHERE sp.rows > 1000
  AND sc.step_count <= 5
ORDER BY sp.rows DESC;

-- ---------------------------------------------------------------------------
-- Partitioned tables — rows per partition (partition skew)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    p.partition_number,
    p.rows,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.partitions p
JOIN sys.indexes i            ON i.object_id = p.object_id AND i.index_id = p.index_id
JOIN sys.objects o            ON o.object_id = p.object_id
LEFT JOIN sys.dm_db_partition_stats ps
      ON ps.object_id = p.object_id
     AND ps.index_id  = p.index_id
     AND ps.partition_number = p.partition_number
WHERE i.index_id IN (0, 1)
  AND EXISTS (SELECT 1 FROM sys.partitions p2
               WHERE p2.object_id = p.object_id
                 AND p2.index_id  = p.index_id
                 AND p2.partition_number > 1)
  AND o.is_ms_shipped = 0
GROUP BY o.schema_id, o.name, i.name, p.partition_number, p.rows
ORDER BY schema_name, table_name, p.partition_number;

-- ---------------------------------------------------------------------------
-- Columns with very high NULL fraction (inferred from first histogram step)
-- ---------------------------------------------------------------------------
;WITH null_stats AS (
    SELECT
        s.object_id,
        s.stats_id,
        s.name                                        AS stat_name,
        MIN(dh.range_high_key)                        AS first_bucket_high_key,
        dh_first.equal_rows                           AS first_bucket_rows
    FROM sys.stats s
    CROSS APPLY sys.dm_db_stats_histogram(s.object_id, s.stats_id) dh
    CROSS APPLY (
        SELECT TOP 1 dh2.equal_rows, dh2.range_high_key
          FROM sys.dm_db_stats_histogram(s.object_id, s.stats_id) dh2
         ORDER BY dh2.step_number
    ) dh_first
    JOIN sys.objects o ON o.object_id = s.object_id
    WHERE o.is_ms_shipped = 0
    GROUP BY s.object_id, s.stats_id, s.name, dh_first.equal_rows
)
SELECT TOP 30
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    ns.stat_name,
    ns.first_bucket_rows,
    sp.rows,
    CAST(100.0 * ns.first_bucket_rows / NULLIF(sp.rows, 0) AS DECIMAL(5,2)) AS first_bucket_pct
FROM null_stats ns
JOIN sys.objects o ON o.object_id = ns.object_id
OUTER APPLY sys.dm_db_stats_properties(ns.object_id, ns.stats_id) sp
WHERE sp.rows > 1000
  AND ns.first_bucket_rows > sp.rows * 0.5
ORDER BY first_bucket_pct DESC;
