-- =============================================================================
-- perf_21_partition_health.sql
-- Priority: MEDIUM
-- Purpose: Inventory partition functions, partition schemes, partitioned
--          tables/indexes, row skew across partitions, boundary values.
--          Sliding-window partitioning with a missing right-hand empty
--          partition is a silent time-bomb.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Partition functions — one per table family, plus boundary type and
-- whether the range is LEFT or RIGHT.
-- ---------------------------------------------------------------------------
SELECT
    pf.name                                               AS partition_function,
    pf.function_id,
    pf.type_desc,
    pf.fanout                                             AS boundary_count,
    CASE pf.boundary_value_on_right
        WHEN 1 THEN 'RIGHT'
        ELSE 'LEFT'
    END                                                   AS range_direction,
    pf.create_date,
    pf.modify_date
FROM sys.partition_functions pf
ORDER BY pf.name;

-- ---------------------------------------------------------------------------
-- Partition schemes — map functions to filegroups
-- ---------------------------------------------------------------------------
SELECT
    ps.name                                               AS partition_scheme,
    pf.name                                               AS partition_function,
    ps.is_default,
    (SELECT COUNT(*) FROM sys.destination_data_spaces dds
      WHERE dds.partition_scheme_id = ps.data_space_id)   AS destination_count
FROM sys.partition_schemes ps
JOIN sys.partition_functions pf ON pf.function_id = ps.function_id
ORDER BY ps.name;

-- ---------------------------------------------------------------------------
-- Partitioned tables — row count per partition, size per partition
-- ---------------------------------------------------------------------------
SELECT
    s.name                                                AS schema_name,
    o.name                                                AS table_name,
    i.name                                                AS index_name,
    i.type_desc                                           AS index_type,
    p.partition_number,
    p.rows                                                AS row_count,
    CAST(SUM(au.total_pages)   * 8 / 1024.0 AS DECIMAL(18,1))  AS total_mb,
    CAST(SUM(au.used_pages)    * 8 / 1024.0 AS DECIMAL(18,1))  AS used_mb,
    ds.name                                               AS filegroup,
    pf.name                                               AS partition_function
FROM sys.partitions p
JOIN sys.objects         o  ON o.object_id = p.object_id
JOIN sys.schemas         s  ON s.schema_id = o.schema_id
JOIN sys.indexes         i  ON i.object_id = p.object_id AND i.index_id = p.index_id
JOIN sys.allocation_units au ON au.container_id = p.partition_id
JOIN sys.destination_data_spaces dds
     ON dds.partition_scheme_id = i.data_space_id
    AND dds.destination_id      = p.partition_number
JOIN sys.data_spaces     ds ON ds.data_space_id = dds.data_space_id
JOIN sys.partition_schemes ps ON ps.data_space_id = i.data_space_id
JOIN sys.partition_functions pf ON pf.function_id = ps.function_id
WHERE o.type = 'U'
  AND i.index_id IN (0, 1)      -- heap or clustered only; one row per partition
GROUP BY s.name, o.name, i.name, i.type_desc, p.partition_number, p.rows,
         ds.name, pf.name
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Boundary values per partition function — shows the schedule of
-- active ranges and whether a right-edge empty partition exists.
-- ---------------------------------------------------------------------------
SELECT
    pf.name                                               AS partition_function,
    prv.boundary_id,
    prv.value                                             AS boundary_value
FROM sys.partition_range_values prv
JOIN sys.partition_functions pf ON pf.function_id = prv.function_id
ORDER BY pf.name, prv.boundary_id;

-- ---------------------------------------------------------------------------
-- Tables with extreme partition skew — largest partition > 5× median
-- of the rest. Indicates hot partition / poor key choice.
-- ---------------------------------------------------------------------------
;WITH per_tbl AS (
    SELECT
        o.object_id, s.name AS schema_name, o.name AS table_name,
        p.partition_number, p.rows
    FROM sys.partitions p
    JOIN sys.objects  o ON o.object_id = p.object_id
    JOIN sys.schemas  s ON s.schema_id = o.schema_id
    WHERE o.type = 'U' AND p.index_id IN (0,1) AND p.rows > 0
), agg AS (
    SELECT
        schema_name, table_name,
        COUNT(*)                                          AS part_count,
        MAX(rows)                                         AS max_rows,
        AVG(CAST(rows AS BIGINT))                         AS avg_rows,
        SUM(rows)                                         AS total_rows
    FROM per_tbl
    GROUP BY schema_name, table_name
)
SELECT
    schema_name, table_name, part_count, max_rows, avg_rows, total_rows,
    CASE WHEN avg_rows > 0 THEN
        CAST(max_rows * 1.0 / avg_rows AS DECIMAL(10,2))
    END                                                   AS max_over_avg_ratio
FROM agg
WHERE part_count > 1
ORDER BY max_over_avg_ratio DESC;

-- ---------------------------------------------------------------------------
-- Partitioned tables missing a right-edge empty partition — sliding-window
-- pattern should keep an empty future partition so SWITCH IN can merge.
-- Heuristic: highest-numbered partition has rows = 0 → good. Has rows → risk.
-- ---------------------------------------------------------------------------
;WITH last_part AS (
    SELECT
        o.object_id, s.name AS schema_name, o.name AS table_name,
        MAX(p.partition_number)                            AS last_part_num
    FROM sys.partitions p
    JOIN sys.objects  o ON o.object_id = p.object_id
    JOIN sys.schemas  s ON s.schema_id = o.schema_id
    WHERE p.index_id IN (0,1)
    GROUP BY o.object_id, s.name, o.name
    HAVING MAX(p.partition_number) > 1
)
SELECT
    lp.schema_name,
    lp.table_name,
    lp.last_part_num,
    p.rows                                                AS rows_in_last_part,
    CASE WHEN p.rows = 0 THEN 'ok — empty right edge'
         ELSE 'no right-edge empty partition — SWITCH window risk' END AS assessment
FROM last_part lp
JOIN sys.partitions p
  ON p.object_id = lp.object_id AND p.partition_number = lp.last_part_num
 AND p.index_id IN (0,1)
ORDER BY p.rows DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.partition_functions)        AS partition_functions,
    (SELECT COUNT(*) FROM sys.partition_schemes)          AS partition_schemes,
    (SELECT COUNT(DISTINCT object_id)
       FROM sys.partitions
      WHERE partition_number > 1)                         AS partitioned_tables,
    (SELECT COUNT(*) FROM sys.partitions
      WHERE partition_number > 1 AND index_id IN (0,1))   AS total_data_partitions;
