-- =============================================================================
-- perf_21_partition_health.sql
-- Priority: MEDIUM
-- Purpose: Inventory declarative partitioned tables, child partitions,
--          bound definitions, sizes, and pruning signals. A partitioned
--          table with thousands of children or a missing default
--          partition is a planner hazard.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Planner knobs that govern partition behaviour
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'enable_partition_pruning',
    'enable_partitionwise_join',
    'enable_partitionwise_aggregate',
    'constraint_exclusion'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Declarative partitioned parents + strategy + partition-key definition
-- partstrat: 'r' range, 'l' list, 'h' hash
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    c.relname                                             AS parent_table,
    CASE pt.partstrat
        WHEN 'r' THEN 'range'
        WHEN 'l' THEN 'list'
        WHEN 'h' THEN 'hash'
    END                                                   AS strategy,
    pg_get_partkeydef(c.oid)                              AS partition_key,
    (SELECT COUNT(*) FROM pg_inherits i WHERE i.inhparent = c.oid) AS child_count,
    pg_size_pretty(pg_total_relation_size(c.oid))         AS total_size
FROM pg_partitioned_table pt
JOIN pg_class c     ON c.oid = pt.partrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
ORDER BY pg_total_relation_size(c.oid) DESC;

-- ---------------------------------------------------------------------------
-- Child partitions + bound expressions + per-partition size + row estimate
-- ---------------------------------------------------------------------------
SELECT
    pn.nspname                                            AS parent_schema,
    p.relname                                             AS parent_table,
    cn.nspname                                            AS child_schema,
    c.relname                                             AS child_partition,
    pg_get_expr(c.relpartbound, c.oid)                    AS partition_bound,
    c.reltuples::bigint                                   AS est_rows,
    pg_size_pretty(pg_total_relation_size(c.oid))         AS size,
    pg_total_relation_size(c.oid)                         AS size_bytes
FROM pg_inherits i
JOIN pg_class      p  ON p.oid  = i.inhparent
JOIN pg_namespace  pn ON pn.oid = p.relnamespace
JOIN pg_class      c  ON c.oid  = i.inhrelid
JOIN pg_namespace  cn ON cn.oid = c.relnamespace
WHERE p.relkind = 'p'          -- only declarative partition parents
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- Parents with DEFAULT partition presence check — a missing DEFAULT on a
-- list/range partitioned table causes INSERT failures on unmatched keys.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    p.relname                                             AS parent,
    CASE pt.partstrat WHEN 'r' THEN 'range' WHEN 'l' THEN 'list' WHEN 'h' THEN 'hash' END AS strategy,
    EXISTS (
        SELECT 1
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = p.oid
           AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
    )                                                     AS has_default_partition
FROM pg_partitioned_table pt
JOIN pg_class p     ON p.oid = pt.partrelid
JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE pt.partstrat IN ('r', 'l')
ORDER BY has_default_partition, n.nspname, p.relname;

-- ---------------------------------------------------------------------------
-- Partition count distribution — parents with > 1 000 children stress
-- the planner; partitionwise features fall back to non-partitioned plans
-- past certain thresholds.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                             AS schema,
    p.relname                                             AS parent,
    (SELECT COUNT(*) FROM pg_inherits i WHERE i.inhparent = p.oid) AS child_count,
    CASE
        WHEN (SELECT COUNT(*) FROM pg_inherits i WHERE i.inhparent = p.oid) > 1000
            THEN 'extreme — planner stress'
        WHEN (SELECT COUNT(*) FROM pg_inherits i WHERE i.inhparent = p.oid) > 200
            THEN 'high — review retention'
        ELSE 'ok'
    END                                                   AS assessment
FROM pg_partitioned_table pt
JOIN pg_class p     ON p.oid = pt.partrelid
JOIN pg_namespace n ON n.oid = p.relnamespace
ORDER BY child_count DESC;

-- ---------------------------------------------------------------------------
-- Child partitions last-analyze / last-vacuum — stale stats on partitions
-- break plan-time pruning.
-- ---------------------------------------------------------------------------
SELECT
    s.schemaname,
    s.relname,
    s.n_live_tup,
    s.last_analyze,
    s.last_autoanalyze,
    s.last_vacuum,
    s.last_autovacuum
FROM pg_stat_all_tables s
JOIN pg_class c ON c.oid = s.relid
WHERE c.relispartition = true
ORDER BY COALESCE(s.last_analyze, s.last_autoanalyze) NULLS FIRST
LIMIT 100;

-- ---------------------------------------------------------------------------
-- Legacy inheritance-based partitioning (pre-10) — detect non-declarative
-- parents still in use. Heuristic: parent tables with children but no
-- entry in pg_partitioned_table.
-- ---------------------------------------------------------------------------
SELECT
    pn.nspname                                            AS schema,
    p.relname                                             AS legacy_parent,
    (SELECT COUNT(*) FROM pg_inherits i WHERE i.inhparent = p.oid) AS child_count
FROM pg_class p
JOIN pg_namespace pn ON pn.oid = p.relnamespace
WHERE p.relkind = 'r'
  AND EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = p.oid)
  AND NOT EXISTS (SELECT 1 FROM pg_partitioned_table pt WHERE pt.partrelid = p.oid)
ORDER BY child_count DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM pg_partitioned_table)                            AS partitioned_parents,
    (SELECT COUNT(*) FROM pg_class WHERE relispartition = true)            AS partition_children,
    (SELECT COUNT(*) FROM pg_partitioned_table pt
       WHERE pt.partstrat IN ('r','l')
         AND NOT EXISTS (SELECT 1 FROM pg_inherits i
                          JOIN pg_class c ON c.oid = i.inhrelid
                         WHERE i.inhparent = pt.partrelid
                           AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'))
                                                                            AS parents_missing_default;
