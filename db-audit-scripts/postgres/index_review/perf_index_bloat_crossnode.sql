-- =============================================================================
-- perf_index_bloat_crossnode.sql
-- Purpose: Per-node index-usage capture for an unused / low-use index review
--          across a multi-node cluster (Aurora PostgreSQL writer + readers,
--          or RDS / self-managed primary + streaming replicas).
--
-- Why per node: pg_stat_user_indexes counters live in each instance's own
-- memory and are NOT replicated. An index used only by reader traffic shows
-- idx_scan = 0 on the writer. Run this script once on EVERY instance (use the
-- instance endpoints, not the cluster / reader DNS endpoints) and combine the
-- outputs with merge_index_usage.py - an index is unused only if it is unused
-- on all nodes.
--
-- Output: ONE CSV result set, one row per leaf index, every row carrying the
-- node identity and stats window so each capture file is self-describing.
-- Run with:  psql -X -q --csv -f perf_index_bloat_crossnode.sql -o <file>.csv
--
-- Partition-aware: each leaf index is mapped to its root (parent-level)
-- index and gets a newest-first rank among its table's partitions, so the
-- merge step can judge a parent-level index by its use in recent partitions.
--
-- Requires: PostgreSQL 13+ (pg_partition_root), psql 12+ client (--csv).
-- Read-only: catalog / statistics views only.
-- =============================================================================

\set ON_ERROR_STOP on

-- Node identity: Aurora exposes the instance identifier (stable across
-- restarts and failovers, unlike the private IP); elsewhere fall back to the
-- server address and port. Aurora hides the function from pg_proc, so probe
-- it with to_regprocedure() instead of a catalog lookup.
SELECT to_regprocedure('aurora_db_instance_identifier()') IS NOT NULL AS is_aurora
\gset
\if :is_aurora
SELECT aurora_db_instance_identifier() AS node_id
\gset
\else
SELECT coalesce(host(inet_server_addr()), 'local') || ':' || current_setting('port') AS node_id
\gset
\endif

WITH tbl AS (
    -- Every table / matview with its partition root and a newest-first rank
    -- among the leaf partitions of that root. Rank uses creation order (OID);
    -- partition_bound is emitted so the order can be verified by eye.
    SELECT
        c.oid                                                    AS relid,
        coalesce(pg_partition_root(c.oid), c.oid)                AS root_relid,
        c.relispartition                                         AS is_partition,
        pg_get_expr(c.relpartbound, c.oid)                       AS partition_bound,
        CASE WHEN c.relispartition THEN
            row_number() OVER (
                PARTITION BY coalesce(pg_partition_root(c.oid), c.oid),
                             c.relispartition
                ORDER BY c.oid DESC)
        END                                                      AS partition_rank_newest
    FROM pg_class c
    WHERE c.relkind IN ('r', 'm')
),
idx AS (
    SELECT
        s.indexrelid,
        s.relid,
        coalesce(pg_partition_root(s.indexrelid), s.indexrelid)  AS root_indexrelid
    FROM pg_stat_user_indexes s
)
SELECT
    :'node_id'                                                   AS node_id,
    CASE WHEN pg_is_in_recovery() THEN 'reader' ELSE 'writer' END AS node_role,
    now()                                                        AS captured_at,
    (SELECT d.stats_reset FROM pg_stat_database d
      WHERE d.datname = current_database())                      AS stats_reset,
    pg_postmaster_start_time()                                   AS postmaster_start,
    current_database()                                           AS database,
    s.schemaname                                                 AS schema_name,
    s.relname                                                    AS table_name,
    s.indexrelname                                               AS index_name,
    (SELECT format('%I.%I', n.nspname, c.relname)
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.oid = t.root_relid)                                AS root_table,
    (SELECT format('%I.%I', n.nspname, c.relname)
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.oid = x.root_indexrelid)                           AS root_index,
    (SELECT c.relkind = 'I' FROM pg_class c
      WHERE c.oid = x.root_indexrelid)                           AS root_is_partitioned_index,
    t.is_partition,
    t.partition_rank_newest,
    t.partition_bound,
    pg_relation_size(s.indexrelid)                               AS index_bytes,
    s.idx_scan,
    s.idx_tup_read,
    s.idx_tup_fetch,
    -- last_idx_scan exists from PG16; read it via jsonb so older versions
    -- return NULL instead of failing on a missing column.
    to_jsonb(s) ->> 'last_idx_scan'                              AS last_idx_scan,
    i.indisunique                                                AS is_unique,
    i.indisprimary                                               AS is_primary,
    EXISTS (SELECT 1 FROM pg_constraint con
             WHERE con.conindid = s.indexrelid)                  AS backs_constraint,
    i.indisvalid                                                 AS is_valid,
    -- Index maintenance driver on the writer: every insert and every
    -- non-HOT update touches every index on the table. Readers report ~0.
    coalesce(ut.n_tup_ins, 0) + coalesce(ut.n_tup_upd, 0)
        - coalesce(ut.n_tup_hot_upd, 0)                          AS table_index_write_ops,
    pg_get_indexdef(s.indexrelid)                                AS index_def,
    pg_get_indexdef(x.root_indexrelid)                           AS root_index_def
FROM pg_stat_user_indexes s
JOIN idx x                    ON x.indexrelid = s.indexrelid
JOIN pg_index i               ON i.indexrelid = s.indexrelid
JOIN tbl t                    ON t.relid      = s.relid
LEFT JOIN pg_stat_user_tables ut ON ut.relid  = s.relid
ORDER BY index_bytes DESC;
