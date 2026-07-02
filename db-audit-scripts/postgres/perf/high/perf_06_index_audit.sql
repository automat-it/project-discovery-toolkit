-- =============================================================================
-- perf_06_index_audit.sql
-- Priority: HIGH
-- Purpose: Find unused, duplicate, invalid, and missing indexes.
--          Direct impact on read latency and write overhead.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Unused indexes (zero or near-zero scans, > 1 MB)
-- Excludes primary keys and unique constraint indexes.
-- ---------------------------------------------------------------------------
SELECT
    s.schemaname,
    s.relname                                            AS table,
    s.indexrelname                                       AS index,
    pg_size_pretty(pg_relation_size(s.indexrelid))       AS size,
    pg_relation_size(s.indexrelid)                       AS size_bytes,
    s.idx_scan                                           AS scans,
    s.idx_tup_read                                       AS tuples_read,
    s.idx_tup_fetch                                      AS tuples_fetched
FROM pg_stat_user_indexes s
JOIN pg_index i ON i.indexrelid = s.indexrelid
WHERE s.idx_scan < 50
  AND NOT i.indisunique
  AND NOT i.indisprimary
  AND pg_relation_size(s.indexrelid) > 1024 * 1024
ORDER BY pg_relation_size(s.indexrelid) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Indexes that have NEVER been scanned
-- ---------------------------------------------------------------------------
SELECT
    s.schemaname,
    s.relname                                            AS table,
    s.indexrelname                                       AS index,
    pg_size_pretty(pg_relation_size(s.indexrelid))       AS size,
    i.indisunique                                        AS is_unique,
    i.indisprimary                                       AS is_primary
FROM pg_stat_user_indexes s
JOIN pg_index i ON i.indexrelid = s.indexrelid
WHERE s.idx_scan = 0
ORDER BY pg_relation_size(s.indexrelid) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Duplicate indexes (strict): same table, same key columns, same opclass,
-- same collation, same column options (DESC/NULLS FIRST), same predicate,
-- same INCLUDE columns, same uniqueness. This is the safe "drop candidate
-- detector" — pairs found here are functionally equivalent.
--
-- Quick heuristic comparison by indkey alone is intentionally NOT used here
-- because it produces false positives across partial indexes, INCLUDE
-- columns, and different opclass / collation / sort order.
-- ---------------------------------------------------------------------------
WITH idx AS (
    SELECT
        i.indexrelid,
        i.indrelid,
        i.indkey::text                                   AS keycols,
        i.indclass::text                                 AS opclasses,
        i.indcollation::text                             AS collations,
        i.indoption::text                                AS options,
        coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS predicate,
        i.indisunique                                    AS is_unique,
        i.indnkeyatts                                    AS key_attrs,
        i.indnatts                                       AS total_attrs,
        -- INCLUDE columns are positions (key_attrs+1 .. total_attrs)
        CASE WHEN i.indnatts > i.indnkeyatts
             THEN (string_to_array(i.indkey::text, ' '))[i.indnkeyatts + 1 : i.indnatts]
             ELSE NULL
        END                                              AS include_cols
    FROM pg_index i
    WHERE i.indisvalid
)
SELECT
    a.indrelid::regclass                                 AS table,
    a.indexrelid::regclass                               AS index_a,
    b.indexrelid::regclass                               AS index_b,
    pg_size_pretty(pg_relation_size(a.indexrelid))       AS size_a,
    pg_size_pretty(pg_relation_size(b.indexrelid))       AS size_b,
    pg_get_indexdef(a.indexrelid)                        AS definition_a,
    pg_get_indexdef(b.indexrelid)                        AS definition_b
FROM idx a
JOIN idx b
  ON a.indrelid    = b.indrelid
 AND a.indexrelid <> b.indexrelid
 AND a.indexrelid  < b.indexrelid
 AND a.keycols     = b.keycols
 AND a.opclasses   = b.opclasses
 AND a.collations  = b.collations
 AND a.options     = b.options
 AND a.predicate   = b.predicate
 AND a.is_unique   = b.is_unique
 AND a.key_attrs   = b.key_attrs
 AND a.total_attrs = b.total_attrs
 AND coalesce(a.include_cols, ARRAY[]::text[])
   = coalesce(b.include_cols, ARRAY[]::text[]);

-- ---------------------------------------------------------------------------
-- Heuristic duplicate hint (loose): same key columns ignoring everything
-- else. Use this as a SECOND look — investigate each pair manually before
-- dropping anything. Pairs already returned by the strict query above
-- are excluded.
-- ---------------------------------------------------------------------------
SELECT
    a.indrelid::regclass                                 AS table,
    a.indexrelid::regclass                               AS index_a,
    b.indexrelid::regclass                               AS index_b,
    pg_size_pretty(pg_relation_size(a.indexrelid))       AS size_a,
    pg_size_pretty(pg_relation_size(b.indexrelid))       AS size_b,
    pg_get_indexdef(a.indexrelid)                        AS definition_a,
    pg_get_indexdef(b.indexrelid)                        AS definition_b,
    'review — partial / opclass / collation / INCLUDE may differ' AS note
FROM pg_index a
JOIN pg_index b
  ON a.indrelid     = b.indrelid
 AND a.indkey::text = b.indkey::text
 AND a.indexrelid  <> b.indexrelid
 AND a.indexrelid   < b.indexrelid
WHERE pg_get_indexdef(a.indexrelid) <> pg_get_indexdef(b.indexrelid);

-- ---------------------------------------------------------------------------
-- Overlapping indexes (one is a prefix of another — possibly redundant)
-- ---------------------------------------------------------------------------
SELECT
    a.indrelid::regclass                                 AS table,
    a.indexrelid::regclass                               AS narrow_index,
    pg_size_pretty(pg_relation_size(a.indexrelid))       AS narrow_size,
    b.indexrelid::regclass                               AS wide_index,
    pg_size_pretty(pg_relation_size(b.indexrelid))       AS wide_size,
    pg_get_indexdef(a.indexrelid)                        AS narrow_def,
    pg_get_indexdef(b.indexrelid)                        AS wide_def
FROM pg_index a
JOIN pg_index b
  ON a.indrelid    = b.indrelid
 AND a.indexrelid <> b.indexrelid
 AND b.indkey::text LIKE a.indkey::text || ' %'
WHERE NOT a.indisunique
  AND NOT a.indisprimary;

-- ---------------------------------------------------------------------------
-- Invalid indexes (failed CREATE INDEX CONCURRENTLY — must be rebuilt)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS index,
    pg_size_pretty(pg_relation_size(c.oid))              AS size,
    i.indrelid::regclass                                 AS table
FROM pg_index i
JOIN pg_class c     ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE NOT i.indisvalid;

-- ---------------------------------------------------------------------------
-- Indexes not ready (CREATE INDEX CONCURRENTLY in progress or failed)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS index,
    i.indrelid::regclass                                 AS table
FROM pg_index i
JOIN pg_class c     ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE NOT i.indisready;

-- ---------------------------------------------------------------------------
-- Missing indexes hint: tables with high seq scans on large data
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_live_tup                                           AS rows,
    pg_size_pretty(pg_relation_size(relid))              AS table_size,
    CASE WHEN seq_scan > 0
         THEN round(seq_tup_read::numeric / seq_scan, 0)
         ELSE 0
    END                                                  AS avg_rows_per_seq_scan
FROM pg_stat_user_tables
WHERE seq_scan > 100
  AND n_live_tup > 10000
  AND seq_tup_read > 1000000
ORDER BY seq_tup_read DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Foreign keys without supporting indexes (slow DELETEs / cascades).
-- A FK is "supported" iff some index on the referencing table starts with
-- exactly the same column list, in the same order, as the FK columns.
-- This handles BOTH single-column and composite foreign keys correctly.
-- ---------------------------------------------------------------------------
WITH fk AS (
    SELECT
        c.oid                                            AS conid,
        c.conrelid                                       AS table_oid,
        c.conrelid::regclass                             AS table,
        c.conname                                        AS fk_constraint,
        c.conkey                                         AS fk_cols,
        array_length(c.conkey, 1)                        AS fk_col_count,
        pg_get_constraintdef(c.oid)                      AS definition,
        pg_relation_size(c.conrelid)                     AS table_size_bytes
    FROM pg_constraint c
    WHERE c.contype = 'f'
),
ix AS (
    SELECT
        i.indrelid                                       AS table_oid,
        i.indexrelid                                     AS index_oid,
        -- Take only the leading key columns (exclude INCLUDE columns)
        (string_to_array(i.indkey::text, ' '))[1 : i.indnkeyatts]::int[]
                                                         AS key_cols,
        i.indnkeyatts                                    AS key_attrs,
        i.indpred IS NULL                                AS is_full
    FROM pg_index i
    WHERE i.indisvalid
)
SELECT
    fk.table,
    fk.fk_constraint,
    fk.fk_col_count                                      AS fk_columns,
    fk.definition,
    pg_size_pretty(fk.table_size_bytes)                  AS table_size
FROM fk
WHERE NOT EXISTS (
    SELECT 1
    FROM ix
    WHERE ix.table_oid = fk.table_oid
      AND ix.is_full
      AND ix.key_attrs >= fk.fk_col_count
      -- Index leading columns must equal FK columns in the same order
      AND ix.key_cols[1 : fk.fk_col_count] = fk.fk_cols::int[]
)
ORDER BY fk.table_size_bytes DESC;
