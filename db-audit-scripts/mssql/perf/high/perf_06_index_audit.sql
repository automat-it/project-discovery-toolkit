-- =============================================================================
-- perf_06_index_audit.sql
-- Priority: HIGH
-- Purpose: Find unused, duplicate, overlapping, disabled, and missing
--          indexes. Direct impact on read latency and write overhead.
-- Sources: sys.indexes, sys.dm_db_index_usage_stats,
--          sys.dm_db_missing_index_details, sys.foreign_keys.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
-- FOR XML PATH / .value() require QUOTED_IDENTIFIER ON. sqlcmd defaults
-- to OFF, so this has to be set explicitly for the XML aggregation to
-- run without "SELECT failed because ... QUOTED_IDENTIFIER" errors.
SET QUOTED_IDENTIFIER ON;

-- ---------------------------------------------------------------------------
-- Unused indexes (zero or negligible reads, excluding PK / unique)
-- > 1 MB only, sorted by size.
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    i.is_unique,
    i.is_primary_key,
    ISNULL(us.user_seeks,   0)                        AS user_seeks,
    ISNULL(us.user_scans,   0)                        AS user_scans,
    ISNULL(us.user_lookups, 0)                        AS user_lookups,
    ISNULL(us.user_updates, 0)                        AS user_updates,
    ISNULL(us.last_user_seek, us.last_user_scan)      AS last_read,
    CAST((ps.reserved_page_count * 8.0 / 1024) AS DECIMAL(18,2)) AS size_mb
FROM sys.indexes i
JOIN sys.objects o ON o.object_id = i.object_id AND o.type = 'U'
LEFT JOIN sys.dm_db_index_usage_stats us
      ON us.object_id = i.object_id
     AND us.index_id  = i.index_id
     AND us.database_id = DB_ID()
JOIN (
    SELECT object_id, index_id, SUM(reserved_page_count) AS reserved_page_count
      FROM sys.dm_db_partition_stats
     GROUP BY object_id, index_id
) ps ON ps.object_id = i.object_id AND ps.index_id = i.index_id
WHERE i.type IN (1,2)
  AND i.is_primary_key  = 0
  AND i.is_unique       = 0
  AND ISNULL(us.user_seeks + us.user_scans + us.user_lookups, 0) < 50
  AND (ps.reserved_page_count * 8.0 / 1024) > 1
  AND o.is_ms_shipped   = 0
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Indexes that have NEVER been read
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type,
    i.is_unique,
    i.is_primary_key,
    ISNULL(us.user_updates, 0)                        AS user_updates,
    CAST((ps.reserved_page_count * 8.0 / 1024) AS DECIMAL(18,2)) AS size_mb
FROM sys.indexes i
JOIN sys.objects o ON o.object_id = i.object_id AND o.type = 'U'
LEFT JOIN sys.dm_db_index_usage_stats us
      ON us.object_id = i.object_id AND us.index_id = i.index_id
     AND us.database_id = DB_ID()
JOIN (
    SELECT object_id, index_id, SUM(reserved_page_count) AS reserved_page_count
      FROM sys.dm_db_partition_stats
     GROUP BY object_id, index_id
) ps ON ps.object_id = i.object_id AND ps.index_id = i.index_id
WHERE i.type IN (1,2)
  AND (us.user_seeks IS NULL AND us.user_scans IS NULL AND us.user_lookups IS NULL)
  AND o.is_ms_shipped = 0
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Duplicate / overlapping indexes — same table, same leading key columns.
-- Aggregates the ordered key column list for every index and returns
-- pairs whose lists share the same prefix. Exact duplicates + candidates
-- for consolidation.
-- ---------------------------------------------------------------------------
;WITH idx_cols AS (
    SELECT
        i.object_id,
        i.index_id,
        i.name AS index_name,
        i.is_unique,
        i.has_filter,
        i.filter_definition,
        STUFF((
            SELECT ',' + QUOTENAME(c.name) + CASE WHEN ic.is_descending_key = 1 THEN ' DESC' ELSE '' END
              FROM sys.index_columns ic
              JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
             WHERE ic.object_id = i.object_id
               AND ic.index_id  = i.index_id
               AND ic.is_included_column = 0
             ORDER BY ic.key_ordinal
             FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 1, '') AS key_columns,
        STUFF((
            SELECT ',' + QUOTENAME(c.name)
              FROM sys.index_columns ic
              JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
             WHERE ic.object_id = i.object_id
               AND ic.index_id  = i.index_id
               AND ic.is_included_column = 1
             ORDER BY ic.key_ordinal
             FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 1, '') AS included_columns
    FROM sys.indexes i
    WHERE i.type IN (1,2)
      AND i.is_hypothetical = 0
)
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    a.index_name                                      AS index_a,
    b.index_name                                      AS index_b,
    a.key_columns                                     AS key_columns,
    a.included_columns                                AS included_a,
    b.included_columns                                AS included_b,
    CASE WHEN a.key_columns = b.key_columns
          AND ISNULL(a.included_columns,'') = ISNULL(b.included_columns,'')
         THEN 'EXACT DUPLICATE'
         WHEN a.key_columns = b.key_columns
         THEN 'KEYS IDENTICAL (INCLUDEs differ)'
         ELSE 'PREFIX OVERLAP'
    END                                               AS relation
FROM idx_cols a
JOIN idx_cols b
      ON a.object_id = b.object_id
     AND a.index_id  < b.index_id
     AND (a.key_columns = b.key_columns
          OR b.key_columns LIKE a.key_columns + ',%')
JOIN sys.objects o ON o.object_id = a.object_id
WHERE o.is_ms_shipped = 0
ORDER BY schema_name, table_name, a.index_name;

-- ---------------------------------------------------------------------------
-- Disabled indexes (must be rebuilt to be useful again)
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    i.name                                            AS index_name,
    i.type_desc                                       AS index_type
FROM sys.indexes i
JOIN sys.objects o ON o.object_id = i.object_id
WHERE i.is_disabled = 1
  AND o.is_ms_shipped = 0
ORDER BY schema_name, table_name, index_name;

-- ---------------------------------------------------------------------------
-- Missing-index suggestions from the optimizer (ranked by improvement)
-- ---------------------------------------------------------------------------
SELECT TOP 25
    OBJECT_NAME(mid.object_id, mid.database_id)       AS table_name,
    DB_NAME(mid.database_id)                          AS database_name,
    migs.user_seeks,
    migs.user_scans,
    migs.avg_total_user_cost,
    migs.avg_user_impact,
    CAST(migs.avg_total_user_cost
         * (migs.avg_user_impact / 100.0)
         * (migs.user_seeks + migs.user_scans) AS DECIMAL(18,2)) AS improvement_score,
    mid.equality_columns,
    mid.inequality_columns,
    mid.included_columns
FROM sys.dm_db_missing_index_details mid
JOIN sys.dm_db_missing_index_groups mig   ON mig.index_handle = mid.index_handle
JOIN sys.dm_db_missing_index_group_stats migs ON migs.group_handle = mig.index_group_handle
WHERE mid.database_id = DB_ID()
ORDER BY improvement_score DESC;

-- ---------------------------------------------------------------------------
-- Foreign keys without a supporting index (common cause of slow DELETE /
-- UPDATE of the parent). Matches the FK's ordered column list against
-- every index's leading key prefix.
-- ---------------------------------------------------------------------------
;WITH fk_cols AS (
    SELECT
        fkc.constraint_object_id                      AS fk_id,
        fkc.parent_object_id                          AS table_id,
        STUFF((
            SELECT ',' + QUOTENAME(c.name)
              FROM sys.foreign_key_columns fkc2
              JOIN sys.columns c ON c.object_id = fkc2.parent_object_id
                                AND c.column_id = fkc2.parent_column_id
             WHERE fkc2.constraint_object_id = fkc.constraint_object_id
             ORDER BY fkc2.constraint_column_id
             FOR XML PATH(''), TYPE).value('.','NVARCHAR(MAX)'), 1, 1, '') AS fk_columns
    FROM sys.foreign_key_columns fkc
    GROUP BY fkc.constraint_object_id, fkc.parent_object_id
),
idx_cols AS (
    SELECT
        ic.object_id,
        ic.index_id,
        STUFF((
            SELECT ',' + QUOTENAME(c2.name)
              FROM sys.index_columns ic2
              JOIN sys.columns c2 ON c2.object_id = ic2.object_id AND c2.column_id = ic2.column_id
             WHERE ic2.object_id = ic.object_id
               AND ic2.index_id  = ic.index_id
               AND ic2.is_included_column = 0
             ORDER BY ic2.key_ordinal
             FOR XML PATH(''), TYPE).value('.','NVARCHAR(MAX)'), 1, 1, '') AS index_columns
    FROM sys.index_columns ic
    GROUP BY ic.object_id, ic.index_id
)
SELECT
    OBJECT_SCHEMA_NAME(fk.parent_object_id)           AS schema_name,
    OBJECT_NAME(fk.parent_object_id)                  AS table_name,
    fk.name                                           AS fk_name,
    fkc.fk_columns                                    AS fk_columns,
    'NO COVERING INDEX'                               AS finding
FROM sys.foreign_keys fk
JOIN fk_cols fkc ON fkc.fk_id = fk.object_id
WHERE NOT EXISTS (
    SELECT 1
      FROM idx_cols ic
     WHERE ic.object_id = fk.parent_object_id
       AND (ic.index_columns = fkc.fk_columns
         OR ic.index_columns LIKE fkc.fk_columns + ',%')
)
ORDER BY schema_name, table_name, fk_name;
