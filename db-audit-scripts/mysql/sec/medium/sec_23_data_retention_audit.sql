-- =============================================================================
-- sec_23_data_retention_audit.sql
-- Priority: MEDIUM
-- Purpose: Identify large tables with no retention signal — large,
--          growing, non-partitioned, and without a scheduled EVENT
--          that prunes them. Helps GDPR / HIPAA reviewers.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Top 100 tables by size with row count + create / update timestamps.
-- information_schema.TABLES.UPDATE_TIME is maintained for InnoDB when
-- innodb_stats_persistent is on; may be NULL otherwise.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    ENGINE,
    TABLE_ROWS,
    ROUND(DATA_LENGTH  / 1024 / 1024, 1)                  AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 1)                  AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 1)  AS total_mb,
    CREATE_TIME,
    UPDATE_TIME,
    TABLE_COMMENT
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
LIMIT 100;

-- ---------------------------------------------------------------------------
-- Large tables WITHOUT partitioning — prime retention candidates.
-- A table appearing here is effectively append-only or uses ad-hoc
-- DELETEs (which are expensive and bloat the tablespace).
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.ENGINE,
    ROUND((t.DATA_LENGTH + t.INDEX_LENGTH) / 1024 / 1024, 1) AS total_mb,
    t.TABLE_ROWS,
    t.CREATE_TIME,
    t.UPDATE_TIME
FROM information_schema.TABLES t
LEFT JOIN information_schema.PARTITIONS p
       ON p.TABLE_SCHEMA = t.TABLE_SCHEMA
      AND p.TABLE_NAME   = t.TABLE_NAME
      AND p.PARTITION_NAME IS NOT NULL
WHERE t.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND t.TABLE_TYPE = 'BASE TABLE'
  AND (t.DATA_LENGTH + t.INDEX_LENGTH) > 1024 * 1024 * 1024     -- > 1 GB
  AND p.TABLE_NAME IS NULL
ORDER BY (t.DATA_LENGTH + t.INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Tables with time-like columns — retention candidate columns
-- ---------------------------------------------------------------------------
SELECT
    c.TABLE_SCHEMA,
    c.TABLE_NAME,
    c.COLUMN_NAME,
    c.DATA_TYPE,
    ROUND((t.DATA_LENGTH + t.INDEX_LENGTH) / 1024 / 1024, 1) AS total_mb
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES  t
      ON  t.TABLE_SCHEMA = c.TABLE_SCHEMA
      AND t.TABLE_NAME   = c.TABLE_NAME
WHERE c.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND t.TABLE_TYPE = 'BASE TABLE'
  AND (t.DATA_LENGTH + t.INDEX_LENGTH) > 100 * 1024 * 1024
  AND (c.DATA_TYPE IN ('datetime','timestamp','date')
       OR c.COLUMN_NAME REGEXP '(created_at|updated_at|inserted_at|event_time|log_time|occurred_at|timestamp|_date)$')
ORDER BY (t.DATA_LENGTH + t.INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Scheduled EVENTS — often encode retention ("DELETE ... WHERE ts <
-- NOW() - INTERVAL N DAY"). Disabled events are an easy-to-miss
-- regression.
-- ---------------------------------------------------------------------------
SELECT
    EVENT_SCHEMA,
    EVENT_NAME,
    EVENT_TYPE,
    STATUS,
    STARTS,
    ENDS,
    INTERVAL_VALUE,
    INTERVAL_FIELD,
    LAST_EXECUTED,
    LEFT(EVENT_DEFINITION, 300)                           AS definition_sample
FROM information_schema.EVENTS
WHERE EVENT_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
ORDER BY EVENT_SCHEMA, EVENT_NAME;

-- Event scheduler global state
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'event_scheduler';

-- ---------------------------------------------------------------------------
-- Schema sizes — total per database
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    COUNT(*)                                              AS tables,
    ROUND(SUM(DATA_LENGTH  + INDEX_LENGTH) / 1024 / 1024, 1) AS total_mb,
    ROUND(SUM(DATA_LENGTH) / 1024 / 1024, 1)              AS data_mb,
    ROUND(SUM(INDEX_LENGTH)/ 1024 / 1024, 1)              AS index_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
  AND TABLE_TYPE = 'BASE TABLE'
GROUP BY TABLE_SCHEMA
ORDER BY total_mb DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM information_schema.TABLES
      WHERE TABLE_TYPE = 'BASE TABLE'
        AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
        AND (DATA_LENGTH + INDEX_LENGTH) > 1024*1024*1024)                   AS tables_over_1gb,
    (SELECT COUNT(*) FROM information_schema.EVENTS
      WHERE STATUS = 'ENABLED'
        AND EVENT_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')) AS enabled_events,
    (SELECT COUNT(DISTINCT CONCAT(TABLE_SCHEMA,'.',TABLE_NAME))
       FROM information_schema.PARTITIONS
      WHERE PARTITION_NAME IS NOT NULL
        AND TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')) AS partitioned_tables;
