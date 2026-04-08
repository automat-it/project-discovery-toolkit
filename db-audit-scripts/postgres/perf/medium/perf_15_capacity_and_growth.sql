-- =============================================================================
-- perf_15_capacity_and_growth.sql
-- Priority: MEDIUM
-- Purpose: Snapshot of storage usage, connection trends, and other
--          capacity indicators for resource planning.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Cluster-wide storage usage (sum of all databases)
-- ---------------------------------------------------------------------------
SELECT
    pg_size_pretty(sum(pg_database_size(datname)))       AS total_db_size,
    sum(pg_database_size(datname))                       AS total_bytes,
    count(*) FILTER (WHERE NOT datistemplate)            AS user_databases
FROM pg_database;

-- ---------------------------------------------------------------------------
-- Per-database size and growth indicators
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    pg_size_pretty(pg_database_size(datname))            AS size,
    pg_database_size(datname)                            AS bytes,
    (SELECT xact_commit + xact_rollback
     FROM pg_stat_database
     WHERE datname = d.datname)                          AS total_transactions,
    (SELECT tup_inserted + tup_updated + tup_deleted
     FROM pg_stat_database
     WHERE datname = d.datname)                          AS total_writes,
    (SELECT stats_reset
     FROM pg_stat_database
     WHERE datname = d.datname)                          AS stats_since
FROM pg_database d
WHERE NOT datistemplate
ORDER BY pg_database_size(datname) DESC;

-- ---------------------------------------------------------------------------
-- Largest tables with row counts (where the data lives)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    pg_size_pretty(pg_total_relation_size(relid))        AS total_size,
    n_live_tup                                           AS rows,
    n_tup_ins                                            AS inserts,
    n_tup_upd                                            AS updates,
    n_tup_del                                            AS deletes,
    n_tup_hot_upd                                        AS hot_updates
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Connection limits and headroom
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections')
                                                         AS max_connections,
    (SELECT count(*) FROM pg_stat_activity
     WHERE backend_type = 'client backend')              AS current_clients,
    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections')
        - (SELECT count(*) FROM pg_stat_activity
           WHERE backend_type = 'client backend')        AS available_connections;

-- ---------------------------------------------------------------------------
-- Transaction ID consumption (wraparound capacity)
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    age(datfrozenxid)                                    AS xid_age,
    round(100.0 * age(datfrozenxid) / 2000000000, 2)     AS pct_to_wraparound,
    round(100.0 * age(datfrozenxid)
          / current_setting('autovacuum_freeze_max_age')::int, 2)
                                                         AS pct_to_autovacuum_freeze
FROM pg_database
WHERE NOT datistemplate
ORDER BY age(datfrozenxid) DESC;

-- ---------------------------------------------------------------------------
-- Tablespace usage (default 'pg_default' is the main data directory)
-- ---------------------------------------------------------------------------
SELECT
    spcname                                              AS tablespace,
    pg_size_pretty(pg_tablespace_size(oid))              AS size
FROM pg_tablespace
ORDER BY pg_tablespace_size(oid) DESC;

-- ---------------------------------------------------------------------------
-- Sequence headroom (how much room until int4/int8 overflow)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    sequencename,
    last_value,
    max_value,
    CASE WHEN max_value > 0
         THEN round(100.0 * last_value::numeric / max_value, 4)
         ELSE 0
    END                                                  AS pct_consumed
FROM pg_sequences
WHERE last_value IS NOT NULL
ORDER BY pct_consumed DESC NULLS LAST
LIMIT 30;
