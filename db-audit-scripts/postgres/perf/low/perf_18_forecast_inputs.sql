-- =============================================================================
-- perf_18_forecast_inputs.sql
-- Priority: LOW
-- Purpose: Snapshot data points useful as inputs to capacity forecasting.
--          PostgreSQL itself does not store time-series — these snapshots
--          should be collected periodically and stored externally
--          (Prometheus, CloudWatch, etc.) to build forecasts.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Single-row snapshot of cluster-wide usage indicators
-- ---------------------------------------------------------------------------
SELECT
    now()                                                AS snapshot_at,
    (SELECT sum(pg_database_size(datname))
     FROM pg_database
     WHERE NOT datistemplate
       AND has_database_privilege(datname, 'CONNECT'))   AS total_db_bytes,
    (SELECT count(*) FROM pg_stat_activity
     WHERE backend_type = 'client backend')              AS client_connections,
    (SELECT count(*) FROM pg_stat_activity
     WHERE state = 'active'
       AND backend_type = 'client backend')              AS active_connections,
    (SELECT setting::int FROM pg_settings
     WHERE name = 'max_connections')                     AS max_connections,
    (SELECT sum(xact_commit + xact_rollback)
     FROM pg_stat_database
     WHERE datname IS NOT NULL)                          AS total_transactions_since_reset,
    (SELECT sum(tup_inserted + tup_updated + tup_deleted)
     FROM pg_stat_database
     WHERE datname IS NOT NULL)                          AS total_writes_since_reset,
    (SELECT sum(blks_read)
     FROM pg_stat_database
     WHERE datname IS NOT NULL)                          AS total_disk_reads_since_reset,
    (SELECT sum(blks_hit)
     FROM pg_stat_database
     WHERE datname IS NOT NULL)                          AS total_cache_hits_since_reset,
    (SELECT max(age(datfrozenxid))
     FROM pg_database WHERE NOT datistemplate)           AS max_xid_age;

-- ---------------------------------------------------------------------------
-- Per-database snapshot
-- ---------------------------------------------------------------------------
SELECT
    now()                                                AS snapshot_at,
    datname                                              AS database,
    pg_database_size(datname)                            AS db_bytes,
    numbackends                                          AS connections,
    xact_commit,
    xact_rollback,
    blks_read,
    blks_hit,
    tup_returned,
    tup_fetched,
    tup_inserted,
    tup_updated,
    tup_deleted,
    temp_files,
    temp_bytes,
    deadlocks,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
  AND has_database_privilege(datname, 'CONNECT');

-- ---------------------------------------------------------------------------
-- Per-table snapshot for top 50 tables by size
-- ---------------------------------------------------------------------------
SELECT
    now()                                                AS snapshot_at,
    schemaname,
    relname                                              AS table,
    pg_total_relation_size(relid)                        AS total_bytes,
    pg_relation_size(relid)                              AS heap_bytes,
    pg_indexes_size(relid)                               AS indexes_bytes,
    n_live_tup,
    n_dead_tup,
    n_tup_ins,
    n_tup_upd,
    n_tup_del,
    seq_scan,
    idx_scan
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 50;
