-- =============================================================================
-- perf_10_replication_and_backup_impact.sql
-- Priority: HIGH
-- Purpose: Replication lag, WAL pressure, redo activity, and ongoing
--          base backups that may impact write latency.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Recovery / replica status
-- ---------------------------------------------------------------------------
SELECT
    pg_is_in_recovery()                                  AS is_replica,
    CASE WHEN pg_is_in_recovery()
         THEN pg_last_wal_receive_lsn()::text
         ELSE pg_current_wal_lsn()::text
    END                                                  AS current_lsn;

-- ---------------------------------------------------------------------------
-- PRIMARY: Streaming replicas and their lag
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    state,
    sync_state,
    sync_priority,
    backend_start,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, write_lsn)) AS write_lag_size,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, flush_lsn)) AS flush_lag_size,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, replay_lsn))
                                                         AS replay_lag_size,
    write_lag,
    flush_lag,
    replay_lag
FROM pg_stat_replication;

-- ---------------------------------------------------------------------------
-- PRIMARY: Replication slots (watch for inactive slots holding WAL)
-- ---------------------------------------------------------------------------
SELECT
    slot_name,
    plugin,
    slot_type,
    database,
    temporary,
    active,
    active_pid,
    xmin,
    catalog_xmin,
    restart_lsn,
    confirmed_flush_lsn,
    pg_size_pretty(
        pg_wal_lsn_diff(
            CASE WHEN pg_is_in_recovery()
                 THEN pg_last_wal_receive_lsn()
                 ELSE pg_current_wal_lsn()
            END,
            restart_lsn
        )
    )                                                    AS retained_wal_size
FROM pg_replication_slots
ORDER BY active, slot_name;

-- ---------------------------------------------------------------------------
-- REPLICA: WAL receiver state
-- ---------------------------------------------------------------------------
SELECT *
FROM pg_stat_wal_receiver;

-- ---------------------------------------------------------------------------
-- REPLICA: Lag in seconds (NULL on primary)
-- ---------------------------------------------------------------------------
SELECT
    pg_last_wal_receive_lsn()                            AS last_received_lsn,
    pg_last_wal_replay_lsn()                             AS last_replayed_lsn,
    pg_last_xact_replay_timestamp()                      AS last_xact_replay_time,
    CASE WHEN pg_is_in_recovery()
         THEN extract(epoch FROM (now() - pg_last_xact_replay_timestamp()))
         ELSE NULL
    END                                                  AS replica_lag_seconds;

-- ---------------------------------------------------------------------------
-- WAL activity (cumulative, from pg_stat_wal — PostgreSQL 14+ only).
-- Guarded by server version so the script does not error on PG 13.
-- ---------------------------------------------------------------------------
SELECT current_setting('server_version_num')::int >= 140000 AS pg14_or_newer
\gset
\if :pg14_or_newer
SELECT *
FROM pg_stat_wal;
\else
SELECT 'pg_stat_wal requires PostgreSQL 14 or newer — skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Currently running base backups
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    backend_start,
    state,
    backend_type,
    left(query, 200)                                     AS query
FROM pg_stat_activity
WHERE backend_type LIKE '%walsender%'
   OR query ILIKE '%pg_basebackup%'
   OR query ILIKE '%pg_start_backup%';

-- ---------------------------------------------------------------------------
-- Replication-related parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit
FROM pg_settings
WHERE name IN (
    'wal_level',
    'max_wal_senders',
    'max_replication_slots',
    'wal_keep_size',
    'wal_sender_timeout',
    'wal_receiver_timeout',
    'hot_standby',
    'hot_standby_feedback',
    'max_standby_streaming_delay',
    'max_standby_archive_delay',
    'synchronous_standby_names',
    'synchronous_commit'
)
ORDER BY name;
