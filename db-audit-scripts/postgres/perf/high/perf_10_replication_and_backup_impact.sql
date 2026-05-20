-- =============================================================================
-- perf_10_replication_and_backup_impact.sql
-- Priority: HIGH
-- Purpose: Replication lag, WAL pressure, redo activity, and ongoing
--          base backups that may impact write latency.
-- Read-only.
--
-- Portability:
--   * On AWS Aurora PostgreSQL the WAL exposure functions (pg_current_wal_lsn,
--     pg_last_wal_receive_lsn, pg_walfile_name, pg_stat_get_wal_receiver) are
--     deliberately blocked because Aurora uses its own storage layer instead
--     of streaming WAL. We detect Aurora via the presence of the rdsadmin
--     role and skip the affected blocks with a [note] line so the rest of
--     the script still produces output.
--   * Standard (self-managed) PostgreSQL runs every block.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Environment detection
-- ---------------------------------------------------------------------------
SELECT
    EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdsadmin')   AS is_aws_rds,
    current_setting('server_version_num')::int >= 140000        AS pg14_or_newer
\gset

-- ---------------------------------------------------------------------------
-- Recovery / replica status (always safe)
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT
    pg_is_in_recovery()                                  AS is_replica,
    '[note] WAL LSN functions are blocked on AWS Aurora — refer to Aurora replication / storage console instead' AS current_lsn;
\else
SELECT
    pg_is_in_recovery()                                  AS is_replica,
    CASE WHEN pg_is_in_recovery()
         THEN pg_last_wal_receive_lsn()::text
         ELSE pg_current_wal_lsn()::text
    END                                                  AS current_lsn;
\endif

-- ---------------------------------------------------------------------------
-- PRIMARY: Streaming replicas and their lag (Aurora's pg_stat_replication
-- is normally empty because Aurora doesn't use streaming replication, but
-- the view itself queries fine, so we run it everywhere.)
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
-- On Aurora we cannot compute retained_wal_size because pg_current_wal_lsn
-- is blocked. Emit the slot inventory without the size column instead.
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT
    slot_name, plugin, slot_type, database, temporary, active, active_pid,
    xmin, catalog_xmin, restart_lsn, confirmed_flush_lsn,
    '(skipped on Aurora -- WAL LSN diff blocked)' AS retained_wal_size
FROM pg_replication_slots
ORDER BY active, slot_name;
\else
SELECT
    slot_name, plugin, slot_type, database, temporary, active, active_pid,
    xmin, catalog_xmin, restart_lsn, confirmed_flush_lsn,
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
\endif

-- ---------------------------------------------------------------------------
-- REPLICA: WAL receiver state (pg_stat_wal_receiver is blocked on Aurora)
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT '[note] pg_stat_wal_receiver is blocked on AWS Aurora -- skipped' AS note;
\else
SELECT * FROM pg_stat_wal_receiver;
\endif

-- ---------------------------------------------------------------------------
-- REPLICA: Lag in seconds (NULL on primary; functions blocked on Aurora)
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT '[note] pg_last_wal_* and pg_last_xact_replay_timestamp are blocked on AWS Aurora' AS note;
\else
SELECT
    pg_last_wal_receive_lsn()                            AS last_received_lsn,
    pg_last_wal_replay_lsn()                             AS last_replayed_lsn,
    pg_last_xact_replay_timestamp()                      AS last_xact_replay_time,
    CASE WHEN pg_is_in_recovery()
         THEN extract(epoch FROM (now() - pg_last_xact_replay_timestamp()))
         ELSE NULL
    END                                                  AS replica_lag_seconds;
\endif

-- ---------------------------------------------------------------------------
-- WAL activity (cumulative, from pg_stat_wal — PostgreSQL 14+ only).
-- Guarded by server version + Aurora -- pg_stat_get_wal() is blocked there.
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT '[note] pg_stat_wal is blocked on AWS Aurora -- skipped' AS note;
\elif :pg14_or_newer
SELECT * FROM pg_stat_wal;
\else
SELECT 'pg_stat_wal requires PostgreSQL 14 or newer -- skipped' AS note;
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
