-- =============================================================================
-- perf_22_replication_deepdive.sql
-- Priority: HIGH
-- Purpose: Per-sender / per-replica lag breakdown, replication-slot
--          retention, logical replication worker state, conflict stats.
--          Upstream: pg_stat_replication (primary side),
--          pg_stat_wal_receiver / pg_stat_subscription (replica side).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Global replication config
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'wal_level',
    'max_wal_senders',
    'max_replication_slots',
    'max_logical_replication_workers',
    'max_sync_workers_per_subscription',
    'synchronous_commit',
    'synchronous_standby_names',
    'hot_standby',
    'hot_standby_feedback',
    'wal_receiver_status_interval',
    'wal_sender_timeout',
    'wal_receiver_timeout',
    'primary_conninfo',
    'primary_slot_name'
)
ORDER BY name;

-- Is this node a primary or a standby?
SELECT
    pg_is_in_recovery()                                   AS is_standby,
    CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END AS role,
    current_setting('cluster_name', true)                 AS cluster_name;

-- ---------------------------------------------------------------------------
-- Primary-side: per-standby lag breakdown
-- pg_stat_replication columns: write_lag/flush_lag/replay_lag are
-- interval durations — the time between the walsender sending the WAL
-- and the standby acknowledging each step. sync_state tells you whether
-- this replica is 'sync', 'potential', 'async', 'quorum'.
-- ---------------------------------------------------------------------------
SELECT
    application_name,
    client_addr,
    usename,
    state,
    sync_state,
    sync_priority,
    pg_wal_lsn_diff(pg_current_wal_lsn(), sent_lsn)       AS send_pending_bytes,
    pg_wal_lsn_diff(sent_lsn, flush_lsn)                  AS flush_pending_bytes,
    pg_wal_lsn_diff(flush_lsn, replay_lsn)                AS replay_pending_bytes,
    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)     AS total_lag_bytes,
    write_lag,
    flush_lag,
    replay_lag,
    backend_start,
    reply_time
FROM pg_stat_replication
ORDER BY total_lag_bytes DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- Replication slots — retained WAL per slot. An inactive slot with a
-- growing restart_lsn is the #1 cause of a primary filling its WAL.
-- ---------------------------------------------------------------------------
SELECT
    slot_name,
    slot_type,
    database,
    plugin,
    active,
    active_pid,
    temporary,
    restart_lsn,
    confirmed_flush_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)    AS retained_wal_bytes,
    CASE
        WHEN active = false
             AND pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 1073741824::bigint
          THEN 'CRITICAL — inactive slot retaining > 1 GB WAL'
        WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 10737418240::bigint
          THEN 'HIGH — > 10 GB WAL retention'
        ELSE 'ok'
    END                                                   AS assessment
FROM pg_replication_slots
ORDER BY retained_wal_bytes DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- Standby-side: WAL receiver status
-- pg_stat_wal_receiver is empty on a primary.
-- ---------------------------------------------------------------------------
SELECT
    pid, status, receive_start_lsn, receive_start_tli,
    written_lsn, flushed_lsn,
    received_tli,
    last_msg_send_time, last_msg_receipt_time,
    latest_end_lsn, latest_end_time,
    slot_name,
    sender_host, sender_port,
    conninfo
FROM pg_stat_wal_receiver;

-- Replay lag relative to wall clock on a standby
SELECT
    now() - pg_last_xact_replay_timestamp()               AS replay_clock_lag,
    pg_last_wal_receive_lsn()                             AS last_received,
    pg_last_wal_replay_lsn()                              AS last_replayed,
    CASE WHEN pg_last_wal_receive_lsn() IS NOT NULL
              AND pg_last_wal_replay_lsn()  IS NOT NULL
         THEN pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())
    END                                                   AS receive_to_replay_bytes;

-- ---------------------------------------------------------------------------
-- Logical replication — subscriptions and per-subscription workers
-- ---------------------------------------------------------------------------
SELECT
    s.subname,
    s.subenabled,
    s.subconninfo,
    s.subslotname,
    s.subsynccommit,
    s.subpublications
FROM pg_subscription s
ORDER BY s.subname;

SELECT
    subname,
    pid,
    received_lsn,
    last_msg_send_time,
    last_msg_receipt_time,
    latest_end_lsn,
    latest_end_time,
    now() - latest_end_time                               AS apply_clock_lag
FROM pg_stat_subscription
ORDER BY subname, pid;

-- ---------------------------------------------------------------------------
-- Conflicts on standbys (query cancel / deadlock caused by replay)
-- ---------------------------------------------------------------------------
SELECT
    datname,
    confl_tablespace,
    confl_lock,
    confl_snapshot,
    confl_bufferpin,
    confl_deadlock
FROM pg_stat_database_conflicts
WHERE (confl_tablespace + confl_lock + confl_snapshot +
       confl_bufferpin + confl_deadlock) > 0
ORDER BY (confl_tablespace + confl_lock + confl_snapshot +
          confl_bufferpin + confl_deadlock) DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM pg_stat_replication)                              AS connected_standbys,
    (SELECT COUNT(*) FROM pg_replication_slots)                             AS slots_total,
    (SELECT COUNT(*) FROM pg_replication_slots WHERE active = false)        AS slots_inactive,
    (SELECT COUNT(*) FROM pg_subscription WHERE subenabled = true)          AS logical_subs_enabled,
    pg_is_in_recovery()                                                     AS is_standby;
