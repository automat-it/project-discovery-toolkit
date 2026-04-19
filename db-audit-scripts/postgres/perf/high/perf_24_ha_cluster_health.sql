-- =============================================================================
-- perf_24_ha_cluster_health.sql
-- Priority: HIGH
-- Purpose: Cluster-level health signals: WAL archiving, synchronous
--          commit quorum / degradation, standby feedback loop,
--          orchestrator residue (Patroni / repmgr), and backup readiness.
--          Complements perf_22 (per-standby lag) with cluster posture.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Node role + write-ability
-- ---------------------------------------------------------------------------
SELECT
    pg_is_in_recovery()                                   AS is_standby,
    CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END AS role,
    current_setting('cluster_name', true)                 AS cluster_name,
    current_setting('primary_conninfo', true)             AS primary_conninfo,
    current_setting('primary_slot_name', true)            AS primary_slot_name;

-- ---------------------------------------------------------------------------
-- Synchronous replication quorum state
-- synchronous_standby_names syntax: 'num_sync (standby_name, ...)' or
-- 'ANY num_sync (standby_name, ...)' (quorum) — degraded quorum is
-- invisible without comparing names against pg_stat_replication sync_state.
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'synchronous_commit',
    'synchronous_standby_names',
    'recovery_min_apply_delay',
    'wal_sender_timeout',
    'wal_receiver_timeout',
    'hot_standby_feedback',
    'max_standby_archive_delay',
    'max_standby_streaming_delay'
)
ORDER BY name;

-- Count of standbys currently sync vs async — if
-- synchronous_standby_names is set but no replica has sync_state='sync',
-- the primary is running in effectively synchronous-degraded state.
SELECT
    sync_state,
    COUNT(*) AS replica_count,
    STRING_AGG(application_name, ', ' ORDER BY application_name) AS apps
FROM pg_stat_replication
GROUP BY sync_state
ORDER BY sync_state;

-- ---------------------------------------------------------------------------
-- WAL archiving state — archive_command failure stalls the primary's
-- WAL retention. stats_reset is the moment the counters last cleared.
-- ---------------------------------------------------------------------------
SELECT
    archived_count,
    last_archived_wal,
    last_archived_time,
    failed_count,
    last_failed_wal,
    last_failed_time,
    stats_reset,
    CASE
        WHEN failed_count > 0 AND last_failed_time > COALESCE(last_archived_time, '1970-01-01')
          THEN 'CRITICAL — last attempt failed'
        WHEN last_archived_time < now() - interval '1 hour' AND archived_count > 0
          THEN 'stale — nothing archived in > 1 hour'
        ELSE 'ok'
    END                                                   AS archive_health
FROM pg_stat_archiver;

SELECT name, setting
FROM pg_settings
WHERE name IN ('archive_mode','archive_command','archive_timeout',
               'archive_library','restore_command');

-- ---------------------------------------------------------------------------
-- Backup readiness — last pg_basebackup / walsender, recovery ready
-- ---------------------------------------------------------------------------
SELECT
    application_name,
    client_addr,
    state,
    backend_start,
    sent_lsn
FROM pg_stat_replication
WHERE application_name ILIKE '%base%backup%'
   OR application_name ILIKE 'pg_basebackup%';

-- ---------------------------------------------------------------------------
-- Orchestrator residue — Patroni / repmgr leave tables in specific
-- schemas. A primary that LOST its orchestrator row is a split-brain risk.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname, c.relname, c.relkind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE (n.nspname IN ('repmgr','patroni') OR c.relname ILIKE 'repl_nodes%'
       OR c.relname ILIKE 'repmgr_%')
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Long-running transactions — they block WAL recycling and pin
-- autovacuum horizons cluster-wide.
-- ---------------------------------------------------------------------------
SELECT
    pid, usename, datname, state,
    xact_start,
    now() - xact_start                                    AS xact_duration,
    backend_xmin,
    wait_event_type, wait_event,
    LEFT(query, 200)                                      AS query
FROM pg_stat_activity
WHERE xact_start IS NOT NULL
  AND xact_start < now() - interval '5 minutes'
ORDER BY xact_start;

-- Oldest prepared transaction age — a forgotten 2PC locks WAL forever
SELECT
    gid,
    prepared,
    now() - prepared                                      AS age,
    owner, database
FROM pg_prepared_xacts
ORDER BY prepared;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    pg_is_in_recovery()                                                     AS is_standby,
    (SELECT COUNT(*) FROM pg_stat_replication)                              AS connected_replicas,
    (SELECT COUNT(*) FROM pg_stat_replication WHERE sync_state = 'sync')    AS sync_replicas,
    (SELECT failed_count FROM pg_stat_archiver)                             AS archive_failures,
    (SELECT COUNT(*) FROM pg_prepared_xacts)                                AS open_prepared_xacts,
    (SELECT COUNT(*) FROM pg_stat_activity
      WHERE xact_start < now() - interval '5 minutes')                      AS long_running_xacts;
