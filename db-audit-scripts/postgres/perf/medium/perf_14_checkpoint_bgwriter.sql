-- =============================================================================
-- perf_14_checkpoint_bgwriter.sql
-- Priority: MEDIUM
-- Purpose: Checkpoint frequency, write bursts, and bgwriter activity.
--          Forced checkpoints cause latency spikes.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Background writer / checkpointer cumulative stats.
--
-- Version note: PostgreSQL 17 split the bgwriter / checkpointer counters.
-- Checkpoint metrics moved to the new pg_stat_checkpointer view, with
-- renamed columns (num_timed, num_requested, write_time, sync_time,
-- buffers_written). buffers_backend / buffers_backend_fsync were removed
-- entirely -- backend-initiated writes are now tracked in pg_stat_io.
-- pg_stat_bgwriter retains only buffers_clean / maxwritten_clean /
-- buffers_alloc / stats_reset on PG 17+.
-- ---------------------------------------------------------------------------
SELECT current_setting('server_version_num')::int >= 170000 AS pg17_or_newer
\gset

\if :pg17_or_newer
-- PG 17+: pg_stat_checkpointer for checkpoint counters, pg_stat_bgwriter for
-- background-writer counters. Combine via cross join (each view is single-row).
SELECT
    ckpt.num_timed                                       AS scheduled_checkpoints,
    ckpt.num_requested                                   AS forced_checkpoints,
    CASE WHEN ckpt.num_timed + ckpt.num_requested > 0
         THEN round(100.0 * ckpt.num_requested
                    / (ckpt.num_timed + ckpt.num_requested), 2)
         ELSE 0
    END                                                  AS forced_pct,
    ckpt.write_time                                      AS checkpoint_write_time_ms,
    ckpt.sync_time                                       AS checkpoint_sync_time_ms,
    ckpt.buffers_written                                 AS buffers_written_by_checkpoint,
    bgw.buffers_clean                                    AS buffers_written_by_bgwriter,
    bgw.buffers_alloc                                    AS buffers_allocated,
    bgw.maxwritten_clean                                 AS bgwriter_max_written_stops,
    ckpt.restartpoints_timed                             AS restartpoints_scheduled,
    ckpt.restartpoints_req                               AS restartpoints_requested,
    ckpt.restartpoints_done                              AS restartpoints_completed,
    ckpt.stats_reset                                     AS ckpt_stats_reset,
    bgw.stats_reset                                      AS bgw_stats_reset
FROM pg_stat_checkpointer ckpt
CROSS JOIN pg_stat_bgwriter bgw;

-- PG 17+: backend-initiated writes live in pg_stat_io. Surface the totals
-- so the operator can spot "queries are doing their own writes" pressure.
SELECT
    backend_type,
    sum(writes)                                          AS backend_writes,
    sum(fsyncs)                                          AS backend_fsyncs,
    sum(extends)                                         AS backend_extends
FROM pg_stat_io
WHERE writes > 0 OR fsyncs > 0 OR extends > 0
GROUP BY backend_type
ORDER BY backend_writes DESC;

\else
-- PG <= 16: all counters live in pg_stat_bgwriter.
SELECT
    checkpoints_timed                                    AS scheduled_checkpoints,
    checkpoints_req                                      AS forced_checkpoints,
    CASE WHEN checkpoints_timed + checkpoints_req > 0
         THEN round(100.0 * checkpoints_req
                    / (checkpoints_timed + checkpoints_req), 2)
         ELSE 0
    END                                                  AS forced_pct,
    checkpoint_write_time                                AS write_time_ms,
    checkpoint_sync_time                                 AS sync_time_ms,
    buffers_checkpoint                                   AS buffers_written_by_checkpoint,
    buffers_clean                                        AS buffers_written_by_bgwriter,
    buffers_backend                                      AS buffers_written_by_backends,
    buffers_backend_fsync                                AS backend_fsyncs,
    buffers_alloc                                        AS buffers_allocated,
    maxwritten_clean                                     AS bgwriter_max_written_stops,
    stats_reset
FROM pg_stat_bgwriter;
\endif

-- ---------------------------------------------------------------------------
-- Checkpoint and bgwriter configuration
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'checkpoint_timeout',
    'checkpoint_completion_target',
    'checkpoint_flush_after',
    'checkpoint_warning',
    'max_wal_size',
    'min_wal_size',
    'bgwriter_delay',
    'bgwriter_lru_maxpages',
    'bgwriter_lru_multiplier',
    'bgwriter_flush_after',
    'wal_writer_delay',
    'wal_writer_flush_after',
    'wal_buffers',
    'commit_delay',
    'synchronous_commit'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- WAL activity (PostgreSQL 14+ only). Guarded by server version + Aurora.
-- pg_stat_wal's backing function pg_stat_get_wal() is blocked on Aurora.
-- ---------------------------------------------------------------------------
SELECT
    current_setting('server_version_num')::int >= 140000   AS pg14_or_newer,
    EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdsadmin') AS is_aws_rds
\gset
\if :is_aws_rds
SELECT '[note] pg_stat_wal is blocked on AWS Aurora -- skipped' AS note;
\elif :pg14_or_newer
SELECT * FROM pg_stat_wal;
\else
SELECT 'pg_stat_wal requires PostgreSQL 14 or newer -- skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Quick interpretation hints (post-PG17 nomenclature in parentheses)
-- ---------------------------------------------------------------------------
SELECT
    'forced_pct (num_requested / num_timed in PG17) should stay under 5%' AS hint_1,
    'buffers_written_by_backends (pg_stat_io writes in PG17) should be << buffers_written_by_checkpoint' AS hint_2,
    'backend fsyncs > 0 indicates wal_buffers / sync IO pressure'         AS hint_3,
    'bgwriter_max_written_stops > 0 means bgwriter_lru_maxpages too low'  AS hint_4;
