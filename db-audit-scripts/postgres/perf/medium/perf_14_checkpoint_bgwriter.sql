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
-- Checkpoint columns (checkpoints_timed, checkpoints_req, checkpoint_write_time,
-- checkpoint_sync_time, buffers_checkpoint, buffers_backend,
-- buffers_backend_fsync) moved to the new pg_stat_checkpointer view and were
-- removed from pg_stat_bgwriter. On PG 17+ run this block against
-- pg_stat_checkpointer (for checkpoint metrics) and keep pg_stat_bgwriter
-- only for buffers_clean / maxwritten_clean / buffers_alloc / stats_reset.
-- ---------------------------------------------------------------------------
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
-- WAL activity (PostgreSQL 14+ only). Guarded by server version.
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
-- Quick interpretation hints
-- ---------------------------------------------------------------------------
SELECT
    'checkpoint_req should be << checkpoint_timed (forced_pct < 5%)' AS hint_1,
    'buffers_backend should be << buffers_checkpoint'                 AS hint_2,
    'buffers_backend_fsync should be 0'                               AS hint_3,
    'maxwritten_clean > 0 means bgwriter_lru_maxpages too low'        AS hint_4;
