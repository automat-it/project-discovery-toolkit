-- =============================================================================
-- perf_04_wait_events_and_io.sql
-- Priority: CRITICAL
-- Purpose: Identify the bottleneck — CPU, disk I/O, locks, or network —
--          via wait events and I/O statistics.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Current wait events (instantaneous snapshot)
-- ---------------------------------------------------------------------------
SELECT
    coalesce(wait_event_type, 'CPU/Running')             AS wait_event_type,
    coalesce(wait_event, '-')                            AS wait_event,
    count(*)                                             AS sessions,
    round(100.0 * count(*)
                / sum(count(*)) OVER (), 2)              AS pct
FROM pg_stat_activity
WHERE state = 'active'
  AND backend_type = 'client backend'
  AND pid <> pg_backend_pid()
GROUP BY wait_event_type, wait_event
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Wait events grouped by type only (CPU vs IO vs Lock vs LWLock vs ...)
-- ---------------------------------------------------------------------------
SELECT
    coalesce(wait_event_type, 'CPU/Running')             AS category,
    count(*)                                             AS sessions,
    round(100.0 * count(*)
                / sum(count(*)) OVER (), 2)              AS pct
FROM pg_stat_activity
WHERE state = 'active'
  AND backend_type = 'client backend'
  AND pid <> pg_backend_pid()
GROUP BY wait_event_type
ORDER BY sessions DESC;

-- ---------------------------------------------------------------------------
-- Per-session wait detail (for active sessions)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    state,
    coalesce(wait_event_type, 'CPU')                     AS wait_event_type,
    coalesce(wait_event, '-')                            AS wait_event,
    now() - query_start                                  AS query_age,
    left(query, 200)                                     AS query
FROM pg_stat_activity
WHERE state <> 'idle'
  AND backend_type = 'client backend'
  AND pid <> pg_backend_pid()
ORDER BY query_age DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- Database-level I/O totals
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    blks_read                                            AS disk_reads,
    blks_hit                                             AS cache_hits,
    pg_size_pretty(blks_read * 8192::bigint)             AS disk_read_bytes,
    CASE WHEN blks_hit + blks_read > 0
         THEN round(100.0 * blks_hit / (blks_hit + blks_read), 2)
         ELSE 0
    END                                                  AS hit_ratio_pct,
    tup_returned                                         AS rows_returned,
    tup_fetched                                          AS rows_fetched,
    tup_inserted                                         AS rows_inserted,
    tup_updated                                          AS rows_updated,
    tup_deleted                                          AS rows_deleted,
    temp_files,
    pg_size_pretty(temp_bytes)                           AS temp_size,
    deadlocks,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY blks_read + blks_hit DESC;

-- ---------------------------------------------------------------------------
-- Per-table I/O (heap and TOAST)
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    heap_blks_read                                       AS heap_disk_reads,
    heap_blks_hit                                        AS heap_cache_hits,
    idx_blks_read                                        AS idx_disk_reads,
    idx_blks_hit                                         AS idx_cache_hits,
    toast_blks_read                                      AS toast_disk_reads,
    toast_blks_hit                                       AS toast_cache_hits,
    CASE WHEN heap_blks_hit + heap_blks_read > 0
         THEN round(100.0 * heap_blks_hit
                    / (heap_blks_hit + heap_blks_read), 2)
         ELSE 0
    END                                                  AS heap_hit_pct
FROM pg_statio_user_tables
WHERE heap_blks_read + idx_blks_read > 0
ORDER BY heap_blks_read + idx_blks_read DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Per-statement I/O (top by physical reads from pg_stat_statements).
--
-- Version note: in PostgreSQL 17 the blk_read_time / blk_write_time columns
-- were split into shared_blk_read_time / shared_blk_write_time (and
-- local_blk_read_time / local_blk_write_time). On PG 17+ replace the two
-- columns below with their shared_* counterparts.
-- ---------------------------------------------------------------------------
SELECT
    shared_blks_read                                     AS disk_reads,
    pg_size_pretty(shared_blks_read * 8192::bigint)      AS disk_read_size,
    shared_blks_hit                                      AS cache_hits,
    blk_read_time                                        AS read_time_ms,
    blk_write_time                                       AS write_time_ms,
    calls,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    left(query, 200)                                     AS query
FROM pg_stat_statements
WHERE shared_blks_read > 0
ORDER BY shared_blks_read DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- track_io_timing setting (must be ON for blk_read_time / blk_write_time)
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN ('track_io_timing', 'track_functions', 'track_activities', 'track_counts');
