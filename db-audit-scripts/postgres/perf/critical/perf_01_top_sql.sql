-- =============================================================================
-- perf_01_top_sql.sql
-- Priority: CRITICAL
-- Purpose: Identify the most expensive SQL by total time, mean latency,
--          call frequency, CPU, and I/O. This is the single most useful
--          query for finding the real cause of database load.
-- Requires: pg_stat_statements extension loaded via shared_preload_libraries.
--
-- Version notes:
--   * total_exec_time / mean_exec_time / stddev_exec_time / min_exec_time /
--     max_exec_time and wal_records / wal_bytes are the PostgreSQL 13+
--     column names. On PG 12 and earlier use total_time / mean_time / etc.
--   * pg_stat_statements_info is PostgreSQL 14+; the query below will fail
--     on PG 13 and earlier. Skip that query or wrap it in a
--     server_version_num guard if you need PG 13 compatibility.
-- Read-only.
-- =============================================================================

-- Verify extension availability
SELECT extname, extversion
FROM pg_extension
WHERE extname = 'pg_stat_statements';

-- Gate the whole file on the extension being installed; compute once.
SELECT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
) AS has_pgss
\gset
\if :has_pgss

-- Statistics reset timestamp (interpret all stats relative to this).
-- pg_stat_statements_info needs PG14+ AND extension version >= 1.9 (a
-- pg_upgraded cluster may still run an older extversion), so gate on the
-- view actually existing rather than on the server version.
SELECT to_regclass('pg_stat_statements_info') IS NOT NULL AS has_pgss_info
\gset
\if :has_pgss_info
SELECT stats_reset
FROM pg_stat_statements_info;
\else
SELECT 'pg_stat_statements_info not available (needs PG14+ and pg_stat_statements >= 1.9) - skipped' AS note;
\endif

-- ---------------------------------------------------------------------------
-- Top 25 queries by TOTAL execution time (overall load contributors)
-- ---------------------------------------------------------------------------
SELECT
    round(total_exec_time::numeric, 2)                   AS total_ms,
    round((total_exec_time / 1000 / 60)::numeric, 2)     AS total_min,
    calls,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    round(stddev_exec_time::numeric, 2)                  AS stddev_ms,
    rows                                                 AS total_rows,
    round((100 * total_exec_time
                / NULLIF(sum(total_exec_time) OVER (), 0))::numeric, 2)
                                                         AS pct_total,
    round((100 * calls
                / NULLIF(sum(calls) OVER (), 0))::numeric, 2)
                                                         AS pct_calls,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top 25 queries by MEAN execution time (slowest individual calls)
-- Filter out one-shot queries to reduce noise.
-- ---------------------------------------------------------------------------
SELECT
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    round(min_exec_time::numeric, 2)                     AS min_ms,
    round(max_exec_time::numeric, 2)                     AS max_ms,
    round(stddev_exec_time::numeric, 2)                  AS stddev_ms,
    calls,
    round(total_exec_time::numeric, 2)                   AS total_ms,
    rows,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE calls > 10
ORDER BY mean_exec_time DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top 25 queries by CALL FREQUENCY (find chatty clients / N+1 patterns)
-- ---------------------------------------------------------------------------
SELECT
    calls,
    round(total_exec_time::numeric, 2)                   AS total_ms,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    rows,
    round((rows::numeric / NULLIF(calls, 0)), 2)         AS rows_per_call,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
ORDER BY calls DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top queries by CPU time (planning + execution, no I/O wait)
-- pg_stat_statements does not separate CPU from wall time directly,
-- but high mean_exec_time with low shared_blks_read indicates CPU-bound work.
-- ---------------------------------------------------------------------------
SELECT
    round(total_exec_time::numeric, 2)                   AS total_ms,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    calls,
    shared_blks_hit                                      AS cache_hits,
    shared_blks_read                                     AS disk_reads,
    CASE WHEN shared_blks_hit + shared_blks_read > 0
         THEN round(100.0 * shared_blks_hit
                    / (shared_blks_hit + shared_blks_read), 2)
         ELSE 0
    END                                                  AS cache_hit_pct,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE shared_blks_read = 0
  AND mean_exec_time > 10
ORDER BY total_exec_time DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top queries by I/O (disk reads — likely bottleneck on slow storage)
-- ---------------------------------------------------------------------------
SELECT
    shared_blks_read                                     AS disk_reads,
    pg_size_pretty(shared_blks_read * 8192::bigint)      AS disk_read_size,
    shared_blks_hit                                      AS cache_hits,
    CASE WHEN shared_blks_hit + shared_blks_read > 0
         THEN round(100.0 * shared_blks_hit
                    / (shared_blks_hit + shared_blks_read), 2)
         ELSE 0
    END                                                  AS hit_ratio_pct,
    calls,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE shared_blks_read > 0
ORDER BY shared_blks_read DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Top WRITE-heavy queries (DML pressure)
-- ---------------------------------------------------------------------------
SELECT
    shared_blks_dirtied                                  AS blocks_dirtied,
    shared_blks_written                                  AS blocks_written,
    wal_records,
    pg_size_pretty(wal_bytes)                            AS wal_size,
    calls,
    rows,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE shared_blks_dirtied > 0
ORDER BY shared_blks_dirtied DESC
LIMIT 25;

\else
SELECT 'pg_stat_statements not installed - section skipped' AS note;
\endif
