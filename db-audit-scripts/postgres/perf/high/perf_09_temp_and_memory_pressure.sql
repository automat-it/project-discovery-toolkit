-- =============================================================================
-- perf_09_temp_and_memory_pressure.sql
-- Priority: HIGH
-- Purpose: Detect spills to disk caused by undersized work_mem,
--          large sorts/hashes/joins, and temp file usage.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Database-level temp file usage (cumulative since stats reset)
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    temp_files                                           AS temp_file_count,
    pg_size_pretty(temp_bytes)                           AS temp_total_size,
    temp_bytes                                           AS temp_bytes_total,
    CASE WHEN temp_files > 0
         THEN pg_size_pretty(temp_bytes / temp_files)
         ELSE NULL
    END                                                  AS avg_temp_file_size,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY temp_bytes DESC;

-- ---------------------------------------------------------------------------
-- Top queries spilling to disk (pg_stat_statements)
-- ---------------------------------------------------------------------------
SELECT
    temp_blks_read                                       AS temp_blocks_read,
    temp_blks_written                                    AS temp_blocks_written,
    pg_size_pretty(temp_blks_written * 8192::bigint)     AS temp_size_written,
    calls,
    round(mean_exec_time::numeric, 2)                    AS mean_ms,
    round(total_exec_time::numeric, 2)                   AS total_ms,
    rows,
    queryid,
    left(query, 300)                                     AS query
FROM pg_stat_statements
WHERE temp_blks_written > 0
ORDER BY temp_blks_written DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- Currently active queries using temp files
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    state,
    wait_event_type,
    wait_event,
    now() - query_start                                  AS duration,
    left(query, 300)                                     AS query
FROM pg_stat_activity
WHERE state = 'active'
  AND wait_event IN ('BufFileRead', 'BufFileWrite');

-- ---------------------------------------------------------------------------
-- work_mem and related parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'work_mem',
    'hash_mem_multiplier',
    'maintenance_work_mem',
    'temp_buffers',
    'temp_file_limit',
    'log_temp_files'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Per-role / per-database work_mem overrides
-- ---------------------------------------------------------------------------
SELECT
    coalesce(r.rolname, 'ALL ROLES')                     AS role,
    coalesce(d.datname, 'ALL DBS')                       AS database,
    s.setconfig                                          AS settings
FROM pg_db_role_setting s
LEFT JOIN pg_roles r    ON r.oid = s.setrole
LEFT JOIN pg_database d ON d.oid = s.setdatabase
WHERE array_to_string(s.setconfig, ' ') ILIKE '%work_mem%'
   OR array_to_string(s.setconfig, ' ') ILIKE '%temp%';
