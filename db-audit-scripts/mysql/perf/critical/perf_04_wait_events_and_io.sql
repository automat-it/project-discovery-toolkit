-- =============================================================================
-- perf_04_wait_events_and_io.sql
-- Priority: CRITICAL
-- Purpose: Identify the bottleneck — CPU, disk I/O, locks, or network —
--          via wait events and I/O statistics.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL wait events are surfaced through performance_schema.
--       events_waits_summary_by_event_name aggregates cumulative waits.
--       Current per-session waits are in events_waits_current (requires
--       the 'events_waits_current' consumer to be enabled).
--       There is no direct equivalent of pg_stat_database I/O totals;
--       the closest is performance_schema.file_summary_by_instance and
--       global status variables.

-- ---------------------------------------------------------------------------
-- Verify wait event consumers are enabled
-- ---------------------------------------------------------------------------
SELECT NAME, ENABLED
FROM performance_schema.setup_consumers
WHERE NAME LIKE 'events_waits%'
ORDER BY NAME;

-- ---------------------------------------------------------------------------
-- Current wait events per active thread (instantaneous snapshot)
-- ---------------------------------------------------------------------------
SELECT
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_HOST                                      AS host,
    t.PROCESSLIST_DB                                        AS database_name,
    t.PROCESSLIST_STATE                                     AS thread_state,
    ew.EVENT_NAME                                           AS wait_event,
    ROUND(ew.TIMER_WAIT / 1e9, 2)                           AS wait_ms,
    LEFT(t.PROCESSLIST_INFO, 200)                           AS query
FROM performance_schema.events_waits_current ew
JOIN performance_schema.threads t
  ON t.THREAD_ID = ew.THREAD_ID
WHERE t.PROCESSLIST_ID IS NOT NULL
  AND ew.EVENT_NAME <> 'idle'
ORDER BY ew.TIMER_WAIT DESC;

-- ---------------------------------------------------------------------------
-- Top wait events by total accumulated wait time (grouped)
-- ---------------------------------------------------------------------------
SELECT
    EVENT_NAME                                              AS wait_event,
    COUNT_STAR                                              AS wait_count,
    ROUND(SUM_TIMER_WAIT / 1e12, 2)                         AS total_wait_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS avg_wait_ms,
    ROUND(MAX_TIMER_WAIT / 1e9, 2)                          AS max_wait_ms
FROM performance_schema.events_waits_summary_global_by_event_name
WHERE SUM_TIMER_WAIT > 0
  AND EVENT_NAME NOT LIKE 'idle%'
ORDER BY SUM_TIMER_WAIT DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Wait events grouped by category (IO vs Lock vs Synch vs CPU-proxy)
-- ---------------------------------------------------------------------------
SELECT
    CASE
        WHEN EVENT_NAME LIKE 'wait/io/%'    THEN 'I/O'
        WHEN EVENT_NAME LIKE 'wait/lock/%'  THEN 'Lock'
        WHEN EVENT_NAME LIKE 'wait/synch/%' THEN 'Synch/Latch'
        ELSE 'Other'
    END                                                     AS wait_category,
    COUNT(*)                                                AS distinct_events,
    ROUND(SUM(SUM_TIMER_WAIT) / 1e12, 2)                    AS total_wait_ms
FROM performance_schema.events_waits_summary_global_by_event_name
WHERE SUM_TIMER_WAIT > 0
GROUP BY wait_category
ORDER BY total_wait_ms DESC;

-- ---------------------------------------------------------------------------
-- Per-session wait detail (for active sessions)
-- ---------------------------------------------------------------------------
SELECT
    t.PROCESSLIST_ID                                        AS pid,
    t.PROCESSLIST_USER                                      AS user,
    t.PROCESSLIST_COMMAND                                   AS command,
    t.PROCESSLIST_STATE                                     AS state,
    ew.EVENT_NAME                                           AS current_wait,
    ROUND(ew.TIMER_WAIT / 1e9, 2)                           AS wait_ms,
    t.PROCESSLIST_TIME                                      AS query_age_sec,
    LEFT(t.PROCESSLIST_INFO, 200)                           AS query
FROM performance_schema.threads t
LEFT JOIN performance_schema.events_waits_current ew
  ON ew.THREAD_ID = t.THREAD_ID
WHERE t.PROCESSLIST_COMMAND <> 'Sleep'
  AND t.TYPE = 'FOREGROUND'
ORDER BY t.PROCESSLIST_TIME DESC;

-- ---------------------------------------------------------------------------
-- Global I/O totals (status variables)
-- NOTE: MySQL does not expose per-database block reads/hits like
--       pg_stat_database. Global InnoDB buffer pool stats are the
--       closest equivalent.
-- ---------------------------------------------------------------------------
SELECT
    VARIABLE_NAME,
    VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Innodb_buffer_pool_reads',
    'Innodb_buffer_pool_read_requests',
    'Innodb_buffer_pool_write_requests',
    'Innodb_data_read',
    'Innodb_data_written',
    'Innodb_data_reads',
    'Innodb_data_writes',
    'Innodb_os_log_written',
    'Innodb_pages_read',
    'Innodb_pages_written',
    'Handler_read_rnd_next',
    'Handler_read_rnd',
    'Handler_read_key',
    'Handler_read_next',
    'Select_scan',
    'Select_full_join'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB buffer pool hit ratio
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests')
                                                            AS buffer_pool_requests,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads')
                                                            AS buffer_pool_disk_reads,
    ROUND(100.0
          - 100.0
          * (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
             WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads')
          / NULLIF(
              (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
               WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests'), 0),
          2)                                                AS buffer_pool_hit_pct;

-- ---------------------------------------------------------------------------
-- Per-table I/O statistics (requires sys schema)
-- NOTE: sys schema ships by default in MySQL 8.0.
-- ---------------------------------------------------------------------------
SELECT
    table_schema,
    table_name,
    rows_fetched,
    fetch_latency,
    rows_inserted,
    insert_latency,
    rows_updated,
    update_latency,
    rows_deleted,
    delete_latency,
    io_read_requests,
    io_read,
    io_write_requests,
    io_write
FROM sys.schema_table_statistics
ORDER BY io_read_requests + io_write_requests DESC
LIMIT 30;

-- ---------------------------------------------------------------------------
-- Per-statement I/O via performance_schema (top by rows examined)
-- ---------------------------------------------------------------------------
SELECT
    SUM_ROWS_EXAMINED                                       AS rows_examined,
    SUM_ROWS_SENT                                           AS rows_sent,
    ROUND(SUM_TIMER_WAIT / 1e9, 2)                          AS total_ms,
    ROUND(AVG_TIMER_WAIT / 1e9, 2)                          AS mean_ms,
    COUNT_STAR                                              AS calls,
    LEFT(DIGEST_TEXT, 200)                                  AS query
FROM performance_schema.events_statements_summary_by_digest
WHERE SUM_ROWS_EXAMINED > 0
  AND DIGEST_TEXT IS NOT NULL
ORDER BY SUM_ROWS_EXAMINED DESC
LIMIT 25;

-- ---------------------------------------------------------------------------
-- track_io_timing equivalent — check if performance_schema is tracking timing
-- ---------------------------------------------------------------------------
SELECT NAME, ENABLED, TIMED
FROM performance_schema.setup_instruments
WHERE NAME LIKE 'wait/io/file/%'
  OR NAME LIKE 'wait/io/table/%'
LIMIT 20;
