-- =============================================================================
-- perf_14_checkpoint_bgwriter.sql
-- Priority: MEDIUM
-- Purpose: InnoDB flushing activity, checkpoint pressure, and redo log
--          write patterns.
--          MySQL equivalent of PostgreSQL checkpoint/bgwriter monitoring.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL / InnoDB does not have the PostgreSQL bgwriter / checkpointer
--       split or pg_stat_bgwriter. The closest analogs are:
--         * InnoDB fuzzy checkpointing (controlled by innodb_io_capacity)
--         * Page cleaner threads (innodb_page_cleaners)
--         * Redo log (analogous to WAL) controlled by
--           innodb_log_file_size / innodb_redo_log_capacity
--         * innodb_flush_log_at_trx_commit controls fsync frequency
--       There is no equivalent of pg_stat_wal or pg_stat_bgwriter as
--       structured tables; InnoDB metrics are in global status variables
--       and SHOW ENGINE INNODB STATUS.

-- ---------------------------------------------------------------------------
-- InnoDB I/O and flushing counters (cumulative since server start)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Innodb_buffer_pool_pages_dirty',
    'Innodb_buffer_pool_pages_flushed',
    'Innodb_buffer_pool_write_requests',
    'Innodb_buffer_pool_read_requests',
    'Innodb_buffer_pool_reads',
    'Innodb_data_fsyncs',
    'Innodb_data_writes',
    'Innodb_data_reads',
    'Innodb_data_pending_fsyncs',
    'Innodb_data_pending_reads',
    'Innodb_data_pending_writes',
    'Innodb_log_waits',
    'Innodb_log_write_requests',
    'Innodb_log_writes',
    'Innodb_os_log_fsyncs',
    'Innodb_os_log_pending_fsyncs',
    'Innodb_os_log_pending_writes',
    'Innodb_os_log_written',
    'Innodb_pages_written',
    'Innodb_pages_read'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Checkpoint / flushing configuration parameters
-- (analogous to PostgreSQL checkpoint_timeout, checkpoint_completion_target)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_io_capacity',
    'innodb_io_capacity_max',
    'innodb_flush_method',
    'innodb_flush_log_at_trx_commit',
    'innodb_flush_log_at_timeout',
    'innodb_flush_sync',
    'innodb_fsync_threshold',
    'innodb_log_file_size',
    'innodb_log_files_in_group',
    'innodb_redo_log_capacity',
    'innodb_max_dirty_pages_pct',
    'innodb_max_dirty_pages_pct_lwm',
    'innodb_lru_scan_depth',
    'innodb_page_cleaners',
    'innodb_write_io_threads',
    'innodb_read_io_threads',
    'innodb_doublewrite',
    'innodb_doublewrite_pages',
    'innodb_adaptive_flushing',
    'innodb_adaptive_flushing_lwm',
    'sync_binlog'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Redo log usage (analogous to WAL activity in PostgreSQL 14+)
-- NOTE: MySQL does not have a pg_stat_wal equivalent as a structured table.
--       InnoDB_os_log_written gives cumulative redo log bytes written.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN (
    'Innodb_os_log_written',
    'Innodb_os_log_fsyncs',
    'Innodb_log_writes',
    'Innodb_log_write_requests',
    'Innodb_log_waits'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Buffer pool flushing efficiency
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_dirty') + 0
                                                            AS dirty_pages,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_total') + 0
                                                            AS total_pages,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_status
     WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_flushed') + 0
                                                            AS pages_flushed,
    ROUND(
        100.0
        * (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
           WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_dirty')
        / NULLIF(
            (SELECT VARIABLE_VALUE + 0 FROM performance_schema.global_status
             WHERE VARIABLE_NAME = 'Innodb_buffer_pool_pages_total'), 0),
        2)                                                  AS dirty_pct;

-- ---------------------------------------------------------------------------
-- Quick interpretation hints
-- ---------------------------------------------------------------------------
SELECT
    'innodb_io_capacity should match your disk IOPS capacity'            AS hint_1,
    'Innodb_log_waits > 0 means redo log is too small (increase innodb_redo_log_capacity)' AS hint_2,
    'innodb_flush_log_at_trx_commit=1 is safest but highest fsync cost'  AS hint_3,
    'High Innodb_data_pending_writes indicates I/O saturation'           AS hint_4,
    'innodb_max_dirty_pages_pct > 90 risks checkpoint storms on crash'   AS hint_5;
