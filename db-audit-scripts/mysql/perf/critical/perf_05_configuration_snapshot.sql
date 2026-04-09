-- =============================================================================
-- perf_05_configuration_snapshot.sql
-- Priority: CRITICAL
-- Purpose: Snapshot of key tunable parameters. Use this to quickly spot
--          gross misconfigurations (default settings on production HW,
--          missing InnoDB tuning, wrong sort_buffer_size, etc.).
-- Read-only.
-- =============================================================================

-- NOTE: MySQL configuration lives in performance_schema.global_variables
--       or can be read via SHOW GLOBAL VARIABLES. There is no pg_settings
--       equivalent with boot_val / source metadata in MySQL; the source
--       (config file vs runtime SET) is not directly exposed via SQL.

-- ---------------------------------------------------------------------------
-- Memory parameters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_buffer_pool_size',
    'innodb_buffer_pool_instances',
    'innodb_log_buffer_size',
    'key_buffer_size',
    'sort_buffer_size',
    'join_buffer_size',
    'read_buffer_size',
    'read_rnd_buffer_size',
    'tmp_table_size',
    'max_heap_table_size',
    'bulk_insert_buffer_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Connection / session parameters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'max_connections',
    'max_user_connections',
    'thread_cache_size',
    'wait_timeout',
    'interactive_timeout',
    'net_read_timeout',
    'net_write_timeout',
    'connect_timeout',
    'lock_wait_timeout',
    'innodb_lock_wait_timeout',
    'max_allowed_packet'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Parallelism / thread parameters
-- NOTE: MySQL 8.0 does not have true parallel query execution in the way
--       PostgreSQL does. Thread-pool options (if using the thread pool
--       plugin) would appear here. innodb_thread_concurrency controls
--       InnoDB kernel concurrency.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_thread_concurrency',
    'innodb_read_io_threads',
    'innodb_write_io_threads',
    'innodb_io_capacity',
    'innodb_io_capacity_max',
    'thread_pool_size',
    'thread_pool_max_active_query_threads',
    'thread_handling'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- InnoDB redo log / durability parameters
-- (analogous to PostgreSQL WAL/checkpoint parameters)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_flush_log_at_trx_commit',
    'sync_binlog',
    'innodb_log_file_size',
    'innodb_log_files_in_group',
    'innodb_redo_log_capacity',
    'innodb_flush_method',
    'innodb_doublewrite',
    'innodb_checksum_algorithm',
    'innodb_page_size',
    'binlog_format',
    'log_bin',
    'binlog_expire_logs_seconds',
    'expire_logs_days',
    'binlog_cache_size',
    'max_binlog_cache_size',
    'max_binlog_size'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Autovacuum equivalent — no direct analog in MySQL.
-- InnoDB does background purge automatically. These settings affect it.
-- NOTE: VACUUM does not exist in MySQL; InnoDB handles MVCC cleanup
--       via the purge thread automatically.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'innodb_purge_threads',
    'innodb_purge_batch_size',
    'innodb_max_purge_lag',
    'innodb_max_purge_lag_delay',
    'innodb_max_undo_log_size',
    'innodb_undo_log_truncate',
    'innodb_undo_tablespaces'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Planner / optimizer parameters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'optimizer_switch',
    'optimizer_prune_level',
    'optimizer_search_depth',
    'eq_range_index_dive_limit',
    'range_optimizer_max_mem_size',
    'max_seeks_for_key',
    'sort_buffer_size',
    'join_buffer_size',
    'innodb_stats_persistent',
    'innodb_stats_auto_recalc',
    'innodb_stats_sample_pages',
    'innodb_stats_transient_sample_pages'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Replication parameters
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'server_id',
    'log_bin',
    'binlog_format',
    'gtid_mode',
    'enforce_gtid_consistency',
    'replica_parallel_workers',
    'slave_parallel_workers',
    'replica_parallel_type',
    'sync_master_info',
    'sync_relay_log',
    'relay_log_recovery',
    'master_info_repository',
    'relay_log_info_repository'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- All NON-DEFAULT variables that have been changed
-- NOTE: MySQL does not track whether a variable was changed vs default
--       via SQL. This approximation shows variables that differ from
--       compiled-in defaults by querying performance_schema.variables_info
--       (MySQL 8.0.11+).
-- ---------------------------------------------------------------------------
SELECT
    vi.VARIABLE_NAME,
    gv.VARIABLE_VALUE                                       AS current_value,
    vi.VARIABLE_SOURCE                                      AS source,
    vi.VARIABLE_PATH                                        AS config_file,
    vi.MIN_VALUE,
    vi.MAX_VALUE,
    vi.SET_TIME,
    vi.SET_USER,
    vi.SET_HOST
FROM performance_schema.variables_info vi
JOIN performance_schema.global_variables gv
  ON gv.VARIABLE_NAME = vi.VARIABLE_NAME
WHERE vi.VARIABLE_SOURCE NOT IN ('COMPILED', 'GLOBAL')
ORDER BY vi.VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Quick sanity checks: key ratios
-- ---------------------------------------------------------------------------
SELECT
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'innodb_buffer_pool_size')       AS innodb_buffer_pool_bytes,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'max_connections')               AS max_connections,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'innodb_flush_log_at_trx_commit') AS flush_log_at_trx_commit,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'sync_binlog')                   AS sync_binlog,
    (SELECT VARIABLE_VALUE FROM performance_schema.global_variables
     WHERE VARIABLE_NAME = 'innodb_io_capacity')            AS io_capacity;
