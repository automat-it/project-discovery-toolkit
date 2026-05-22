-- =============================================================================
-- perf_05_configuration_snapshot.sql
-- Priority: CRITICAL
-- Purpose: Snapshot of key tunable parameters. Use this to quickly spot
--          gross misconfigurations (default settings on production HW,
--          missing autovacuum tuning, wrong work_mem, etc.).
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Fingerprint header -- single-row context the report analyzer reads to
-- populate the Environment Fingerprint card. Keep as the FIRST query so
-- the analyzer can find it deterministically.
-- ---------------------------------------------------------------------------
SELECT
    current_setting('server_version')                     AS server_version,
    current_setting('server_version_num')::int            AS server_version_num,
    current_database()                                    AS database_name,
    current_user                                          AS connection_user,
    inet_server_addr()                                    AS server_ip,
    inet_server_port()                                    AS server_port,
    pg_is_in_recovery()                                   AS is_in_recovery,
    pg_postmaster_start_time()                            AS postmaster_start_time,
    now() - pg_postmaster_start_time()                    AS uptime,
    current_setting('cluster_name', true)                 AS cluster_name,
    EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdsadmin') AS is_aws_rds,
    (SELECT count(*) FROM pg_database WHERE datistemplate=false) AS user_databases,
    (SELECT pg_size_pretty(pg_database_size(current_database()))) AS this_db_size,
    current_setting('shared_buffers')                     AS shared_buffers,
    current_setting('max_connections')                    AS max_connections,
    current_setting('wal_level')                          AS wal_level,
    version()                                             AS version_full;

-- ---------------------------------------------------------------------------
-- Memory parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source, boot_val
FROM pg_settings
WHERE name IN (
    'shared_buffers',
    'effective_cache_size',
    'work_mem',
    'maintenance_work_mem',
    'temp_buffers',
    'wal_buffers',
    'huge_pages',
    'hash_mem_multiplier',
    'logical_decoding_work_mem'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Connection / session parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'max_connections',
    'superuser_reserved_connections',
    'idle_in_transaction_session_timeout',
    'idle_session_timeout',
    'statement_timeout',
    'lock_timeout',
    'tcp_keepalives_idle',
    'tcp_keepalives_interval',
    'tcp_keepalives_count',
    'client_connection_check_interval'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Parallelism parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'max_worker_processes',
    'max_parallel_workers',
    'max_parallel_workers_per_gather',
    'max_parallel_maintenance_workers',
    'parallel_setup_cost',
    'parallel_tuple_cost',
    'min_parallel_table_scan_size',
    'min_parallel_index_scan_size'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- WAL / checkpoint parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'wal_level',
    'wal_compression',
    'wal_log_hints',
    'fsync',
    'synchronous_commit',
    'commit_delay',
    'commit_siblings',
    'min_wal_size',
    'max_wal_size',
    'checkpoint_timeout',
    'checkpoint_completion_target',
    'checkpoint_flush_after',
    'wal_writer_delay',
    'wal_writer_flush_after'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Autovacuum parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name LIKE 'autovacuum%'
   OR name IN ('vacuum_cost_delay', 'vacuum_cost_limit',
               'vacuum_freeze_min_age', 'vacuum_freeze_table_age',
               'vacuum_multixact_freeze_min_age', 'vacuum_multixact_freeze_table_age')
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Planner / cost parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'random_page_cost',
    'seq_page_cost',
    'cpu_tuple_cost',
    'cpu_index_tuple_cost',
    'cpu_operator_cost',
    'effective_io_concurrency',
    'maintenance_io_concurrency',
    'default_statistics_target',
    'jit',
    'jit_above_cost',
    'jit_inline_above_cost',
    'jit_optimize_above_cost',
    'plan_cache_mode',
    'enable_partitionwise_join',
    'enable_partitionwise_aggregate'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Background writer parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name LIKE 'bgwriter%'
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Replication parameters
-- ---------------------------------------------------------------------------
SELECT name, setting, unit, source
FROM pg_settings
WHERE name IN (
    'max_wal_senders',
    'max_replication_slots',
    'wal_sender_timeout',
    'wal_receiver_timeout',
    'hot_standby',
    'hot_standby_feedback',
    'max_standby_streaming_delay',
    'max_standby_archive_delay',
    'max_logical_replication_workers',
    'max_sync_workers_per_subscription'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- All NON-DEFAULT parameters (everything tuned away from boot value)
-- ---------------------------------------------------------------------------
SELECT
    name,
    setting,
    unit,
    boot_val                                             AS default_value,
    source,
    context
FROM pg_settings
WHERE source NOT IN ('default', 'override')
  AND setting IS DISTINCT FROM boot_val
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Pending-restart parameters (changed but require reboot)
-- ---------------------------------------------------------------------------
SELECT name, setting, pending_restart, context
FROM pg_settings
WHERE pending_restart = true;

-- ---------------------------------------------------------------------------
-- Quick sanity checks: ratios that often catch misconfig
-- ---------------------------------------------------------------------------
SELECT
    (SELECT setting FROM pg_settings WHERE name = 'shared_buffers')        AS shared_buffers_8kB,
    (SELECT setting FROM pg_settings WHERE name = 'effective_cache_size')  AS effective_cache_8kB,
    (SELECT setting FROM pg_settings WHERE name = 'work_mem')              AS work_mem_kB,
    (SELECT setting FROM pg_settings WHERE name = 'maintenance_work_mem')  AS maint_work_mem_kB,
    (SELECT setting FROM pg_settings WHERE name = 'max_connections')       AS max_connections,
    (SELECT setting FROM pg_settings WHERE name = 'random_page_cost')      AS random_page_cost;
