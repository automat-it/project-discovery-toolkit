# Performance audit scripts

Read-only diagnostic queries for MySQL performance analysis.
Each script is independent and can be run standalone with `mysql < script.sql`.

## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT` and `SHOW`
statements. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`,
`TRUNCATE`, `GRANT`, or `REVOKE` is used anywhere. No temporary tables,
no functions, no objects of any kind are created.

## Target version

MySQL 8.0+. Several queries depend on `performance_schema` features
available only in 8.0 (CTEs, window functions, `variables_info` table,
`data_lock_waits` table, `replication_*` tables). Running against
MySQL 5.7 will produce errors in those blocks — skip them manually.

## Required privileges

Most scripts work for **any login user** with default privileges.
Specific elevated requirements:

* `PROCESS` privilege — required to see other users' queries in
  `information_schema.PROCESSLIST` and `performance_schema.threads`.
  Without it, only the current user's own sessions are visible.
* `SELECT` on `performance_schema` — required for all `perf_01`,
  `perf_04`, `perf_09`, `perf_13`, `perf_16` and related scripts.
  Grant with: `GRANT SELECT ON performance_schema.* TO 'user'@'host';`
* `SELECT` on `mysql.*` system tables — required for `perf_03`
  (per-user connection limits from `mysql.user`).
* `SELECT` on `sys.*` — required for scripts that query the `sys` schema
  (`perf_06`, `perf_07`, `perf_09`, `perf_12`). The `sys` schema ships
  by default in MySQL 8.0.
* `REPLICATION CLIENT` — required for `perf_10` replication queries
  (`SHOW REPLICA STATUS`, `SHOW BINARY LOGS`).

## Performance Schema prerequisites

The following `performance_schema` consumers and instruments must be
enabled for full script coverage. Check current status with:

```sql
SELECT * FROM performance_schema.setup_consumers WHERE enabled = 'NO';
SELECT * FROM performance_schema.setup_instruments
WHERE name LIKE 'wait/%' AND enabled = 'NO' LIMIT 20;
```

Key consumers needed:
* `events_statements_history_long` — for `perf_01`, `perf_04`, `perf_16`
* `events_waits_history_long` — for `perf_04`
* `events_stages_history_long` — optional, improves `perf_04`

Enable at runtime (resets on restart — add to `my.cnf` for persistence):
```sql
UPDATE performance_schema.setup_consumers SET enabled = 'YES'
WHERE name IN ('events_statements_history_long','events_waits_history_long');
```

## Recommended execution order

Run priorities top-to-bottom — `critical` first gives roughly 80% of the
insight needed to identify performance problems.

## Critical priority

### `perf_01_top_sql.sql`

Top SQL queries by total time, mean latency, call frequency, and I/O —
using `performance_schema.events_statements_summary_by_digest`. Timer
values are in picoseconds; the script converts them to milliseconds.
Equivalent to `pg_stat_statements` analysis in PostgreSQL.

### `perf_02_blocking_and_locks.sql`

Blocking pairs and lock waits from `performance_schema.data_lock_waits`
and `data_locks`; long-running and idle transactions from
`information_schema.INNODB_TRX`; InnoDB lock summary. Use
`SHOW ENGINE INNODB STATUS` for detailed deadlock text (noted in script).

### `perf_03_sessions_and_connections.sql`

Connection inventory by user, host, state, and database from
`information_schema.PROCESSLIST` and `performance_schema.threads`.
Per-user connection limits from `mysql.user.max_user_connections`.

### `perf_04_wait_events_and_io.sql`

Wait event breakdown by class (CPU vs I/O vs Lock vs Sync) from
`performance_schema.events_waits_summary_global_by_event_name`; InnoDB
I/O counters from `global_status`; per-table I/O from
`sys.schema_table_statistics`.

### `perf_05_configuration_snapshot.sql`

Snapshot of key `global_variables` covering memory (InnoDB buffer pool,
sort/join buffers), connections, timeouts, replication, InnoDB I/O,
query cache, and binary log settings. Non-default variables via
`performance_schema.variables_info`.

## High priority

### `perf_06_index_audit.sql`

Unused and never-used indexes from `sys.schema_unused_indexes` and
`performance_schema.table_io_waits_summary_by_index_usage`. Duplicate
indexes (same table + matching column at same position) from
`information_schema.STATISTICS`. **Foreign-key coverage check**:
aggregates the ordered FK column list and compares it against every
candidate index's leading prefix, so composite FKs whose first column
is indexed but whose full key is not are correctly flagged as
unsupported.

### `perf_07_table_stats_health.sql`

Stale optimizer statistics from `information_schema.TABLES.UPDATE_TIME`
vs `mysql.innodb_table_stats.last_update`; tables with no statistics
update recorded; large tables whose `AUTO_ANALYZE` threshold may be
exceeded. MySQL has no VACUUM concept — dead row cleanup is handled
automatically by InnoDB purge; the script notes current purge lag via
`SHOW ENGINE INNODB STATUS` counters.

### `perf_08_object_sizes.sql`

Largest tables and indexes from `information_schema.TABLES`
(`DATA_LENGTH`, `INDEX_LENGTH`); total schema sizes; tables with high
free-space fragmentation (`DATA_FREE`). MySQL has no TOAST or materialized
views — views are listed as informational.

### `perf_09_temp_and_memory_pressure.sql`

Temporary table and disk-spill counts from `global_status`
(`Created_tmp_disk_tables`, `Created_tmp_tables`) and per-digest
counters in `events_statements_summary_by_digest`
(`SUM_CREATED_TMP_DISK_TABLES`). Indicates undersized `tmp_table_size` /
`max_heap_table_size` or large sort/group operations.

### `perf_10_replication_and_backup_impact.sql`

Replication lag and applier status:
- Connection state from `performance_schema.replication_connection_status`.
- Applier (SQL thread) status from `replication_applier_status`, with
  `LAST_ERROR_*` columns pulled via LEFT JOIN from
  `replication_applier_status_by_coordinator` (single-threaded apply)
  and `replication_applier_status_by_worker` (parallel replication) —
  the base view does not expose them in MySQL 8.0+.
- Per-worker progress from `replication_applier_status_by_worker`.
- Connection configuration from `replication_connection_configuration`
  using current column names (`AUTO_POSITION`, `SSL_CERTIFICATE`,
  `CONNECTION_RETRY_INTERVAL` / `CONNECTION_RETRY_COUNT`).
- Binary log size and retention from `SHOW BINARY LOGS`.
- Connected replicas from `SHOW REPLICAS` (MySQL 8.0.22+; on earlier
  minor versions use `SHOW SLAVE HOSTS`).
- InnoDB redo log activity from `global_status`.

Results differ between source and replica — some blocks are empty on
one side; this is expected.

## Medium priority

### `perf_11_bloat_estimation.sql`

InnoDB free-space waste (`DATA_FREE`) per table as a bloat proxy — a
high `DATA_FREE` ratio indicates fragmentation that can be reclaimed with
`OPTIMIZE TABLE`. MySQL has no pg_freespace or dead-tuple catalog;
`DATA_FREE` is the closest available metric. Does not cover index bloat
directly.

### `perf_12_sequential_scans.sql`

Tables with high full-scan I/O from
`performance_schema.table_io_waits_summary_by_index_usage` where
`index_name IS NULL`; large tables with no secondary indexes from
`information_schema.STATISTICS` and `TABLES` — classic missing-index
indicators.

### `perf_13_deadlock_history.sql`

Global deadlock counter from `global_status` (`Innodb_deadlocks`);
InnoDB lock timeout and deadlock variables; last deadlock detail note
directing to `SHOW ENGINE INNODB STATUS`. MySQL exposes the most recent
deadlock only (not a full history) — use the `performance_schema` error
log table or application logs for historical analysis.

### `perf_14_checkpoint_bgwriter.sql`

InnoDB flush activity from `global_status` (`Innodb_pages_written`,
`Innodb_buffer_pool_pages_flushed`, `Innodb_os_log_written`); InnoDB
I/O configuration variables. MySQL has no pg_stat_bgwriter equivalent —
flush behavior is driven by `innodb_io_capacity`, `innodb_flush_method`,
and adaptive flushing settings shown in the script.

### `perf_15_capacity_and_growth.sql`

Per-schema data and index sizes; tablespace usage from
`information_schema.FILES`; `AUTO_INCREMENT` headroom per column data
type (TINYINT, SMALLINT, INT, BIGINT) — MySQL's equivalent of PostgreSQL
sequence headroom. No XID wraparound concept in MySQL.

## Low priority

### `perf_16_plan_instability.sql`

Queries with high max/min execution time ratio from
`events_statements_summary_by_digest` — detects plan instability and
outlier executions. MySQL does not expose `stddev_exec_time` directly;
max/min ratio is used as a proxy. Queries with few executions are
filtered to reduce noise.

### `perf_17_skewed_data.sql`

InnoDB index cardinality from `information_schema.STATISTICS` to detect
low-cardinality indexes and potential bad plan choices; per-schema null
ratio approximation from column metadata. MySQL has no `pg_stats`
histogram equivalent — cardinality is the best available proxy.

### `perf_18_forecast_inputs.sql`

Cluster-level, per-schema, and per-table size and activity snapshots
designed to be collected periodically and fed into external time-series
forecasting tools. Covers data size, row counts, index sizes, and
`AUTO_INCREMENT` consumption.

## Notes and caveats

* **`performance_schema` counters reset on restart.** All
  `events_statements_summary_by_digest` and wait-event counters
  accumulate since the last server restart or explicit
  `TRUNCATE TABLE performance_schema.<table>`. Always note the uptime
  (`SHOW GLOBAL STATUS LIKE 'Uptime'`) before interpreting totals.
* **`perf_10` returns different results on source vs replica.** On a
  source, replication connection tables are empty; on a replica,
  the binary-log-based blocks may be empty. This is expected.
* **No VACUUM or CHECKPOINT concept.** InnoDB manages row cleanup via
  the purge thread and flushes pages via adaptive flushing — there is no
  manual equivalent to `VACUUM` or `CHECKPOINT`. Scripts `perf_11` and
  `perf_14` approximate the closest observable metrics.
* **Duplicate index detection in `perf_06`** matches on table + ordered
  column list only (from `information_schema.STATISTICS`). Unlike the
  PostgreSQL version it cannot inspect opclasses, predicates, or INCLUDE
  columns because MySQL does not expose those in standard catalogs. Treat
  all duplicate pairs as candidates for manual review before dropping.
* **`sys` schema must be installed.** It ships by default in MySQL 8.0
  but may be missing in minimal installs. Check with:
  `SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'sys';`
