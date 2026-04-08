# Performance audit scripts

Read-only diagnostic queries for PostgreSQL performance analysis.
Each script is independent and can be run standalone with `psql -f`.

## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT` and `SHOW`
statements. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`,
`TRUNCATE`, `GRANT`, or `REVOKE` is used anywhere. No temporary tables,
no functions, no objects of any kind are created.

## Target version

PostgreSQL 13+. A few queries reference catalogs added in newer versions
(`pg_stat_wal` in 14+); those blocks are guarded by a server-version
check and degrade to a `skipped` note instead of erroring out.

## Required privileges

Most scripts work for **any login role** with default privileges.
Specific elevated requirements:

* To see other users' query text in `pg_stat_activity`, the role needs
  membership in `pg_read_all_stats` or `pg_monitor` (or be superuser /
  `rds_superuser` on AWS RDS).
* Scripts that read `pg_stat_statements` (`perf_01`, `perf_04`,
  `perf_09`, `perf_13`, `perf_16`) require the extension to be loaded
  via `shared_preload_libraries`. On AWS RDS this is set in the
  Parameter Group.

## Recommended execution order

Run priorities top-to-bottom — `critical` first gives roughly 80% of the
insight needed to identify performance problems.

## Critical priority

### `perf_01_top_sql.sql`

Top SQL queries by total time, mean latency, call frequency, CPU and
I/O — the single most useful query for finding the real cause of
database load.

### `perf_02_blocking_and_locks.sql`

Blocking pairs, recursive blocking tree, long-running transactions, and
idle-in-transaction sessions — the most common cause of latency spikes
and timeouts.

### `perf_03_sessions_and_connections.sql`

Connection inventory by user, app, state, and client address — finds
connection storms, pool misconfigurations, and oldest sessions.

### `perf_04_wait_events_and_io.sql`

Breakdown of wait events (CPU vs I/O vs Lock vs LWLock) and per-database
I/O statistics — determines whether the bottleneck is CPU, disk, or
contention.

### `perf_05_configuration_snapshot.sql`

Snapshot of memory, parallelism, WAL, autovacuum, planner, and bgwriter
parameters — quickly spots gross misconfigurations and non-default
overrides.

## High priority

### `perf_06_index_audit.sql`

Unused, never-scanned, strict-duplicate, and invalid indexes plus
foreign keys without supporting indexes (with full composite-key
prefix matching) — direct impact on read latency and write overhead.

### `perf_07_table_stats_health.sql`

Stale statistics, never-analyzed tables, dead tuple ratios, autovacuum
activity, and per-table autovacuum overrides — bad stats produce bad
plans.

### `perf_08_object_sizes.sql`

Largest tables, indexes, TOAST tables, materialized views, and
partitions — identifies hot spots and growth candidates.

### `perf_09_temp_and_memory_pressure.sql`

Temp file usage per database and per query, sessions spilling to disk —
shows undersized `work_mem` and large sort/hash/join problems.

### `perf_10_replication_and_backup_impact.sql`

Replication lag (primary and replica side), replication slots holding
WAL, ongoing base backups, and WAL activity — backup and replica
pressure on write latency.

## Medium priority

### `perf_11_bloat_estimation.sql`

Heuristic table and index bloat estimation based on row width and tuple
count — affects I/O and cache efficiency.

### `perf_12_sequential_scans.sql`

Tables with high sequential scan ratio, large tables with no indexes —
classic missing-index indicators.

### `perf_13_deadlock_history.sql`

Deadlock counters per database, recovery conflicts on replicas, and
lock-wait logging settings — for finding race conditions.

### `perf_14_checkpoint_bgwriter.sql`

Checkpoint frequency (forced vs scheduled), background writer activity,
and WAL stats — forced checkpoints cause latency spikes.

### `perf_15_capacity_and_growth.sql`

Cluster-wide storage, per-database size, transaction ID consumption,
tablespace usage, sequence headroom — for capacity planning.

## Low priority

### `perf_16_plan_instability.sql`

Queries with high stddev/mean ratio and large min/max gaps — detects
plan instability and outlier executions.

### `perf_17_skewed_data.sql`

Columns with low cardinality, heavy hitters in MCV histograms, highly
null columns, partition row count skew — uneven data distribution.

### `perf_18_forecast_inputs.sql`

Cluster, database, and per-table snapshots designed to be collected
periodically and fed into external time-series forecasting.

## Notes and caveats

* **Statistics are cumulative.** Most counters in `pg_stat_*` views
  accumulate since the last `pg_stat_reset()` call. Always check the
  `stats_reset` timestamp (visible in `pg_stat_database` and
  `pg_stat_statements_info`) before drawing conclusions about totals.
* **Script 10 (`perf_10_replication_and_backup_impact.sql`)** returns
  different result sets depending on whether the instance is a primary
  or a replica. Some blocks are empty on one side and populated on the
  other — this is expected.
* **Version-guarded blocks** use `psql` meta-commands (`\gset` + `\if`)
  to skip queries that require a newer PostgreSQL version. They produce
  a `note` row instead of an error. These guards work in `psql` but are
  ignored by other clients (DBeaver, pgAdmin); to run the scripts in
  those, simply skip the guarded blocks manually.
* **Index audit duplicate detection** in `perf_06` uses a strict
  comparison (key columns + opclass + collation + sort options +
  predicate + uniqueness + INCLUDE columns). Pairs returned by the
  strict block are safe drop candidates; the loose heuristic block
  marks the rest for manual review.
