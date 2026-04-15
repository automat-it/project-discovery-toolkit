# Performance audit scripts

Read-only diagnostic queries for Microsoft SQL Server performance
analysis. Each script is independent and can be run standalone with
`sqlcmd -i <script>.sql`.

## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT`,
`DBCC TRACESTATUS(-1) WITH NO_INFOMSGS`, and read-only system stored
procedures (`xp_readerrorlog`, `xp_instance_regread`,
`sys.sp_cdc_*` *listings only*) are used. No `CREATE`, `ALTER`, `DROP`,
`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `GRANT`, or `REVOKE` anywhere.
No temporary tables, no functions, no objects of any kind are created.

Table variables (`DECLARE @t TABLE …`) are used in a couple of scripts
for intermediate aggregation; they live only in the calling session and
vanish automatically. No persistent objects.

## Target version

SQL Server 2019+, verified on 2022 Developer (Linux). Blocks that
require newer features (`sys.dm_db_log_stats`, columnstore DMVs,
external tables) are wrapped in `TRY/CATCH` or gated by
`IF EXISTS (…)` so they fail gracefully on older editions.

## Required privileges

Default login with `VIEW SERVER STATE` is enough for ~90% of the output.
Elevated needs:

* `VIEW SERVER STATE` — every DMV used below
* `VIEW ANY DEFINITION` — module text, `sys.sql_modules.definition`
* sysadmin — `xp_readerrorlog`, `xp_instance_regread`,
  `sys.dm_server_audit_status` (some paths)

## Recommended execution order

Run priorities top-to-bottom — `critical` first gives roughly 80% of the
insight needed to identify performance problems.

## Critical priority

### `perf_01_top_sql.sql`

Top SQL by total / mean / frequency / CPU / I/O. Uses Query Store
when the target database has it enabled; falls back to
`sys.dm_exec_query_stats` + `sys.dm_exec_sql_text` for plan-cache
server-wide view.

### `perf_02_blocking_and_locks.sql`

Direct blocking pairs, recursive blocking chain, long-running
transactions, sleeping sessions with open transactions (SQL Server
analog of PostgreSQL's "idle in transaction"), lock summary, and
deadlock counter from `sys.dm_os_performance_counters`.

### `perf_03_sessions_and_connections.sql`

Connection inventory by login / host / app, client IP breakdown,
endpoint / protocol inventory. Finds connection storms and pool
misconfiguration.

### `perf_04_wait_events_and_io.sql`

Current active waits, accumulated wait stats (server lifetime)
excluding benign sleep waits, wait categorisation (I/O vs Lock vs
Latch vs Parallelism vs CPU-proxy vs Network vs Memory grant), per-file
I/O totals + stall averages, buffer cache hit ratio, page life
expectancy per NUMA node.

### `perf_05_configuration_snapshot.sql`

Edition / version, OS/hardware snapshot, all `sp_configure` settings
(non-default highlighted), database options per user database, file
auto-growth settings, trace flags on, tempdb file layout.

## High priority

### `perf_06_index_audit.sql`

Unused indexes, never-read indexes, duplicate / overlapping indexes
(exact + prefix matching), disabled indexes, missing-index optimizer
suggestions, and foreign keys without a covering index (composite-key
prefix aware).

### `perf_07_table_stats_health.sql`

Tables with no stats ever, stale stats (high `modification_counter /
rows`), disabled auto-update stats, index fragmentation (>30%), row
counts + sizing, statistics sample percentage.

### `perf_08_object_sizes.sql`

Database sizes (data + log separated), schema sizes, top 50 tables and
top 50 indexes, tables where indexes are larger than data, partitioned
table per-partition sizes, columnstore row-group / segment inventory.

### `perf_09_temp_and_memory_pressure.sql`

TempDB file allocation (user / internal / version store / mixed-extent),
current memory grants, resource semaphore queue backlog, top memory
clerks, buffer pool per database, plan-cache queries with spills, top
queries by grant size, TempDB contention waits (`PAGELATCH_*` on
GAM/SGAM/PFS).

### `perf_10_replication_and_backup_impact.sql`

AlwaysOn AG state + per-database redo / log-send queue, CDC enabled
databases + capture instances + cleanup job status, Change Tracking,
replication distribution presence, in-flight backup / restore,
last-backup-per-database, log-shipping monitor tables.

## Medium priority

### `perf_11_bloat_estimation.sql`

Low page-fullness indexes (wasted space per page), heap tables with
forwarded records, large heaps, ghost records awaiting cleanup, LOB
vs in-row allocation per table. SQL Server has no "dead tuple" concept
like PostgreSQL — these metrics approximate the same pressure.

### `perf_12_sequential_scans.sql`

Tables where table-scan ratio dominates seeks, big tables with zero
non-clustered indexes, optimizer missing-index suggestions, queries
with table / index scan operators in their plan XML (Query Store).

### `perf_13_deadlock_history.sql`

Deadlock counter, lock timeout / wait-time counters, recent deadlock
reports parsed from the `system_health` Extended Events session,
recent blocked-process reports (requires
`blocked process threshold > 0`), sub-minute agent jobs.

### `perf_14_checkpoint_bgwriter.sql`

Checkpoint / lazy writer counters, log-file statistics
(`sys.dm_db_log_stats` in 2017+), log reuse-wait cause per database,
per-file log I/O throughput, `WRITELOG` family wait accumulation.

### `perf_15_capacity_and_growth.sql`

Cluster-wide storage summary, per-database size + growth indicators,
top tables by rows / size, connection limit vs usage, **identity-column
headroom** (TINYINT / SMALLINT / INT / BIGINT percent consumed),
sequence-object consumption, filegroup layout per database.

## Low priority

### `perf_16_plan_instability.sql`

Queries with multiple plans over time (Query Store), high-variance
queries (stdev ≥ mean, coefficient-of-variation ranking), regressed
plans (current plan slower than historical), plan-cache max/min ratio
outliers, forced plans + their force-failure count.

### `perf_17_skewed_data.sql`

Columns with a dominant value from the statistics histogram, histograms
with very few steps (low cardinality), partition row-count skew,
columns with very high NULL fraction inferred from the first histogram
bucket.

### `perf_18_forecast_inputs.sql`

Single-row cluster snapshot + per-database / per-table / per-file /
identity-column snapshots designed to be collected periodically and
pushed to an external time-series store for forecasting.

## Notes and caveats

* **Most metrics are cumulative since SQL Server start.**
  `sys.dm_os_wait_stats`, `sys.dm_exec_query_stats`,
  `sys.dm_io_virtual_file_stats` accumulate since the instance started
  or since `DBCC SQLPERF(…, CLEAR)` — always note uptime
  (`sys.dm_os_sys_info.sqlserver_start_time`) before interpreting totals.
* **Query Store is per-database.** `perf_01`, `perf_12`, `perf_16` fall
  back to plan-cache DMVs when the current database's Query Store is
  off. The scripts check `sys.database_query_store_options.actual_state`
  before running Query Store blocks.
* **Ring-buffer XE parsing** in `perf_13` depends on events present in
  the `system_health` session — new SQL Server builds may rename events
  (`xml_deadlock_report` vs `deadlock_report`); both are handled.
* **Partitioning / columnstore** queries return empty when the engine
  edition does not support the feature (e.g. SQL Server Express).
