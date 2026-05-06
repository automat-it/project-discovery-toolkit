# Performance audit scripts

Read-only diagnostic queries for Microsoft SQL Server performance
analysis. Each script is independent and can be run standalone with
`sqlcmd -i <script>.sql`.

## Runner scripts

Both PowerShell scripts live in the **`mssql\` root folder** (one level above
this `perf\` folder). Run them from there — they resolve paths automatically.

```powershell
cd db-audit-scripts\mssql

# Single database — perf only, Windows Authentication
.\run_audit.ps1 -Server "sql-server.internal" -Category perf

# All user databases — perf only
.\run_all_databases.ps1 -Server "sql-server.internal" -Category perf

# SQL Server Authentication — password via env (stays out of shell history)
$env:SQLCMDPASSWORD = "s3cr3t"
.\run_all_databases.ps1 -Server "sql-server.internal,1433" -User auditor -Category perf

# Filter databases
.\run_all_databases.ps1 -Server "sql-server.internal" -Category perf `
    -IncludeLike "prod_%" -ExcludeRegex "staging|archive"

# If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "sql-server.internal" -Category perf
```

## Report analyzer (`analyze_report.ps1`)

Generates a **consultant-grade PDF** report (HTML intermediate) with:

* Cover page (server, customer, severity donut chart)
* Environment fingerprint (edition, build, CPU, RAM, uptime, AG state)
* Executive summary (KPIs + findings-by-domain bar chart)
* **Server-wide findings** (deduplicated, instance-level)
* **Database fleet rollup** ("X of N databases affected")
* Backup-freshness alert (databases > 72h since last full backup)
* **Compliance mapping** (CIS, GDPR Art.32, SOC2)
* **Phased remediation roadmap** (Week 1-2 / 3-6 / 7-12)
* T-SQL remediation snippets (executable, with placeholders)
* Per-database appendix
* Glossary (wait types, DMV terms)
* Branded watermark

```powershell
# Default: produces perf_analysis.pdf
.\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_20260429_230243" `
                     -ServerName "sql-server.internal" -Customer "ACME Corp"

# HTML only (skip PDF)
.\analyze_report.ps1 -ReportDir "..." -NoPdf

# Keep both PDF and HTML
.\analyze_report.ps1 -ReportDir "..." -KeepHtml

# Custom branding
.\analyze_report.ps1 -ReportDir "..." -Brand "Your Company"
```

### PDF rendering pipeline

PDF is produced even when Microsoft Edge is not installed. The analyzer
tries the following methods in order:

1. Microsoft Edge headless (`msedge.exe --headless --print-to-pdf`)
2. Google Chrome / Chromium / Brave headless (Program Files, x86, LocalAppData)
3. `wkhtmltopdf` in PATH or `Program Files\wkhtmltopdf\bin\`
4. Microsoft Word COM (`SaveAs2 wdFormatPDF=17`) -- ships with Office
5. HTML only -- if none of the above is available

The method that succeeded is logged on stdout
(`PDF: rendered via msedge.exe`).

Output layout:

```
reports\mssql_perf_YYYYMMDD_HHMMSS\          ← run_audit.ps1 -Category perf
  _summary.txt
  critical_perf_01_top_sql.log
  critical_perf_02_blocking_and_locks.log
  ...
  low_perf_18_forecast_inputs.log

reports\mssql_audit_all_YYYYMMDD_HHMMSS\     ← run_all_databases.ps1
  _summary.txt
  _server\mssql_perf_YYYYMMDD_HHMMSS\
  <DatabaseName>\mssql_perf_YYYYMMDD_HHMMSS\
  ...
```

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

### `perf_19_storage_topology.sql`

Instance-wide `sys.master_files` inventory, current-database file
layout with filegroup placement, per-filegroup size roll-up, per-table
filegroup placement, per-file I/O latency from
`sys.dm_io_virtual_file_stats`, tempdb file layout, drive-letter roll-
up. All `sys.master_files` blocks are wrapped in TRY/CATCH so the
script degrades cleanly on Azure SQL Database.

### `perf_20_workload_management.sql`

Resource Governor configuration + runtime (pools, workload groups,
memory-grant stats), parallelism / memory knobs from
`sys.configurations` (MAXDOP, CTFP, max server memory, max worker
threads, blocked-process threshold), session-to-workload-group
mapping, long-running user requests (>60s) with current statement,
Query Store wait-category summary when Query Store is enabled.

### `perf_23_plan_regression.sql`

Query Store state + config, queries with > 1 plan in Query Store
(regression candidates), latest-vs-fastest plan comparison with
2× threshold regression flagging, forced-plan inventory with
force-failure counts, sys.dm_exec_query_stats fallback for plan-
cache max/min variance when Query Store is off, parameter-
sensitivity signals (many plans for the same query_hash).

### `perf_24_ha_cluster_health.sql`

WSFC node inventory, AG-level settings (automated backup preference,
failure condition level, required synchronised secondaries, cluster
type), per-replica availability / failover / seeding mode, quorum-
readiness — synchronised secondaries counted against
`required_synchronized_secondaries_to_commit` with a
FAILOVER-DEGRADED flag, AG listener IPs (multi-subnet), HADR
endpoint inventory, long-running transactions pinning log
truncation.

### `perf_25_tempdb_contention.sql`

tempdb file layout, CPU-count vs data-file count assessment against
Microsoft guidance (1:1 up to 8 cores, then groups of 4), per-file
free space + user/internal/version-store breakdown via
`dm_db_file_space_usage`, active PFS / GAM / SGAM page latch waits
(resource_description parsed to 2:*:1 / 2:*:2 / 2:*:3), cumulative
`PAGELATCH*` wait stats, top sessions by tempdb allocation,
version-store growth per database.

### `perf_22_replication_deepdive.sql`

Always On availability groups + replica state (availability mode /
failover mode / sync health / connected state), per-database replica
sync state with `log_send_queue` / `redo_queue` sizes and rates (and
a computed "seconds behind" estimate), AG listener configuration,
legacy database mirroring, log-shipping monitor (primary + secondary,
minutes-since-last-restore), `sp_replcounters` for transactional
replication. Every DMV wrapped in TRY/CATCH so HA-off instances do
not abort the script.

## Medium priority additional

### `perf_21_partition_health.sql`

`sys.partition_functions` + `sys.partition_schemes`, per-partition
row counts / size in MB / filegroup placement, `sys.partition_range_
values` boundary schedule, partition-skew detection (`max_rows` vs
average ratio), sliding-window right-edge empty-partition check —
a partition containing rows at the highest partition number blocks
SWITCH-based retention.

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
