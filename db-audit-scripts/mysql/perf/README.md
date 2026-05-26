# Performance audit scripts

Read-only diagnostic queries for MySQL performance analysis.
Each script is independent and can be run standalone with `mysql < script.sql`.

## Batch runner (`run_audit.sh`)

`run_audit.sh` executes every script in this folder in priority order
(`critical` → `high` → `medium` → `low`) and writes one log file per
script into a timestamped report folder.

```bash
# Password supplied via MYSQL_PWD env var (kept out of `ps`)
MYSQL_PWD=secret ./run_audit.sh -u auditor -h db.internal -P 3306 -d mysql
```

Flags: `-u USER` (required) `-h HOST` `-P PORT` `-d DATABASE`
`-o OUT_ROOT` (default `./reports`).

### Authentication mechanics

When `MYSQL_PWD` is set, the runner writes it to a **temporary
`--defaults-file`** (mode 0600, cleaned up on exit) and passes that
as the FIRST argument to `mysql(1)`. This handles two real-world
traps:

1. **MySQL client 9.x** (Homebrew default on macOS) silently ignores
   `MYSQL_PWD` on some builds.
2. **`~/.my.cnf` overrides** — the mysql client reads `~/.my.cnf`
   *after* any `--defaults-extra-file`, so a stale local
   `[client] user=root password=...` block would override the audit
   credentials. `--defaults-file` (singular) replaces the entire
   option-file search, so isolation is guaranteed.

If `MYSQL_PWD` is not set the runner falls back to mysql's default
authentication path.

### Failure detection

Failure is detected by the mysql client's exit code plus a post-run
grep for `^ERROR NNNN` in the log — `--abort-source-on-error` is not
uniformly supported across mysql client builds, so the grep is the
portable backstop.

Output layout:

```
reports/mysql_perf_YYYYMMDD_HHMMSS/
  _summary.txt                          # OK/FAIL per script + totals
  critical_perf_01_top_sql.log
  critical_perf_02_blocking_and_locks.log
  ...
  low_perf_18_forecast_inputs.log
```

## Report analyzer (`analyze_report.py`)

After a run completes, parse the report folder into an HTML report:

```bash
# Single-database run output (the folder run_audit.sh wrote into)
./analyze_report.py reports/mysql_perf_YYYYMMDD_HHMMSS

# Multi-database run (parent folder containing per-DB sub-folders)
./analyze_report.py /path/to/parent_report_dir --server prod-mysql-01

# Render to PDF (optional -- HTML is always produced)
google-chrome --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf=perf_analysis.pdf \
    "file://$(pwd)/reports/mysql_perf_YYYYMMDD_HHMMSS/perf_analysis.html"
```

The analyzer is pure Python standard library (no `pip install` step).

### What the HTML report contains

* **Environment Fingerprint card** -- host, database, MySQL version,
  AWS-managed flag (RDS / Aurora), server role (primary writeable vs
  replica), max_connections, innodb_buffer_pool, time zone, character
  set, `performance_schema` / `log_bin` / `gtid_mode` state. Sourced
  from a single-row fingerprint header that `perf_05` emits as its
  first query specifically for the analyzer.

* **Quick-nav strip** with anchor links: Environment, Executive
  Summary, Findings, SQL Appendix. Hidden in print.

* **Executive Summary**
  - Five KPI cards (Databases analysed, Scripts OK, Failed scripts,
    Critical findings, Warnings) -- crit / warn / fail cards turn red /
    orange when non-zero.
  - **Top issues -- what to fix**: highest-priority findings as an
    ordered list with severity badge + action line + anchor link to
    the detailed finding card. Capped at 10.

* **Findings** -- one card per finding. Each card:
  - severity colour bar (red / orange / blue)
  - title + script reference
  - boxed "Action:" recommendation
  - one or more **concrete-objects** sub-tables (top 10 rows by default
    with `... +N more rows -- consult the raw .log file` overflow note)
  - **"How to fix -- starter commands"** code block with copy-pastable
    SQL / `aws rds` snippets
  - **"Further reading"** list of links to dev.mysql.com / AWS docs
    pages for that specific control

  Coverage:

  | Finding                                       | Concrete objects shown |
  |-----------------------------------------------|------------------------|
  | `perf_01` Top SQL                             | queryid (linked), calls, total_min, mean_ms, pct_total (5 sub-tables: by total/mean/calls/rows/examined ratio) |
  | `perf_02` Blocking / long-running             | data_locks_waits rows + active sessions > 0 s |
  | `perf_06` Index hygiene                       | Index I/O activity, sys.schema_unused_indexes, cardinality, duplicates, FK without index |
  | `perf_07` Stale stats / never analyzed        | TABLE_SCHEMA, TABLE_NAME, approx_rows, last_modified |
  | `perf_08` Top tables by size                  | schema, table, ENGINE, data_mb, index_mb |
  | `perf_09` Temp tables to disk                 | per-digest temp counters |
  | `perf_11` Free-space / bloat                  | TABLE_SCHEMA, TABLE_NAME, data_mb, free_mb, free_pct |
  | `perf_12` Missing-index candidates            | tables without useful indexes |
  | `perf_15` Capacity (AUTO_INCREMENT, conns)    | objects above 50% consumption |
  | `perf_21` Partitions                          | per-partition row count and size |

* **SQL Appendix** -- one entry per unique
  `events_statements_summary_by_digest` queryid surfaced in Top SQL,
  with the **full** digest text in a `<pre>` block. A collapsible
  jump-to index at the top lists every queryid with a one-line
  preview. queryid cells in the Top SQL tables link straight to the
  matching appendix entry; each appendix entry has a `top ↑` link
  back.

### Finding triggers

Each rule has a `mode`:
* `has_data` -- fire when the log has any data rows.
* `pattern`  -- fire when a regex matches (used for variables like
  `Created_tmp_disk_tables`, `Seconds_Behind_Source`, capacity %).
* `check`    -- custom predicate. Used by `perf_02` to fire only on
  *actionable* sub-tables (real blocking, real long-running tx),
  not on the always-populated InnoDB lock summary / event scheduler
  daemon row.


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
`performance_schema.variables_info`. **First query is a single-row
"fingerprint header"** the report analyzer reads to populate the
Environment Fingerprint card (`@@version`, current database, host,
buffer pool, RDS/Aurora flag, performance_schema / log_bin state).

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

### `perf_19_storage_topology.sql`

`datadir` / `tmpdir` / InnoDB directory variables, InnoDB tablespace
inventory (`INNODB_TABLESPACES` + `INNODB_DATAFILES` file paths), per-
database and top-30 largest-table size, non-InnoDB tables that need
different backup handling, buffer-pool-to-data-footprint ratio.

### `perf_20_workload_management.sql`

Resource Groups (MySQL 8.0+) probed with a prepared statement so the
query still runs on 5.7; concurrency knobs (thread pool, InnoDB
threads, replica parallel workers); per-account rate caps from
`mysql.user` (MAX_QUERIES/UPDATES/CONNECTIONS_PER_HOUR,
MAX_USER_CONNECTIONS); timeouts; current activity snapshot by
`PROCESSLIST.STATE`; statements running >60s; in-flight progress
from `events_stages_current`.

### `perf_21_partition_health.sql`

Partitioned-table inventory grouped per table (`PARTITION_METHOD`,
`SUBPARTITION_METHOD`, expressions, total size), per-partition row /
size distribution for skew detection, partition-count assessment
(8 192 hard limit awareness), missing `MAXVALUE` / `DEFAULT` catch-all
detection for `RANGE` / `LIST`, hottest-by-`UPDATE_TIME` partitions.

### `perf_23_plan_regression.sql`

High `max_over_avg` digest detection from
`events_statements_summary_by_digest`, index-less digest inventory
(`SUM_NO_INDEX_USED` / `SUM_NO_GOOD_INDEX_USED`), per-digest error /
warning rates, optimizer_switch / optimizer_trace configuration
surfaces for plan-shift debugging.

### `perf_24_ha_cluster_health.sql`

Semi-sync status (`Rpl_semi_sync_*`), Group Replication member
inventory and per-member stats (prepared-statement guarded), flow-
control config, InnoDB Cluster metadata-schema presence, long-running
`INNODB_TRX`. Complements `perf_22_replication_deepdive` with cluster-
posture signals.

### `perf_22_replication_deepdive.sql`

`@@server_id`, binlog / GTID config, per-channel connection state
(`replication_connection_configuration` + `_status`), applier
coordinator and per-worker apply lag computed as
`original_commit_timestamp` → `end_apply_timestamp`, GTID executed /
purged, Group Replication members (prepared-statement guarded).

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
