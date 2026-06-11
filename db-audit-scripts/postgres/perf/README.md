# Performance audit scripts

Read-only diagnostic queries for PostgreSQL performance analysis.
Each script is independent and can be run standalone with `psql -f`.

## Batch runner (`run_audit.sh`)

`run_audit.sh` executes every script in this folder in priority order
(`critical` → `high` → `medium` → `low`) and writes one log file per
script into a timestamped report folder.

```bash
# password comes from the PGPASSWORD env var (kept out of `ps`)
PGPASSWORD=secret ./run_audit.sh -h db.internal -P 5432 -U auditor -d prod
```

Flags: `-h HOST` `-P PORT` `-U USER` `-d DATABASE` `-o OUT_ROOT`
(default `./reports`). Failure detection uses `psql -v ON_ERROR_STOP=1`,
so any script that errors mid-run is marked FAIL in the summary.

Output layout:

```
reports/postgres_perf_YYYYMMDD_HHMMSS/
  _summary.txt                          # OK/FAIL per script + totals
  critical_perf_01_top_sql.log
  critical_perf_02_blocking_and_locks.log
  ...
  low_perf_18_forecast_inputs.log
```

## Report analyzer (`analyze_report.py`)

After a run completes, parse the report folder into a customer-friendly
HTML report:

```bash
# Single-database run output (the folder run_audit.sh wrote into)
./analyze_report.py reports/postgres_perf_YYYYMMDD_HHMMSS

# Multi-database run (parent folder containing per-DB sub-folders)
./analyze_report.py /path/to/parent_report_dir --server prod-postgres-01

# Render to PDF (optional -- HTML is always produced)
google-chrome --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf=postgres_perf_analysis.pdf \
    "file://$(pwd)/reports/postgres_perf_YYYYMMDD_HHMMSS/postgres_perf_analysis.html"
```

The analyzer is pure Python standard library (no `pip install` step).

### What the HTML report contains

* **Branded cover page** -- Automat-IT background (`ait_bg_cover.png`),
  report title, server label, optional customer subtitle, generation
  timestamp. Same `ait_bg_page.png` watermark appears on every inner
  page when rendered as PDF.

* **Environment Fingerprint card** -- host, database, PostgreSQL
  version, Aurora / RDS flag, primary / replica role, uptime, this
  DB's size, shared_buffers, max_connections, wal_level. Populated
  from a single-row fingerprint header that `perf_05` emits as its
  first query specifically for the analyzer.

* **Quick-nav strip** with anchor links: Environment, Executive
  Summary, Findings, SQL Appendix. Hidden in print.

* **1. Executive Summary**
  - **Bottom line** TL;DR callout - one plain-language sentence with the
    severity mix and the single most urgent item, followed by a
    **Next steps - what to fix first** top-3 action list.
  - Five large KPI cards: Databases analyzed, Critical, Warning, Info,
    Failed scripts.
  - Severity-mix **donut chart** with legend (Critical / Warning / Info).
  - **Findings by Domain** horizontal bar chart -- groups perf findings
    by area (Top SQL, Blocking, Indexes, Waits & I/O, ...).
  - **Top issues -- what to fix**: the highest-priority findings as an
    ordered list with severity badge + action line + anchor link to
    the detailed finding card. Capped at 10; the rest are still in the
    Findings section below.
  - **Context rollup** table (only when more than one database was
    audited; redundant for single-DB runs).

* **2. Findings** -- one card per finding (not a giant 4-column table any
  more). Each card:
  - severity colour bar (red / orange / blue)
  - title + script reference
  - boxed "Action:" recommendation
  - one or more **concrete-objects** sub-tables (top 10 rows by default
    with `... +N more rows -- consult the raw .log file` overflow note)
  - **"How to fix -- starter commands"** code block with copy-pastable
    SQL / `aws rds` snippets
  - **"Further reading"** list of links to postgresql.org / AWS docs
    pages for that specific control

  The concrete objects are extracted from the actual psql log so the
  reader sees real names (e.g. `hist_hr_emp_leave_balance_i1`, 414 MB,
  0 scans) instead of "review the log". Coverage:

  | Finding                              | Concrete objects shown                   |
  |--------------------------------------|------------------------------------------|
  | `perf_01` Top SQL                    | queryid (linked to appendix), calls, total_min, mean_ms, pct_total |
  | `perf_02` Blocking / long-running    | blocker_pid + blocked_pid + blocked_query, long-running tx, idle-in-tx |
  | `perf_04` Wait events                | wait_event_type, wait_event, sessions, pct |
  | `perf_06` Index hygiene              | 5 sub-tables: unused, duplicates, narrow-vs-wide, FK without index, etc. -- with `index_name` column |
  | `perf_07` Stale autovacuum targets   | schema, table, live rows, dead %, last_analyze |
  | `perf_09` Temp files spilled         | per-database + per-statement temp counters |
  | `perf_11` Bloated objects            | schema, table, bloat_pct, est_bytes      |
  | `perf_14` Forced checkpoints         | num_timed vs num_requested, write/sync time |
  | `perf_15` Capacity headroom          | sequences / storage > 50% consumed       |

* **3. SQL Appendix** -- one entry per unique pg_stat_statements queryid
  surfaced in Top SQL, with the **full** untruncated query text in a
  `<pre>` block. A collapsible jump-to index at the top lists every
  queryid with a one-line preview. queryid cells in the Top SQL
  tables link straight to the matching appendix entry; each appendix
  entry has a `top ↑` link back.

### Finding triggers

Each rule has a `mode`:
* `has_data` -- fire when the log has any data rows.
* `pattern`  -- fire when a regex matches (used for off-by-default
  GUCs like `wal_level=trust`, forced checkpoints, replay lag in
  `HH:MM:SS` format).
* `check`    -- fire when a custom predicate returns True. Used by
  `perf_02` to avoid false-positive "blocking" findings: the rule
  fires only when actionable sub-tables (blocking pairs, long-running
  active tx, idle-in-tx) have rows, not when the always-non-empty
  lock-summary / deadlock-stats tables do.


## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT` and `SHOW`
statements. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`,
`TRUNCATE`, `GRANT`, or `REVOKE` is used anywhere. No temporary tables,
no functions, no objects of any kind are created.

## Target version

PostgreSQL 13+. A few queries reference catalogs added in newer versions
(`pg_stat_wal` in 14+); those blocks are guarded by a server-version
check and degrade to a `skipped` note instead of erroring out.

### PG17 schema renames (handled automatically by version branches)

The scripts detect the server version at runtime and branch between
the pre-17 and PG17+ shapes, so the same file runs unchanged on
PG13–17:

- `pg_stat_statements.blk_read_time` / `blk_write_time` were removed
  in PG17 and split into `shared_blk_read_time` / `shared_blk_write_time`
  / `local_blk_*` / `temp_blk_*`. `perf_04` branches on
  `server_version_num >= 170000` and uses the right column set.
- `pg_stat_bgwriter` checkpoint counters (`checkpoints_timed`,
  `checkpoints_req`, `checkpoint_write_time`, `checkpoint_sync_time`,
  `buffers_checkpoint`) moved to the new `pg_stat_checkpointer` view
  in PG17 with renamed columns (`num_timed`, `num_requested`,
  `write_time`, `sync_time`, `buffers_written`). `buffers_backend` /
  `buffers_backend_fsync` were removed -- backend writes now live in
  `pg_stat_io`. `perf_14` renders the PG17 layout (incl. a
  per-backend-type `pg_stat_io` summary) on PG17+ and the legacy
  `pg_stat_bgwriter` layout on PG13–16.
- `pg_stat_progress_vacuum.max_dead_tuples` / `num_dead_tuples` were
  replaced in PG17 with byte-oriented `max_dead_tuple_bytes` /
  `dead_tuple_bytes` / `num_dead_item_ids` plus
  `indexes_total` / `indexes_processed`. `perf_20` branches on
  version and uses the right column set.
- `pg_stat_statements_info` was added in PG14; `perf_01` uses it at
  the top, guarded by a server-version check.

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

## Aurora / RDS PostgreSQL caveats

The scripts run on Amazon Aurora PostgreSQL and RDS for PostgreSQL
clusters. Aurora is **auto-detected at runtime** via presence of the
`rdsadmin` role: every Aurora-incompatible block emits a `[note]`
marker and the rest of the script continues normally. Standard
PostgreSQL is unaffected -- the `\if :is_aws_rds` guards activate only
on Aurora.

* **Run against the writer endpoint.** `pg_stat_bgwriter`,
  write-related IO counters, and log-flush stats are meaningful only
  on the primary. Reader endpoints accept the connection but surface
  a subset of metrics.

* **Aurora-blocked functions handled automatically.** Aurora rejects
  these with `currently not supported for Aurora` regardless of
  `wal_level` or role membership. Affected scripts now branch on the
  Aurora flag and emit `[note]` rows in place of the call:
  - `pg_current_wal_lsn`, `pg_walfile_name` -- `perf_10`, `perf_19`,
    `perf_22`
  - `pg_last_wal_receive_lsn`, `pg_last_wal_replay_lsn`,
    `pg_last_xact_replay_timestamp` -- `perf_10`, `perf_22`
  - `pg_stat_get_wal_receiver` (backs `pg_stat_wal_receiver`) --
    `perf_10`, `perf_22`
  - `pg_stat_get_wal` (backs `pg_stat_wal`) -- `perf_10`, `perf_14`

* **`primary_conninfo` / `primary_slot_name` SUSET GUCs** are
  hard-blocked on Aurora even when `pg_has_role(...)` claims
  `pg_read_all_settings` membership. `perf_24` checks the Aurora flag
  *before* the `pg_has_role` fallback and skips the read on Aurora.

* **Aurora reader-lag is not in `pg_stat_replication`.** Aurora
  replicates at the storage layer, not via WAL-shipping or replication
  slots. The view is queryable but typically empty. For real reader-
  lag data use CloudWatch (`AuroraReplicaLag`,
  `AuroraReplicaLagMaximum`, `AuroraReplicaLagMinimum`).

* **No blocked server-side APIs are used anywhere.** Nothing calls
  `pg_read_file`, `pg_ls_dir`, `pg_ls_waldir`, `pg_ls_logdir`,
  `pg_ls_tmpdir`, `pg_read_server_files`, `pg_rotate_logfile`,
  `pg_reload_conf`, `pg_switch_wal`, or `ALTER SYSTEM`.

* **`pg_stat_statements` must be enabled in the audited database.**
  Default Aurora parameter groups already load the library via
  `shared_preload_libraries`; you still need to run, once per database:
  `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`. Without it,
  `perf_01`, `perf_04`, `perf_13`, `perf_16`, `perf_23` raise `relation
  "pg_stat_statements" does not exist`.

* **Recommended parameter-group tweaks** (take effect after reboot on
  cluster parameter group):
  * `track_io_timing = on` -- required for read/write timing columns in
    `pg_stat_statements` and `pg_statio_*`.
  * `track_activities = on` and `track_counts = on` (defaults; verify).

* **Recommended auditor role:**
  ```sql
  CREATE ROLE auditor LOGIN PASSWORD '...';
  GRANT pg_monitor, pg_read_all_stats, pg_read_all_settings TO auditor;
  GRANT rds_superuser TO auditor;  -- optional; unlocks pg_authid / pg_hba_file_rules
  ```
  Without `rds_superuser`, privileged-catalog blocks are guarded via
  `has_table_privilege(...)` and degrade to a "Skipped: ... not
  readable by <current_user>" row rather than an error.

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
overrides. **First query is a single-row "fingerprint header"** the
report analyzer reads to populate the Environment Fingerprint card
(version, current_database, host:port, uptime, Aurora flag, this DB
size, shared_buffers, max_connections, wal_level).

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

Heuristic table bloat estimation (ioguix / check_postgres style)
based on row width, tuple count, and block size; joins back to
`pg_class` **via `pg_namespace`** so identically-named tables in
different schemas are not double-counted. Also shows index-to-heap
size ratio as a secondary bloat indicator. For exact numbers use the
`pgstattuple` extension; this script stays pure-SQL and extension-
free.

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

### `perf_19_storage_topology.sql`

Tablespace inventory with on-disk location, data/WAL/log directories,
objects placed off the default tablespace, per-schema size roll-up,
replication-slot WAL retention, per-database temp-file spill.
Essential for DR planning and I/O balancing.

### `perf_20_workload_management.sql`

Concurrency and worker limits (max_connections, max_parallel_workers,
autovacuum_max_workers), per-role caps from `pg_roles`, per-role / per-
database GUC overrides, activity breakdown by state + wait class,
autovacuum workers in flight, progress from every `pg_stat_progress_*`
view (vacuum, analyze, cluster, create_index, basebackup, copy),
and prepared transactions.

### `perf_24_ha_cluster_health.sql`

Cluster-level HA posture: node role (primary/standby), synchronous
replication quorum state (sync vs async replica counts against
`synchronous_standby_names`), WAL archiver health from
`pg_stat_archiver` with staleness / failure assessment, backup-sender
activity, orchestrator residue (Patroni / repmgr schema presence),
long-running transactions / prepared transactions that pin WAL.

### `perf_22_replication_deepdive.sql`

Primary-side per-standby lag (send / flush / replay bytes + intervals),
replication-slot WAL retention with assessment buckets, standby-side
`pg_stat_wal_receiver` + replay-clock lag, logical subscriptions and
worker apply lag, per-database replay conflicts.

## Medium priority additional

### `perf_23_plan_regression.sql`

High-variance statement detection via `pg_stat_statements` —
coefficient-of-variation (stddev/mean) and max/min execution-time
ratio are the two signals PostgreSQL exposes without explicit plan
history. Per-session prepared-statement plan-cache state
(`generic_plans` vs `custom_plans`), per-database cache-hit ratio,
`auto_explain` configuration so operators know whether plans are
being logged. Script is guarded to run on clusters without
`pg_stat_statements` installed.

### `perf_21_partition_health.sql`

Declarative partition parents + strategy + partition key, child-
partition bounds / size / row estimate, missing `DEFAULT` partition
detection for list/range parents, partition-count assessment
buckets (>1000 children is a planner hazard), stale-stats child
scan, legacy inheritance-based parents.

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
