# PostgreSQL audit scripts

Read-only diagnostic scripts for PostgreSQL. **47 scripts** total —
24 performance + 23 security — plus a Bash runner per category and a
Python report analyzer that produces HTML (with optional PDF).

Works on **self-managed PostgreSQL 13 – 17** *and* **Amazon Aurora
PostgreSQL** out of the box. Aurora-blocked functions are detected at
runtime and skipped with `[note]` markers; PG17 column / view renames
(pg_stat_statements, pg_stat_bgwriter → pg_stat_checkpointer,
pg_stat_progress_vacuum) are handled via version-branched queries.

## Quick start (5 minutes)

```bash
cd db-audit-scripts/postgres

# 1. Performance audit -- runs every perf script in priority order
PGPASSWORD=secret ./perf/run_audit.sh \
    -h db.internal -P 5432 -U auditor -d prod

# 2. Security audit
PGPASSWORD=secret ./sec/run_audit.sh \
    -h db.internal -P 5432 -U auditor -d prod

# 3. Build the branded HTML report. --customer is optional and just
#    drives the subtitle on the cover page.
python3 ./perf/analyze_report.py ./reports/postgres_perf_<TIMESTAMP> \
        --server db.internal --customer "Acme"
python3 ./sec/analyze_report.py  ./reports/postgres_sec_<TIMESTAMP> \
        --server db.internal --customer "Acme"

# 4. (Optional) render the HTML to PDF
google-chrome --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf=postgres_perf_analysis.pdf \
    "file://$(pwd)/reports/postgres_perf_<TIMESTAMP>/postgres_perf_analysis.html"
```

`<TIMESTAMP>` is the folder created by the runner — look in
`./reports/`.

## What the analyzer produces

The HTML report contains, top-to-bottom:

* **Branded cover page** — the Automat-IT background (`ait_bg_cover.png`)
  with title, server label, optional `--customer` subtitle, and
  generation timestamp. The same `ait_bg_page.png` watermark renders on
  every subsequent page in the PDF.
* **Environment Fingerprint** — host, database, PostgreSQL version,
  Aurora / RDS flag, uptime, this DB size, shared_buffers,
  max_connections, wal_level. Populated from a single-row header that
  `perf_05` / `sec_21` emit specifically for the analyzer.
* **1. Executive Summary** — five large KPI cards (Databases analyzed /
  Critical / Warning / Info / Failed), a severity-mix **donut chart**,
  a **"Findings by Domain"** horizontal bar chart, and a **Top issues —
  what to fix** block listing the highest-priority findings as anchor
  links straight to their detail cards.
* **2. Findings** — one card per finding with severity colour bar,
  recommendation, a curated table of **concrete objects** flagged
  (table / index / queryid / role / cert / ...), a **"How to fix —
  starter commands"** code block with copy-pastable SQL / `aws rds`
  snippets, and a **"Further reading"** list of links to
  postgresql.org and AWS docs for that specific control. Long lists
  are capped at 10 rows with `... +N more rows -- consult the raw
  .log file` so the reader gets the actionable set without being
  drowned in noise.
* **3. SQL Appendix** (perf only) — full pg_stat_statements query text
  per unique queryid, indexed by a collapsible jump-to list. Top SQL
  queryid cells link straight to the corresponding appendix entry.

The analyzer uses **standard library only** — no Python packages
required. PDF rendering uses headless Chrome / Edge if available; HTML
remains the primary, always-emitted output. The two brand PNGs are
copied next to the rendered HTML automatically (sourced from
`db-audit-scripts/assets/`).

## Target version

PostgreSQL **13 – 17**. Verified on PG 13, 14, 15, and Aurora PG 17.
Some queries reference catalogs added in newer versions (`pg_stat_wal`
in 14+); those blocks are guarded with a `server_version_num` check and
degrade to a `note` row instead of erroring out.

PG17 schema renames (handled automatically by version-branched queries):

* `pg_stat_statements.blk_read_time` / `blk_write_time` →
  `shared_blk_read_time` / `shared_blk_write_time` (+ `local_blk_*`,
  `temp_blk_*`).
* `pg_stat_bgwriter` checkpoint columns → new `pg_stat_checkpointer`
  view; `buffers_backend` / `buffers_backend_fsync` removed (now in
  `pg_stat_io`).
* `pg_stat_progress_vacuum.max_dead_tuples` / `num_dead_tuples` →
  byte-oriented `max_dead_tuple_bytes` / `dead_tuple_bytes` /
  `num_dead_item_ids`, plus new `indexes_total` / `indexes_processed`.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance — top SQL, locks, indexes, bloat, WAL, I/O    |
| `sec/`    | Security — roles, privileges, auth, encryption, PII       |

## Priority order

Run priorities top-to-bottom — `critical` first gives roughly 80% of
the insight needed:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/`     — main optimization / hardening value
3. `medium/`   — long-term tuning and stability
4. `low/`      — deeper investigation, edge cases

## Prerequisites

- **`psql` client** (PostgreSQL 13+ client tools).
- **Bash** (Linux / macOS / WSL) for the runner scripts.
- **Python 3.9+** for the analyzer (standard library only).
- **Headless Chrome / Edge** (optional) if you want PDF output.

## Required privileges

A minimum-privilege audit role:

```sql
CREATE ROLE auditor LOGIN PASSWORD '...';
GRANT pg_monitor, pg_read_all_stats, pg_read_all_settings TO auditor;
```

`pg_monitor` covers ~90% of the output (it bundles
`pg_read_all_settings` and `pg_read_all_stats`).

For full coverage of password-hash / pg_hba checks on AWS RDS / Aurora:

```sql
GRANT rds_superuser TO auditor;
```

Without elevation, privileged blocks degrade to a `Skipped: …` row;
they never abort the script.

## Aurora / RDS PostgreSQL

The scripts run on Amazon Aurora and RDS for PostgreSQL with no
modifications. The analyzer detects Aurora at runtime (presence of the
`rdsadmin` role) and the scripts skip Aurora-blocked functions:

* `pg_current_wal_lsn`, `pg_walfile_name`, `pg_last_wal_*`,
  `pg_last_xact_replay_timestamp`, `pg_stat_get_wal_receiver`,
  `pg_stat_get_wal` — all return `is currently not supported for Aurora`.
  Affected scripts (`perf_10`, `perf_14`, `perf_19`, `perf_22`,
  `perf_24`) emit `[note]` markers instead of erroring.
* `pg_user_mapping` (the privileged catalog table) is replaced by
  the unprivileged `pg_user_mappings` view (`sec_10`, `sec_15`).
* `primary_conninfo` / `primary_slot_name` are hard-blocked SUSET GUCs
  on Aurora regardless of `pg_read_all_settings` membership; `perf_24`
  detects Aurora and skips them.

For real Aurora reader-lag data, use CloudWatch
(`AuroraReplicaLag`) — Aurora replicates at the storage layer, not via
WAL streaming.

## Running a single script

```bash
psql -h <host> -U <user> -d <database> \
     -v ON_ERROR_STOP=0 --pset=pager=off \
     -f perf/critical/perf_01_top_sql.sql
```

Several scripts use `psql` meta-commands (`\gset` + `\if`) to guard
privileged or version-specific blocks. **These work in `psql -f` but
are ignored by IDE SQL editors** (DBeaver, DataGrip, pgAdmin) — for
complete output, run from `psql`.

## Folder layout

```
postgres/
  _analyze_lib.py            ← shared parser / fingerprint / HTML helpers
  perf/
    run_audit.sh             ← Bash runner for the perf category
    analyze_report.py        ← builds postgres_perf_analysis.html (+ PDF if Chrome)
    {critical,high,medium,low}/   ← the .sql scripts
  sec/
    run_audit.sh
    analyze_report.py
    {critical,high,medium,low}/
```

See `perf/README.md` and `sec/README.md` for the full per-script
catalog, runner flags, analyzer options, and engine-version caveats.
