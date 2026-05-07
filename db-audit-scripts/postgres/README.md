# PostgreSQL audit scripts

Read-only diagnostic scripts for PostgreSQL. **36 scripts** total —
18 performance + 18 security — plus a Bash runner per category and a
Python report analyzer that produces a PDF.

## Quick start (5 minutes)

```bash
cd db-audit-scripts/postgres

# 1. Performance audit — runs every perf script in priority order
PGPASSWORD=secret ./perf/run_audit.sh \
    -h db.internal -P 5432 -U auditor -d prod

# 2. Security audit
PGPASSWORD=secret ./sec/run_audit.sh \
    -h db.internal -P 5432 -U auditor -d prod

# 3. Build the PDF reports (needs Python 3 + WeasyPrint)
python3 ./perf/analyze_report.py ./reports/postgres_perf_<TIMESTAMP> \
        --server db.internal --customer "ACME Corp"
python3 ./sec/analyze_report.py  ./reports/postgres_sec_<TIMESTAMP> \
        --server db.internal --customer "ACME Corp"
```

`<TIMESTAMP>` is the folder created by the runner — look in `./reports/`.

## Target version

PostgreSQL **13 and newer**. Verified on 13, 14, and 15. Some queries
reference catalogs added in newer versions (`pg_stat_wal` in 14+).
Those blocks are guarded with a `server_version_num` check and degrade
to a `note` row instead of erroring out.

A few columns were renamed or moved in PG17 (e.g. `blk_read_time` →
`shared_blk_read_time` in `pg_stat_statements`, checkpoint counters
moved to `pg_stat_checkpointer`); individual scripts document the
adjustment needed for PG17.

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
- **Python 3.9+** with `weasyprint` if you want PDF reports:
  ```bash
  pip install weasyprint
  ```
  See `perf/README.md` and `sec/README.md` for analyzer details.

## Required privileges

- `pg_monitor` role (PG 10+) covers ~90% of the output —
  ```sql
  GRANT pg_monitor TO auditor;
  ```
- `pg_read_all_settings` and `pg_read_all_stats` are subsets of
  `pg_monitor`.
- A few security scripts read `pg_authid.rolpassword` and
  `pg_hba_file_rules` — these need superuser. The blocks are guarded
  and emit a `note` row when the role can't see them.

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
  perf/
    run_audit.sh           ← Bash runner for the perf category
    analyze_report.py      ← builds perf_analysis.pdf
    {critical,high,medium,low}/   ← the .sql scripts
  sec/
    run_audit.sh
    analyze_report.py
    {critical,high,medium,low}/
```

See `perf/README.md` and `sec/README.md` for the full per-script
catalog, runner flags, analyzer options, and engine-version caveats.
