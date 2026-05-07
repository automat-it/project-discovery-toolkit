# MySQL audit scripts

Read-only diagnostic scripts for MySQL. **36 scripts** total —
18 performance + 18 security — plus a Bash runner per category and a
Python report analyzer that produces a PDF.

## Quick start (5 minutes)

```bash
cd db-audit-scripts/mysql

# 1. Performance audit — runs every perf script in priority order
MYSQL_PWD=secret ./perf/run_audit.sh \
    -h db.internal -P 3306 -u auditor -d prod

# 2. Security audit
MYSQL_PWD=secret ./sec/run_audit.sh \
    -h db.internal -P 3306 -u auditor -d prod

# 3. Build the PDF reports (needs Python 3 + WeasyPrint)
python3 ./perf/analyze_report.py ./reports/mysql_perf_<TIMESTAMP> \
        --server db.internal --customer "ACME Corp"
python3 ./sec/analyze_report.py  ./reports/mysql_sec_<TIMESTAMP> \
        --server db.internal --customer "ACME Corp"
```

`<TIMESTAMP>` is the folder created by the runner — look in `./reports/`.

## Target version

MySQL **8.0 and newer**. Verified against 8.0 and 8.3 community builds.

Some blocks (`SHOW REPLICAS`, `performance_schema.variables_info`,
`replication_applier_status_by_worker`) require specific 8.x minor
versions — see `perf/README.md` and `sec/README.md` for per-script
notes. Scripts will produce errors in those blocks on MySQL 5.7.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance — top SQL, locks, indexes, temp, growth, I/O  |
| `sec/`    | Security — accounts, privileges, auth, encryption, PII    |

## Priority order

Run priorities top-to-bottom — `critical` first gives roughly 80% of
the insight needed:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/`     — main optimization / hardening value
3. `medium/`   — long-term tuning and stability
4. `low/`      — deeper investigation, edge cases

## Prerequisites

- **`mysql` client** (8.0+).
- **`performance_schema` enabled** on the target server (default in 8.0).
  Several `perf/` scripts read `performance_schema.events_statements_*`
  and `events_waits_*`. They emit `[note]` lines if the consumer is off.
- **Bash** (Linux / macOS / WSL) for the runner scripts.
- **Python 3.9+** with `weasyprint` if you want PDF reports:
  ```bash
  pip install weasyprint
  ```

## Required privileges

```sql
-- Minimum auditor user
CREATE USER 'auditor'@'%' IDENTIFIED BY '<strong-password>';
GRANT SELECT, PROCESS, REPLICATION CLIENT, SHOW DATABASES,
      SHOW VIEW ON *.* TO 'auditor'@'%';
```

Some `sec/` queries read `mysql.user.authentication_string` and
`mysql.role_edges`. These need `SELECT` on the `mysql` schema and emit
a `[note]` line if denied.

## Running a single script

```bash
mysql -h <host> -u <user> -p <database> --batch --table \
      < perf/critical/perf_01_top_sql.sql
```

All scripts are read-only and do not create temporary tables.

## Folder layout

```
mysql/
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
catalog, runner flags, analyzer options, and `performance_schema`
prerequisites.
