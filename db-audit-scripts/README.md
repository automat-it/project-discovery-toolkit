# db-audit-scripts

Read-only diagnostic SQL scripts for database health, performance, and
security audits across **PostgreSQL**, **MySQL**, and **Microsoft SQL
Server**. Designed for ad-hoc investigations, pre-migration discovery,
and baseline assessments on existing deployments.

> **Read-only by design.** Every script uses only `SELECT` / `SHOW` /
> read-only system procedures. Nothing is created, altered, or deleted
> on your databases. Safe to run on production.

## What you get

| Engine        | perf | sec | Verified on                                           |
|---------------|-----:|----:|-------------------------------------------------------|
| PostgreSQL    |   24 |  23 | 13, 14, 15, 16, 17; AWS RDS / Aurora PostgreSQL       |
| MySQL         |   24 |  23 | 8.0 / 8.3 community; AWS RDS MySQL; Aurora MySQL v3   |
| SQL Server    |   25 |  23 | 2019, 2022 Developer (Linux); Azure SQL DB / MI       |

Each engine ships ~24 performance + 23 security scripts, organised into
four priority tiers (`critical` → `high` → `medium` → `low`). Numbering
is shared across engines so finding-IDs (e.g. `sec_05`) refer to the
same control regardless of engine.

## Layout

```
db-audit-scripts/
├── assets/                      ← brand assets (cover + watermark PNGs)
│                                  shared by every engine analyzer
├── postgres/
│   ├── perf/{run_audit.sh, analyze_report.py, critical/, high/, medium/, low/}
│   └── sec/{run_audit.sh, analyze_report.py, critical/, high/, medium/, low/}
├── mysql/
│   ├── perf/{run_audit.sh, analyze_report.py, critical/, high/, medium/, low/}
│   └── sec/{run_audit.sh, analyze_report.py, critical/, high/, medium/, low/}
├── mssql/
│   ├── run_audit.ps1            ← runs all scripts on a single database
│   ├── run_all_databases.ps1    ← runs across every user database
│   ├── perf/{analyze_report.ps1, critical/, high/, medium/, low/}
│   └── sec/{analyze_report.ps1,  critical/, high/, medium/, low/}
└── tools/
    └── aggregate_report.py      ← roll multiple engine runs into one report
```

Every engine has a runner + analyzer pair. Runners produce one `.log` per
script in a timestamped `reports/<engine>_<cat>_<TS>/` folder; analyzers
turn that folder into a branded HTML report (and optionally PDF via
headless Chrome).

## Quick start

### Step 1 — Pick the engine you need

```text
postgres/   →  PostgreSQL 13+
mysql/      →  MySQL 8.0+
mssql/      →  SQL Server 2019+ / Azure SQL DB / Managed Instance
```

### Step 2 — Run the scripts

#### PostgreSQL

```bash
cd db-audit-scripts/postgres

# Run all perf + all sec scripts in priority order
export PGPASSWORD='<your-password>'
bash perf/run_audit.sh -h <host> -P 5432 -U <user> -d <database> -o ./reports
bash sec/run_audit.sh  -h <host> -P 5432 -U <user> -d <database> -o ./reports

# Build the branded HTML report (cover + watermark from ../assets/)
python3 perf/analyze_report.py ./reports/postgres_perf_<TS> \
        --server <label> --customer "<Optional Customer>"
python3 sec/analyze_report.py  ./reports/postgres_sec_<TS> \
        --server <label> --customer "<Optional Customer>"
```

#### MySQL

```bash
cd db-audit-scripts/mysql

export MYSQL_PWD='<your-password>'
bash perf/run_audit.sh -u <user> -h <host> -P 3306 -d <database> -o ./reports
bash sec/run_audit.sh  -u <user> -h <host> -P 3306 -d <database> -o ./reports

python3 perf/analyze_report.py ./reports/mysql_perf_<TS> \
        --server <label> --customer "<Optional Customer>"
python3 sec/analyze_report.py  ./reports/mysql_sec_<TS> \
        --server <label> --customer "<Optional Customer>"
```

#### SQL Server

```powershell
cd db-audit-scripts\mssql

# Audit all user databases, performance + security, Windows auth
.\run_all_databases.ps1 -Server "sql-server.internal"

# Build branded PDFs (cover + watermark from assets/)
.\perf\analyze_report.ps1 -ReportDir ".\reports\mssql_audit_all_<TS>" `
                          -ServerName "sql-server.internal" -Customer "ACME Corp"
.\sec\analyze_report.ps1  -ReportDir ".\reports\mssql_audit_all_<TS>" `
                          -ServerName "sql-server.internal" -Customer "ACME Corp"
```

The runner produces a timestamped folder under `reports/` containing one
`.log` per script. See each engine's `README.md` for auth options,
multi-database runs, and PDF generation details.

### Step 3 — Render to PDF (optional)

The Python analyzers emit a self-contained HTML report **and copy the
brand PNGs next to it** (`ait_bg_cover.png`, `ait_bg_page.png`). To
produce a PDF, pipe the HTML through headless Chrome from the same
folder so the relative image references resolve:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="./reports/<run>/<engine>_perf_analysis.pdf" \
  "file://$(pwd)/reports/<run>/<engine>_perf_analysis.html"
```

The SQL Server analyzer renders PDF natively (Edge / Chromium head-
less driven from PowerShell). Both engines share the same cover-page +
watermark layout sourced from `db-audit-scripts/assets/`.

## Report structure

Every PDF/HTML report — regardless of engine — follows the same outline:

1. **Cover page** — title, server label, optional customer, generation
   timestamp; branded background.
2. **Environment Fingerprint** — host, database, version, role, AWS-
   managed flag, time zone, key tuning variables.
3. **1. Executive Summary** — opens with a plain-language **"Bottom
   line"** TL;DR callout plus a **"Next steps - what to fix first"**
   top-3 action list, followed by five KPI cards (databases analyzed /
   critical / warning / info / failed), a severity-mix donut chart, a
   "Findings by Domain" bar chart, and a "Top issues — what to fix"
   block linking to the detailed finding rows.
4. **2. Findings** — one card per finding with severity badge, "Action"
   recommendation, concrete-objects sub-tables, "How to fix" code
   snippets, and "Further reading" doc links.
5. **3. SQL Appendix** (perf only) — full digest text per `queryid`,
   anchored from the Top SQL tables.

## Conventions

- **Read-only.** No `CREATE` / `ALTER` / `DROP` / `INSERT` / `UPDATE` /
  `DELETE` / `GRANT` / `REVOKE` anywhere. No temp tables, no functions,
  no objects.
- **Filenames** are prefixed with category and number for ordering, e.g.
  `perf_01_top_sql.sql`, `sec_03_admin_and_superusers.sql`.
- **Privileged blocks** (e.g. reading `pg_authid`, `sys.sql_logins`,
  registry probes) are guarded so they skip cleanly when the current
  user lacks access — they never abort the whole script.
- **Priority tiers** — `critical/` first gives roughly 80% of the
  insight. Run `high/` next, then `medium/` and `low/` for deeper work.

## Categories

| Category | Purpose                                                       |
|----------|---------------------------------------------------------------|
| `perf/`  | Performance — top SQL, locks, indexes, bloat/fragmentation, I/O |
| `sec/`   | Security — accounts, privileges, auth, encryption, PII discovery |

## IDE caveat

Scripts use client meta-commands (`\if`, `\gset` in psql; `:setvar` /
`GO` batches in sqlcmd). IDEs that strip those (DBeaver, DataGrip,
pgAdmin, SSMS in some modes) may skip guarded blocks.

**For complete output, prefer the native CLI**:

- `psql -f` (PostgreSQL)
- `mysql <` (MySQL)
- `sqlcmd -i` or the bundled `run_audit.ps1` runner (SQL Server)

## Where to go next

- `postgres/README.md`, `mysql/README.md`, `mssql/README.md` — engine
  overview, version notes, runner usage.
- `<engine>/perf/README.md`, `<engine>/sec/README.md` — full per-script
  catalog with required privileges and engine-version caveats.
- `COMPLIANCE.md` — how the findings map to CIS / GDPR / SOC2 / HIPAA /
  PCI DSS controls.
- `INCIDENT_RESPONSE.md` — playbook for using these scripts during an
  active incident.
