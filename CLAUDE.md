# Project guide

Read-only database audit toolkit for **PostgreSQL**, **MySQL**, and **Microsoft
SQL Server**. The deliverable is the SQL scripts plus the runner/analyzer
tooling that turns their output into branded HTML/PDF reports.

## Repository layout

```
db-audit-scripts/
├── assets/        brand PNGs (ait_bg_cover.png, ait_bg_page.png) shared by all analyzers
├── postgres/      perf/ + sec/  (run_audit.sh, analyze_report.py, critical|high|medium|low/)
├── mysql/         perf/ + sec/  (run_audit.sh, analyze_report.py, critical|high|medium|low/)
├── mssql/         run_audit.ps1, run_all_databases.ps1, perf/ + sec/ (analyze_report.ps1, tiers)
└── tools/         aggregate_report.py
```

- Postgres/MySQL: bash runner + Python analyzer (`analyze_report.py`, shared `_analyze_lib.py`).
- MSSQL: PowerShell runner + analyzer (`analyze_report.ps1`, shared `_analyze_lib.ps1`).
- Each runner writes one `.log` per script into a timestamped `reports/<engine>_<cat>_<TS>/` folder; the analyzer turns that folder into a report.

## Run commands

PostgreSQL:
```bash
cd db-audit-scripts/postgres
export PGPASSWORD='<password>'
bash perf/run_audit.sh -u <user> -h <host> -p 5432 -d <db> -o ./reports
bash sec/run_audit.sh  -u <user> -h <host> -p 5432 -d <db> -o ./reports
python3 perf/analyze_report.py ./reports/postgres_perf_<TS> --server <label>
python3 sec/analyze_report.py  ./reports/postgres_sec_<TS>  --server <label>
```

MySQL:
```bash
cd db-audit-scripts/mysql
export MYSQL_PWD='<password>'
bash perf/run_audit.sh -u <user> -h <host> -P 3306 -d <db> -o ./reports
bash sec/run_audit.sh  -u <user> -h <host> -P 3306 -d <db> -o ./reports
python3 perf/analyze_report.py ./reports/mysql_perf_<TS> --server <label>
python3 sec/analyze_report.py  ./reports/mysql_sec_<TS>  --server <label>
```

SQL Server:
```powershell
cd db-audit-scripts\mssql
.\run_all_databases.ps1 -Server "<host>"
.\perf\analyze_report.ps1 -ReportDir ".\reports\mssql_audit_all_<TS>" -ServerName "<host>"
.\sec\analyze_report.ps1  -ReportDir ".\reports\mssql_audit_all_<TS>" -ServerName "<host>"
```

## Report naming

Report filenames must carry the engine name:
`postgres_perf_analysis.*`, `postgres_sec_analysis.*`, `mysql_perf_analysis.*`,
`mysql_sec_analysis.*`, `mssql_perf_analysis.*`, `mssql_sec_analysis.*`.

## Conventions

- **Read-only audits.** Scripts use only `SELECT` / `SHOW` / read-only system
  procedures — no `CREATE`/`ALTER`/`DROP`/`INSERT`/`UPDATE`/`DELETE`/`GRANT`/`REVOKE`,
  no temp objects. Safe to run on production.
- **Filenames** prefixed with category + number for ordering, e.g.
  `perf_01_top_sql.sql`, `sec_03_admin_and_superusers.sql`.
- **Priority tiers**: `critical/` → `high/` → `medium/` → `low/`. Numbering is
  shared across engines so finding-IDs (e.g. `sec_05`) refer to the same control.
- **Branding**: every report uses the cover + per-page watermark from
  `db-audit-scripts/assets/`. Keep the existing layout consistent across engines.
- **Print pagination**: section headers must not be orphaned above a page break;
  keep small atomic blocks together but allow long finding lists to flow.

## House rules

- The repo is **public** — never commit sensitive data of any kind.
- No real customer names, hostnames, IPs, or credentials anywhere in tracked
  files. Use generic placeholders (`<host>`, `<db>`, `ACME Corp`) and example-only
  passwords.
- Do not commit helper/test scaffolding: local `docker/` stacks, compose files,
  seed/fixture SQL, generated `reports/`, `*.html`, `*.pdf`, `*.csv`, dumps. These
  are already covered by `.gitignore`.
- Default branch is `dba`.
- Commit only when explicitly asked. Write clean, descriptive commit messages.
- Keep secret-bearing local config (`.claude/settings.local.json`, `.env`,
  `*.pem`, `*.key`) out of version control.

## Local testing notes

- Azure SQL Edge ships a self-signed cert that go-sqlcmd rejects; use the ODBC
  `mssql-tools18` `sqlcmd -C` (OpenSSL tolerates it).
- A Docker `pwsh` image with `mssql-tools18` is handy for running the MSSQL
  PowerShell toolchain off-host. Keep all such scaffolding local (gitignored).
- PDF rendering is via headless Chrome:
  `--headless --disable-gpu --no-pdf-header-footer --print-to-pdf`.
