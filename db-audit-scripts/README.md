# db-audit-scripts

Read-only diagnostic SQL scripts for database health, performance, and
security audits across **PostgreSQL**, **MySQL**, and **Microsoft SQL
Server**. Designed for ad-hoc investigations, pre-migration discovery,
and baseline assessments on existing deployments.

> **Read-only by design.** Every script uses only `SELECT` / `SHOW` /
> read-only system procedures. Nothing is created, altered, or deleted
> on your databases. Safe to run on production.

## What you get

| Engine        | Scripts | Verified on                                           |
|---------------|--------:|-------------------------------------------------------|
| PostgreSQL    | 36      | 13, 14, 15 (notes for 17)                             |
| MySQL         | 36      | 8.0, 8.3 community builds                             |
| SQL Server    | 36      | 2019, 2022 Developer (Linux); Azure SQL DB / MI       |

Each engine ships **18 performance + 18 security** scripts, organised
into four priority tiers (`critical` → `high` → `medium` → `low`).

## Layout

```
db-audit-scripts/
├── postgres/
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
├── mysql/
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
└── mssql/
    ├── run_audit.ps1            ← runs all scripts on a single database
    ├── run_all_databases.ps1    ← runs across every user database
    ├── perf/
    │   ├── analyze_report.ps1   ← turns logs into a branded PDF report
    │   └── {critical,high,medium,low}/
    ├── sec/
    │   ├── analyze_report.ps1
    │   └── {critical,high,medium,low}/
    └── assets/                  ← cover / watermark images for PDF reports
```

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
psql -h <host> -U <user> -d <database> \
     -v ON_ERROR_STOP=0 --pset=pager=off \
     -f postgres/perf/critical/perf_01_top_sql.sql > perf_01.log
```

#### MySQL

```bash
mysql -h <host> -u <user> -p <database> --batch --table \
      < mysql/perf/critical/perf_01_top_sql.sql > perf_01.log
```

#### SQL Server (recommended — uses the bundled runner)

```powershell
cd db-audit-scripts\mssql

# Audit all user databases, performance + security, Windows auth
.\run_all_databases.ps1 -Server "sql-server.internal"
```

The runner produces a timestamped folder under `reports\` containing one
`.log` per script. See `mssql/README.md` for SQL auth, filtering, and
PDF report generation.

### Step 3 — (SQL Server only) Build the PDF report

```powershell
.\perf\analyze_report.ps1 -ReportDir ".\reports\mssql_audit_all_<TIMESTAMP>" `
                          -ServerName "sql-server.internal" `
                          -Customer   "ACME Corp"
.\sec\analyze_report.ps1  -ReportDir ".\reports\mssql_audit_all_<TIMESTAMP>" `
                          -ServerName "sql-server.internal" `
                          -Customer   "ACME Corp"
```

You get two branded PDFs (`perf_analysis.pdf`, `sec_analysis.pdf`) with
cover page, executive summary, severity breakdown, compliance mapping
(CIS / GDPR / SOC2 / HIPAA / PCI), remediation roadmap, and per-database
appendix.

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
