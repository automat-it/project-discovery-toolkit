# mssql audit scripts

Read-only diagnostic scripts for Microsoft SQL Server. 36 scripts total —
18 performance + 18 security — organised by priority tier, mirroring the
structure used for PostgreSQL and MySQL.

## Target version

SQL Server 2019 and newer. Verified on **SQL Server 2022 Developer
(Linux)**. Most queries also run unchanged on SQL Server 2017 and
Azure SQL Database / Managed Instance — version-specific blocks
(Query Store views, `sys.dm_db_log_stats`, external tables) are
guarded or clearly marked.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance audit (top SQL, locks, indexes, waits, sizing)|
| `sec/`    | Security audit (principals, permissions, auth, encryption,|
|           | PII discovery)                                            |

## Priority order

Run in this order for the most efficient audit:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/` — after critical findings are triaged
3. `medium/` — tuning and stability
4. `low/` — deeper investigation

## Runner scripts

Both PowerShell runner scripts live in **this folder** (`mssql\`) and
discover `perf\` and `sec\` sub-folders automatically — no configuration
needed, no dependency on parent directories.

```
mssql\
  run_audit.ps1           ← single database, -Category perf|sec|both
  run_all_databases.ps1   ← all user databases, -Category perf|sec|both
  perf\                   ← SQL scripts (critical / high / medium / low)
  sec\                    ← SQL scripts (critical / high / medium / low)
```

### Prerequisites (one-time)

```powershell
winget install Microsoft.go-sqlcmd
```

### Usage

```powershell
cd db-audit-scripts\mssql

# All user databases, perf + sec, Windows Authentication
.\run_all_databases.ps1 -Server "sql-server.internal"

# All user databases, perf only
.\run_all_databases.ps1 -Server "sql-server.internal" -Category perf

# Single database
.\run_audit.ps1 -Server "sql-server.internal" -Database "AppDatabase" -Category perf

# SQL Server Authentication — password via env (stays out of shell history)
$env:SQLCMDPASSWORD = "s3cr3t"
.\run_all_databases.ps1 -Server "sql-server.internal,1433" -User auditor

# Filter databases
.\run_all_databases.ps1 -Server "sql-server.internal" -IncludeLike "prod_%" -ExcludeRegex "staging"

# Explicit list of databases (when names share no common LIKE pattern,
# e.g. retrying only the databases that failed in a previous run).
# run_audit.ps1 is invoked once per name; -OutRoot puts every run into
# its own per-database sub-folder so the analyzer can render them as
# separate sections of one report.
$databases = @(
    "DatabaseA"
    "DatabaseB"
    "DatabaseC"
)
foreach ($db in $databases) {
    Write-Host "===== $db ====="
    .\run_audit.ps1 -Server "sql-server.internal" -Database $db -OutRoot ".\reports_subset\$db"
}

# Single combined PDF report covering every database under reports_subset\
.\perf\analyze_report.ps1 -ReportDir ".\reports_subset" -ServerName "sql-server.internal"
.\sec\analyze_report.ps1  -ReportDir ".\reports_subset" -ServerName "sql-server.internal"

# If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "sql-server.internal"
```

### Output layout

```
reports\
  mssql_audit_all_YYYYMMDD_HHMMSS\     ← run_all_databases.ps1
    _summary.txt
    _server\mssql_perf_YYYYMMDD_HHMMSS\
    _server\mssql_sec_YYYYMMDD_HHMMSS\
    <DatabaseName>\mssql_perf_YYYYMMDD_HHMMSS\
    <DatabaseName>\mssql_sec_YYYYMMDD_HHMMSS\
    ...
  mssql_perf_YYYYMMDD_HHMMSS\          ← run_audit.ps1 -Category perf
    _summary.txt
    critical_perf_01_top_sql.log
    ...
```

## Report analyzer (`perf/analyze_report.ps1`, `sec/analyze_report.ps1`)

After a run completes, the analyzer turns the raw log folder into a
**PDF file**. Two analyzers — one per audit
category. Each produces a single multi-page report covering every
database in the run:

* **Cover page** — server name, customer name, severity donut chart, generation date
* **Environment fingerprint** — edition / version / CPU / RAM / uptime
  / collation / AG-state (perf), or auth mode / sysadmin count / audit
  status (sec)
* **Executive summary** — KPI cards + findings-by-domain bar chart
* **Server-wide findings** — instance-level issues, deduplicated (one
  row per finding, not 123 copies)
* **Database fleet rollup** — per-DB findings as "X of N databases
  affected" with the top-affected database list
* **Backup freshness alert** (perf) — databases with last full backup
  older than 72 hours
* **Top-N inventories** (sec) — privileged accounts, weak-password
  logins, PII columns extracted directly from `sec_03` / `sec_05` /
  `sec_09` log content
* **Compliance mapping** — CIS Microsoft SQL Server Benchmark, GDPR
  Art.32, SOC2 Trust Services Criteria; sec also adds HIPAA Security
  Rule and PCI DSS v4
* **Phased remediation roadmap** — Phase 1 (Week 1-2, Critical),
  Phase 2 (Week 3-6, Warning), Phase 3 (Week 7-12, Info / hardening)
* **T-SQL remediation snippets** — executable templates per finding
  type, with placeholders explicitly marked
* **Per-database appendix** — the full per-DB finding list for
  reference
* **Glossary appendix** — wait types, DMV terms, encryption
  primitives for non-DBA readers
* **Title page** — green Automat-it band with logo, AWS Partner Network
  badge, customer name, server, generation date

```powershell
cd db-audit-scripts\mssql

# Default: produce perf_analysis.pdf and sec_analysis.pdf in the report folder
.\perf\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_YYYYMMDD_HHMMSS" `
                          -ServerName "sql-server.internal" -Customer "ACME Corp"
.\sec\analyze_report.ps1  -ReportDir "C:\reports\mssql_audit_all_YYYYMMDD_HHMMSS" `
                          -ServerName "sql-server.internal" -Customer "ACME Corp"

# Skip PDF -- write HTML only (lighter, opens in any browser)
.\perf\analyze_report.ps1 -ReportDir "..." -NoPdf

# Keep both PDF and the intermediate HTML
.\perf\analyze_report.ps1 -ReportDir "..." -KeepHtml

# Custom cover-page brand text (default 'Automat-it')
.\perf\analyze_report.ps1 -ReportDir "..." -Brand "Your Company"

# Custom output path
.\perf\analyze_report.ps1 -ReportDir "..." -OutFile "C:\reports\client_perf.pdf"
```

### PDF rendering pipeline

PDF is produced even when Microsoft Edge is not installed. The analyzer
tries the following methods in order:

1. **Microsoft Edge headless** (`msedge.exe --headless --print-to-pdf`)
   -- preinstalled on every modern Windows.
2. **Google Chrome / Chromium / Brave** headless -- if any is found in
   `Program Files` / `Program Files (x86)` / `LocalAppData`.
3. **wkhtmltopdf** -- in `PATH` or default install folder.
4. **Microsoft Word COM** -- ships with Office; opens the HTML and saves
   as PDF via `SaveAs2 wdFormatPDF=17`.
5. **HTML only** -- if none of the above is found, the analyzer keeps
   the HTML next to where the PDF would have been and prints a warning.

The chosen method is logged: `PDF: rendered via msedge.exe`.

### Brand assets

`mssql/assets/ait_bg_cover.png` is used as the cover-page background;
`mssql/assets/ait_bg_page.png` is the watermark on every content page.
The analyzer copies both files next to the HTML before rendering so
relative `url('ait_bg_*.png')` references in CSS resolve. Replace these
files in place to rebrand without editing PowerShell.

### Layout grouping

Within each report the findings are grouped **by database** (one
section per DB), with the executive summary and rollup tables giving
the cross-fleet view. Severity is colour-coded (Critical = red,
Warning = orange, Info = blue) consistently across cover, charts, and
tables.

Script behaviour notes:

- Scripts operate on the **current database** where applicable (object /
  permission / index / PII queries). Change DB with `USE <name>;` or
  `-d <name>` to audit each user database.
- Server-wide scripts (`perf_03`, `perf_05`, `sec_01`, `sec_03`, etc.)
  are context-independent.
- Privileged blocks (`sys.sql_logins`, `msdb.dbo.sysjobhistory`,
  `xp_instance_regread`, `xp_readerrorlog`) are wrapped in `TRY/CATCH`
  so a non-sysadmin execution falls back to a `[note]` line instead of
  aborting the script.

## Required privileges

Most scripts work for **any login** with `VIEW SERVER STATE` and
`VIEW ANY DEFINITION`. Specific elevated needs:

* `VIEW SERVER STATE` — for every DMV (`sys.dm_exec_*`,
  `sys.dm_os_*`, `sys.dm_io_*`). Grant with
  `GRANT VIEW SERVER STATE TO <login>;`.
* `VIEW ANY DEFINITION` — for catalog queries that list other users'
  objects (`sys.sql_modules.definition`, `sys.linked_logins`).
* `CONTROL SERVER` / sysadmin — for `sys.server_audits`,
  `sys.sql_logins.password_hash`, `xp_instance_regread`,
  `xp_readerrorlog`. Scripts that need these guard the calls with
  `TRY/CATCH` so lower-privilege runs still get useful output.
* `pg_monitor` equivalent does not exist in SQL Server — consider a
  custom server role with `VIEW SERVER STATE`,
  `VIEW ANY DEFINITION`, `VIEW ANY DATABASE` for a dedicated auditor.

See `perf/README.md` and `sec/README.md` for the full per-script
catalog and version caveats.
