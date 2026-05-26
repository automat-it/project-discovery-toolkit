# SQL Server audit scripts

Read-only diagnostic scripts for Microsoft SQL Server. **48 scripts**
total — 25 performance + 23 security — plus PowerShell runners and a
PDF report generator.

This README is written for **end users running the audit on their own
server**. No prior knowledge of the toolkit is assumed.

---

## Quick start (5 minutes)

If you just want a PDF report on a SQL Server instance:

```powershell
# 1. One-time: install the sqlcmd client
winget install Microsoft.go-sqlcmd

# 2. Open PowerShell in this folder
cd db-audit-scripts\mssql

# 3. Run the audit on every user database (Windows authentication)
.\run_all_databases.ps1 -Server "sql-server.internal"

# 4. Build the PDF reports
.\perf\analyze_report.ps1 -ReportDir ".\reports\mssql_audit_all_<TIMESTAMP>" `
                          -ServerName "sql-server.internal" `
                          -Customer   "ACME Corp"
.\sec\analyze_report.ps1  -ReportDir ".\reports\mssql_audit_all_<TIMESTAMP>" `
                          -ServerName "sql-server.internal" `
                          -Customer   "ACME Corp"
```

`<TIMESTAMP>` is replaced by the runner — look in `.\reports\` for the
folder it just created.

You'll find `perf_analysis.pdf` and `sec_analysis.pdf` inside the
report folder. Open and share.

---

## What the scripts cover

| Category | Purpose                                                          |
|----------|------------------------------------------------------------------|
| `perf/`  | Top SQL, blocking, waits, indexes, sizing, backups, replication  |
| `sec/`   | Principals, permissions, auth, encryption, PII discovery, audit  |

Each category is split into four priority tiers. **Run the higher tiers
first** — they have the highest signal-to-noise ratio.

| Tier       | When to look at it                                |
|------------|---------------------------------------------------|
| `critical` | Always — covers ~80% of real findings             |
| `high`     | After the critical findings are triaged           |
| `medium`   | Long-term tuning and stability                    |
| `low`      | Deeper investigation, forecast, edge cases        |

## Supported versions

- **SQL Server 2019** and newer. Verified on SQL Server 2022 Developer
  (Linux).
- Most queries also run on SQL Server 2017 and on **Azure SQL Database
  / Managed Instance**. Version-specific blocks (Query Store views,
  `sys.dm_db_log_stats`, external tables, registry probes) are guarded
  with `TRY/CATCH` and emit a `[note]` line where the feature is
  unavailable instead of aborting.

---

## Prerequisites

### 1. The `sqlcmd` client (required, one-time)

```powershell
winget install Microsoft.go-sqlcmd
```

This installs the modern Go-based `sqlcmd` (also called `go-sqlcmd`).
The runner uses it for every query.

### 2. PowerShell (already on Windows)

PowerShell 5.1 (built into Windows 10/11 and Windows Server) is
sufficient. PowerShell 7 also works.

### 3. Database privileges

A login with `VIEW SERVER STATE` and `VIEW ANY DEFINITION` is enough
for ~90% of the output. Sysadmin gives full output.

```sql
-- Minimum auditor login (run as sysadmin once, then hand off):
CREATE LOGIN auditor WITH PASSWORD = '<strong-password>';
GRANT VIEW SERVER STATE   TO auditor;
GRANT VIEW ANY DEFINITION TO auditor;
GRANT VIEW ANY DATABASE   TO auditor;
```

Privileged blocks (`sys.sql_logins.password_hash`, `xp_readerrorlog`,
`xp_instance_regread`, `sys.server_audits`) are wrapped in `TRY/CATCH`
so a non-sysadmin run still produces useful output — sensitive blocks
just emit `[note] insufficient privilege` lines.

---

## Running the audit

### Folder layout

```
mssql\
  run_audit.ps1              ← single database
  run_all_databases.ps1      ← every user database
  _analyze_lib.ps1           ← shared library for the PDF analyzers
  assets\                    ← cover and watermark images
  perf\
    analyze_report.ps1       ← builds perf_analysis.pdf
    critical\, high\, medium\, low\   ← the .sql scripts
  sec\
    analyze_report.ps1       ← builds sec_analysis.pdf
    critical\, high\, medium\, low\   ← the .sql scripts
```

### Common scenarios

```powershell
cd db-audit-scripts\mssql

# All user databases — perf + sec, Windows auth (default)
.\run_all_databases.ps1 -Server "sql-server.internal"

# All user databases — performance only
.\run_all_databases.ps1 -Server "sql-server.internal" -Category perf

# Single database
.\run_audit.ps1 -Server "sql-server.internal" -Database "AppDatabase" -Category perf

# SQL Server Authentication — keep the password OUT of shell history
$env:SQLCMDPASSWORD = "s3cr3t"
.\run_all_databases.ps1 -Server "sql-server.internal,1433" -User auditor

# Filter databases by name pattern
.\run_all_databases.ps1 -Server "sql-server.internal" `
                        -IncludeLike "prod_%" -ExcludeRegex "staging|archive"

# Explicit list (e.g. retrying only the databases that failed earlier)
$databases = @("DatabaseA", "DatabaseB", "DatabaseC")
foreach ($db in $databases) {
    Write-Host "===== $db ====="
    .\run_audit.ps1 -Server "sql-server.internal" -Database $db `
                    -OutRoot ".\reports_subset\$db"
}

# Single combined PDF over a custom report folder
.\perf\analyze_report.ps1 -ReportDir ".\reports_subset" -ServerName "sql-server.internal"
.\sec\analyze_report.ps1  -ReportDir ".\reports_subset" -ServerName "sql-server.internal"
```

### If PowerShell blocks the script

Windows sometimes blocks unsigned PowerShell scripts. Bypass for a
single run:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "sql-server.internal"
```

### Output layout

```
reports\
  mssql_audit_all_YYYYMMDD_HHMMSS\         ← run_all_databases.ps1
    _summary.txt
    _server\mssql_perf_YYYYMMDD_HHMMSS\
    _server\mssql_sec_YYYYMMDD_HHMMSS\
    <DatabaseName>\mssql_perf_YYYYMMDD_HHMMSS\
    <DatabaseName>\mssql_sec_YYYYMMDD_HHMMSS\
    ...
  mssql_perf_YYYYMMDD_HHMMSS\              ← run_audit.ps1 -Category perf
    _summary.txt
    critical_perf_01_top_sql.log
    ...
```

`_server\` holds **instance-level** results (waits, sessions,
configuration). Each `<DatabaseName>\` folder holds the **database-
level** results for that DB.

---

## PDF report (`perf/analyze_report.ps1`, `sec/analyze_report.ps1`)

Two analyzers — one per audit category. Each produces a single
multi-page **PDF report** covering every database in the run:

- **Cover page** — server, customer, severity donut, generation date
- **Environment fingerprint** — edition / build / CPU / RAM / uptime /
  collation / AG state (perf) or auth mode / sysadmin count / audit
  status (sec)
- **Executive summary** — KPI cards + findings-by-domain bar chart
- **Server-wide findings** — instance-level issues, deduplicated
- **Database fleet rollup** — "X of N databases affected" per finding
- **Backup freshness alert** (perf) — databases with last full backup
  older than 72 hours
- **Top-N inventories** (sec) — privileged accounts, weak-password
  logins, PII columns extracted from `sec_03` / `sec_05` / `sec_09`
- **Compliance mapping** — CIS Benchmark, GDPR Art.32, SOC2 (sec also
  adds HIPAA Security Rule and PCI DSS v4)
- **Phased remediation roadmap** — Phase 1 (Week 1-2, Critical),
  Phase 2 (Week 3-6, Warning), Phase 3 (Week 7-12, hardening)
- **T-SQL remediation snippets + Further-reading links** — executable
  templates per finding, each paired with vendor documentation URLs
  (learn.microsoft.com) for the specific control
- **Per-database appendix** — full per-DB finding list
- **Glossary appendix** — wait types, DMV terms, encryption primitives

### Analyzer commands

```powershell
cd db-audit-scripts\mssql

# Default: writes <category>_analysis.pdf into the report folder
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

### How the PDF is rendered

The analyzer tries the following methods in order — the first one
available wins:

1. **Microsoft Edge headless** (`msedge.exe --headless --print-to-pdf`)
   — preinstalled on every modern Windows.
2. **Google Chrome / Chromium / Brave** headless — searched in
   `Program Files`, `Program Files (x86)`, and `LocalAppData`.
3. **wkhtmltopdf** — in `PATH` or its default install folder.
4. **Microsoft Word COM** — ships with Office; the HTML is opened and
   saved as PDF via `SaveAs2 wdFormatPDF=17`.
5. **HTML only** — if none of the above is found, the analyzer keeps
   the HTML file next to where the PDF would have been and prints a
   warning.

The chosen method is logged: `PDF: rendered via msedge.exe`.

The chromium-based path uses a unique temporary user-data directory and
polls the output file until its size stabilises, so it works even when
Chrome is already running on the same machine and even when Chrome
prints non-fatal warnings to stderr.

### Brand assets

`mssql\assets\ait_bg_cover.png` is the cover-page background and
`mssql\assets\ait_bg_page.png` is the watermark on every content page.
The analyzer copies both files next to the HTML before rendering so
relative `url('ait_bg_*.png')` references in CSS resolve. **Replace
these two PNGs in place to rebrand without editing PowerShell.**

### Layout grouping

Within each report, findings are grouped **by database** (one section
per DB), with the executive summary and rollup tables giving the
cross-fleet view. Severity is colour-coded (Critical = red, Warning =
orange, Info = blue) consistently across cover, charts, and tables.

---

## Read-only guarantee

Every script in this set is **read-only**. Only `SELECT`, read-only
system stored procedures (`xp_readerrorlog`, `xp_instance_regread`,
`sys.sp_cdc_*` *listings only*), `DBCC TRACESTATUS(-1)`, and `PRINT`
are used. There is no `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`,
`DELETE`, `TRUNCATE`, `GRANT`, or `REVOKE` anywhere.

A few scripts declare table variables (`DECLARE @t TABLE …`) for
intermediate aggregation; those live only in the calling session and
disappear automatically. **No persistent objects are created.**

Privileged blocks (`sys.sql_logins`, `msdb.dbo.sysjobhistory`,
`xp_instance_regread`, `xp_readerrorlog`) are wrapped in `TRY/CATCH`
so a non-sysadmin execution falls back to a `[note]` line instead of
aborting the script.

---

## Troubleshooting

### "sqlcmd is not recognised"

Install it: `winget install Microsoft.go-sqlcmd`. Open a fresh
PowerShell window after installing so the new `PATH` is picked up.

### Login failure / "Cannot open database"

- For Windows auth, run PowerShell as a user that has access to the
  SQL Server.
- For SQL auth, set `$env:SQLCMDPASSWORD` and pass `-User <login>`.
- Verify connectivity with a one-shot query first:
  ```powershell
  sqlcmd -S "sql-server.internal" -Q "SELECT @@SERVERNAME"
  ```

### "WARNING: Could not render PDF"

The analyzer fell through every renderer. Either install Microsoft
Edge / Chrome / Word, or use `-NoPdf` to keep the HTML file (any
browser opens it). On Windows Server Core where no GUI app is
present, install `wkhtmltopdf` and rerun.

### PDF was created but the analyzer says "HTML only"

This was a known race when an older Chrome instance intercepted the
launch — fixed in current `_analyze_lib.ps1`. If you see it, refresh
the file from the repo and rerun:

```powershell
$u = "https://raw.githubusercontent.com/automat-it/project-discovery-toolkit/dba/db-audit-scripts/mssql/_analyze_lib.ps1?nocache=$([guid]::NewGuid())"
Invoke-WebRequest -Uri $u -Headers @{ 'Cache-Control'='no-cache' } -OutFile .\_analyze_lib.ps1
```

### Some logs contain `[note] insufficient privilege`

The login used to run the audit doesn't have `sysadmin` /
`CONTROL SERVER`. The script gracefully skipped the privileged block.
Either accept the gap or rerun that script under a higher-privilege
login.

### The PDF report shows fewer databases than expected

`run_all_databases.ps1` enumerates only **online user databases**
visible to the connecting login. Databases that are offline,
restoring, or that the login can't see (`VIEW ANY DATABASE` denied)
are skipped. Check `_summary.txt` in the report folder for the
exact list.

---

## Required privileges (detail)

* `VIEW SERVER STATE` — every DMV (`sys.dm_exec_*`, `sys.dm_os_*`,
  `sys.dm_io_*`).
  Grant: `GRANT VIEW SERVER STATE TO <login>;`
* `VIEW ANY DEFINITION` — catalog queries that list other users'
  objects (`sys.sql_modules.definition`, `sys.linked_logins`).
* `CONTROL SERVER` / sysadmin — `sys.server_audits`,
  `sys.sql_logins.password_hash`, `xp_instance_regread`,
  `xp_readerrorlog`. Scripts that need these guard the calls with
  `TRY/CATCH`, so lower-privilege runs still get useful output.
* On Azure SQL Database / Managed Instance, `xp_instance_regread` and
  some `sys.master_files` queries are not available — affected scripts
  emit `[note]` lines.

See `perf/README.md` and `sec/README.md` for the full per-script
catalog and version caveats.
