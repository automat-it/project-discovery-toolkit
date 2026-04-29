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

All runner scripts live in **this folder** (`mssql\`). They discover
the `perf\` and `sec\` sub-folders automatically — no configuration needed.

```
mssql\
  run_audit.ps1           ← Windows (PowerShell) — single database
  run_all_databases.ps1   ← Windows (PowerShell) — all user databases
  perf\run_audit.sh       ← Linux / macOS (bash)  — single database, perf
  sec\run_audit.sh        ← Linux / macOS (bash)  — single database, sec
  perf\run_all_databases.sh  ← Linux / macOS — all user databases, perf
  sec\run_all_databases.sh   ← Linux / macOS — all user databases, sec
```

### Windows (PowerShell 5.1+)

Install sqlcmd once:
```powershell
winget install Microsoft.go-sqlcmd
```

```powershell
cd db-audit-scripts\mssql

# Both perf + sec, all user databases, Windows Authentication
.\run_all_databases.ps1 -Server "STG-SQL-N1"

# Perf only, single database, Windows Authentication
.\run_audit.ps1 -Server "STG-SQL-N1" -Database "Moodle" -Category perf

# SQL Server Authentication — password via env (stays out of shell history)
$env:SQLCMDPASSWORD = "s3cr3t"
.\run_all_databases.ps1 -Server "STG-SQL-N1,1433" -User auditor -Category sec

# Filter databases by name
.\run_all_databases.ps1 -Server "STG-SQL-N1" -IncludeLike "prod_%" -ExcludeRegex "staging"

# If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "STG-SQL-N1"
```

### Linux / macOS (bash)

```bash
# Perf — all user databases
SQLCMDPASSWORD=secret ./perf/run_all_databases.sh -U auditor -S db.internal,1433

# Sec — single database
SQLCMDPASSWORD=secret ./sec/run_audit.sh -U auditor -S db.internal -d mydb
```

### Output layout (both runners)

```
reports\mssql_audit_all_YYYYMMDD_HHMMSS\   ← PowerShell multi-DB
  _summary.txt
  _server\mssql_perf_...\
  _server\mssql_sec_...\
  <DatabaseName>\mssql_perf_...\
  <DatabaseName>\mssql_sec_...\

reports/mssql_perf_YYYYMMDD_HHMMSS/        ← bash single-category
  _summary.txt
  critical_perf_01_top_sql.log
  ...
```

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
