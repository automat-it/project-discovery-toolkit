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

## Running

Scripts use only `SELECT`, `DBCC TRACESTATUS`, `EXEC` (read-only system
stored procs like `xp_readerrorlog`) and `PRINT`. They never create
objects or modify data.

```bash
sqlcmd -C -N -S <host> -U <user> -P '<pwd>' -d <database> \
       -i perf/critical/perf_01_top_sql.sql
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
