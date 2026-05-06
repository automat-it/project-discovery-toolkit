# Security audit scripts

Read-only diagnostic queries for Microsoft SQL Server security
analysis. Each script is independent and can be run standalone with
`sqlcmd -i <script>.sql`.

## Runner scripts

Both PowerShell scripts live in the **`mssql\` root folder** (one level above
this `sec\` folder). Run them from there — they resolve paths automatically.

```powershell
cd db-audit-scripts\mssql

# Single database — sec only, Windows Authentication
.\run_audit.ps1 -Server "sql-server.internal" -Category sec

# All user databases — sec only
.\run_all_databases.ps1 -Server "sql-server.internal" -Category sec

# SQL Server Authentication — password via env (stays out of shell history)
$env:SQLCMDPASSWORD = "s3cr3t"
.\run_all_databases.ps1 -Server "sql-server.internal,1433" -User auditor -Category sec

# Filter databases
.\run_all_databases.ps1 -Server "sql-server.internal" -Category sec `
    -IncludeLike "prod_%" -ExcludeRegex "staging|archive"

# If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "sql-server.internal" -Category sec
```

## Report analyzer (`analyze_report.ps1`)

Generates a **PDF file** report (HTML intermediate) with:

* Cover page (server, customer, severity donut chart)
* Environment fingerprint (auth mode, sysadmin count, audit status)
* Executive summary (KPIs + findings-by-domain bar chart)
* **Server-wide findings** (deduplicated, instance-level)
* **Database fleet rollup** ("X of N databases affected")
* **Top-N inventories** -- privileged accounts, weak-password logins,
  PII columns extracted from sec_03 / sec_05 / sec_09 logs
* **Compliance mapping** (CIS Benchmark, GDPR Art.32, SOC2, HIPAA, PCI DSS)
* **Phased remediation roadmap** (Week 1-2 / 3-6 / 7-12)
* T-SQL remediation snippets (executable, with placeholders)
* Per-database appendix
* Glossary (sysadmin, TDE, Always Encrypted, DDM, ...)

```powershell
# Default: produces sec_analysis.pdf
.\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_20260429_230243" `
                     -ServerName "sql-server.internal" -Customer "ACME Corp"

# HTML only
.\analyze_report.ps1 -ReportDir "..." -NoPdf

# Keep both PDF and HTML
.\analyze_report.ps1 -ReportDir "..." -KeepHtml

# Custom branding
.\analyze_report.ps1 -ReportDir "..." -Brand "Your Company"
```

### PDF rendering pipeline

PDF is produced even when Microsoft Edge is not installed. The analyzer
tries the following methods in order:

1. Microsoft Edge headless (`msedge.exe --headless --print-to-pdf`)
2. Google Chrome / Chromium / Brave headless (Program Files, x86, LocalAppData)
3. `wkhtmltopdf` in PATH or `Program Files\wkhtmltopdf\bin\`
4. Microsoft Word COM (`SaveAs2 wdFormatPDF=17`) -- ships with Office
5. HTML only -- if none of the above is available

The method that succeeded is logged on stdout
(`PDF: rendered via msedge.exe`).

Output layout:

```
reports\mssql_sec_YYYYMMDD_HHMMSS\           ← run_audit.ps1 -Category sec
  _summary.txt
  critical_sec_01_users_and_roles_inventory.log
  critical_sec_02_effective_privileges.log
  ...
  low_sec_18_audit_gaps.log

reports\mssql_audit_all_YYYYMMDD_HHMMSS\     ← run_all_databases.ps1
  _summary.txt
  _server\mssql_sec_YYYYMMDD_HHMMSS\
  <DatabaseName>\mssql_sec_YYYYMMDD_HHMMSS\
  ...
```

## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT`, read-only
system stored procedures (`xp_readerrorlog`, `xp_instance_regread`),
and `PRINT` are used. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`,
`DELETE`, `GRANT`, or `REVOKE` anywhere.

Per-session table variables (`DECLARE @t TABLE …`) are used in
`sec_02_effective_privileges.sql` to hold a small working set and are
cleaned up automatically at session end.

## Target version

SQL Server 2019+, verified on 2022 Developer (Linux). Older editions
work with one or two caveats noted on specific scripts.

## Required privileges

Most queries work for **any login** with `VIEW SERVER STATE` and
`VIEW ANY DEFINITION`. Specific elevated needs:

* Reading `sys.sql_logins.password_hash` (used by `sec_05` weak-password
  check via `PWDCOMPARE`) requires sysadmin or `VIEW ANY DEFINITION`
  plus `CONTROL SERVER` — the script falls back to NULL hash if the
  current login can't see them.
* `xp_instance_regread` / `xp_readerrorlog` require sysadmin; blocks
  that use them are guarded by `TRY/CATCH`.
* `sys.server_audits` + `sys.dm_server_audit_status` require
  `VIEW SERVER STATE` (for running audits) and `ALTER ANY SERVER AUDIT`
  (for definition).
* On Azure SQL Database / Managed Instance, `xp_instance_regread` is
  not available — `sec_05`, `sec_07`, `sec_17` will emit `[note]` lines
  where the registry isn't reachable.

## Recommended execution order

Run priorities top-to-bottom — `critical` first covers the highest-risk
access and compromise paths.

## Critical priority

### `sec_01_users_and_roles_inventory.sql`

Complete inventory of server principals (logins + server roles +
certificates + asymmetric keys), fixed-role membership, custom server
roles, database-level users + role membership in the current database,
orphan users (SID without server-side principal), count summary.

### `sec_02_effective_privileges.sql`

Server-level + database-level explicit grants, schema / object / column
grants, effective per-table access per database user via
`HAS_PERMS_BY_NAME` (respects full role expansion — the SQL Server
analog of PostgreSQL `has_table_privilege`), and all `WITH GRANT
OPTION` grants.

### `sec_03_admin_and_superusers.sql`

`sysadmin` / `securityadmin` / `serveradmin` / `setupadmin` /
`processadmin` / `diskadmin` / `bulkadmin` / `dbcreator` role
membership, holders of `CONTROL SERVER` / `ALTER ANY LOGIN` /
`IMPERSONATE ANY LOGIN` / `UNSAFE ASSEMBLY` etc., recursive nested
role chains ending in sysadmin, `db_owner` / `db_securityadmin` in the
current database.

### `sec_04_public_and_excessive_grants.sql`

Privileges granted to the `public` role at server and database scope,
schema / object access granted to public, guest account status
(should be disabled), `CONNECT SQL` to public at server scope, grants
on system schemas (`sys`, `INFORMATION_SCHEMA`) to non-sa principals.

### `sec_05_authentication_and_passwords.sql`

Authentication mode (Mixed vs Windows-only), SQL logins with
`CHECK_POLICY` or `CHECK_EXPIRATION` off, expired passwords,
passwords never changed or older than 180 days, **weak-password
detection** via `PWDCOMPARE` against a short list of common
passwords plus `login_name = password` check, disabled-login
inventory.

## High priority

### `sec_06_audit_logging.sql`

Server Audits defined + running, server / database audit specs +
their action groups, default trace status, Extended Events sessions
running, last error-log entries.

### `sec_07_encryption_status.sql`

Per-session TLS state from `sys.dm_exec_connections`,
`ForceEncryption` registry value, **TDE** status per database
(`sys.dm_database_encryption_keys`), database master keys,
certificates (with expiry), symmetric keys, **Always Encrypted**
columns, **Dynamic Data Masking** columns, last N backups and
whether they were encrypted.

### `sec_08_network_exposure.sql`

Endpoints (type + state + protocol), TCP endpoint port / IP binding,
remote (non-loopback) current connections, distinct client IPs,
endpoint grants, linked servers + stored credentials
(credential *masked*), server services state (`sys.dm_server_services`).

### `sec_09_sensitive_data_discovery.sql`

Heuristic PII discovery by column name (national ID, government ID,
payment card, bank account, credential, email, phone, name,
date-of-birth, address, demographic, financial, health, IP address,
geo, biometric), tables containing credential-like columns, columns
protected by DDM, Row-Level Security policies + predicates.

### `sec_10_dangerous_objects.sql`

`EXECUTE AS OWNER` / `SELF` / `'user'` procedures (escalation surface),
CLR assemblies (especially `UNSAFE` / `EXTERNAL_ACCESS`), DML and DDL
triggers, server-level triggers, server-wide feature switches
(`xp_cmdshell`, `OLE Automation`, `Ad Hoc Distributed Queries`, etc.),
Service Broker queue activation procedures, linked servers with
`data_access / RPC` enabled, text-scan of modules for
`xp_cmdshell / sp_OACreate / xp_regread / OPENROWSET` usage,
server-level credentials.

### `sec_20_failed_login_patterns.sql`

`AuditLevel` registry probe via `xp_instance_regread` (wrapped in
TRY/CATCH); Server Audit / audit-specification coverage for
FAILED_LOGIN / LOGIN_CHANGE groups; ERRORLOG scrape via
`xp_readerrorlog` with ordered fallback for older builds;
aggregation of failed-login rows by extracted login / client IP /
reason; `LOGINPROPERTY`-based lockout, bad-password-count,
expiration state per SQL login; currently connected sessions grouped
by client IP.

### `sec_21_patch_and_cve_level.sql`

`SERVERPROPERTY` (ProductVersion / Level / Build / UpdateLevel /
UpdateReference), edition + engine edition, `@@VERSION` banner,
branch EOL matrix for SQL 2012 → SQL 2022, `sys.dm_os_host_info`,
`sys.dm_server_services` (Azure-guarded) with `last_startup_time` —
long uptime is a signal of skipped Cumulative Updates (CU installs
require service restart).

### `sec_22_cert_and_key_expiry.sql`

`sys.certificates` in the current DB and in `master` (wrapped in
TRY/CATCH), days-until-expiry bucket per certificate, TDE encryption
state per database via `sys.dm_database_encryption_keys`, Always
Encrypted CMK / CEK inventory, TLS endpoint certs, SQL-login
expiration state via `LOGINPROPERTY(DaysUntilExpiration / IsExpired /
IsMustChange / IsLocked / HistoryLength / PasswordLastSetTime)`.

## Medium priority

### `sec_11_role_inheritance_chains.sql`

Direct server-role membership, full transitive server-role chain
(recursive, depth ≤ 10), effective-role count per login, direct +
transitive database-role membership, **cyclic membership detection**
with an explicit `closed` flag (the naïve "filter visited nodes"
approach never detects cycles — the walk uses a
`closed` flag that flips on the closing edge).

### `sec_12_dormant_users.sql`

Disabled logins, logins with no active session that haven't been
modified in 90 days, expired-password SQL logins still enabled,
orphan database users (SID without server principal), logins with no
database mappings anywhere, logins that own nothing (no database /
job / endpoint).

### `sec_13_service_accounts.sql`

Service-account naming heuristic (`_svc`, `_app`, `_etl`, `_bot`,
`_backup`, `_monitor`, etc.), service-like logins with elevated
fixed-role membership, current sessions by program_name, logins
with unusually high session counts (pooled daemons), service
accounts with `CHECK_EXPIRATION` off, object ownership by service
principals.

### `sec_14_backup_security.sql`

Who can take backups (sysadmin, dbcreator, db_backupoperator), last
full / diff / log per database + encryptor, unencrypted backup sets,
recent 30-day backup history, in-flight BACKUP / RESTORE operations,
Agent jobs that run `BACKUP DATABASE / LOG`.

### `sec_15_external_integrations.sql`

Linked servers, linked logins (`remote_password` always masked — never
printed), server-level credentials, Agent proxies, Service Broker
services / queues / contracts / message types / routes, external data
sources and tables (PolyBase), replication publications.

### `sec_23_data_retention_audit.sql`

Top 100 tables by reserved pages, large non-partitioned tables
(> 1 GB) flagged as retention candidates, time-like column
inventory, SQL Agent jobs whose steps contain `DELETE` /
`TRUNCATE` / `purge` / `retention` keywords (TRY/CATCH-wrapped
against Azure SQL DB where msdb is absent), temporal tables +
`HISTORY_RETENTION_PERIOD` state (temporal tables with NULL
retention keep history forever).

### `sec_19_schema_change_history.sql`

Server- and database-scoped DDL triggers; Server Audit configuration
capturing `SCHEMA_OBJECT_CHANGE_GROUP` / `DATABASE_OBJECT_CHANGE_GROUP`
/ `%LOGIN%` / `%PRINCIPAL%` actions; default-trace DDL events read via
`sys.fn_trace_gettable` (wrapped in TRY/CATCH); recently created /
altered objects by `modify_date`; recently created logins and database
principals; Extended Event sessions capturing
`object_altered / _created / _deleted`.

## Low priority

### `sec_16_pii_naming_heuristics.sql`

Extended PII patterns — international identifiers (US/EU/CIS/CA/UK),
health codes (ICD / SNOMED / LOINC), biometric, auth tokens, crypto
wallets, device / tracking IDs, immigration. Plus log / audit / history
table inventory and extended properties mentioning
`personal / sensitive / pii / gdpr / hipaa / secret / confidential`.

### `sec_17_deprecated_features.sql`

Databases on an old compatibility level, counter-based **"deprecated
features in use"** stats from `sys.dm_os_performance_counters`, SQL
logins with `CHECK_POLICY` / `CHECK_EXPIRATION` off, legacy server
options (cross-db chaining, remote access, xp_cmdshell, Ole
Automation, Ad Hoc Distributed Queries), deprecated data types in use
(`text`, `ntext`, `image`, `timestamp`), Database Mail profile
inventory.

### `sec_18_audit_gaps.sql`

Is any Server Audit running? Which of the standard high-value action
groups are covered / missing? Per-database Query Store coverage,
CDC / Change Tracking coverage, logging-related server configuration,
Extended Events session coverage, failed-Agent-job summary from
`msdb.dbo.sysjobhistory`.

## Notes and caveats

* **`sec_02` effective-access matrix** uses `HAS_PERMS_BY_NAME(…)` which
  always reflects the **current connection's** effective permissions.
  If you need to audit a specific login's effective permissions, run the
  script connected as that login, or wrap the permission cross-join in
  `EXECUTE AS LOGIN = 'target'; … REVERT;`.
* **`sec_05` weak-password check** uses `PWDCOMPARE` against a small
  built-in list. Extend `@weak` with your own policy terms for more
  coverage. The check runs only when the current login can read
  `sys.sql_logins.password_hash` (sysadmin or `CONTROL SERVER`).
* **Registry-read queries** in `sec_05`, `sec_07`, `sec_17` use
  `xp_instance_regread`, which is unavailable on SQL Server on Linux for
  some paths and on Azure SQL. The calls are wrapped in `TRY/CATCH` and
  emit a `[note]` line when unreachable.
* **Cycle detection** in `sec_11` uses a carried `visited` list and a
  `closed` boolean. An earlier approach that filtered visited rows out
  before the recursive step silently never closed cycles — this one
  does.
