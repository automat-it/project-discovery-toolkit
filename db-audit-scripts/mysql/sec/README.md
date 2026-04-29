# Security audit scripts

Read-only diagnostic queries for MySQL security analysis.
Each script is independent and can be run standalone with `mysql < script.sql`.

## Batch runner (`run_audit.sh`)

`run_audit.sh` executes every script in this folder in priority order
(`critical` → `high` → `medium` → `low`) and writes one log file per
script into a timestamped report folder.

```bash
# password comes from MYSQL_PWD (preferred over -p, stays out of `ps`)
MYSQL_PWD=secret ./run_audit.sh -u auditor -h db.internal -P 3306 -d mysql
```

Flags: `-u USER` (required) `-h HOST` `-P PORT` `-d DATABASE`
`-o OUT_ROOT` (default `./reports`). Failure is detected by the mysql
client's exit code plus a post-run grep for `^ERROR NNNN` in the log —
`--abort-source-on-error` is not uniformly supported across mysql
client builds, so the grep is the portable backstop.

Output layout:

```
reports/mysql_sec_YYYYMMDD_HHMMSS/
  _summary.txt                          # OK/FAIL per script + totals
  critical_sec_01_users_and_roles_inventory.log
  critical_sec_02_effective_privileges.log
  ...
  low_sec_18_audit_gaps.log
```

## Report analyzer (`analyze_report.py`)

After a run completes, parse the report folder into a customer-friendly
HTML summary highlighting potential issues across all databases:

```bash
# Single-database run output (the folder run_audit.sh wrote into)
./analyze_report.py reports/mysql_sec_YYYYMMDD_HHMMSS

# Multi-database run (parent folder containing per-DB sub-folders)
./analyze_report.py /path/to/parent_report_dir --server prod-mysql-01
```

The analyzer writes `sec_analysis.html` into the report folder. The HTML
contains an executive-summary table (counts of Critical / Warning / Info
findings per database) plus a section per database with the matched
findings, severity, and remediation hints. Standard library only --
no Python packages to install.


## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT` and `SHOW`
statements. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`,
`TRUNCATE`, `GRANT`, or `REVOKE` is used anywhere. No temporary tables,
no functions, no objects of any kind are created.

## Target version

MySQL 8.0+. Role support (`mysql.role_edges`, `mysql.default_roles`,
`SHOW GRANTS FOR … USING …`) and CTEs (used in role chain traversal in
`sec_11`) require MySQL 8.0. Dynamic privileges (`mysql.global_grants`,
`SYSTEM_USER`) are also 8.0+. Running against MySQL 5.7 will produce
errors in those blocks — skip them manually.

## Required privileges

Most queries work for **any login user** with `SELECT` on `mysql.*`
and `information_schema`. Specific elevated requirements:

* `SELECT` on `mysql.user`, `mysql.db`, `mysql.role_edges`,
  `mysql.global_grants`, `mysql.default_roles`, `mysql.func`,
  `mysql.servers` — required by `sec_01` through `sec_15`. Granting
  the `SELECT_CATALOG_ADMIN` dynamic privilege covers all of these.
* `SELECT` on `performance_schema.*` — required by `sec_06`, `sec_12`.
* `PROCESS` privilege — required to see connection-origin details in
  `information_schema.PROCESSLIST` for `sec_08`.
* `REPLICATION CLIENT` — required for `sec_14` (`SHOW BINARY LOGS`,
  `SHOW REPLICA STATUS`).
* `SUPER` or `SYSTEM_USER` — required to see all rows in
  `information_schema.PROCESSLIST` including other users' sessions.
  Without it, `sec_08` connection data is limited to the current user.

## Recommended execution order

Run priorities top-to-bottom — `critical` first covers the highest-risk
access and compromise paths.

## Critical priority

### `sec_01_users_and_roles_inventory.sql`

Complete inventory of all users and roles from `mysql.user` with account
attributes (authentication plugin, password expiry, account lock state,
connection limits, privileges). Role membership from `mysql.role_edges`
and `mysql.default_roles`. Foundation for all security analysis.

### `sec_02_effective_privileges.sql`

Direct grants at global, schema, and table level from `mysql.user`,
`mysql.db`, and `information_schema.TABLE_PRIVILEGES` /
`COLUMN_PRIVILEGES`. **Routine grants** are read from
`mysql.procs_priv` — `information_schema.ROUTINE_PRIVILEGES` was
dropped in MySQL 8.0 and is no longer populated. Role membership and
effective privilege expansion via `mysql.role_edges`. MySQL 8.0's
`SHOW GRANTS FOR user USING role` is noted for interactive effective-
access verification.

### `sec_03_admin_and_superusers.sql`

Users with `Super_priv` or `SYSTEM_USER` dynamic privilege;
`Create_user_priv` (CREATEROLE equivalent); `Repl_slave_priv`
(REPLICATION); `FILE` privilege (server-side file access). MySQL has no
`BYPASSRLS` concept — noted in script. Dynamic privileges from
`mysql.global_grants`.

### `sec_04_public_and_excessive_grants.sql`

MySQL has no `PUBLIC` pseudo-role. The equivalent risks are:
anonymous accounts (`mysql.user.User = ''`), wildcard-host accounts
(`Host = '%'`), and overly broad schema-level grants in `mysql.db`.
The script identifies all three, plus `GRANT OPTION` holders who can
further distribute privileges.

### `sec_05_authentication_and_passwords.sql`

Authentication plugin per account (`mysql_native_password` is deprecated
in 8.0 and removed in 9.0); accounts with empty passwords; password
expiry status and policy; accounts with `password_expired = 'Y'`;
accounts with no expiration policy. MySQL has no direct `pg_hba.conf`
equivalent — network exposure is covered in `sec_08` via `mysql.user.Host`.

## High priority

### `sec_06_audit_logging.sql`

MySQL audit coverage: `general_log`, `slow_query_log`, binary log
format and retention, `audit_log` plugin status (MySQL Enterprise
Audit). `performance_schema` consumer enablement as a partial open-
source substitute. Without the Enterprise Audit plugin, statement-level
traceability is limited — this script surfaces exactly that gap.

### `sec_07_encryption_status.sql`

SSL/TLS configuration and cipher from `global_variables`
(`have_ssl`, `ssl_ca`, `tls_version`); per-session SSL state from
`performance_schema.status_by_thread`; InnoDB tablespace-level
encryption from `information_schema.INNODB_TABLESPACES`; binary log
encryption setting. Covers **encryption in transit and at-rest
indicators only** — verify KMS / storage-layer encryption separately.

### `sec_08_network_exposure.sql`

`bind_address` and `port` configuration; host patterns in `mysql.user`
with risk classification (`%`, `/8` wildcards, localhost-only, specific
hosts); currently connected client addresses from
`information_schema.PROCESSLIST`. MySQL has no `pg_hba.conf` —
`mysql.user.Host` is the sole network access control mechanism.

### `sec_09_sensitive_data_discovery.sql`

Heuristic PII discovery by column name (national IDs, payment cards,
credentials, contact info, demographics, health data) from
`information_schema.COLUMNS` using `REGEXP`. MySQL has no Row-Level
Security (RLS) or policies — the script notes this and lists views with
`SECURITY DEFINER` as the closest analog for row-level access control.

### `sec_10_dangerous_objects.sql`

`DEFINER`-privilege routines and views from `information_schema.ROUTINES`
and `VIEWS`. Routines whose definer holds `SUPER` are matched on both
user **and** host so accounts that happen to share a name on a
different host do not generate false positives. UDFs from `mysql.func`
(columns `name, ret, dl, type` — the `User / Host / Aggregate`
columns that existed in MySQL 5.x were removed in 8.0). Scheduled
events from `information_schema.EVENTS`; DML triggers from
`information_schema.TRIGGERS`; FEDERATED engine tables and external
server definitions from `mysql.servers`. Routines executable by
wildcard-host grantees are read from `mysql.procs_priv` (replacing
the removed `ROUTINE_PRIVILEGES` view).

### `sec_20_failed_login_patterns.sql`

Connection-control plugin presence and variables; accounts tracked by
`CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS` (probed with a prepared
statement so the script does not error when the plugin is not
installed); access-denied aggregates from
`events_errors_summary_by_account_by_error` /
`events_errors_summary_by_host_by_error`; `Aborted_connects` /
`Connection_errors_*` counters; per-host `host_cache` error counts;
account lock / password-expiry state from `mysql.user`;
`max_connect_errors` / `max_user_connections` thresholds.

### `sec_21_patch_and_cve_level.sql`

`VERSION()`, compile arch / OS / edition, branch EOL matrix for MySQL
(8.4 LTS / 8.0 / 5.7 / 5.6) and MariaDB (11.4 / 10.11 / 10.6 / 10.5 /
10.4) as of Nov 2024, active plugin inventory with versions, components
registered via the 8.0 `mysql.component` table (prepared-statement
guarded for 5.7), SSL library version in use.

### `sec_22_cert_and_key_expiry.sql`

Server-side TLS variables (`ssl_cert`, `ssl_key`, `tls_version`,
`require_secure_transport`, FIPS mode), active server cert validity
window from `performance_schema.global_status` (`Ssl_server_not_before`
/ `Ssl_server_not_after`) with `STR_TO_DATE` parsing and days-until-
expiry bucketing, per-account `password_lifetime` + `password_expired`
state with policy-computed expiry date, currently-connected SSL vs
plaintext session ratio, keyring / encryption plugin inventory.

## Medium priority

### `sec_11_role_inheritance_chains.sql`

Direct role membership from `mysql.role_edges`; full transitive
membership chains via recursive CTE; users with the most effective roles;
roles not set as `DEFAULT ROLE` (NOINHERIT analog); cyclic membership
detection. Requires MySQL 8.0 for both role tables and recursive CTE
support.

### `sec_12_dormant_users.sql`

MySQL does not track last successful login natively. The script uses
`performance_schema.accounts` (total connection count since last
reset/restart) as a proxy for dormancy — accounts with zero connections
since the last restart are flagged. Expired accounts from `mysql.user`
and locked accounts are also listed. **This is approximate** — see
caveats below.

### `sec_13_service_accounts.sql`

Technical accounts identified by naming heuristics (`_svc`, `_app`,
`_etl`, `_bot`, `_api`, `_job` suffixes/prefixes), high `max_user_
connections` limits, connection counts from `performance_schema.accounts`,
and absence of password expiration — behavioral indicators of service
accounts rather than human users.

### `sec_14_backup_security.sql`

Users with `Repl_slave_priv` or `BACKUP_ADMIN` dynamic privilege; active
binary log files and sizes (`SHOW BINARY LOGS`); replica connection status
(`performance_schema.replication_connection_status`); `FILE` privilege
holders (server-side read/write access). MySQL has no `pg_read_all_data`
or `pg_basebackup`-style slot concept.

### `sec_15_external_integrations.sql`

FEDERATED engine tables from `information_schema.TABLES`; external
server definitions from `mysql.servers` (connection strings **masked
by default** — see credential masking note below); linked server
users from `mysql.servers.Username`. UDFs from `mysql.func` using
the current column set (`name, ret, dl, type`); the `Aggregate`
column was removed in MySQL 8.0 and its meaning is now encoded in
the `type` enum. Replication subscriptions.

### `sec_23_data_retention_audit.sql`

Top tables by size with `CREATE_TIME` / `UPDATE_TIME`, large
non-partitioned tables (> 1 GB) flagged as retention candidates,
time-like column inventory for retention-key discovery, scheduled
`EVENTS` sampling (retention is often implemented here), event-
scheduler global state, per-schema size roll-up.

### `sec_19_schema_change_history.sql`

Audit-plugin presence (MySQL Enterprise Audit / MariaDB Audit);
binlog / general-log / slow-log configuration as coarse DDL-trail
surrogates; recently created / altered tables, routines, triggers
from `information_schema`; DDL statements still visible in
`performance_schema.events_statements_history_long`; summary
assessment of whether any persistent DDL trail exists.

## Low priority

### `sec_16_pii_naming_heuristics.sql`

Extended PII patterns including international identifiers, biometric
data, auth tokens, crypto wallets, device tracking, and financial data —
broader naming heuristics than `sec_09`. Queries `information_schema.COLUMNS`
with an extended `REGEXP`. Same column-name limitations apply.

### `sec_17_deprecated_features.sql`

`mysql_native_password` plugin (deprecated in 8.0, removed in 9.0);
accounts with empty passwords; old `PASSWORD()` function usage flags;
`skip_name_resolve` status; `local_infile` (server-side file risk);
`old_passwords` variable; TLS version configuration. MySQL-specific
deprecation surface — no direct `pg_hba` method analog.

### `sec_18_audit_gaps.sql`

Audit completeness checklist: `general_log` enabled, `slow_query_log`
enabled with threshold, binary log format (`ROW` vs `STATEMENT`),
`audit_log` plugin presence, `performance_schema` consumer enablement,
`log_error` configuration. Surfaces what is **not** being captured.

## Notes and caveats

* **MySQL has no Row-Level Security.** PostgreSQL RLS (`sec_09` policies)
  has no direct equivalent in MySQL. The closest analog is views defined
  with `SQL SECURITY DEFINER` and `WHERE` clauses. The scripts note this
  where relevant.
* **`mysql_native_password` is deprecated.** In MySQL 8.0 it is still
  functional but produces deprecation warnings; in MySQL 9.0 it has been
  removed. `sec_05` and `sec_17` flag all accounts still using it.
* **Dormant user detection in `sec_12` is approximate.** MySQL does not
  record last successful login in any built-in catalog. The
  `performance_schema.accounts` counter resets on server restart and
  can be reset manually with `TRUNCATE`. For accurate dormancy tracking,
  enable the Enterprise Audit plugin or parse the general log.
* **Encryption at rest is not visible from inside MySQL.** `sec_07`
  covers InnoDB tablespace-level encryption (the `ENCRYPTION` column in
  `INNODB_TABLESPACES`) and transit SSL settings. Verify filesystem or
  cloud-layer encryption (AWS KMS, LUKS, EBS) separately.
* **PII discovery in `sec_09` and `sec_16` is heuristic** and based on
  column names only. The scripts do not read row content, do not evaluate
  encryption or masking at the data level, and do not detect PII inside
  JSON columns or opaque blob fields. Expect false positives and false
  negatives. Use as one input into a broader data classification process —
  not as primary compliance evidence.
* **Credential masking in `sec_15`.** The `mysql.servers` table stores
  `Host`, `Db`, `Username`, and `Password` for FEDERATED connections. The
  default output redacts the `Password` column. Review the raw value only
  in a controlled session when authorized.
* **`performance_schema` must be enabled.** Some instances are started
  with `performance_schema=OFF` for marginal memory savings. Verify with:
  `SHOW VARIABLES LIKE 'performance_schema';` — scripts that query
  `performance_schema` tables return empty results when it is disabled.
* **Role queries require MySQL 8.0.** Scripts `sec_01`, `sec_02`,
  `sec_03`, `sec_11` query `mysql.role_edges` and `mysql.default_roles`
  which do not exist in MySQL 5.7. Running on 5.7 will produce table-not-
  found errors in those sections.
