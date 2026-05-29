# Security audit scripts

Read-only diagnostic queries for PostgreSQL security analysis.
Each script is independent and can be run standalone with `psql -f`.

## Batch runner (`run_audit.sh`)

`run_audit.sh` executes every script in this folder in priority order
(`critical` → `high` → `medium` → `low`) and writes one log file per
script into a timestamped report folder.

```bash
# password comes from the PGPASSWORD env var (kept out of `ps`)
PGPASSWORD=secret ./run_audit.sh -h db.internal -P 5432 -U auditor -d prod
```

Flags: `-h HOST` `-P PORT` `-U USER` `-d DATABASE` `-o OUT_ROOT`
(default `./reports`). Failure detection uses `psql -v ON_ERROR_STOP=1`,
so any script that errors mid-run is marked FAIL in the summary.

Output layout:

```
reports/postgres_sec_YYYYMMDD_HHMMSS/
  _summary.txt                          # OK/FAIL per script + totals
  critical_sec_01_users_and_roles_inventory.log
  critical_sec_02_effective_privileges.log
  ...
  low_sec_18_audit_gaps.log
```

## Report analyzer (`analyze_report.py`)

After a run completes, parse the report folder into a customer-friendly
HTML report:

```bash
# Single-database run output (the folder run_audit.sh wrote into)
./analyze_report.py reports/postgres_sec_YYYYMMDD_HHMMSS

# Multi-database run (parent folder containing per-DB sub-folders)
./analyze_report.py /path/to/parent_report_dir --server prod-postgres-01

# Render to PDF (optional -- HTML is always produced)
google-chrome --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf=postgres_sec_analysis.pdf \
    "file://$(pwd)/reports/postgres_sec_YYYYMMDD_HHMMSS/postgres_sec_analysis.html"
```

Standard Python library only -- no `pip install` step.

### What the HTML report contains

* **Branded cover page** -- Automat-IT background (`ait_bg_cover.png`),
  report title, server label, optional customer subtitle, generation
  timestamp. Same `ait_bg_page.png` watermark appears on every inner
  page when rendered as PDF.

* **Environment Fingerprint card** -- host, database, PostgreSQL
  version, Aurora / RDS flag, primary / replica role, uptime, SSL
  enabled, password_encryption, user databases. Populated from a
  single-row fingerprint header that `sec_21` emits as its first query.

* **Quick-nav strip** with anchor links: Environment, Executive
  Summary, Findings. Hidden in print.

* **1. Executive Summary**
  - Five large KPI cards: Databases analyzed, Critical, Warning, Info,
    Failed scripts.
  - Severity-mix **donut chart** with legend (Critical / Warning / Info).
  - **Findings by Domain** horizontal bar chart -- groups security
    findings by area (Identity & access, Authentication, Encryption,
    Audit & logging, Sensitive data (PII), Dangerous objects, ...).
  - **Top issues -- what to fix**: the highest-priority findings as an
    ordered list with severity badge + action line + anchor link to
    the detailed finding card. Capped at 10.
  - **Context rollup** table (only when more than one database was
    audited).

* **2. Findings** -- one card per finding (not a giant 4-column table).
  Each card carries severity colour bar, boxed "Action:"
  recommendation, curated **concrete-objects** sub-tables, a
  **"How to fix -- starter commands"** code block with copy-pastable
  SQL / `aws rds` snippets, and a **"Further reading"** list of links
  to postgresql.org and AWS docs pages for that specific control. Top
  10 rows per group with `... +N more rows -- consult the raw .log
  file` overflow note. Concrete objects shown:

  | Finding                                | Concrete objects shown                |
  |----------------------------------------|---------------------------------------|
  | `sec_03` Privileged accounts           | rolname + attributes (sample)         |
  | `sec_04` Public / excessive grants     | sub-tables per grantee scope          |
  | `sec_09` PII columns                   | schema.table.column + reason          |
  | `sec_10` Dangerous objects             | SECURITY DEFINER funcs, untrusted langs, event triggers, etc. -- one sub-table per type |
  | `sec_12` Dormant users                 | rolname + last activity proxy         |
  | `sec_20` Failed-login activity         | login_name, client_addr, reason       |
  | `sec_22` Expiring credentials / certs  | rolname, expiry_state, days_until_expiry |


## Read-only guarantee

All scripts in this set are **read-only**: only `SELECT` and `SHOW`
statements. No `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, `DELETE`,
`TRUNCATE`, `GRANT`, or `REVOKE` is used anywhere. No temporary tables,
no functions, no objects of any kind are created.

## Target version

PostgreSQL 13+. Some queries reference catalogs added in newer
versions (`pg_hba_file_rules` in 10, `pg_ident_file_mappings` in 16).
Blocks that depend on elevated privileges or newer catalogs are guarded
by runtime checks and degrade to a `skipped` note instead of erroring
out.

## Required privileges

Most queries work for **any login role** with default privileges.
Specific elevated requirements:

* Reading `pg_authid` (password hashes) requires superuser /
  `rds_superuser` / `pg_read_server_files`. Affected scripts:
  `sec_01`, `sec_05`, `sec_12`, `sec_17`. All are guarded — they fall
  back to a `skipped` note when the current role cannot read
  `pg_authid`.
* Reading `pg_hba_file_rules` and `pg_ident_file_mappings` requires
  superuser / `pg_read_server_files`. Affected scripts: `sec_05`,
  `sec_07`, `sec_08`, `sec_17`. All are guarded and skip cleanly
  for non-privileged roles.
* On AWS RDS use the `rds_superuser` role for elevated blocks.

## Recommended execution order

Run priorities top-to-bottom — `critical` first covers the highest-risk
access and compromise paths.

## Aurora / RDS PostgreSQL caveats

The scripts run on Amazon Aurora PostgreSQL and RDS for PostgreSQL
clusters. Aurora is **auto-detected at runtime** via presence of the
`rdsadmin` role; standard PostgreSQL is unaffected.

* **`pg_user_mapping` is replaced by the `pg_user_mappings` view**
  (`sec_10`, `sec_15`). The catalog table requires server ownership /
  `pg_read_server_files` and is denied to `rds_superuser` on Aurora;
  the view is granted to PUBLIC everywhere and automatically masks
  `umoptions` to NULL where the caller lacks visibility.

* **`rds_superuser` unlocks pg_authid / pg_hba.** Every access to
  `pg_authid`, `pg_hba_file_rules`, and `pg_ident_file_mappings` is
  wrapped in `has_table_privilege(...)`. Without `rds_superuser` (or
  a managed role granting equivalent privileges) these blocks emit a
  `Skipped: ... not readable by <current_user>` row and the script
  continues. Scripts affected: `sec_01`, `sec_03`, `sec_05`,
  `sec_07`, `sec_08`, `sec_12`, `sec_17`, `sec_20`.

* **`sec_22` handles `'infinity'` rolvaliduntil.** Aurora's default
  managed accounts sometimes carry `rolvaliduntil = 'infinity'`, which
  fails the naive `EXTRACT(day FROM rolvaliduntil - now())::int` cast.
  The script treats infinity / -infinity as "no expiry" and emits NULL
  for `days_until_expiry`.

* **No blocked server-side APIs.** No `pg_read_file` / `pg_ls_*` /
  `pg_read_server_files` / `ALTER SYSTEM` anywhere -- nothing hits
  the Aurora blocklist.

* **`pg_stat_statements` must be enabled in the audited database.**
  `sec_20_failed_login_patterns.sql` references it. Run once per
  database: `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;`.

* **Run against the writer endpoint.** A few DMVs (e.g.
  `pg_stat_database` counters) are authoritative only on the primary.

* **Recommended auditor role:**
  ```sql
  CREATE ROLE auditor LOGIN PASSWORD '...';
  GRANT pg_monitor, pg_read_all_stats, pg_read_all_settings TO auditor;
  GRANT rds_superuser TO auditor;  -- for full sec_* coverage
  ```

## Critical priority

### `sec_01_users_and_roles_inventory.sql`

Complete inventory of all roles with attributes, login users, group
roles, predefined role membership — the foundation for all security
analysis.

### `sec_02_effective_privileges.sql`

Direct grants per role plus **effective per-table access by login user**
(via `has_table_privilege`, which respects full role-inheritance
expansion). This is the authoritative effective-access view, not just
explicit grants.

### `sec_03_admin_and_superusers.sql`

Direct and effective superusers (via recursive role membership),
`CREATEROLE` / `CREATEDB` / `REPLICATION` / `BYPASSRLS` roles —
highest compromise risk.

### `sec_04_public_and_excessive_grants.sql`

Privileges granted to `PUBLIC` at database, schema, table, function,
and sequence level — classic security holes.

### `sec_05_authentication_and_passwords.sql`

Password encryption method, accounts without passwords, MD5-hashed
accounts, expired credentials, and `pg_hba.conf` rules with risk
classification (privileged blocks are guarded and skip cleanly when
the current role lacks access).

## High priority

### `sec_06_audit_logging.sql`

Logging destinations, what is being logged (connections, statements,
locks, slow queries), pgaudit extension status — without traceability
there is no incident response.

### `sec_07_encryption_status.sql`

SSL/TLS configuration, per-session SSL state, plaintext non-localhost
connections, `pg_hba.conf` SSL enforcement. Covers **encryption in
transit only** — encryption at rest is not visible from inside
PostgreSQL.

### `sec_08_network_exposure.sql`

Listen addresses, `pg_hba.conf` rules with risk classification,
currently connected client networks, `pg_ident.conf` mappings — defines
attack surface.

### `sec_09_sensitive_data_discovery.sql`

Heuristic PII discovery by column name (national IDs, payment cards,
credentials, contact info, demographics, health), tables with RLS
enabled, RLS policies in detail. Column-name analysis only — see
limitations below.

### `sec_10_dangerous_objects.sql`

`SECURITY DEFINER` functions (especially superuser-owned), untrusted
procedural languages (plperlu, plpythonu, pltclu, c — `internal` is
tracked separately as informational), event triggers, foreign data
wrappers and **user mappings via `pg_user_mappings`** (the
unprivileged view, not the privileged `pg_user_mapping` catalog) —
privilege escalation paths.

### `sec_20_failed_login_patterns.sql`

Authentication-logging configuration, `pg_hba` auth methods, per-role
login limits, connected-client clustering by IP, and any
auth-tracking extensions (credcheck, passwordcheck). PostgreSQL does
not surface failed logins via SQL; the script reports what *is*
visible and calls out the gap if `log_connections` is off.

### `sec_21_patch_and_cve_level.sql`

Server version, major-branch EOL matrix (10 → 17 + upcoming),
installed extensions compared against `pg_available_extensions` for
outdated-version detection, procedural languages. Cross-reference
the banner with the PostgreSQL Security Information page. **First
query is a single-row "fingerprint header"** the report analyzer
reads to populate the Environment Fingerprint card (version,
current_database, host, Aurora flag, SSL, password_encryption).

### `sec_22_cert_and_key_expiry.sql`

Per-role `rolvaliduntil` with days-until-expiry bucketing (`EXPIRED`
/ 30d / 90d / ok / no expiry / **no expiry (infinity)**), TLS session
inventory via `pg_stat_ssl`, TLS protocol / cipher distribution,
foreign-server `srvoptions` containing `ssl*` / `cert*` / `key*`. TLS
file expiry (`ssl_cert_file`) is not visible via SQL — operator_action
calls for `openssl x509 -enddate`. Infinity-valued `rolvaliduntil`
(common on Aurora managed accounts) is detected and rendered as
"no expiry (infinity)" rather than failing the `::int` cast.

## Medium priority

### `sec_11_role_inheritance_chains.sql`

Direct role membership, full transitive recursive chain, users with
most effective roles, NOINHERIT roles, and cyclic membership
detection. The cycle-detection CTE carries an explicit `closed` flag
that flips when the walk reaches an already-visited role, and
surfaces only closed paths — an earlier version filtered visited
roles out before the membership edge was evaluated, making real
cycles invisible.

### `sec_12_dormant_users.sql`

Login users not currently connected, expired accounts, orphan roles
without grants or owned objects — inactive accounts that should be
reviewed. Approximate only — see limitations below.

### `sec_13_service_accounts.sql`

Technical accounts identified by naming heuristics and behavioral
indicators (high connection count, no expiration, generic
`application_name`).

### `sec_14_backup_security.sql`

Roles with `REPLICATION` or `pg_read_all_data` privilege, currently
running base backups and WAL senders, **separately** any active
`COPY ... TO` sessions (which are possible data export channels but
not necessarily backups), replication slots, archive settings, last
successful WAL archive.

### `sec_15_external_integrations.sql`

Foreign data wrappers, foreign servers, **user mappings via
`pg_user_mappings`** (the unprivileged view), foreign tables, dblink,
logical replication subscriptions and publications. Connection
strings and user mapping options are **masked by default** — pass
`-v unmask_secrets=true` to `psql` to see unmasked values when
authorized.

### `sec_23_data_retention_audit.sql`

Top 100 tables by total size with insert/update/delete counters, large
append-only tables (zero deletes, > 1 GB) flagged as retention
candidates, time-like column inventory for retention-key discovery,
presence of `pg_partman` / `timescaledb` / `pg_cron` / `pgagent`
extensions as retention-mechanism signals.

### `sec_19_schema_change_history.sql`

DDL / schema-change trail inventory: pgaudit / pgmemento presence,
`log_statement` setting, event triggers, recently modified objects
via `pg_stat_all_tables`, and the 50 most recently-allocated OIDs as
a fallback "newest objects" signal. Flags whether any persistent DDL
audit trail exists on the server.

## Low priority

### `sec_16_pii_naming_heuristics.sql`

Extended PII patterns including international identifiers, biometric,
auth tokens, crypto wallets, device tracking — broader naming
heuristics than `sec_09`. Same column-name limitations apply.

### `sec_17_deprecated_features.sql`

MD5 password hashes, `pg_hba` entries with deprecated auth methods,
untrusted procedural languages, TLS protocol versions, accounts
without expiration.

### `sec_18_audit_gaps.sql`

Logging completeness checklist, `log_line_prefix` coverage, pgaudit
class coverage, statistics tracking parameters — what is **not** being
logged.

## Notes and caveats

* **Encryption at rest is not visible from inside PostgreSQL.** Verify
  it at the storage / cloud layer (AWS KMS, LUKS, EBS encryption,
  etc.). Script `sec_07` covers only encryption in transit.
* **Dormant user detection in `sec_12` is approximate.** PostgreSQL
  does not track last successful login natively. The script uses
  current connection state, expiration, and object ownership as
  proxies. For accurate dormancy tracking, use pgaudit or log
  analysis.
* **PII discovery in `sec_09` and `sec_16` is heuristic** and based on
  column names only. The scripts do not read row content, do not
  evaluate encryption / masking / hashing at the data level, and do
  not detect PII in opaque columns (`data`, `value`, `payload`, JSONB
  blobs). Expect both false positives (e.g. `password_hint` matched
  as credential) and false negatives. Use as **one input** into a
  broader data classification process — not as primary compliance
  evidence.
* **pgaudit-specific queries** in `sec_06` and `sec_18` return empty
  results if the extension is not loaded via
  `shared_preload_libraries`.
* **Privileged blocks are guarded.** Scripts `sec_01` and `sec_05`
  contain `psql` meta-command guards (`\gset` + `\if`) that skip
  blocks reading `pg_authid` or `pg_hba_file_rules` when the current
  role lacks access. These guards work in `psql` but are ignored by
  other clients (DBeaver, pgAdmin); to run the scripts in those,
  manually skip the guarded blocks or run as a privileged role.
* **Credential masking in `sec_15`.** User mapping options
  (`umoptions`) and subscription connection strings (`subconninfo`)
  may contain plaintext passwords for foreign systems. The default
  output masks any option matching `password=`, `secret=`, `key=`,
  `token=`, and credentials embedded in URL form (`user:password@`).
  The unmasked variant is gated behind
  `psql -v unmask_secrets=true` and should be used only by an
  authorized security reviewer who will not export the result.
