# Security audit scripts

Read-only diagnostic queries for PostgreSQL security analysis.
Each script is independent and can be run standalone with `psql -f`.

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
  `sec_01`, `sec_05`. Both are guarded — they fall back to a `skipped`
  note when the current role cannot read `pg_authid`.
* Reading `pg_hba_file_rules` and `pg_ident_file_mappings` requires
  superuser. Affected scripts: `sec_05`, `sec_07`, `sec_08`. The
  `pg_hba` blocks in `sec_05` are guarded; the others will return
  empty results for non-privileged roles.
* On AWS RDS use the `rds_superuser` role for elevated blocks.

## Recommended execution order

Run priorities top-to-bottom — `critical` first covers the highest-risk
access and compromise paths.

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
wrappers and user mappings — privilege escalation paths.

## Medium priority

### `sec_11_role_inheritance_chains.sql`

Direct role membership, full transitive recursive chain, users with
most effective roles, NOINHERIT roles, and cyclic membership detection.

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

Foreign data wrappers, foreign servers, user mappings, foreign tables,
dblink, logical replication subscriptions and publications. Connection
strings and user mapping options are **masked by default** — pass
`-v unmask_secrets=true` to `psql` to see unmasked values when
authorized.

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
