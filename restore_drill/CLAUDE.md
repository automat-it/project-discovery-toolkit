# Restore-drill toolkit - project guide

Backup **restore drills** for **PostgreSQL**, **MySQL** and **Microsoft SQL
Server**, built in the spirit of `../db-audit-scripts/`: a per-engine runner
that performs the drill and writes one `.log` per check into a timestamped
`reports/<engine>_restore_<TS>/` folder, plus an analyzer that turns that folder
into a branded HTML/PDF report (reusing the audit toolkit's `_analyze_lib`
cover, watermark, CSS and charts).

A drill takes a backup, restores it into a throw-away **scratch** database on
the same instance, verifies the restored copy against the source, and measures
the recovery objectives (RTO = restore time, RPO = backup age).

## Layout

```
restore_drill/
├── _restore_common.py            shared analyzer core for PostgreSQL + MySQL
├── postgres/  run_restore_drill.sh   analyze_report.py
├── mysql/     run_restore_drill.sh   analyze_report.py
└── mssql/     run_restore_drill.ps1  analyze_report.ps1
```

- PostgreSQL/MySQL: bash runner + thin Python analyzer wrapper over
  `_restore_common.py`, which imports the rendering primitives from
  `../db-audit-scripts/postgres/_analyze_lib.py` (so the report looks identical
  to the perf/sec reports). Analyzers emit HTML; render PDF via headless Chrome.
- MSSQL: PowerShell runner + analyzer. The analyzer dot-sources
  `../db-audit-scripts/mssql/_analyze_lib.ps1` for `Esc` / `Convert-HtmlToPdf`
  and renders PDF itself (`-NoPdf` for HTML only).

## Run commands

See `README.md` for the full per-engine commands. Quick form:

```bash
# PostgreSQL / MySQL
PGPASSWORD=… bash postgres/run_restore_drill.sh -h H -P 5432 -U U -d DB -o ./reports
python3 postgres/analyze_report.py ./reports/postgres_restore_<TS> --server "<label>"
```
```powershell
# SQL Server (self-managed: native BACKUP/RESTORE to disk)
pwsh mssql/run_restore_drill.ps1 -Server "H,1433" -User U -Password P -Database DB
# Amazon RDS for SQL Server (no BACKUP-to-disk): RDS-native S3 path
pwsh mssql/run_restore_drill.ps1 -Server "rds-ep,1433" -User U -Password P -Database DB `
     -S3BackupArn "arn:aws:s3:::<bucket>/<db>.bak"
```

## The check model

Nine checks with **shared IDs across engines** (`rd_01` means the same control
everywhere), in tiers critical → high → medium → low:

`rd_01` backup, `rd_02` restore (RTO timer), `rd_03` online, `rd_04` object
parity, `rd_05` row-count parity, `rd_06` integrity (PG invalid-index/constraint,
MySQL `CHECK TABLE`, MSSQL `DBCC CHECKDB`), `rd_07` RTO target, `rd_08` RPO /
backup age, `rd_09` content-checksum parity.

**Two modes.** Default = full restore (above). Verify-only (`-V`/`-VerifyOnly`)
validates the backup WITHOUT a scratch DB and runs only `rd_01`,
`rd_02_backup_verify` (PG `pg_restore` decode / MySQL dump-complete marker /
MSSQL `RESTORE VERIFYONLY WITH CHECKSUM`; RDS S3 has no VERIFYONLY so it confirms
the `rds_backup_database` task) and `rd_08`. `rd_03-rd_07`+`rd_09` need a restored
copy and are wrapped in a mode guard. Verify-only proves the backup is
readable, not that data restores faithfully - document that trade-off.

### Log + summary format (the runner↔analyzer contract - keep byte-compatible)

Each check writes `<tier>_<id>.log` with this exact header, then the raw output:
```
=== RESTORE DRILL CHECK ========================================================
Check:      rd_02_restore_execute
Tier:       critical
Title:      …
Status:     PASS|WARN|FAIL
Metric:     key=value;key=value   (or -)
Threshold:  …                     (or -)
Detail:     …
--- output ---------------------------------------------------------------------
<raw command output>
```
`_summary.txt` ends with a labelled footer the analyzers parse:
`Engine / Category / Timestamp / Source / Target / Backup / RTO / RPO / Rows /
Verdict / Pass / Warn / Fail`. **Verdict** = `PASS` (all pass), `WARN` (only
objectives missed), `FAIL` (any check fails). All three runners must emit the
same field names; both analyzers parse them identically.

## Conventions

- **Source is read-only / non-destructive.** PG/MySQL = logical dump
  (`pg_dump` / `mysqldump --single-transaction`); MSSQL = `BACKUP … COPY_ONLY`
  (or RDS `rds_backup_database` to S3). Never run write DDL/DML on the source.
- **Scratch DB**: created fresh, name defaults to `<src>_drill_<TS>_<pid>`,
  dropped on exit (EXIT + INT/TERM traps). Only ever drop a DB the run created
  (`SCRATCH_CREATED`/`$scratchCreated`); refuse scratch == source.
- **Report naming** carries the engine: `postgres_restore_analysis.*`,
  `mysql_restore_analysis.*`, `mssql_restore_analysis.*`.
- **Reuse** the existing `_analyze_lib` primitives; do not fork the CSS/branding.

## Invariants - do not regress these (each cost a real bug)

- **No false PASS on a broken restore.** PG `pg_restore` MUST use
  `--exit-on-error` (it exits 0 on partial failure otherwise) and plain-SQL
  restore runs under `ON_ERROR_STOP=1`; MySQL restore greps the client log for
  `^ERROR [0-9]+` as a backstop (the client doesn't reliably abort). Gate
  `rd_07` on restore success, not just on a non-empty RTO value.
- **No false PASS on a failed verification query.** Every diff-based check
  (`rd_04/05/09`) FAILs when the source side is empty/errored - an
  empty-vs-empty diff must not read as "identical".
- **MSSQL `rds_task_status` polling MUST use `-Raw`** (`-h -1 -W -s '|'`).
  Without it sqlcmd emits space-aligned output, the `|`-field match never hits,
  and every RDS task hangs to timeout. Match the lifecycle by exact pipe-field
  equality, never a substring grep of the whole row.
- **T-SQL interpolation is escaped**: `''` in `N'…'` literals, `]]` in `[…]`
  identifiers (`$DbLit/$ScrLit/$S3Lit` vs `$DbId/$ScrId`).
- **PowerShell array safety**: wrap `Sql-Rows`/sorted results in `@(…)` so a
  1-row result isn't unrolled to a scalar (`.Count`/`[0]` then break).
- **Locale**: bash sets `LC_ALL=C`; the PS donut formats SVG coords with
  `InvariantCulture` - a comma decimal corrupts metrics / SVG paths.
- **Exit codes**: `0` = PASS (or WARN without strict), `1` = FAIL (or WARN with
  `-s`/`-Strict`), `2` = bad args / missing client. A swallowed mid-drill
  exception is recorded as a FAIL check, never silently dropped.

## Testing

Point each runner at a disposable source database whose schema exercises every
check - a view, a routine, FK/CHECK constraints, a sequence and (PG) a
materialized view. After any change, re-run all three engines end to end and
confirm 9/9 PASS and a cleanly rendered report; also test a deliberately failing
case (e.g. a non-existent source) to confirm the verdict is FAIL, not a false
PASS.

## House rules

- The repo is **public**: no real hostnames/IPs/credentials in tracked files.
  `../terraform/` (its state holds plaintext passwords) is gitignored, as are
  generated `reports/`, `*.html`, `*.pdf`. Only the `.sh/.py/.ps1` and
  the two `*.md` here are tracked.
- Commit only when explicitly asked.
