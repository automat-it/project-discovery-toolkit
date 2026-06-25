# Restore-drill toolkit

Read-only-on-source **backup restore drills** for **PostgreSQL**, **MySQL** and
**Microsoft SQL Server**, built in the same spirit as `db-audit-scripts/`: a
runner per engine that produces a timestamped `reports/<engine>_restore_<TS>/`
folder, and an analyzer that turns that folder into a branded HTML/PDF report
(same cover, watermark, executive at-a-glance, severity colours and charts as
the perf/sec audits).

A restore drill answers the only question that matters about a backup: **can we
actually restore it, and is the restored copy faithful to the source?** It
takes a backup, restores it into a throw-away *scratch* database on the same
instance, verifies the copy against the source, and measures the recovery
objectives (RTO / RPO).

No separate server is needed - the restore goes into a *scratch database on the
same instance*, which is dropped on exit.

## Modes: full restore vs verify-only

- **Full restore (default)** - the gold standard. Restores into a scratch
  database and verifies the data against the source (object/row/checksum parity,
  integrity). Proves the backup yields a working, faithful database.
- **Verify-only** (`-V` / `-VerifyOnly`) - validates the backup **without
  restoring** (no scratch database), so it is fast and zero-footprint, but only
  proves the backup is complete/readable, **not** that the data restores
  faithfully. Per engine: SQL Server `RESTORE VERIFYONLY ... WITH CHECKSUM`
  (backups are taken `WITH CHECKSUM`); PostgreSQL `pg_restore -l` + a full
  archive decode (`pg_restore -f /dev/null`); MySQL confirms the `-- Dump
  completed` marker (mysqldump has no verify - weakest assurance). Verify-only
  runs only `rd_01` (backup), `rd_02_backup_verify` and `rd_08` (RPO).

Run verify-only frequently/cheaply; run a full restore drill periodically.

## Safety

- **Source is never modified.** PostgreSQL/MySQL use logical dumps
  (`pg_dump` / `mysqldump --single-transaction`); SQL Server uses a
  `COPY_ONLY` backup, which does not disrupt the real backup chain.
- **The scratch database is created fresh and dropped on exit** (unless
  `-k` / `-Keep`). The runner refuses to use a scratch name equal to the
  source, and only drops a database it created.
- Safe to run against production. The scratch restore competes for CPU/IO/disk,
  so prefer a dedicated recovery instance for very large databases.

## The checks (shared IDs across engines)

| ID | Tier | Verifies |
|----|------|----------|
| `rd_01_backup_create`   | critical | A backup of the source can be produced (size + duration captured) |
| `rd_02_restore_execute` | critical | The backup restores into the scratch database without error (this is the RTO timer) |
| `rd_03_restore_online`  | critical | The restored database comes online and is queryable |
| `rd_04_object_parity`   | high     | Schema-object counts match the source. PG also checks views, materialized views (incl. populated state), sequences (incl. `last_value`), FK/CHECK constraints, triggers, types/domains, policies and extensions; MySQL adds triggers + events |
| `rd_05_rowcount_parity` | high     | Per-table (and populated-matview) row counts match the source |
| `rd_06_integrity_check` | high     | Engine-native deep check passes (PG: invalid indexes / unvalidated constraints; MySQL: `CHECK TABLE ... EXTENDED`; SQL Server: `DBCC CHECKDB`) |
| `rd_07_rto`             | medium   | Restore time is within the RTO target |
| `rd_08_rpo_backup_age`  | medium   | The backup is fresher than the RPO target |
| `rd_09_data_checksum`   | low      | Per-table row-content checksums match the source (PG: hashed-row sum; MySQL: `CHECKSUM TABLE`; SQL Server: `CHECKSUM_AGG(BINARY_CHECKSUM(*))`) |

A comparison check that cannot read the source (query error, empty result)
reports **FAIL**, never a green "0 differences" - a failed verification is never
mistaken for a clean restore.

Each check writes one `<tier>_<id>.log` with a structured header
(`Status: PASS|WARN|FAIL`, `Metric:`, `Threshold:`, `Detail:`) plus the raw
command output. A `_summary.txt` footer records the overall **verdict**
(`PASS` if all checks pass, `WARN` if only objectives are missed, `FAIL` if any
check fails) and the headline RTO / RPO / size numbers.

## Run commands

### PostgreSQL
```bash
cd restore_drill/postgres
export PGPASSWORD='<password>'
bash run_restore_drill.sh -h <host> -P 5432 -U <user> -d <source_db> -o ./reports
python3 analyze_report.py ./reports/postgres_restore_<TS> --server "<label>" --customer "<name>"
```

### MySQL
```bash
cd restore_drill/mysql
export MYSQL_PWD='<password>'
bash run_restore_drill.sh -h <host> -P 3306 -u <user> -d <source_db> -o ./reports
python3 analyze_report.py ./reports/mysql_restore_<TS> --server "<label>" --customer "<name>"
```

### SQL Server
```powershell
cd restore_drill/mssql
pwsh run_restore_drill.ps1 -Server "<host>,1433" -User <user> -Password '<pw>' -Database <source_db> -OutRoot ./reports
pwsh analyze_report.ps1 -ReportDir ./reports/mssql_restore_<TS> -ServerName "<label>" -Customer "<name>"
# add -NoPdf to emit HTML only (e.g. on a host with no browser)
```

**Amazon RDS for SQL Server** cannot `BACKUP`/`RESTORE` to local disk. Pass
`-S3BackupArn` to switch the drill to RDS-native S3 backup/restore
(`msdb.dbo.rds_backup_database` / `rds_restore_database`, polled via
`rds_task_status`). This needs the `SQLSERVER_BACKUP_RESTORE` option group and
an IAM role with access to the bucket (see `terraform/rds-audit-sandbox/`):
```powershell
pwsh run_restore_drill.ps1 -Server "<rds-endpoint>,1433" -User <user> -Password '<pw>' `
     -Database <source_db> -S3BackupArn "arn:aws:s3:::<bucket>/<db>.bak" -OutRoot ./reports
```

The Python analyzers emit HTML; render the PDF with headless Chrome (matching
the audit toolkit):
```bash
chrome --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=report.pdf file:///abs/path/postgres_restore_analysis.html
```

## Runner flags

Shared: `-o` report root, `-r`/`-RtoSeconds` RTO target (default 900s),
`-R`/`-RpoHours` RPO target (default 24h), `-t`/`-Scratch` scratch name
(default `<src>_drill_<TS>`), `-k`/`-Keep` keep the scratch database + backup,
`-s`/`-Strict` exit non-zero on WARN as well as FAIL (for CI gates - by
default only FAIL is non-zero so a missed RTO/RPO objective still "passes" the
gate), `-V`/`-VerifyOnly` validate the backup without restoring (no scratch DB -
see Modes above). PostgreSQL also takes `-F c|p` (custom dump + `pg_restore`, or
plain SQL).
SQL Server takes `-S3BackupArn` (RDS S3-native mode) and `-BackupDir`/`-DataDir`
(server-side paths; default to the Linux `/var/opt/mssql/data` - override on
Windows hosts).

Exit codes: `0` = PASS (or WARN without `-s`), `1` = FAIL (or WARN with `-s`),
`2` = bad arguments / missing client.

## Report naming

Engine-prefixed, like the rest of the toolkit:
`postgres_restore_analysis.*`, `mysql_restore_analysis.*`,
`mssql_restore_analysis.*`.

## Notes

- **RPO / backup age** is most meaningful when pointed at a pre-existing
  backup; for an on-demand drill the backup is fresh (age ~0).
- **RTO** measured here is the scratch-restore time on the drill host; size it
  against your production hardware and database size.
- The drills are logical/full-restore drills. They prove restorability and data
  fidelity; they are not a substitute for point-in-time-recovery (PITR) tests of
  your WAL / binlog / log-backup chain.
