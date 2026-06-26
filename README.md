# Project Discovery Toolkit

Database discovery, audit and recovery-assurance tooling for **PostgreSQL**,
**MySQL** and **Microsoft SQL Server**. Read-only and safe to run on production:
every toolkit turns script output into branded HTML/PDF reports.

Created and maintained by **Automat-IT** for database engineering and delivery.

## What's in here

| Folder | Purpose |
|--------|---------|
| [`db-audit-scripts/`](db-audit-scripts/README.md) | Read-only **performance + security audits** - ~24 perf and ~23 sec SQL checks per engine, organised into `critical`/`high`/`medium`/`low` tiers, with a runner per engine and an analyzer that produces a branded report. |
| [`restore_drill/`](restore_drill/README.md) | Backup **restore drills** - back up a database, restore it into a throw-away scratch database on the same instance, and verify the restored copy against the source (object/row/checksum parity, integrity). Also a lighter **verify-only** mode that validates a backup without restoring. |
| [`dms/`](dms/postgres/README.md) | **AWS DMS migration-readiness** reports - scan schema/column metadata and flag migration risks (data types, structural constraints) as OK / REVIEW / RISK before a DMS migration. |

## Common conventions

- **Read-only on the source.** The audit and DMS scripts run only `SELECT` /
  `SHOW` / read-only system procedures. The restore drills dump or
  `COPY_ONLY`-back up the source and restore into a disposable scratch database
  that is dropped on exit - the source is never modified.
- **Three engines, shared structure.** PostgreSQL/MySQL use a bash runner +
  Python analyzer; SQL Server uses PowerShell. Reports carry the engine name and
  share the Automat-IT cover + watermark branding.
- **Public repo, no secrets.** No real hostnames, IPs or credentials in tracked
  files - generated `reports/`, local `docker/` sandboxes and `terraform/` state
  are gitignored. Use placeholders (`<host>`, `<password>`).

See each folder's `README.md` for run commands and details.

## Maintained by

Automat-IT DBA Team
