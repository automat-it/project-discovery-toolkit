# DBA Scripts Repository

This repository contains database administration (DBA) related scripts and utilities designed to support day-to-day operational tasks, troubleshooting, automation, and database assessments.

This repository is created and maintained by **Automat-IT** and is used internally to support delivery, operational excellence, and database engineering activities across customer environments.

## Repository structure

- `dms/`  
  Scripts related to AWS Database Migration Service (DMS), including compatibility and readiness checks.
  - `dms/postgres/`
    - `dms_postgres_compatibility_report.sql` — Generates a DMS compatibility report for PostgreSQL schemas and exports a detailed CSV report. Includes a console summary by status (OK / REVIEW / RISK / UNKNOWN).

- `postgres/`  
  PostgreSQL DBA scripts (maintenance, diagnostics, performance, operations).

- `mysql/`  
  MySQL / Aurora MySQL DBA scripts (maintenance, diagnostics, performance, operations).

## Usage

Each script is intended to be executed in read-only mode unless explicitly stated otherwise.  
Refer to the header block in each script for prerequisites, required permissions, and execution examples.

## Disclaimer

These scripts are provided as-is and should be reviewed and tested in non-production environments before use in production systems.

## Contribution

Contributions and improvements are welcome. When adding new scripts, please ensure:
- Clear naming
- Readability
- Safety (avoid destructive operations unless clearly documented)
- Basic usage instructions in the script header

---

**Maintained by Automat-IT DBA team**

