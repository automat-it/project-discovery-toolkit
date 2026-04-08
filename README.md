# DBA Scripts Repository

This repository contains database administration (DBA) scripts and utilities used for operational support, diagnostics, automation, and migration readiness assessments.

The repository is created and maintained by **Automat-IT** and supports internal delivery and database engineering activities across customer environments.

---

## Repository structure

### dms/
Scripts related to AWS Database Migration Service (DMS) readiness and compatibility checks.

#### dms/postgres/
- `dms_postgres_compatibility_report.sql`  
  PostgreSQL DMS readiness assessment script generating aggregated summary and detailed CSV report.

#### dms/mysql/
- `generate_dms_report.sh`  
  Shell wrapper executing MySQL compatibility checks and producing timestamped CSV report.

---

### postgres/
General PostgreSQL DBA scripts (maintenance, diagnostics, performance, operations).

### mysql/
General MySQL / Aurora MySQL DBA scripts (maintenance, diagnostics, performance, operations).

---

## Purpose

This repository provides reusable scripts for:

- Migration readiness assessments
- Schema and metadata analysis
- Performance diagnostics
- Operational automation
- Health checks and troubleshooting
- Reporting and data analysis

---

## Usage

Each script is self-contained and intended to be executed in read-only mode unless explicitly stated otherwise.

Refer to individual folder README files for:
- Prerequisites
- Required permissions
- Execution instructions
- Output description

---

## Security and safety

- Scripts avoid destructive operations unless clearly documented
- Credentials should not be stored in scripts
- Use environment variables, `.my.cnf`, or secret managers for authentication

---

## Contribution guidelines

When adding new scripts:
- Use clear naming conventions
- Include header documentation
- Provide folder-level README updates
- Avoid destructive operations unless explicitly required
- Include example execution instructions

---

## Maintained by

Automat-IT DBA Team
