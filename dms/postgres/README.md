# PostgreSQL DMS Compatibility Report

This folder contains scripts used to assess PostgreSQL database readiness for AWS Database Migration Service (DMS).

The primary script analyzes database metadata and identifies potential migration risks related to data types, schema design, and structural characteristics.

---

## Script

### dms_postgres_compatibility_report.sql

Generates a PostgreSQL DMS compatibility assessment report.

The script:
- Scans all non-system schemas
- Evaluates table and column metadata
- Detects potential migration risks
- Classifies findings into:
  - OK
  - REVIEW
  - RISK
  - UNKNOWN
- Prints a summary to the console
- Exports a detailed CSV report with a timestamped filename

The script is read-only and does not modify any data.

---

## Report contents

The generated CSV includes:

- Execution timestamp
- Schema name
- Table name
- Column name
- Data type and formatted type
- Array / domain / enum / composite indicators
- Extension usage
- Primary key presence
- Numeric precision and scale
- Compatibility status
- Reason for classification

---

## Usage

Run using psql:

```bash
psql -d <database> -f dms_postgres_compatibility_report.sql
