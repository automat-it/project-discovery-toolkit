# MySQL DMS Compatibility Report

This folder contains scripts used to assess MySQL database readiness for AWS Database Migration Service (DMS).

The main goal is to identify potential migration risks related to schema design, data types, and structural constraints before starting a DMS migration.

---

## Scripts

### generate_dms_report.sh

Shell wrapper that executes the MySQL DMS compatibility SQL script and generates a timestamped CSV report.

The script:
- Connects to a target MySQL database
- Runs the compatibility assessment SQL
- Produces a CSV report with detected risks and recommendations
- Prints the generated report path

---

## Report contents

The generated CSV includes:

- Schema name
- Table name
- Column name
- Data type and column definition
- Nullability and default values
- Primary key presence
- Numeric precision/scale
- Character set and collation
- Compatibility status:
  - OK
  - REVIEW
  - RISK
  - UNKNOWN
- Reason for classification

---

## Usage

Make the script executable:

```bash
chmod +x generate_dms_report.sh
