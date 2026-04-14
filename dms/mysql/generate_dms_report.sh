#!/bin/bash

# ==============================================================================
# Safety: fail fast, surface errors in pipelines, catch unset variables
# ==============================================================================
set -euo pipefail
trap 'echo "[ERROR] $0: failed at line $LINENO" >&2' ERR

# ==============================================================================
# Default Variables & Usage Function
# ==============================================================================
DB_HOST="localhost"
DB_PORT="3306"
DB_NAME="information_schema"
DB_USER=""

usage() {
    echo "================================================================================"
    echo "Usage: $0 -u <user> [-h <host>] [-P <port>] [-d <database>]"
    echo "  -u  MySQL username (Required)"
    echo "  -h  MySQL host (Default: localhost)"
    echo "  -P  MySQL port (Default: 3306)"
    echo "  -d  Database to connect to (Default: information_schema)"
    echo "================================================================================"
    exit 1
}

# ==============================================================================
# Parse Command Line Arguments
# ==============================================================================
while getopts "u:h:P:d:" opt; do
    case ${opt} in
        u ) DB_USER=$OPTARG ;;
        h ) DB_HOST=$OPTARG ;;
        P ) DB_PORT=$OPTARG ;;
        d ) DB_NAME=$OPTARG ;;
        * ) usage ;;
    esac
done

if [ -z "$DB_USER" ]; then
    echo "Error: Database user (-u) is required."
    usage
fi

# Prompt securely for the password
read -sp "Enter MySQL Password for $DB_USER@$DB_HOST: " DB_PASS
echo -e "\n"

# Pass the password via MYSQL_PWD rather than the -p flag.
# The -p"$DB_PASS" form is visible in `ps`, /proc/<pid>/cmdline, and
# accounting logs on shared hosts; MYSQL_PWD is only exposed to the
# spawned mysql process and its children.
export MYSQL_PWD="$DB_PASS"

# Helper: run mysql with consistent flags. All subsequent calls MUST go
# through this function so we don't accidentally reintroduce -p on the
# command line.
run_mysql() {
    mysql --protocol=TCP \
          -u "$DB_USER" \
          -h "$DB_HOST" \
          -P "$DB_PORT" \
          "$DB_NAME" \
          -N -B \
          -e "$1"
}

# Verify credentials / connectivity up-front so we fail loudly instead of
# silently producing an empty CSV when the connection is wrong.
if ! run_mysql "SELECT 1" >/dev/null 2>&1; then
    echo "[ERROR] Could not connect to MySQL as '$DB_USER'@'$DB_HOST:$DB_PORT'." >&2
    echo "        Check host, port, user, password, and network reachability." >&2
    exit 2
fi

# Create the dynamic timestamped CSV filename (Timestamp at the end)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CSV_FILE="dms_mysql_report_${TIMESTAMP}.csv"

# ==============================================================================
# Shared SQL Logic (Common Table Expressions)
# ==============================================================================
BASE_CTE=$(cat << 'EOF'
WITH
pk_tables AS (
  SELECT
    tc.TABLE_SCHEMA AS table_schema,
    tc.TABLE_NAME   AS table_name,
    1               AS has_pk
  FROM information_schema.TABLE_CONSTRAINTS tc
  WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
    AND tc.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
col_base AS (
  SELECT
    c.TABLE_SCHEMA       AS table_schema,
    c.TABLE_NAME         AS table_name,
    c.COLUMN_NAME        AS column_name,
    LOWER(c.DATA_TYPE)   AS data_type,
    c.COLUMN_TYPE        AS column_type,
    c.IS_NULLABLE        AS is_nullable,
    c.COLUMN_DEFAULT     AS column_default,
    c.EXTRA              AS extra,
    c.CHARACTER_SET_NAME AS character_set_name,
    c.COLLATION_NAME     AS collation_name,
    c.NUMERIC_PRECISION  AS numeric_precision,
    c.NUMERIC_SCALE      AS numeric_scale
  FROM information_schema.COLUMNS c
  WHERE c.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
report AS (
  SELECT
    NOW() AS run_ts,
    cb.table_schema,
    cb.table_name,
    cb.column_name,
    cb.data_type,
    cb.column_type,
    cb.is_nullable,
    cb.column_default,
    cb.extra,
    COALESCE(pt.has_pk, 0) AS has_pk,
    cb.numeric_precision,
    cb.numeric_scale,
    cb.character_set_name,
    cb.collation_name,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'RISK'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'RISK'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'REVIEW'
      WHEN cb.data_type = 'json' THEN 'REVIEW'
      WHEN cb.data_type IN ('enum','set') THEN 'REVIEW'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'RISK'
      WHEN cb.data_type IN (
        'tinyint','smallint','mediumint','int','integer','bigint',
        'float','double','real','bit','boolean','bool',
        'date','datetime','timestamp','time','year',
        'char','varchar','binary','varbinary'
      ) THEN 'OK'
      ELSE 'UNKNOWN'
    END AS status,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'Table without primary key'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'Generated column'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'Spatial type'
      WHEN cb.data_type = 'json' THEN 'JSON type'
      WHEN cb.data_type IN ('enum','set') THEN 'ENUM/SET type'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'LOB-like type'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'Unbounded DECIMAL/NUMERIC'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'DECIMAL/NUMERIC precision >= 39'
      ELSE 'General'
    END AS reason
  FROM col_base cb
  LEFT JOIN pk_tables pt
    ON pt.table_schema = cb.table_schema AND pt.table_name = cb.table_name
)
EOF
)

# ==============================================================================
# 1. Output the Summary to the Console
# ==============================================================================
echo "================================================================================"
echo "Generating DMS compatibility report..."
echo "================================================================================"
echo ""
echo "Summary by Status:"
echo "------------------------------------------------------------"
echo " status  | column_count | percentage"
echo "---------+--------------+-----------"

SUMMARY_QUERY="${BASE_CTE}
SELECT
  status,
  COUNT(*) AS column_count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM report
GROUP BY status
ORDER BY CASE status WHEN 'RISK' THEN 1 WHEN 'UNKNOWN' THEN 2 WHEN 'REVIEW' THEN 3 ELSE 4 END;"

# Execute query and format output.
# Note: the `while read` loop runs in a subshell under pipe; with
# `set -o pipefail` a failure of `run_mysql` will propagate.
run_mysql "$SUMMARY_QUERY" | while IFS=$'\t' read -r status count pct; do
    printf " %-7s | %12s | %10s\n" "$status" "$count" "$pct"
done

# Calculate total rows dynamically
ROW_COUNT=$(run_mysql "${BASE_CTE} SELECT COUNT(DISTINCT status) FROM report;")
echo "($ROW_COUNT rows)"
echo ""

# ==============================================================================
# 2. Generate the Detailed CSV Output
# ==============================================================================
CSV_QUERY="${BASE_CTE},
ordered_report AS (
  SELECT *
  FROM report
  ORDER BY
    CASE status WHEN 'RISK' THEN 1 WHEN 'UNKNOWN' THEN 2 WHEN 'REVIEW' THEN 3 ELSE 4 END,
    table_schema, table_name, column_name
)
SELECT CONCAT_WS(',',
  '\"run_ts\"','\"table_schema\"','\"table_name\"','\"column_name\"','\"data_type\"','\"column_type\"',
  '\"is_nullable\"','\"column_default\"','\"extra\"','\"has_pk\"','\"numeric_precision\"','\"numeric_scale\"',
  '\"character_set_name\"','\"collation_name\"','\"status\"','\"reason\"'
)
UNION ALL
SELECT CONCAT_WS(',',
  CONCAT('\"', REPLACE(IFNULL(CAST(run_ts AS CHAR), ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(table_schema, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(table_name, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(column_name, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(data_type, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(column_type, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(is_nullable, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(CAST(column_default AS CHAR), ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(extra, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(CAST(has_pk AS CHAR), ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(CAST(numeric_precision AS CHAR), ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(CAST(numeric_scale AS CHAR), ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(character_set_name, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(collation_name, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(status, ''), '\"', '\"\"'), '\"'),
  CONCAT('\"', REPLACE(IFNULL(reason, ''), '\"', '\"\"'), '\"')
)
FROM ordered_report;"

# Save the CSV to file. Write to a temp file first and rename on success
# so a failing query doesn't leave behind a truncated/empty report.
CSV_TMP="${CSV_FILE}.partial"
if ! run_mysql "$CSV_QUERY" > "$CSV_TMP"; then
    rm -f "$CSV_TMP"
    echo "[ERROR] CSV query failed; no report written." >&2
    exit 3
fi
mv "$CSV_TMP" "$CSV_FILE"

echo "================================================================================"
echo "Detailed CSV report generated locally as: $CSV_FILE"
echo "================================================================================"