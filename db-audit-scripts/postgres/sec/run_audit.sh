#!/usr/bin/env bash
# =============================================================================
# Run every PostgreSQL security audit script in priority order and collect
# the output into a timestamped report folder. One SQL script -> one log file.
# Read-only: the audit scripts themselves perform SELECT-only queries.
# =============================================================================
set -u

usage() {
    cat <<EOF
Usage: $0 [-h HOST] [-P PORT] [-U USER] [-d DATABASE] [-o OUT_ROOT]
  -h  PostgreSQL host (default: localhost)
  -P  PostgreSQL port (default: 5432)
  -U  PostgreSQL user (default: postgres)
  -d  Target database (default: postgres)
  -o  Report root directory (default: ./reports)
Environment:
  PGPASSWORD  Password for PostgreSQL connection (recommended)
EOF
    exit 1
}

DB_HOST="localhost"
DB_PORT="5432"
DB_USER="postgres"
DB_NAME="postgres"
OUT_ROOT="./reports"

while getopts "h:P:U:d:o:?" opt; do
    case "$opt" in
        h) DB_HOST=$OPTARG ;;
        P) DB_PORT=$OPTARG ;;
        U) DB_USER=$OPTARG ;;
        d) DB_NAME=$OPTARG ;;
        o) OUT_ROOT=$OPTARG ;;
        *) usage ;;
    esac
done

command -v psql >/dev/null 2>&1 || { echo "[ERROR] psql not found on PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS=$(date +%Y%m%d_%H%M%S)
OUT="$OUT_ROOT/postgres_sec_$TS"
mkdir -p "$OUT"

echo "================================================================================"
echo "PostgreSQL security audit"
echo "  host=$DB_HOST port=$DB_PORT user=$DB_USER db=$DB_NAME"
echo "  output=$OUT"
echo "================================================================================"

pass=0; fail=0
SUMMARY="$OUT/_summary.txt"
: > "$SUMMARY"

for priority in critical high medium low; do
    [ -d "$SCRIPT_DIR/$priority" ] || continue
    for f in "$SCRIPT_DIR/$priority"/*.sql; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .sql)
        log="$OUT/${priority}_${base}.log"
        if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
                -v ON_ERROR_STOP=1 -X -q -f "$f" > "$log" 2>&1; then
            pass=$((pass+1))
            printf "[OK  ] %-8s %s\n" "$priority" "$base.sql"
            printf "OK  %s/%s\n" "$priority" "$base.sql" >> "$SUMMARY"
        else
            fail=$((fail+1))
            printf "[FAIL] %-8s %s  -> %s\n" "$priority" "$base.sql" "$log"
            printf "FAIL %s/%s\n" "$priority" "$base.sql" >> "$SUMMARY"
        fi
    done
done

{
    echo "--------------------------------------------------------------------------------"
    echo "Engine:    postgres"
    echo "Category:  sec"
    echo "Timestamp: $TS"
    echo "Target:    $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
    echo "Pass:      $pass"
    echo "Fail:      $fail"
} | tee -a "$SUMMARY"

echo "Report directory: $OUT"
[ "$fail" -eq 0 ]
