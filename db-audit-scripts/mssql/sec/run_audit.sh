#!/usr/bin/env bash
# =============================================================================
# Run every SQL Server security audit script in priority order and collect
# the output into a timestamped report folder. One SQL script -> one log file.
# Read-only: the audit scripts themselves perform SELECT-only queries.
# Requires sqlcmd (go-sqlcmd or MS sqlcmd).
# =============================================================================
set -u

usage() {
    cat <<EOF
Usage: $0 -U USER [-S SERVER] [-d DATABASE] [-o OUT_ROOT]
  -U  SQL Server login (required)
  -S  SQL Server host or host,port (default: localhost)
  -d  Default database (default: master)
  -o  Report root directory (default: ./reports)
Environment:
  SQLCMDPASSWORD  Password for the SQL Server login (recommended over -P)
EOF
    exit 1
}

DB_SERVER="localhost"
DB_NAME="master"
DB_USER=""
OUT_ROOT="./reports"

while getopts "U:S:d:o:?" opt; do
    case "$opt" in
        U) DB_USER=$OPTARG ;;
        S) DB_SERVER=$OPTARG ;;
        d) DB_NAME=$OPTARG ;;
        o) OUT_ROOT=$OPTARG ;;
        *) usage ;;
    esac
done

[ -z "$DB_USER" ] && { echo "[ERROR] -U USER is required" >&2; usage; }
command -v sqlcmd >/dev/null 2>&1 || { echo "[ERROR] sqlcmd not found on PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS=$(date +%Y%m%d_%H%M%S)
OUT="$OUT_ROOT/mssql_sec_$TS"
mkdir -p "$OUT"

echo "================================================================================"
echo "SQL Server security audit"
echo "  server=$DB_SERVER user=$DB_USER db=$DB_NAME"
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
        if sqlcmd -S "$DB_SERVER" -U "$DB_USER" -d "$DB_NAME" -C -b \
                  -i "$f" > "$log" 2>&1; then
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
    echo "Engine:    mssql"
    echo "Category:  sec"
    echo "Timestamp: $TS"
    echo "Target:    $DB_USER@$DB_SERVER/$DB_NAME"
    echo "Pass:      $pass"
    echo "Fail:      $fail"
} | tee -a "$SUMMARY"

echo "Report directory: $OUT"
[ "$fail" -eq 0 ]
