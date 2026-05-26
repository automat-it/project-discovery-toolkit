#!/usr/bin/env bash
# =============================================================================
# Run every MySQL security audit script in priority order and collect
# the output into a timestamped report folder. One SQL script -> one log file.
# Read-only: the audit scripts themselves perform SELECT-only queries.
# =============================================================================
set -u

usage() {
    cat <<EOF
Usage: $0 -u USER [-h HOST] [-P PORT] [-d DATABASE] [-o OUT_ROOT]
  -u  MySQL username (required)
  -h  MySQL host (default: 127.0.0.1)
  -P  MySQL port (default: 3306)
  -d  Default database (default: mysql)
  -o  Report root directory (default: ./reports)
Environment:
  MYSQL_PWD   Password for the MySQL connection (recommended over -p)
EOF
    exit 1
}

DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_NAME="mysql"
DB_USER=""
OUT_ROOT="./reports"

while getopts "u:h:P:d:o:?" opt; do
    case "$opt" in
        u) DB_USER=$OPTARG ;;
        h) DB_HOST=$OPTARG ;;
        P) DB_PORT=$OPTARG ;;
        d) DB_NAME=$OPTARG ;;
        o) OUT_ROOT=$OPTARG ;;
        *) usage ;;
    esac
done

[ -z "$DB_USER" ] && { echo "[ERROR] -u USER is required" >&2; usage; }
command -v mysql >/dev/null 2>&1 || { echo "[ERROR] mysql client not found on PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS=$(date +%Y%m%d_%H%M%S)
OUT="$OUT_ROOT/mysql_sec_$TS"
mkdir -p "$OUT"

# Authentication: build a temporary option file and pass it via
# --defaults-file (singular). MySQL client 9.x (Homebrew on macOS) silently
# ignores the MYSQL_PWD env var on some builds. --defaults-extra-file is
# also unreliable because mysql reads ~/.my.cnf AFTER it (last wins), so a
# stale ~/.my.cnf would override our credentials.
# --defaults-file=PATH replaces the entire option-file search with just
# that one file -- guaranteed isolation.
#
# IMPORTANT: in MySQL option-file syntax, `#` starts a comment to end of
# line. A bare `password=ABC#DEF` would be parsed as password=ABC. We
# wrap the password in double quotes and escape `\` and `"` so any
# character (including `#`, `:`, `$`, `;`, `>`, etc.) survives intact.
DEFAULTS_FILE=""
if [ -n "${MYSQL_PWD:-}" ]; then
    DEFAULTS_FILE=$(mktemp -t mysql_audit_defaults.XXXXXX)
    chmod 600 "$DEFAULTS_FILE"
    escaped_pwd=$(printf '%s' "$MYSQL_PWD" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    {
        printf '[client]\n'
        printf 'password="%s"\n' "$escaped_pwd"
    } > "$DEFAULTS_FILE"
    trap 'rm -f "$DEFAULTS_FILE"' EXIT
fi

echo "================================================================================"
echo "MySQL security audit"
echo "  host=$DB_HOST port=$DB_PORT user=$DB_USER db=$DB_NAME"
echo "  output=$OUT"
echo "================================================================================"

pass=0; fail=0
SUMMARY="$OUT/_summary.txt"
: > "$SUMMARY"

# mysql does not uniformly support --abort-source-on-error across builds.
# We detect statement-level errors by grepping the log for "^ERROR NNNN" after
# each run, which is how the mysql client prefixes server errors to stderr.
run_mysql() {
    if [ -n "$DEFAULTS_FILE" ]; then
        # --defaults-file MUST be the first option on the command line.
        mysql --defaults-file="$DEFAULTS_FILE" \
              --protocol=TCP -u "$DB_USER" -h "$DB_HOST" -P "$DB_PORT" \
              --default-character-set=utf8mb4 \
              "$DB_NAME" < "$1"
    else
        mysql --protocol=TCP -u "$DB_USER" -h "$DB_HOST" -P "$DB_PORT" \
              --default-character-set=utf8mb4 \
              "$DB_NAME" < "$1"
    fi
}

for priority in critical high medium low; do
    [ -d "$SCRIPT_DIR/$priority" ] || continue
    for f in "$SCRIPT_DIR/$priority"/*.sql; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .sql)
        log="$OUT/${priority}_${base}.log"
        rc=0
        run_mysql "$f" > "$log" 2>&1 || rc=$?
        if [ "$rc" -eq 0 ] && ! grep -qE '^ERROR [0-9]+' "$log"; then
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
    echo "Engine:    mysql"
    echo "Category:  sec"
    echo "Timestamp: $TS"
    echo "Target:    $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
    echo "Pass:      $pass"
    echo "Fail:      $fail"
} | tee -a "$SUMMARY"

echo "Report directory: $OUT"
[ "$fail" -eq 0 ]
