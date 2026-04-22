#!/usr/bin/env bash
# =============================================================================
# Run the full SQL Server security audit against every user database on an
# instance. Thin wrapper around run_audit.sh — enumerates user databases
# (database_id > 4, ONLINE, not a standby replica, not `distribution`) and
# invokes the audit once per database into a per-database sub-folder.
#
# A single server-level pass against `master` is written to `<OUT>/_server/`
# first; then one pass per user DB lands in `<OUT>/<db_name>/`.
#
#   SQLCMDPASSWORD=secret ./run_all_databases.sh -U sa -S db.internal,1433
#
# -i / -x narrow the list:
#   -i 'prod_%'          include only databases matching the LIKE pattern
#   -x 'tempdb|reportdb' exclude databases matching the POSIX regex
#
# Requires sqlcmd (go-sqlcmd or MS sqlcmd). Read-only.
# =============================================================================
set -u

usage() {
    cat <<EOF
Usage: $0 -U USER [-S SERVER] [-o OUT_ROOT] [-i INCLUDE_LIKE] [-x EXCLUDE_REGEX]
  -U  SQL Server login (required)
  -S  SQL Server host or host,port (default: localhost)
  -o  Report root directory (default: ./reports)
  -i  T-SQL LIKE pattern for databases to INCLUDE (default: all user DBs)
  -x  POSIX ERE to EXCLUDE databases by name (applied after -i)
Environment:
  SQLCMDPASSWORD  Password for the SQL Server login
EOF
    exit 1
}

DB_SERVER="localhost"
DB_USER=""
OUT_ROOT="./reports"
INCLUDE_LIKE="%"
EXCLUDE_RE=""

while getopts "U:S:o:i:x:?" opt; do
    case "$opt" in
        U) DB_USER=$OPTARG ;;
        S) DB_SERVER=$OPTARG ;;
        o) OUT_ROOT=$OPTARG ;;
        i) INCLUDE_LIKE=$OPTARG ;;
        x) EXCLUDE_RE=$OPTARG ;;
        *) usage ;;
    esac
done

[ -z "$DB_USER" ] && { echo "[ERROR] -U USER is required" >&2; usage; }
command -v sqlcmd >/dev/null 2>&1 || { echo "[ERROR] sqlcmd not found on PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_audit.sh"
[ -x "$RUNNER" ] || { echo "[ERROR] $RUNNER missing or not executable" >&2; exit 2; }

TS=$(date +%Y%m%d_%H%M%S)
OUT="$OUT_ROOT/mssql_sec_all_$TS"
mkdir -p "$OUT"

# dm_hadr_database_replica_states has no role_desc; role lives on the replica,
# not on the per-database replica state. Join via dm_hadr_availability_replica_states
# for the LOCAL replica and keep DBs whose local replica is PRIMARY, or whose
# secondary replica allows read connections. Standalone instances hit neither
# join and fall through via the NULL branch.
DB_QUERY="
SET NOCOUNT ON;
SELECT d.name
FROM sys.databases d
LEFT JOIN sys.dm_hadr_database_replica_states drs
  ON drs.database_id = d.database_id AND drs.is_local = 1
LEFT JOIN sys.dm_hadr_availability_replica_states ars
  ON ars.replica_id = drs.replica_id
LEFT JOIN sys.availability_replicas ar
  ON ar.replica_id = drs.replica_id
WHERE d.database_id > 4
  AND d.name <> 'distribution'
  AND d.state_desc = 'ONLINE'
  AND d.name LIKE N'$INCLUDE_LIKE'
  AND (ars.role_desc IS NULL
       OR ars.role_desc = 'PRIMARY'
       OR ar.secondary_role_allow_connections_desc IN ('ALL','READ_ONLY'))
ORDER BY d.name;
"

ENUM_LOG=$(mktemp)
if ! sqlcmd -S "$DB_SERVER" -U "$DB_USER" -d master -C -b -h -1 -W \
            -Q "$DB_QUERY" > "$ENUM_LOG" 2>&1; then
    echo "[ERROR] database enumeration failed:" >&2
    cat "$ENUM_LOG" >&2
    rm -f "$ENUM_LOG"
    exit 4
fi
DBS=$(grep -Ev '^\s*$|rows affected' "$ENUM_LOG")
rm -f "$ENUM_LOG"

if [ -n "$EXCLUDE_RE" ]; then
    DBS=$(echo "$DBS" | grep -Ev "$EXCLUDE_RE" || true)
fi

if [ -z "$DBS" ]; then
    echo "[ERROR] no user databases matched (include='$INCLUDE_LIKE' exclude='$EXCLUDE_RE')" >&2
    exit 3
fi

db_count=$(echo "$DBS" | wc -l | tr -d ' ')
echo "================================================================================"
echo "SQL Server security audit — multi-database"
echo "  server=$DB_SERVER user=$DB_USER databases=$db_count"
echo "  output=$OUT"
echo "--------------------------------------------------------------------------------"
echo "$DBS" | sed 's/^/  - /'
echo "================================================================================"

overall_fail=0
SUMMARY="$OUT/_summary.txt"
: > "$SUMMARY"

echo ""
echo "[*] server-level pass (db=master) -> $OUT/_server"
if "$RUNNER" -U "$DB_USER" -S "$DB_SERVER" -d master -o "$OUT/_server" >/dev/null; then
    echo "  server-level: OK"
    echo "OK   _server" >> "$SUMMARY"
else
    echo "  server-level: FAIL (see $OUT/_server)"
    echo "FAIL _server" >> "$SUMMARY"
    overall_fail=$((overall_fail+1))
fi

while IFS= read -r db; do
    db_trim=$(echo "$db" | sed 's/^ *//; s/ *$//')
    [ -z "$db_trim" ] && continue
    echo ""
    echo "[*] db=$db_trim -> $OUT/$db_trim"
    if "$RUNNER" -U "$DB_USER" -S "$DB_SERVER" -d "$db_trim" -o "$OUT/$db_trim" >/dev/null; then
        echo "  $db_trim: OK"
        echo "OK   $db_trim" >> "$SUMMARY"
    else
        echo "  $db_trim: FAIL (see $OUT/$db_trim)"
        echo "FAIL $db_trim" >> "$SUMMARY"
        overall_fail=$((overall_fail+1))
    fi
done <<< "$DBS"

{
    echo "--------------------------------------------------------------------------------"
    echo "Engine:      mssql"
    echo "Category:    sec (all databases)"
    echo "Timestamp:   $TS"
    echo "Target:      $DB_USER@$DB_SERVER"
    echo "Databases:   $db_count"
    echo "Failed runs: $overall_fail"
} | tee -a "$SUMMARY"

echo "Report root: $OUT"
[ "$overall_fail" -eq 0 ]
