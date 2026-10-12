#!/usr/bin/env bash
# =============================================================================
# collect_index_usage.sh -- run perf_index_bloat_crossnode.sql on every node
# of a cluster and save one CSV capture per node.
#
# Nodes come either from positional host arguments (instance endpoints) or
# from an Aurora cluster identifier (-c), resolved through the AWS CLI.
# Captures accumulate in the output directory, so running this repeatedly
# (e.g. daily) builds a history that merge_index_usage.py can stitch across
# stats resets and failovers.
#
# Password: set PGPASSWORD (or use ~/.pgpass); it is never passed on argv.
# Sessions are forced read-only via PGOPTIONS.
# =============================================================================
set -u

usage() {
    cat <<EOF
Usage: $0 -U USER -d DATABASE [-P PORT] [-o OUT_DIR] [-c CLUSTER_ID [-r REGION]] [HOST ...]
  -U  database user
  -d  database name
  -P  port (default: 5432)
  -o  capture directory (default: ./index_usage_captures)
  -c  Aurora DB cluster identifier: capture every member instance
  -r  AWS region for -c (default: AWS CLI default)
  HOST  instance endpoints (writer and readers); combinable with -c
Environment:
  PGPASSWORD  password for the connection
EOF
    exit 1
}

DB_USER=""; DB_NAME=""; PORT=5432; OUT="./index_usage_captures"
CLUSTER=""; REGION=""
while getopts "U:d:P:o:c:r:h" opt; do
    case "$opt" in
        U) DB_USER="$OPTARG" ;;
        d) DB_NAME="$OPTARG" ;;
        P) PORT="$OPTARG" ;;
        o) OUT="$OPTARG" ;;
        c) CLUSTER="$OPTARG" ;;
        r) REGION="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ -z "$DB_USER" ] || [ -z "$DB_NAME" ] && usage

HOSTS="$*"

if [ -n "$CLUSTER" ]; then
    command -v aws >/dev/null 2>&1 || { echo "aws CLI not found (needed for -c)" >&2; exit 2; }
    REGION_ARGS=""
    [ -n "$REGION" ] && REGION_ARGS="--region $REGION"
    # shellcheck disable=SC2086
    MEMBERS=$(aws rds describe-db-clusters $REGION_ARGS \
        --db-cluster-identifier "$CLUSTER" \
        --query 'DBClusters[0].DBClusterMembers[].DBInstanceIdentifier' \
        --output text) || { echo "cannot describe cluster $CLUSTER" >&2; exit 2; }
    for m in $MEMBERS; do
        # shellcheck disable=SC2086
        EP=$(aws rds describe-db-instances $REGION_ARGS \
            --db-instance-identifier "$m" \
            --query 'DBInstances[0].Endpoint.Address' --output text) \
            || { echo "cannot resolve endpoint of $m" >&2; exit 2; }
        HOSTS="$HOSTS $EP"
    done
fi

[ -z "$HOSTS" ] && { echo "no hosts given (pass instance endpoints or -c CLUSTER_ID)" >&2; usage; }

SQL="$(cd "$(dirname "$0")" && pwd)/perf_index_bloat_crossnode.sql"
[ -f "$SQL" ] || { echo "missing $SQL" >&2; exit 2; }
mkdir -p "$OUT"

# Belt and braces: the script is read-only, but force it at session level too.
export PGOPTIONS="${PGOPTIONS:-} -c default_transaction_read_only=on -c statement_timeout=600000"

TS=$(date +%Y%m%d_%H%M%S)
ok=0; fail=0
for h in $HOSTS; do
    case "$h" in
        *.cluster-*)
            echo "WARN $h is a cluster/reader DNS endpoint - it does not pin one" \
                 "instance; use instance endpoints so every node is captured" >&2 ;;
    esac
    safe=$(printf '%s' "$h" | tr -c 'A-Za-z0-9.-' '_')
    f="$OUT/${TS}_${safe}.csv"
    if psql -X -q --csv -h "$h" -p "$PORT" -U "$DB_USER" -d "$DB_NAME" \
            -f "$SQL" -o "$f"; then
        rows=$(( $(wc -l < "$f") - 1 ))
        echo "OK   $h -> $f ($rows indexes)"
        ok=$((ok + 1))
    else
        echo "FAIL $h" >&2
        rm -f "$f"
        fail=$((fail + 1))
    fi
done

echo "Captured: $ok node(s), failed: $fail. Directory: $OUT"
[ "$fail" -eq 0 ]
