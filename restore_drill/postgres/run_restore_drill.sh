#!/usr/bin/env bash
# =============================================================================
# PostgreSQL restore drill.
#
# Proves a backup is actually restorable: dumps the source database
# (read-only on the source), restores it into a throw-away scratch database
# on the same cluster, and verifies the restored copy against the source
# (object parity, per-table row counts, integrity, content checksums).
# It also measures the recovery objectives (RTO = restore time, RPO =
# backup age). One check -> one .log file, in priority order, mirroring the
# db-audit-scripts runners so the analyzer can turn the folder into a report.
#
# The source is touched read-only (pg_dump). The scratch database is created
# fresh and dropped on exit (unless -k). Safe to run against production.
# =============================================================================
set -u
export LC_ALL=C   # deterministic dot-decimal in awk/printf regardless of host locale

usage() {
    cat <<EOF
Usage: $0 [-h HOST] [-P PORT] [-U USER] [-d SOURCE_DB] [-o OUT_ROOT]
          [-t SCRATCH_DB] [-r RTO_SECONDS] [-R RPO_HOURS] [-F c|p] [-j JOBS] [-k] [-s]
  -h  PostgreSQL host (default: localhost)
  -P  PostgreSQL port (default: 5432)
  -U  PostgreSQL user (default: postgres)
  -d  Source database to drill (default: postgres)
  -o  Report root directory (default: ./reports)
  -t  Scratch database name to restore INTO (default: <src>_drill_<TS>)
  -r  RTO target in seconds  - restore must finish within this (default: 900)
  -R  RPO target in hours    - backup must be fresher than this (default: 24)
  -F  Backup format: c=custom (pg_restore), p=plain SQL (psql) (default: c)
  -j  Parallel restore jobs for pg_restore (custom format only, default: 1)
  -k  Keep the scratch database and backup file (default: drop + remove)
  -s  Strict: exit non-zero on WARN as well as FAIL (for CI gates)
  -V  Verify-only: validate the backup WITHOUT restoring (no scratch database).
      Lighter, but only proves the backup is complete/readable - not that the
      data restores faithfully. Omit for the full restore drill.
Environment:
  PGPASSWORD  Password for PostgreSQL connection (recommended)
EOF
    exit 1
}

DB_HOST="localhost"; DB_PORT="5432"; DB_USER="postgres"; DB_NAME="postgres"
OUT_ROOT="./reports"; TGT=""; RTO_TARGET="900"; RPO_TARGET="24"
FMT="c"; KEEP=""; STRICT=""; VERIFY_ONLY=""; MAINT_DB="postgres"; JOBS="1"

while getopts "h:P:U:d:o:t:r:R:F:j:ksV?" opt; do
    case "$opt" in
        h) DB_HOST=$OPTARG ;;  P) DB_PORT=$OPTARG ;;  U) DB_USER=$OPTARG ;;
        d) DB_NAME=$OPTARG ;;  o) OUT_ROOT=$OPTARG ;; t) TGT=$OPTARG ;;
        r) RTO_TARGET=$OPTARG ;; R) RPO_TARGET=$OPTARG ;;
        F) FMT=$OPTARG ;; j) JOBS=$OPTARG ;; k) KEEP=1 ;; s) STRICT=1 ;; V) VERIFY_ONLY=1 ;; *) usage ;;
    esac
done

for n in "RTO target:-r:$RTO_TARGET" "RPO target:-R:$RPO_TARGET" "port:-P:$DB_PORT" "restore jobs:-j:$JOBS"; do
    lbl=${n%%:*}; rest=${n#*:}; flag=${rest%%:*}; val=${rest#*:}
    case $val in ''|*[!0-9]*) echo "[ERROR] $lbl ($flag) must be a non-negative integer, got '$val'" >&2; exit 2 ;; esac
done

command -v psql     >/dev/null 2>&1 || { echo "[ERROR] psql not found on PATH"     >&2; exit 2; }
command -v pg_dump  >/dev/null 2>&1 || { echo "[ERROR] pg_dump not found on PATH"  >&2; exit 2; }
[ "$FMT" = "c" ] && { command -v pg_restore >/dev/null 2>&1 || { echo "[ERROR] pg_restore not found on PATH" >&2; exit 2; }; }
case "$FMT" in c|p) ;; *) echo "[ERROR] -F must be c (custom) or p (plain)" >&2; exit 2 ;; esac

TS=$(date +%Y%m%d_%H%M%S)
[ -n "$TGT" ] || TGT="${DB_NAME}_drill_${TS}_$$"   # PID suffix: no scratch-name collision between same-second runs
if [ "$TGT" = "$DB_NAME" ]; then
    echo "[ERROR] scratch database (-t) must differ from the source database (-d)" >&2; exit 2
fi
# Identifier guard: both names are interpolated into CREATE/DROP DATABASE, so
# restrict them to word characters (closes the identifier-injection hole).
case "$DB_NAME" in *[!A-Za-z0-9_]*|'') echo "[ERROR] source database name (-d) must match ^[A-Za-z0-9_]+\$, got '$DB_NAME'" >&2; exit 2 ;; esac
case "$TGT"     in *[!A-Za-z0-9_]*|'') echo "[ERROR] scratch database name (-t) must match ^[A-Za-z0-9_]+\$, got '$TGT'" >&2; exit 2 ;; esac

OUT="$OUT_ROOT/postgres_restore_$TS"
ART="$OUT/_artifacts"
mkdir -p "$ART"
[ "$FMT" = "c" ] && BACKUP_FILE="$ART/${DB_NAME}.dump" || BACKUP_FILE="$ART/${DB_NAME}.sql"
FMT_LABEL=$([ "$FMT" = "c" ] && echo "custom" || echo "plain")
SUMMARY="$OUT/_summary.txt"; : > "$SUMMARY"

echo "================================================================================"
echo "PostgreSQL restore drill$([ -n "$VERIFY_ONLY" ] && echo ' (verify-only)')"
echo "  source = $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
[ -n "$VERIFY_ONLY" ] && echo "  mode   = verify-only (no scratch database)" || echo "  scratch= $TGT   format=$FMT_LABEL"
echo "  output = $OUT"
echo "================================================================================"

# ---- helpers ----------------------------------------------------------------
PSQL=(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -v ON_ERROR_STOP=1 -X -q)
q_src() { "${PSQL[@]}" -d "$DB_NAME" -t -A -F'|' -c "$1"; }
q_tgt() { "${PSQL[@]}" -d "$TGT"     -t -A -F'|' -c "$1"; }
q_mnt() { "${PSQL[@]}" -d "$MAINT_DB"            -c "$1"; }

_now() { python3 -c 'import time;print("%.3f"%time.time())' 2>/dev/null || date +%s; }
_elapsed() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", (b-a)}'; }
_human() { awk -v b="$1" 'BEGIN{ s="B K M G T"; split(s,u," "); i=1; while(b>=1024 && i<5){b/=1024;i++} printf (i==1?"%d %s":"%.1f %s"), b, u[i] }'; }

pass=0; warn=0; fail=0
RESULTS=()           # "tier|id|status|metric|threshold|title"
RTO_VALUE=""; RPO_VALUE=""; BACKUP_BYTES=""; ROWS_VERIFIED=""

# emit_check <tier> <id> <title> <status> <metric> <threshold> <detail> <rawfile>
emit_check() {
    local tier="$1" id="$2" title="$3" status="$4" metric="$5" thr="$6" detail="$7" raw="$8"
    local log="$OUT/${tier}_${id}.log"
    {
        echo "=== RESTORE DRILL CHECK ========================================================"
        echo "Check:      $id"
        echo "Tier:       $tier"
        echo "Title:      $title"
        echo "Status:     $status"
        echo "Metric:     ${metric:--}"
        echo "Threshold:  ${thr:--}"
        echo "Detail:     ${detail:--}"
        echo "--- output ---------------------------------------------------------------------"
        [ -n "$raw" ] && [ -f "$raw" ] && cat "$raw" || echo "(no command output captured)"
    } > "$log"
    case "$status" in
        PASS) pass=$((pass+1)) ;;  WARN) warn=$((warn+1)) ;;  *) fail=$((fail+1)) ;;
    esac
    RESULTS+=("$tier|$id|$status|$metric|$thr|$title")
    printf "[%-4s] %-8s %s\n" "$status" "$tier" "$id"
    printf "%s %s/%s\n" "$status" "$tier" "$id" >> "$SUMMARY"
}

SCRATCH_CREATED=""
cleanup() {
    if [ -z "$KEEP" ]; then
        if [ -n "$SCRATCH_CREATED" ]; then
            # WITH (FORCE) kicks out lingering sessions (PG13+); fall back to the
            # plain form on older servers. Never discard a failed drop silently.
            PGCONNECT_TIMEOUT=10 q_mnt "DROP DATABASE IF EXISTS \"$TGT\" WITH (FORCE)" >/dev/null 2>&1 \
                || PGCONNECT_TIMEOUT=10 q_mnt "DROP DATABASE IF EXISTS \"$TGT\"" >/dev/null 2>&1 \
                || echo "[WARN] could not drop scratch database \"$TGT\" - drop it manually" >&2
        fi
        rm -rf "$ART"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP QUIT   # ensure the EXIT trap (scratch drop) runs on Ctrl-C / kill

TMP="$ART/.tmp"; mkdir -p "$TMP"

# ---- rd_01: backup create (critical) ----------------------------------------
BACKUP_OK=""
t0=$(_now)
if [ "$FMT" = "c" ]; then
    pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -Fc -f "$BACKUP_FILE" > "$TMP/rd01" 2>&1
else
    pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$BACKUP_FILE" > "$TMP/rd01" 2>&1
fi
rc=$?; t1=$(_now); dur=$(_elapsed "$t0" "$t1")
if [ "$rc" -eq 0 ] && [ -s "$BACKUP_FILE" ]; then
    BACKUP_OK=1; BACKUP_BYTES=$(wc -c < "$BACKUP_FILE" | tr -d ' ')
    echo "backup file: $BACKUP_FILE ($(_human "$BACKUP_BYTES")), ${dur}s, $FMT_LABEL format" >> "$TMP/rd01"
    emit_check critical rd_01_backup_create "Backup of the source database succeeds" PASS \
        "backup_seconds=$dur;backup_bytes=$BACKUP_BYTES" "-" \
        "pg_dump produced $(_human "$BACKUP_BYTES") $FMT_LABEL backup in ${dur}s" "$TMP/rd01"
else
    emit_check critical rd_01_backup_create "Backup of the source database succeeds" FAIL \
        "backup_seconds=$dur" "-" "pg_dump failed (rc=$rc) - see output" "$TMP/rd01"
fi

# ---- rd_02: restore execute / backup verify (critical) ----------------------
RESTORE_OK=""
if [ -n "$VERIFY_ONLY" ]; then
    # Verify the backup is complete + readable WITHOUT restoring into a scratch
    # database. Custom format: list the TOC and fully decode the archive to SQL
    # (catches truncation/corruption). Plain format: confirm the dump-complete
    # marker so a truncated dump is caught.
    if [ -n "$BACKUP_OK" ]; then
        t0=$(_now)
        if [ "$FMT" = "c" ]; then
            { pg_restore -l "$BACKUP_FILE" >/dev/null && pg_restore -f /dev/null "$BACKUP_FILE"; } > "$TMP/rd02" 2>&1
            vrc=$?
        else
            # Anchor to the file tail: the marker must close the dump, not merely
            # appear somewhere inside it (e.g. in restored data).
            if tail -n 5 "$BACKUP_FILE" | grep -q 'PostgreSQL database dump complete'; then vrc=0; else vrc=1; fi
            echo "checked plain dump tail for the 'PostgreSQL database dump complete' marker (rc=$vrc)" > "$TMP/rd02"
        fi
        t1=$(_now); VERIFY_SECONDS=$(_elapsed "$t0" "$t1")
        if [ "$vrc" -eq 0 ]; then
            emit_check critical rd_02_backup_verify "Backup verifies without restoring" PASS \
                "verify_seconds=$VERIFY_SECONDS" "-" "Backup archive is complete and readable (no scratch database created)" "$TMP/rd02"
        else
            emit_check critical rd_02_backup_verify "Backup verifies without restoring" FAIL \
                "verify_seconds=$VERIFY_SECONDS" "-" "Backup failed verification - see output" "$TMP/rd02"
        fi
    else
        emit_check critical rd_02_backup_verify "Backup verifies without restoring" FAIL "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
    fi
elif [ -n "$BACKUP_OK" ]; then
    t0=$(_now)
    # Match the source's encoding/locale so checksum/text comparisons aren't
    # skewed by a scratch DB created under different defaults. Values come
    # from pg_database (and DB_NAME is validated), but escape quotes anyway.
    SRCPROPS=$("${PSQL[@]}" -d "$MAINT_DB" -t -A -c "SELECT pg_encoding_to_char(encoding)||'|'||datcollate||'|'||datctype FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null)
    if [ -n "$SRCPROPS" ]; then
        enc=${SRCPROPS%%|*}; rest=${SRCPROPS#*|}; coll=${rest%%|*}; ctype=${rest#*|}
        enc=${enc//\'/\'\'}; coll=${coll//\'/\'\'}; ctype=${ctype//\'/\'\'}
        q_mnt "CREATE DATABASE \"$TGT\" TEMPLATE template0 ENCODING '$enc' LC_COLLATE '$coll' LC_CTYPE '$ctype'" > "$TMP/rd02" 2>&1 && SCRATCH_CREATED=1
    else
        q_mnt "CREATE DATABASE \"$TGT\"" > "$TMP/rd02" 2>&1 && SCRATCH_CREATED=1
    fi
    crc=$?
    if [ "$crc" -eq 0 ]; then
        if [ "$FMT" = "c" ]; then
            # --exit-on-error: by default pg_restore continues past failed items
            # and STILL exits 0 (only prints "errors ignored on restore: N"),
            # which would make a half-restored database look successful.
            JOBS_OPT=(); [ "$JOBS" -gt 1 ] && JOBS_OPT=(-j "$JOBS")
            pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TGT" --no-owner --exit-on-error ${JOBS_OPT[@]+"${JOBS_OPT[@]}"} "$BACKUP_FILE" >> "$TMP/rd02" 2>&1
        else
            # PSQL carries -v ON_ERROR_STOP=1, so the plain-SQL restore aborts on
            # the first error too.
            "${PSQL[@]}" -d "$TGT" -f "$BACKUP_FILE" >> "$TMP/rd02" 2>&1
        fi
        rrc=$?
        # Belt-and-suspenders: never let an "errors ignored on restore" slip through as success.
        if [ "$rrc" -eq 0 ] && grep -qiE 'errors ignored on restore' "$TMP/rd02"; then rrc=2; fi
    else
        rrc=1
    fi
    t1=$(_now); RTO_VALUE=$(_elapsed "$t0" "$t1")
    if [ "$rrc" -eq 0 ]; then
        RESTORE_OK=1
        emit_check critical rd_02_restore_execute "Restore into the scratch database completes" PASS \
            "restore_seconds=$RTO_VALUE" "-" "Restored into scratch database \"$TGT\" in ${RTO_VALUE}s" "$TMP/rd02"
    elif [ "$crc" -ne 0 ]; then
        emit_check critical rd_02_restore_execute "Restore into the scratch database completes" FAIL \
            "restore_seconds=$RTO_VALUE" "-" "Scratch database creation failed (rc=$crc) - restore not attempted" "$TMP/rd02"
    else
        emit_check critical rd_02_restore_execute "Restore into the scratch database completes" FAIL \
            "restore_seconds=$RTO_VALUE" "-" "Restore returned rc=$rrc - see output" "$TMP/rd02"
    fi
else
    emit_check critical rd_02_restore_execute "Restore into the scratch database completes" FAIL \
        "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
fi

if [ -z "$VERIFY_ONLY" ]; then   # rd_03-rd_07 + rd_09 need a restored copy; skipped in verify-only mode

# ---- rd_03: restored database online (critical) -----------------------------
if [ -n "$RESTORE_OK" ]; then
    if q_tgt "SELECT current_database() AS database, pg_size_pretty(pg_database_size(current_database())) AS size;" > "$TMP/rd03" 2>&1; then
        emit_check critical rd_03_restore_online "Restored database is online and queryable" PASS \
            "-" "-" "Scratch database accepts connections and queries" "$TMP/rd03"
    else
        emit_check critical rd_03_restore_online "Restored database is online and queryable" FAIL \
            "-" "-" "Scratch database not queryable after restore" "$TMP/rd03"
    fi
else
    emit_check critical rd_03_restore_online "Restored database is online and queryable" FAIL \
        "-" "-" "Skipped: restore prerequisite (rd_02) failed" ""
fi

# ---- object / rowcount / checksum queries -----------------------------------
# Object parity covers tables, views, materialized views (and whether they are
# populated - an unpopulated matview after restore is silent data loss),
# indexes, sequences and routines.
OBJ_SQL="SELECT 'tables' AS kind, count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND table_type='BASE TABLE'
UNION ALL SELECT 'views', count(*) FROM information_schema.views WHERE table_schema NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'matviews', count(*) FROM pg_matviews WHERE schemaname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'matviews_populated', count(*) FROM pg_matviews WHERE schemaname NOT IN ('pg_catalog','information_schema') AND ispopulated
UNION ALL SELECT 'indexes', count(*) FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'sequences', count(*) FROM information_schema.sequences WHERE sequence_schema NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'routines', count(*) FROM information_schema.routines WHERE specific_schema NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'triggers', count(*) FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT tg.tgisinternal AND n.nspname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'fk_constraints', count(*) FROM pg_constraint con JOIN pg_namespace n ON n.oid=con.connamespace WHERE con.contype='f' AND n.nspname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'check_constraints', count(*) FROM pg_constraint con JOIN pg_namespace n ON n.oid=con.connamespace WHERE con.contype='c' AND n.nspname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'types_domains', count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE t.typtype IN ('d','e') AND n.nspname NOT IN ('pg_catalog','information_schema')
UNION ALL SELECT 'policies', count(*) FROM pg_policy
UNION ALL SELECT 'extensions', count(*) FROM pg_extension
ORDER BY 1;"
# Row-count / checksum compare base tables AND populated materialized views
# (unpopulated matviews cannot be scanned, so they are excluded here but are
# still caught by the matviews_populated parity check above).
REL_SRC="SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')
         UNION ALL SELECT schemaname, matviewname FROM pg_matviews WHERE schemaname NOT IN ('pg_catalog','information_schema') AND ispopulated"
ROWCOUNT_BUILD="SELECT string_agg(format('SELECT %L AS t, count(*)::text AS c FROM %I.%I', schemaname||'.'||tablename, schemaname, tablename), ' UNION ALL ' ORDER BY schemaname, tablename) FROM ($REL_SRC) rels;"
CHECKSUM_BUILD="SELECT string_agg(format('SELECT %L AS t, count(*)::text AS c, coalesce(sum((''x''||substr(md5(q::text),1,16))::bit(64)::bigint),0)::text AS ck FROM %I.%I q', schemaname||'.'||tablename, schemaname, tablename), ' UNION ALL ' ORDER BY schemaname, tablename) FROM ($REL_SRC) rels;"

# Per-sequence current value, so sequence drift (a restore that loses setval
# state -> duplicate-key failures on the next insert) is caught as data loss.
SEQ_SQL="SELECT 'seq:'||schemaname||'.'||sequencename, coalesce(last_value::text,'(unset)') FROM pg_sequences WHERE schemaname NOT IN ('pg_catalog','information_schema');"

# ---- rd_04: object parity (high) --------------------------------------------
if [ -n "$RESTORE_OK" ]; then
    # Keep stderr: a partially-failed catalog read must FAIL, not silently
    # compare an incomplete object list.
    { q_src "$OBJ_SQL"; q_src "$SEQ_SQL"; } 2>"$TMP/obj_src.err" | sort > "$TMP/obj_src"
    { q_tgt "$OBJ_SQL"; q_tgt "$SEQ_SQL"; } 2>"$TMP/obj_tgt.err" | sort > "$TMP/obj_tgt"
    { echo "source vs restored object counts (kind|count):"; echo "--- source ---"; cat "$TMP/obj_src"; echo "--- restored ---"; cat "$TMP/obj_tgt"; } > "$TMP/rd04"
    if [ -s "$TMP/obj_src.err" ] || [ -s "$TMP/obj_tgt.err" ]; then
        { echo "--- errors (source) ---"; tail -n 20 "$TMP/obj_src.err"; echo "--- errors (restored) ---"; tail -n 20 "$TMP/obj_tgt.err"; } >> "$TMP/rd04"
        emit_check high rd_04_object_parity "Schema object counts match the source" FAIL \
            "-" "-" "Object-count query errored on one side - possibly incomplete list, not verified" "$TMP/rd04"
    elif [ ! -s "$TMP/obj_src" ]; then
        emit_check high rd_04_object_parity "Schema object counts match the source" FAIL \
            "-" "-" "Could not read object counts from the source - not verified" "$TMP/rd04"
    elif d=$(diff "$TMP/obj_src" "$TMP/obj_tgt"); then
        emit_check high rd_04_object_parity "Schema object counts match the source" PASS \
            "-" "-" "Tables, views, matviews, indexes, sequences and routines match the source" "$TMP/rd04"
    else
        echo "--- differences ---" >> "$TMP/rd04"; echo "$d" >> "$TMP/rd04"
        emit_check high rd_04_object_parity "Schema object counts match the source" FAIL \
            "-" "-" "Object counts differ between source and restored copy" "$TMP/rd04"
    fi
else
    emit_check high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "Skipped: restore failed" ""
fi

# ---- rd_05: row-count parity (high) -----------------------------------------
if [ -n "$RESTORE_OK" ]; then
    RCQ=$(q_src "$ROWCOUNT_BUILD")
    if [ -n "$RCQ" ]; then
        q_src "$RCQ" | sort > "$TMP/rc_src"
        q_tgt "$RCQ" | sort > "$TMP/rc_tgt"
        ROWS_VERIFIED=$(awk -F'|' '{s+=$2} END{print s+0}' "$TMP/rc_src")
        { echo "per-table row counts (table|rows):"; echo "--- source ---"; cat "$TMP/rc_src"; echo "--- restored ---"; cat "$TMP/rc_tgt"; } > "$TMP/rd05"
        if [ ! -s "$TMP/rc_src" ]; then
            emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL \
                "-" "-" "Row-count query against the source produced no output - not verified" "$TMP/rd05"
        elif d=$(diff "$TMP/rc_src" "$TMP/rc_tgt"); then
            emit_check high rd_05_rowcount_parity "Per-table row counts match the source" PASS \
                "rows=$ROWS_VERIFIED" "-" "All tables restored with identical row counts ($ROWS_VERIFIED rows)" "$TMP/rd05"
        else
            echo "--- mismatches ---" >> "$TMP/rd05"; echo "$d" >> "$TMP/rd05"
            emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL \
                "rows=$ROWS_VERIFIED" "-" "Row counts differ between source and restored copy (note: writes to the source between backup and verification also cause mismatches - re-run on a quiesced source to confirm)" "$TMP/rd05"
        fi
    else
        echo "no user tables found" > "$TMP/rd05"
        emit_check high rd_05_rowcount_parity "Per-table row counts match the source" WARN "-" "-" "No user tables to compare" "$TMP/rd05"
    fi
else
    emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL "-" "-" "Skipped: restore failed" ""
fi

# ---- rd_06: integrity check (high) ------------------------------------------
if [ -n "$RESTORE_OK" ]; then
    if q_tgt "SELECT 'invalid_indexes' AS k, count(*) FROM pg_index WHERE NOT indisvalid
UNION ALL SELECT 'not_valid_constraints', count(*) FROM pg_constraint WHERE NOT convalidated
ORDER BY 1;" > "$TMP/rd06" 2>"$TMP/rd06.err"; then
        bad=$(awk -F'|' '{s+=$2} END{print s+0}' "$TMP/rd06")
        rows=$(grep -c '|' "$TMP/rd06")
        if [ "$rows" -ge 2 ] && [ "${bad:-1}" -eq 0 ]; then
            emit_check high rd_06_integrity_check "Restored objects pass integrity checks" PASS \
                "-" "-" "No invalid indexes or unvalidated constraints in the restored copy" "$TMP/rd06"
        else
            emit_check high rd_06_integrity_check "Restored objects pass integrity checks" FAIL \
                "-" "-" "Restored copy has invalid indexes or unvalidated constraints" "$TMP/rd06"
        fi
    else
        cat "$TMP/rd06.err" >> "$TMP/rd06"
        emit_check high rd_06_integrity_check "Restored objects pass integrity checks" FAIL \
            "-" "-" "Integrity probe query failed - restored copy not verified" "$TMP/rd06"
    fi
else
    emit_check high rd_06_integrity_check "Restored objects pass integrity checks" FAIL "-" "-" "Skipped: restore failed" ""
fi

# ---- rd_07: RTO objective (medium) ------------------------------------------
if [ -n "$RESTORE_OK" ] && [ -n "$RTO_VALUE" ]; then
    within=$(awk -v v="$RTO_VALUE" -v t="$RTO_TARGET" 'BEGIN{print (v<=t)?1:0}')
    echo "restore time ${RTO_VALUE}s vs RTO target ${RTO_TARGET}s" > "$TMP/rd07"
    if [ "$within" -eq 1 ]; then
        emit_check medium rd_07_rto "Restore meets the RTO target" PASS \
            "restore_seconds=$RTO_VALUE" "rto_seconds<=$RTO_TARGET" "Restored in ${RTO_VALUE}s, within the ${RTO_TARGET}s RTO target" "$TMP/rd07"
    else
        emit_check medium rd_07_rto "Restore meets the RTO target" WARN \
            "restore_seconds=$RTO_VALUE" "rto_seconds<=$RTO_TARGET" "Restore took ${RTO_VALUE}s, exceeding the ${RTO_TARGET}s RTO target" "$TMP/rd07"
    fi
else
    emit_check medium rd_07_rto "Restore meets the RTO target" FAIL "-" "rto_seconds<=$RTO_TARGET" "Skipped: restore did not complete" ""
fi

fi   # end restore-dependent checks (rd_03-rd_07)

# ---- rd_08: RPO / backup freshness (medium) ---------------------------------
if [ -n "$BACKUP_OK" ]; then
    AGE_H=$(python3 -c 'import os,sys,time;print("%.2f"%((time.time()-os.path.getmtime(sys.argv[1]))/3600))' "$BACKUP_FILE" 2>/dev/null)
    if [ -z "$AGE_H" ]; then   # portable fallback when python3 is unavailable
        mtime=$(stat -f %m "$BACKUP_FILE" 2>/dev/null || stat -c %Y "$BACKUP_FILE" 2>/dev/null)
        [ -n "$mtime" ] && AGE_H=$(awk -v m="$mtime" -v n="$(date +%s)" 'BEGIN{printf "%.2f",(n-m)/3600}')
    fi
    [ -n "$AGE_H" ] || AGE_H="0.00"
    RPO_VALUE="$AGE_H"
    echo "backup age ${AGE_H}h vs RPO target ${RPO_TARGET}h" > "$TMP/rd08"
    within=$(awk -v v="$AGE_H" -v t="$RPO_TARGET" 'BEGIN{print (v<=t)?1:0}')
    # The drill produced this backup itself, so its age reflects this run, not
    # how fresh a production backup would be - say so in the detail.
    RPO_NOTE=" (on-demand drill backup - measures this run, not the production backup cadence)"
    if [ "$within" -eq 1 ]; then
        emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" PASS \
            "backup_age_hours=$AGE_H" "rpo_hours<=$RPO_TARGET" "Backup is ${AGE_H}h old, within the ${RPO_TARGET}h RPO target${RPO_NOTE}" "$TMP/rd08"
    else
        emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" WARN \
            "backup_age_hours=$AGE_H" "rpo_hours<=$RPO_TARGET" "Backup is ${AGE_H}h old, exceeding the ${RPO_TARGET}h RPO target${RPO_NOTE}" "$TMP/rd08"
    fi
else
    emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" FAIL "-" "rpo_hours<=$RPO_TARGET" "Skipped: backup failed" ""
fi

if [ -z "$VERIFY_ONLY" ]; then
# ---- rd_09: content checksum parity (low) -----------------------------------
if [ -n "$RESTORE_OK" ]; then
    CKQ=$(q_src "$CHECKSUM_BUILD")
    if [ -n "$CKQ" ]; then
        # Pin rendering GUCs in the same session as the checksum query so
        # database-level settings can't skew the text rendering on either side.
        CK_GUCS="SET timezone='UTC'; SET datestyle='ISO'; SET extra_float_digits=3;"
        q_src "$CK_GUCS $CKQ" | sort > "$TMP/ck_src"
        q_tgt "$CK_GUCS $CKQ" | sort > "$TMP/ck_tgt"
        { echo "per-table content checksum (table|rows|checksum):"; echo "--- source ---"; cat "$TMP/ck_src"; echo "--- restored ---"; cat "$TMP/ck_tgt"; } > "$TMP/rd09"
        if [ ! -s "$TMP/ck_src" ]; then
            emit_check low rd_09_data_checksum "Row-content checksums match the source" FAIL \
                "-" "-" "Checksum query against the source produced no output - not verified" "$TMP/rd09"
        elif d=$(diff "$TMP/ck_src" "$TMP/ck_tgt"); then
            emit_check low rd_09_data_checksum "Row-content checksums match the source" PASS \
                "-" "-" "Every table's content checksum matches the source - data is byte-faithful" "$TMP/rd09"
        else
            echo "--- mismatches ---" >> "$TMP/rd09"; echo "$d" >> "$TMP/rd09"
            emit_check low rd_09_data_checksum "Row-content checksums match the source" FAIL \
                "-" "-" "Content checksums differ - restored data does not match the source (note: writes to the source between backup and verification also cause mismatches - re-run on a quiesced source to confirm)" "$TMP/rd09"
        fi
    else
        echo "no user tables" > "$TMP/rd09"
        emit_check low rd_09_data_checksum "Row-content checksums match the source" WARN "-" "-" "No user tables to checksum" "$TMP/rd09"
    fi
else
    emit_check low rd_09_data_checksum "Row-content checksums match the source" FAIL "-" "-" "Skipped: restore failed" ""
fi
fi   # end rd_09 (verify-only skips it)

# ---- verdict + summary footer -----------------------------------------------
if   [ "$fail" -gt 0 ]; then VERDICT="FAIL"
elif [ "$warn" -gt 0 ]; then VERDICT="WARN"
else VERDICT="PASS"; fi

BK_HUMAN=$([ -n "$BACKUP_BYTES" ] && _human "$BACKUP_BYTES" || echo "n/a")
RTO_DISP=$([ -n "$RTO_VALUE" ] && echo "${RTO_VALUE}s" || echo "n/a")
RPO_DISP=$([ -n "$RPO_VALUE" ] && echo "${RPO_VALUE}h since backup" || echo "n/a")
TARGET_DISP=$([ -n "$VERIFY_ONLY" ] && echo "(verify-only - no restore performed)" || echo "$DB_USER@$DB_HOST:$DB_PORT/$TGT")
{
    echo "--------------------------------------------------------------------------------"
    echo "Engine:    postgres"
    echo "Category:  restore"
    echo "Mode:      $([ -n "$VERIFY_ONLY" ] && echo verify-only || echo full-restore)"
    echo "Timestamp: $TS"
    echo "Source:    $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
    echo "Target:    $TARGET_DISP"
    echo "Backup:    ${BACKUP_FILE} (${BK_HUMAN}, ${FMT_LABEL})"
    echo "RTO:       ${RTO_DISP} (target <= ${RTO_TARGET}s)"
    echo "RPO:       ${RPO_DISP} (target <= ${RPO_TARGET}h)"
    echo "Rows:      ${ROWS_VERIFIED:-0} verified"
    echo "Verdict:   $VERDICT"
    echo "Pass:      $pass"
    echo "Warn:      $warn"
    echo "Fail:      $fail"
} | tee -a "$SUMMARY"

echo "Report directory: $OUT"
# Exit non-zero on FAIL (always) and on WARN when -s/strict is set.
[ "$VERDICT" = "FAIL" ] && exit 1
{ [ -n "$STRICT" ] && [ "$VERDICT" = "WARN" ]; } && exit 1
exit 0
