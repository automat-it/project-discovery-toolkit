#!/usr/bin/env bash
# =============================================================================
# MySQL restore drill.
#
# Proves a backup is actually restorable: dumps the source schema (read-only
# on the source via mysqldump --single-transaction), restores it into a
# throw-away scratch schema on the same server, and verifies the restored
# copy against the source (object parity, per-table row counts, CHECK TABLE
# integrity, CHECKSUM TABLE content parity). It also measures the recovery
# objectives (RTO = restore time, RPO = backup age). One check -> one .log
# file, in priority order, mirroring the db-audit-scripts runners so the
# analyzer can turn the folder into a report.
#
# The source is touched read-only. The scratch schema is created fresh and
# dropped on exit (unless -k). Safe to run against production.
# =============================================================================
set -u
export LC_ALL=C   # deterministic dot-decimal in awk/printf regardless of host locale

usage() {
    cat <<EOF
Usage: $0 [-h HOST] [-P PORT] [-u USER] [-d SOURCE_DB] [-o OUT_ROOT]
          [-t SCRATCH_DB] [-r RTO_SECONDS] [-R RPO_HOURS] [-k] [-s]
  -h  MySQL host (default: localhost)
  -P  MySQL port (default: 3306)
  -u  MySQL user (default: root)
  -d  Source database/schema to drill (default: mysql)
  -o  Report root directory (default: ./reports)
  -t  Scratch schema name to restore INTO (default: <src>_drill_<TS>)
  -r  RTO target in seconds  - restore must finish within this (default: 900)
  -R  RPO target in hours    - backup must be fresher than this (default: 24)
  -k  Keep the scratch schema and backup file (default: drop + remove)
  -s  Strict: exit non-zero on WARN as well as FAIL (for CI gates)
  -V  Verify-only: validate the backup WITHOUT restoring (no scratch schema).
      For mysqldump this confirms the dump is complete (not truncated); it is a
      weaker assurance than a full restore drill. Omit for the full drill.
Environment:
  MYSQL_PWD  Password for the MySQL connection (recommended)
EOF
    exit 1
}

DB_HOST="localhost"; DB_PORT="3306"; DB_USER="root"; DB_NAME="mysql"
OUT_ROOT="./reports"; TGT=""; RTO_TARGET="900"; RPO_TARGET="24"; KEEP=""; STRICT=""; VERIFY_ONLY=""

while getopts "h:P:u:d:o:t:r:R:ksV?" opt; do
    case "$opt" in
        h) DB_HOST=$OPTARG ;;  P) DB_PORT=$OPTARG ;;  u) DB_USER=$OPTARG ;;
        d) DB_NAME=$OPTARG ;;  o) OUT_ROOT=$OPTARG ;; t) TGT=$OPTARG ;;
        r) RTO_TARGET=$OPTARG ;; R) RPO_TARGET=$OPTARG ;; k) KEEP=1 ;; s) STRICT=1 ;; V) VERIFY_ONLY=1 ;; *) usage ;;
    esac
done

for n in "RTO target:-r:$RTO_TARGET" "RPO target:-R:$RPO_TARGET" "port:-P:$DB_PORT"; do
    lbl=${n%%:*}; rest=${n#*:}; flag=${rest%%:*}; val=${rest#*:}
    case $val in ''|*[!0-9]*) echo "[ERROR] $lbl ($flag) must be a non-negative integer, got '$val'" >&2; exit 2 ;; esac
done

command -v mysql     >/dev/null 2>&1 || { echo "[ERROR] mysql not found on PATH"     >&2; exit 2; }
command -v mysqldump >/dev/null 2>&1 || { echo "[ERROR] mysqldump not found on PATH" >&2; exit 2; }

TS=$(date +%Y%m%d_%H%M%S)
[ -n "$TGT" ] || TGT="${DB_NAME}_drill_${TS}"
if [ "$TGT" = "$DB_NAME" ]; then
    echo "[ERROR] scratch schema (-t) must differ from the source database (-d)" >&2; exit 2
fi

OUT="$OUT_ROOT/mysql_restore_$TS"; ART="$OUT/_artifacts"; mkdir -p "$ART"
BACKUP_FILE="$ART/${DB_NAME}.sql"
SUMMARY="$OUT/_summary.txt"; : > "$SUMMARY"

# Password handling mirrors the audit toolkit: MySQL 9.x can ignore MYSQL_PWD,
# so we write a private defaults file (escaping backslash + double-quote) and
# pass it as --defaults-file (the ONLY option file read -> a stray ~/.my.cnf
# can't override host/user/password). MYSQL_PWD is unset so it is not inherited
# by the mysql/mysqldump child processes.
DEFAULTS_FILE=$(mktemp "${TMPDIR:-/tmp}/rd_mysql.XXXXXX")
chmod 600 "$DEFAULTS_FILE"
_PWD_ESCAPED=$(printf '%s' "${MYSQL_PWD:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
printf '[client]\npassword="%s"\n' "$_PWD_ESCAPED" > "$DEFAULTS_FILE"
unset MYSQL_PWD _PWD_ESCAPED

echo "================================================================================"
echo "MySQL restore drill$([ -n "$VERIFY_ONLY" ] && echo ' (verify-only)')"
echo "  source = $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
[ -n "$VERIFY_ONLY" ] && echo "  mode   = verify-only (no scratch schema)" || echo "  scratch= $TGT"
echo "  output = $OUT"
echo "================================================================================"

# ---- helpers ----------------------------------------------------------------
MY=(mysql --defaults-file="$DEFAULTS_FILE" --protocol=TCP -u "$DB_USER" -h "$DB_HOST" -P "$DB_PORT" --default-character-set=utf8mb4 --batch --skip-column-names)
my_adm() { "${MY[@]}" -e "$1"; }                 # no default schema (admin ops)
my_src() { "${MY[@]}" -D "$DB_NAME" -e "$1"; }   # default schema = source
my_tgt() { "${MY[@]}" -D "$TGT"     -e "$1"; }   # default schema = scratch

_now() { python3 -c 'import time;print("%.3f"%time.time())' 2>/dev/null || date +%s; }
_elapsed() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", (b-a)}'; }
_human() { awk -v b="$1" 'BEGIN{ split("B K M G T",u," "); i=1; while(b>=1024 && i<5){b/=1024;i++} printf (i==1?"%d %s":"%.1f %s"), b, u[i] }'; }

pass=0; warn=0; fail=0
RTO_VALUE=""; RPO_VALUE=""; BACKUP_BYTES=""; ROWS_VERIFIED=""

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
    printf "[%-4s] %-8s %s\n" "$status" "$tier" "$id"
    printf "%s %s/%s\n" "$status" "$tier" "$id" >> "$SUMMARY"
}

SCRATCH_CREATED=""
cleanup() {
    if [ -z "$KEEP" ]; then
        [ -n "$SCRATCH_CREATED" ] && my_adm "DROP DATABASE IF EXISTS \`$TGT\`" >/dev/null 2>&1
        rm -rf "$ART"
    fi
    rm -f "$DEFAULTS_FILE"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP QUIT   # ensure the EXIT trap (scratch drop, temp-file rm) runs on Ctrl-C / kill

TMP="$ART/.tmp"; mkdir -p "$TMP"

# ---- rd_01: backup create (critical) ----------------------------------------
BACKUP_OK=""
t0=$(_now)
mysqldump --defaults-file="$DEFAULTS_FILE" --protocol=TCP -u "$DB_USER" -h "$DB_HOST" -P "$DB_PORT" \
    --single-transaction --routines --triggers --events --no-tablespaces \
    --set-gtid-purged=OFF --default-character-set=utf8mb4 \
    "$DB_NAME" > "$BACKUP_FILE" 2> "$TMP/rd01"
rc=$?; t1=$(_now); dur=$(_elapsed "$t0" "$t1")
if [ "$rc" -eq 0 ] && [ -s "$BACKUP_FILE" ]; then
    BACKUP_OK=1; BACKUP_BYTES=$(wc -c < "$BACKUP_FILE" | tr -d ' ')
    echo "backup file: $BACKUP_FILE ($(_human "$BACKUP_BYTES")), ${dur}s, logical (mysqldump)" >> "$TMP/rd01"
    emit_check critical rd_01_backup_create "Backup of the source database succeeds" PASS \
        "backup_seconds=$dur;backup_bytes=$BACKUP_BYTES" "-" \
        "mysqldump produced $(_human "$BACKUP_BYTES") logical backup in ${dur}s" "$TMP/rd01"
else
    emit_check critical rd_01_backup_create "Backup of the source database succeeds" FAIL \
        "backup_seconds=$dur" "-" "mysqldump failed (rc=$rc) - see output" "$TMP/rd01"
fi

# ---- rd_02: restore execute / backup verify (critical) ----------------------
RESTORE_OK=""
if [ -n "$VERIFY_ONLY" ]; then
    # mysqldump has no VERIFY tool; the best non-restoring signal is that the
    # dump finished completely - it appends "-- Dump completed" on success, so
    # its absence means a truncated/failed dump.
    if [ -n "$BACKUP_OK" ]; then
        if tail -5 "$BACKUP_FILE" | grep -q -- '-- Dump completed'; then vrc=0; else vrc=1; fi
        echo "checked mysqldump output for the '-- Dump completed' completion marker (rc=$vrc)" > "$TMP/rd02"
        tail -3 "$BACKUP_FILE" >> "$TMP/rd02"
        if [ "$vrc" -eq 0 ]; then
            emit_check critical rd_02_backup_verify "Backup verifies without restoring" PASS \
                "-" "-" "mysqldump output is complete (no scratch schema created)" "$TMP/rd02"
        else
            emit_check critical rd_02_backup_verify "Backup verifies without restoring" FAIL \
                "-" "-" "Dump is missing its completion marker - likely truncated" "$TMP/rd02"
        fi
    else
        emit_check critical rd_02_backup_verify "Backup verifies without restoring" FAIL "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
    fi
elif [ -n "$BACKUP_OK" ]; then
    t0=$(_now)
    my_adm "CREATE DATABASE \`$TGT\` CHARACTER SET utf8mb4" > "$TMP/rd02" 2>&1 && SCRATCH_CREATED=1
    crc=$?
    if [ "$crc" -eq 0 ]; then
        "${MY[@]}" -D "$TGT" < "$BACKUP_FILE" >> "$TMP/rd02" 2>&1
        rrc=$?
        # The mysql client does not uniformly abort on the first server error
        # across builds, so a partial restore can still exit 0. Treat any
        # 'ERROR <num>' the client wrote to the log as a hard failure (mirrors
        # the audit toolkit's run_audit.sh backstop).
        if [ "$rrc" -eq 0 ] && grep -qE '^ERROR [0-9]+' "$TMP/rd02"; then rrc=2; fi
    else
        rrc=1
    fi
    t1=$(_now); RTO_VALUE=$(_elapsed "$t0" "$t1")
    if [ "$rrc" -eq 0 ]; then
        RESTORE_OK=1
        emit_check critical rd_02_restore_execute "Restore into the scratch schema completes" PASS \
            "restore_seconds=$RTO_VALUE" "-" "Restored into scratch schema \`$TGT\` in ${RTO_VALUE}s" "$TMP/rd02"
    else
        emit_check critical rd_02_restore_execute "Restore into the scratch schema completes" FAIL \
            "restore_seconds=$RTO_VALUE" "-" "Restore returned rc=$rrc - see output" "$TMP/rd02"
    fi
else
    emit_check critical rd_02_restore_execute "Restore into the scratch schema completes" FAIL \
        "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
fi

if [ -z "$VERIFY_ONLY" ]; then   # rd_03-rd_07 + rd_09 need a restored copy; skipped in verify-only mode

# ---- rd_03: restored database online (critical) -----------------------------
if [ -n "$RESTORE_OK" ]; then
    if my_tgt "SELECT DATABASE() AS db; SELECT 1 AS ok;" > "$TMP/rd03" 2>&1; then
        emit_check critical rd_03_restore_online "Restored schema is online and queryable" PASS \
            "-" "-" "Scratch schema accepts connections and queries" "$TMP/rd03"
    else
        emit_check critical rd_03_restore_online "Restored schema is online and queryable" FAIL \
            "-" "-" "Scratch schema not queryable after restore" "$TMP/rd03"
    fi
else
    emit_check critical rd_03_restore_online "Restored schema is online and queryable" FAIL \
        "-" "-" "Skipped: restore prerequisite (rd_02) failed" ""
fi

# Object-parity query, parameterized by schema name. Covers tables, views,
# indexes, routines, triggers and events so a dump that silently drops any of
# them (e.g. missing --routines/--triggers/--events or a privilege issue) fails.
obj_sql() { local s="$1"; cat <<SQL
SELECT 'tables' AS kind, COUNT(*) AS n FROM information_schema.tables WHERE table_schema='$s' AND table_type='BASE TABLE'
UNION ALL SELECT 'views', COUNT(*) FROM information_schema.views WHERE table_schema='$s'
UNION ALL SELECT 'indexes', COUNT(DISTINCT table_name, index_name) FROM information_schema.statistics WHERE table_schema='$s'
UNION ALL SELECT 'routines', COUNT(*) FROM information_schema.routines WHERE routine_schema='$s'
UNION ALL SELECT 'triggers', COUNT(*) FROM information_schema.triggers WHERE trigger_schema='$s'
UNION ALL SELECT 'events', COUNT(*) FROM information_schema.events WHERE event_schema='$s'
ORDER BY kind;
SQL
}

# ---- rd_04: object parity (high) --------------------------------------------
if [ -n "$RESTORE_OK" ]; then
    my_adm "$(obj_sql "$DB_NAME")" 2>"$TMP/obj_src.err" | sort > "$TMP/obj_src"
    my_adm "$(obj_sql "$TGT")"     2>"$TMP/obj_tgt.err" | sort > "$TMP/obj_tgt"
    { echo "source vs restored object counts (kind|count):"; echo "--- source ---"; cat "$TMP/obj_src"; echo "--- restored ---"; cat "$TMP/obj_tgt"; } > "$TMP/rd04"
    if [ ! -s "$TMP/obj_src" ]; then
        cat "$TMP/obj_src.err" >> "$TMP/rd04" 2>/dev/null
        emit_check high rd_04_object_parity "Schema object counts match the source" FAIL \
            "-" "-" "Could not read object counts from the source - not verified" "$TMP/rd04"
    elif d=$(diff "$TMP/obj_src" "$TMP/obj_tgt"); then
        emit_check high rd_04_object_parity "Schema object counts match the source" PASS \
            "-" "-" "Tables, views, indexes, routines, triggers and events match the source" "$TMP/rd04"
    else
        echo "--- differences ---" >> "$TMP/rd04"; echo "$d" >> "$TMP/rd04"
        emit_check high rd_04_object_parity "Schema object counts match the source" FAIL \
            "-" "-" "Object counts differ between source and restored copy" "$TMP/rd04"
    fi
else
    emit_check high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "Skipped: restore failed" ""
fi

# Table list (used by row-count, integrity, checksum checks). Read line-by-line
# to preserve table names containing spaces; identifiers are backtick-escaped.
qb() { printf '`%s`' "$(printf '%s' "$1" | sed 's/`/``/g')"; }
TABLES=""
[ -n "$RESTORE_OK" ] && TABLES=$(my_adm "SELECT table_name FROM information_schema.tables WHERE table_schema='$DB_NAME' AND table_type='BASE TABLE' ORDER BY table_name")
N_TABLES=$(printf '%s' "$TABLES" | grep -c . || true)
CKLIST=""
while IFS= read -r t; do [ -n "$t" ] || continue; CKLIST="$CKLIST$(qb "$t"), "; done <<< "$TABLES"
CKLIST=${CKLIST%, }

# ---- rd_05: row-count parity (high) -----------------------------------------
if [ -n "$RESTORE_OK" ] && [ -n "$TABLES" ]; then
    RCQ=""
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        esc=$(printf '%s' "$t" | sed "s/'/''/g")
        RCQ="$RCQ SELECT '$esc' AS t, COUNT(*) AS c FROM $(qb "$t") UNION ALL"
    done <<< "$TABLES"
    RCQ=${RCQ% UNION ALL}
    my_src "$RCQ" 2>"$TMP/rc_src.err" | sort > "$TMP/rc_src"
    my_tgt "$RCQ" | sort > "$TMP/rc_tgt"
    ROWS_VERIFIED=$(awk -F'\t' '{s+=$2} END{print s+0}' "$TMP/rc_src")
    { echo "per-table row counts (table|rows):"; echo "--- source ---"; cat "$TMP/rc_src"; echo "--- restored ---"; cat "$TMP/rc_tgt"; } > "$TMP/rd05"
    if [ ! -s "$TMP/rc_src" ]; then
        cat "$TMP/rc_src.err" >> "$TMP/rd05" 2>/dev/null
        emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL \
            "-" "-" "Row-count query against the source produced no output - not verified" "$TMP/rd05"
    elif d=$(diff "$TMP/rc_src" "$TMP/rc_tgt"); then
        emit_check high rd_05_rowcount_parity "Per-table row counts match the source" PASS \
            "rows=$ROWS_VERIFIED" "-" "All tables restored with identical row counts ($ROWS_VERIFIED rows)" "$TMP/rd05"
    else
        echo "--- mismatches ---" >> "$TMP/rd05"; echo "$d" >> "$TMP/rd05"
        emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL \
            "rows=$ROWS_VERIFIED" "-" "Row counts differ between source and restored copy" "$TMP/rd05"
    fi
elif [ -n "$RESTORE_OK" ]; then
    echo "no user tables found" > "$TMP/rd05"
    emit_check high rd_05_rowcount_parity "Per-table row counts match the source" WARN "-" "-" "No user tables to compare" "$TMP/rd05"
else
    emit_check high rd_05_rowcount_parity "Per-table row counts match the source" FAIL "-" "-" "Skipped: restore failed" ""
fi

# ---- rd_06: integrity check (high) - CHECK TABLE ... EXTENDED ----------------
if [ -n "$RESTORE_OK" ] && [ -n "$CKLIST" ]; then
    if my_tgt "CHECK TABLE $CKLIST EXTENDED" > "$TMP/rd06" 2>"$TMP/rd06.err"; then
        n_ok=$(awk -F'\t' '$NF=="OK"{c++} END{print c+0}' "$TMP/rd06")
        n_err=$(awk -F'\t' 'tolower($3)=="error"{c++} END{print c+0}' "$TMP/rd06")
        if [ "$n_err" -eq 0 ] && [ "$n_ok" -ge "$N_TABLES" ]; then
            emit_check high rd_06_integrity_check "Restored tables pass CHECK TABLE" PASS \
                "tables_ok=$n_ok" "-" "All $N_TABLES restored tables report OK under CHECK TABLE ... EXTENDED" "$TMP/rd06"
        else
            emit_check high rd_06_integrity_check "Restored tables pass CHECK TABLE" FAIL \
                "tables_ok=$n_ok;errors=$n_err" "-" "CHECK TABLE reported a non-OK result on the restored copy" "$TMP/rd06"
        fi
    else
        cat "$TMP/rd06.err" >> "$TMP/rd06"
        emit_check high rd_06_integrity_check "Restored tables pass CHECK TABLE" FAIL \
            "-" "-" "CHECK TABLE query failed - restored copy not verified" "$TMP/rd06"
    fi
elif [ -n "$RESTORE_OK" ]; then
    echo "no user tables" > "$TMP/rd06"
    emit_check high rd_06_integrity_check "Restored tables pass CHECK TABLE" WARN "-" "-" "No user tables to check" "$TMP/rd06"
else
    emit_check high rd_06_integrity_check "Restored tables pass CHECK TABLE" FAIL "-" "-" "Skipped: restore failed" ""
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
    if [ "$within" -eq 1 ]; then
        emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" PASS \
            "backup_age_hours=$AGE_H" "rpo_hours<=$RPO_TARGET" "Backup is ${AGE_H}h old, within the ${RPO_TARGET}h RPO target" "$TMP/rd08"
    else
        emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" WARN \
            "backup_age_hours=$AGE_H" "rpo_hours<=$RPO_TARGET" "Backup is ${AGE_H}h old, exceeding the ${RPO_TARGET}h RPO target" "$TMP/rd08"
    fi
else
    emit_check medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" FAIL "-" "rpo_hours<=$RPO_TARGET" "Skipped: backup failed" ""
fi

if [ -z "$VERIFY_ONLY" ]; then
# ---- rd_09: content checksum parity (low) - CHECKSUM TABLE -------------------
if [ -n "$RESTORE_OK" ] && [ -n "$CKLIST" ]; then
    # CHECKSUM TABLE qualifies the name as <schema>.<table>; strip the schema
    # prefix so the source and scratch schemas compare on table name + checksum.
    my_src "CHECKSUM TABLE $CKLIST" 2>"$TMP/ck_src.err" | awk -F'\t' '{sub(/^[^.]*\./,"",$1); print $1"\t"$2}' | sort > "$TMP/ck_src"
    my_tgt "CHECKSUM TABLE $CKLIST" | awk -F'\t' '{sub(/^[^.]*\./,"",$1); print $1"\t"$2}' | sort > "$TMP/ck_tgt"
    { echo "per-table content checksum (table|checksum):"; echo "--- source ---"; cat "$TMP/ck_src"; echo "--- restored ---"; cat "$TMP/ck_tgt"; } > "$TMP/rd09"
    if [ ! -s "$TMP/ck_src" ]; then
        cat "$TMP/ck_src.err" >> "$TMP/rd09" 2>/dev/null
        emit_check low rd_09_data_checksum "Row-content checksums match the source" FAIL \
            "-" "-" "CHECKSUM TABLE against the source produced no output - not verified" "$TMP/rd09"
    elif d=$(diff "$TMP/ck_src" "$TMP/ck_tgt"); then
        emit_check low rd_09_data_checksum "Row-content checksums match the source" PASS \
            "-" "-" "Every table's CHECKSUM TABLE matches the source - data is faithful" "$TMP/rd09"
    else
        echo "--- mismatches ---" >> "$TMP/rd09"; echo "$d" >> "$TMP/rd09"
        emit_check low rd_09_data_checksum "Row-content checksums match the source" FAIL \
            "-" "-" "Content checksums differ - restored data does not match the source" "$TMP/rd09"
    fi
elif [ -n "$RESTORE_OK" ]; then
    echo "no user tables" > "$TMP/rd09"
    emit_check low rd_09_data_checksum "Row-content checksums match the source" WARN "-" "-" "No user tables to checksum" "$TMP/rd09"
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
    echo "Engine:    mysql"
    echo "Category:  restore"
    echo "Mode:      $([ -n "$VERIFY_ONLY" ] && echo verify-only || echo full-restore)"
    echo "Timestamp: $TS"
    echo "Source:    $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
    echo "Target:    $TARGET_DISP"
    echo "Backup:    ${BACKUP_FILE} (${BK_HUMAN}, logical)"
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
