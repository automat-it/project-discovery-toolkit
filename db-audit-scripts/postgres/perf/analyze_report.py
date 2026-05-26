#!/usr/bin/env python3
"""
analyze_report.py -- PostgreSQL performance audit report analyzer.

Reads the report directory produced by run_audit.sh (single database) or
multiple sub-folders containing per-database runs, applies a rule set that
flags known performance issues, and writes one HTML file with:

  * Environment fingerprint card (server, version, role, Aurora flag, ...)
  * Executive summary (KPI counts + Top issues with what-to-do)
  * Per-finding concrete objects (table names, index names, query hashes,
    sequences near limit, etc.) -- pulled from the actual psql log so the
    reader has actionable targets, not "review the log".

Usage:
    ./analyze_report.py <report_dir>
    ./analyze_report.py <report_dir> --server prod-pg-01

Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Import shared analyzer library (postgres/_analyze_lib.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _analyze_lib import (  # noqa: E402
    SHARED_CSS, context_label, esc, find_log, has_data_rows, kv_grid,
    now_str, object_table, parse_result_sets, read_fingerprint,
    read_log_text, read_summary, read_target, render_fingerprint_card,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Rules: how to recognise a finding in a given log file.
# Each rule is processed in two stages:
#   1. trigger -- 'has_data' (any rows present) or 'pattern' (regex match)
#   2. extractor (optional) -- pull a structured list of "objects of
#      concern" from the log to render under the finding row. Each
#      extractor returns a list of dicts; the analyzer renders the first
#      `limit` rows as a small <table>.
# ---------------------------------------------------------------------------
def _ext_rows(log_text: str, set_index: int, picker_columns: list, limit: int = 10):
    """Return the rows of the N-th result set as a list of dicts limited
    to the requested columns (filling blanks for missing ones)."""
    sets = parse_result_sets(log_text)
    if set_index < 0 or set_index >= len(sets):
        return []
    rows = sets[set_index]['rows']
    out = []
    for r in rows[:limit]:
        out.append({c: r.get(c, '') for c in picker_columns})
    return out


def _ext_blocking_pairs(text):
    """perf_02 emits 7 sub-tables. The actionable ones are the first
    four: blocker/blocked pairs, recursive blocking chain, long-running
    active transactions, idle-in-transaction sessions. The remaining
    sets (lock summary by mode, hot-locked relations, deadlock counts)
    are always non-empty on a busy server and pollute the report if
    surfaced as "blocking found". We render groups only for the
    actionable sets that actually have rows."""
    sets = parse_result_sets(text)
    groups = []

    def maybe(set_idx, label, picks):
        if not (0 <= set_idx < len(sets)) or not sets[set_idx]['rows']:
            return
        rows = []
        cols = []
        for p in picks:
            if isinstance(p, tuple):
                cols.append(p[1])
            else:
                cols.append(p)
        for r in sets[set_idx]['rows'][:200]:
            new = {}
            for p in picks:
                src, disp = (p if isinstance(p, tuple) else (p, p))
                new[disp] = r.get(src, '')
            rows.append(new)
        groups.append(dict(label=label, columns=cols, rows=rows))

    # Set 0: explicit blocking pairs -- if anything is here, it is by far
    # the most actionable signal in the whole audit.
    maybe(0, 'Active blocking pairs',
          [('blocking_pid','blocker_pid'), ('blocked_pid','blocked_pid'),
           ('wait_event_type','wait_type'),
           ('blocked_duration','blocked_for'),
           ('blocker_xact_age','blocker_xact_age'),
           ('blocked_user','blocked_user'),
           ('blocked_query','blocked_query')])
    # Set 1: recursive blocking chain
    maybe(1, 'Recursive blocking chain',
          ['level', 'pid', 'usename', 'wait_event', 'state'])
    # Set 2: long-running active transactions
    maybe(2, 'Long-running active transactions',
          ['pid', ('usename','user'), 'client_addr', 'state',
           ('xact_age','xact_age'), ('query','query')])
    # Set 3: idle-in-transaction sessions
    maybe(3, 'Idle-in-transaction sessions (holding locks!)',
          ['pid', ('usename','user'), 'client_addr',
           ('idle_duration','idle_for'),
           ('xact_age','xact_age'),
           ('last_query','last_query')])
    return groups


def _check_perf_02(text):
    """True when any of the perf_02 actionable sub-tables (sets 0-3) has
    rows. Set 4 (lock summary) and 6 (deadlock stats) are always
    populated on a busy server -- they must not trigger the finding."""
    sets = parse_result_sets(text)
    for idx in (0, 1, 2, 3):
        if idx < len(sets) and sets[idx]['rows']:
            return True
    return False


def _ext_top_sql(text):
    """perf_01 emits several pg_stat_statements snapshots (top by total
    time, mean time, calls, ...). We curate columns down to the 5 most
    actionable: queryid (jumps to SQL appendix), calls, total_min,
    mean_ms, and a short query preview. Full SQL is in the appendix."""
    sets = parse_result_sets(text)
    labels = [
        'Top by total execution time',
        'Top by mean execution time',
        'Top by call count',
        'Top by rows returned',
        'Top by buffer reads / writes',
        'Top by temp-file activity',
    ]
    # Compact column set, in display order. Source columns vary slightly
    # between perf_01 snapshots, so we look them up loosely.
    def pick(row, *names, default=''):
        for n in names:
            if n in row and row[n] != '':
                return row[n]
        return default

    groups = []
    for s in sets:
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        if 'queryid' not in lc:
            continue
        new_rows = []
        for r in s['rows'][:200]:
            new_rows.append({
                'queryid'   : pick(r, 'queryid'),
                'calls'     : pick(r, 'calls'),
                'total_min' : pick(r, 'total_min', 'total_ms'),
                'mean_ms'   : pick(r, 'mean_ms', 'mean_exec_time'),
                'pct_total' : pick(r, 'pct_total', 'pct_calls', default=''),
                'query'     : pick(r, 'query'),
            })
        groups.append(dict(
            label=labels[len(groups)] if len(groups) < len(labels)
                  else f'Top SQL set #{len(groups)+1}',
            # Drop 'query' from the inline table -- queryid is a link
            # straight to the SQL appendix below, where the FULL text is
            # rendered in a readable <pre> block. Keeping the truncated
            # SQL inline made rows 1700+ chars tall and unreadable.
            columns=['queryid','calls','total_min','mean_ms','pct_total'],
            rows=new_rows,
        ))
    return groups


def _ext_index_findings(text):
    """perf_06 emits up to 9 sub-tables (unused, duplicates, narrow-vs-wide,
    foreign keys without index, etc.). Each sub-table has different
    columns, so we render them as SEPARATE small tables. For each set we
    *curate* the columns: keep the most actionable ones with clearer
    headers (e.g. rename 'index' -> 'index_name') and drop noise like
    raw byte counts. Returns a list of {label, columns, rows} groups."""
    sets = parse_result_sets(text)

    def reshape(set_idx, label, picks):
        """Build a group dict by mapping (source_col -> display_col) on
        each row. picks is an ordered list of (src, display) tuples or
        bare strings (display = src in that case)."""
        if not (0 <= set_idx < len(sets)) or not sets[set_idx]['rows']:
            return None
        norm = []
        for p in picks:
            if isinstance(p, tuple):
                norm.append(p)
            else:
                norm.append((p, p))
        new_rows = []
        for r in sets[set_idx]['rows'][:200]:
            new_rows.append({disp: r.get(src, '') for src, disp in norm})
        return dict(
            label=label,
            columns=[disp for _, disp in norm],
            rows=new_rows,
        )

    groups = []
    # Set 0: Unused indexes (zero scans)
    # source cols: schemaname, table, index, size, size_bytes, scans, tuples_read, tuples_fetched
    g = reshape(0, 'Unused indexes (low / zero scans)',
                [('schemaname','schema'), 'table', ('index','index_name'),
                 'size', 'scans', 'tuples_read'])
    if g: groups.append(g)

    # Set 2: Duplicate indexes (same key)
    g = reshape(2, 'Duplicate indexes (same key)',
                ['table', ('index_a','index_a (drop candidate)'),
                 ('index_b','index_b'), 'size_a', 'size_b',
                 ('definition_a','definition_a'),
                 ('definition_b','definition_b')])
    if g: groups.append(g)

    # Set 3: Duplicate indexes (key prefix)
    g = reshape(3, 'Duplicate indexes (key prefix)',
                ['table', ('index_a','index_a (drop candidate)'),
                 ('index_b','index_b'), 'size_a', 'size_b', 'note'])
    if g: groups.append(g)

    # Set 4: Narrow vs wide redundancy
    g = reshape(4, 'Narrow vs wide redundancy (narrow_index is redundant)',
                ['table',
                 ('narrow_index','narrow_index (drop candidate)'),
                 'narrow_size', ('wide_index','wide_index'),
                 'wide_size'])
    if g: groups.append(g)

    # Set 5: Indexes on unused tables (rare)
    g = reshape(5, 'Indexes on unused tables',
                [('schema','schema'), ('table','table'),
                 ('index','index_name'), 'size'])
    if g: groups.append(g)

    # Set 6: Indexes never read
    g = reshape(6, 'Indexes never read',
                [('schema','schema'), ('table','table'),
                 ('index','index_name')])
    if g: groups.append(g)

    # Set 7: Tables relying on seq-scan (missing index?)
    g = reshape(7, 'Tables relying on seq-scan (missing index?)',
                ['schemaname', 'table', 'seq_scan', 'seq_tup_read',
                 'idx_scan', 'rows', 'table_size'])
    if g: groups.append(g)

    # Set 8: Foreign keys without supporting index
    g = reshape(8, 'Foreign keys without supporting index',
                ['table', 'fk_constraint', 'fk_columns', 'table_size'])
    if g: groups.append(g)

    return groups


def _ext_table_stats(text):
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if any(c in lc for c in ('relname', 'table_name', 'tablename', 'table')):
            return s['rows'][:200]
    return []


def _ext_bloat(text):
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if any(c in lc for c in ('bloat_pct', 'wasted_bytes', 'wasted_pct', 'bloat_ratio')):
            return s['rows'][:200]
        if 'relname' in lc:
            return s['rows'][:200]
    return []


def _ext_temp_files(text):
    """perf_09 set 0: per-database temp activity. set 1: per-statement.
    Return whichever set has rows whose temp counter is non-zero."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        # Look for any column that smells like temp metric
        temp_cols = [c for c in s['columns'] if 'temp_' in c.lower() or 'temp_blocks' in c.lower()]
        if not temp_cols:
            continue
        kept = []
        for r in s['rows']:
            nonzero = False
            for tc in temp_cols:
                v = (r.get(tc) or '').strip().lower()
                if v and v not in ('0', '0 bytes', '0.00', ''):
                    # treat any digit > 0 as positive
                    if any(ch.isdigit() and ch != '0' for ch in v):
                        nonzero = True
                        break
            if nonzero:
                kept.append(r)
        if kept:
            out = kept[:200]
            break
    return out


def _ext_capacity(text):
    # perf_15 has identity / sequence consumption + storage usage
    out = []
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if any('pct' in c or 'percent' in c or 'consumed' in c for c in lc):
            for r in s['rows']:
                # keep rows with >= 50% in any percent column
                for col, val in r.items():
                    m = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*%?', str(val))
                    if m:
                        try:
                            n = float(m.group(1))
                            if n >= 50 and 'pct' in col.lower():
                                out.append(r); break
                        except ValueError:
                            pass
    return out[:200]


def _ext_checkpoint(text):
    for s in parse_result_sets(text):
        if 'forced_checkpoints' in s['columns'] or 'forced_pct' in s['columns']:
            return s['rows'][:200]
    return []


def _ext_wait_events(text):
    # First table in perf_04: wait_event_type|wait_event|sessions|pct
    for s in parse_result_sets(text):
        if 'wait_event_type' in s['columns'] and 'sessions' in s['columns']:
            return s['rows'][:200]
    return []


RULES = [
    dict(
        script='perf_02_blocking_and_locks',
        mode='check', check=_check_perf_02,  severity='Critical',
        title='Active blocking sessions or long-running transactions',
        recommendation='Investigate blocking pairs and long-running open transactions. '
                       'They block autovacuum and grow the WAL.',
        extractor=_ext_blocking_pairs,
        ext_label='Top blocking / long-running sessions',
        ext_columns=None,
        commands=(
            "-- Inspect the blocking chain\n"
            "SELECT pid, blocked_by, query_start, state, query\n"
            "  FROM pg_stat_activity\n"
            " WHERE pid = ANY(pg_blocking_pids(<waiter-pid>));\n"
            "\n"
            "-- Cancel the offending query (gentle) or terminate the backend (hard)\n"
            "SELECT pg_cancel_backend(<blocker-pid>);\n"
            "SELECT pg_terminate_backend(<blocker-pid>);"
        ),
        docs=[
            ('pg_stat_activity',
             'https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW'),
            ('Lock monitoring',
             'https://wiki.postgresql.org/wiki/Lock_Monitoring'),
        ],
    ),
    dict(
        script='perf_01_top_sql',
        mode='has_data', severity='Warning',
        title='Top SQL by execution cost',
        recommendation='Tune or rewrite the highest-cost statements. Add indexes '
                       'where appropriate; verify that pg_stat_statements is reset '
                       'recently enough to be representative.',
        extractor=_ext_top_sql,
        ext_label='Top statements (snapshot)',
        ext_columns=None,
        commands=(
            "-- Walk the live ranking yourself\n"
            "SELECT queryid, calls, total_exec_time, mean_exec_time, rows, query\n"
            "  FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;\n"
            "\n"
            "-- Reset the stats after a tuning iteration to confirm impact\n"
            "SELECT pg_stat_statements_reset();\n"
            "\n"
            "-- Explain a flagged query\n"
            "EXPLAIN (ANALYZE, BUFFERS, VERBOSE) <statement>;"
        ),
        docs=[
            ('pg_stat_statements',
             'https://www.postgresql.org/docs/current/pgstatstatements.html'),
            ('EXPLAIN',
             'https://www.postgresql.org/docs/current/sql-explain.html'),
        ],
    ),
    dict(
        script='perf_04_wait_events_and_io',
        mode='pattern',
        pattern=r'(?i)\b(IO|LWLock|Lock|BufferPin|Client|Activity)\b',
        severity='Warning',
        title='Wait events captured',
        recommendation='Wait events were recorded. Review their distribution to '
                       'identify the dominant bottleneck (Lock, IO, LWLock, ...).',
        extractor=_ext_wait_events,
        ext_label='Wait event distribution',
        ext_columns=['wait_event_type', 'wait_event', 'sessions', 'pct'],
        commands=(
            "-- Sample live waits with names\n"
            "SELECT wait_event_type, wait_event, COUNT(*) AS sessions\n"
            "  FROM pg_stat_activity\n"
            " WHERE wait_event IS NOT NULL\n"
            " GROUP BY 1, 2 ORDER BY sessions DESC;"
        ),
        docs=[
            ('Wait event types',
             'https://www.postgresql.org/docs/current/monitoring-stats.html#WAIT-EVENT-TABLE'),
        ],
    ),
    dict(
        script='perf_06_index_audit',
        mode='has_data', severity='Warning',
        title='Index hygiene findings (unused / duplicate / missing)',
        recommendation='Drop confirmed-unused indexes, consolidate duplicates, '
                       'add high-value missing indexes after impact analysis.',
        extractor=_ext_index_findings,
        ext_label='Concrete index findings',
        ext_columns=None,
        commands=(
            "-- Verify an index is truly unused (multiple days of stats)\n"
            "SELECT schemaname, relname, indexrelname, idx_scan, idx_tup_read\n"
            "  FROM pg_stat_user_indexes ORDER BY idx_scan, pg_relation_size(indexrelid) DESC;\n"
            "\n"
            "-- Drop without blocking writers\n"
            "DROP INDEX CONCURRENTLY app.idx_users_email_dup;\n"
            "\n"
            "-- Create a missing index online\n"
            "CREATE INDEX CONCURRENTLY idx_orders_user_placed\n"
            "  ON app.orders (user_id, placed_at);"
        ),
        docs=[
            ('CREATE INDEX CONCURRENTLY',
             'https://www.postgresql.org/docs/current/sql-createindex.html#SQL-CREATEINDEX-CONCURRENTLY'),
            ('pg_stat_user_indexes',
             'https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ALL-INDEXES-VIEW'),
        ],
    ),
    dict(
        script='perf_07_table_stats_health',
        mode='has_data', severity='Warning',
        title='Stale autovacuum / autoanalyze targets',
        recommendation='Tables need autovacuum or autoanalyze. Tune per-table '
                       'thresholds or run VACUUM (ANALYZE) manually.',
        extractor=_ext_table_stats,
        ext_label='Tables flagged',
        ext_columns=None,
        commands=(
            "-- Refresh stats on a flagged table immediately\n"
            "VACUUM (ANALYZE, VERBOSE) app.orders;\n"
            "\n"
            "-- Lower the per-table threshold so autovacuum kicks in sooner\n"
            "ALTER TABLE app.orders\n"
            "  SET (autovacuum_vacuum_scale_factor = 0.05,\n"
            "       autovacuum_analyze_scale_factor = 0.02);"
        ),
        docs=[
            ('Autovacuum',
             'https://www.postgresql.org/docs/current/routine-vacuuming.html#AUTOVACUUM'),
        ],
    ),
    dict(
        script='perf_09_temp_and_memory_pressure',
        mode='pattern',
        pattern=r'(?im)temp_files\s*\|.*\b[1-9]\d*\b|temp_bytes\s*\|.*\b[1-9]\d*\b',
        severity='Warning',
        title='Temporary files spilled to disk',
        recommendation='work_mem is too low for some queries. Increase work_mem '
                       '(globally or per-role/db) or rewrite the spilling queries.',
        extractor=_ext_temp_files,
        ext_label='Databases with temp file activity',
        ext_columns=None,
        commands=(
            "-- Raise work_mem cautiously -- each parallel worker allocates this\n"
            "ALTER SYSTEM SET work_mem = '64MB';\n"
            "SELECT pg_reload_conf();\n"
            "\n"
            "-- Or per-role (better for OLTP-vs-analytics mix)\n"
            "ALTER ROLE analytics_reader SET work_mem = '256MB';\n"
            "\n"
            "-- Find which queries spill (pg_stat_statements 1.10+)\n"
            "SELECT query, temp_blks_written\n"
            "  FROM pg_stat_statements WHERE temp_blks_written > 0\n"
            "  ORDER BY temp_blks_written DESC LIMIT 20;"
        ),
        docs=[
            ('Resource consumption: work_mem',
             'https://www.postgresql.org/docs/current/runtime-config-resource.html#GUC-WORK-MEM'),
        ],
    ),
    dict(
        script='perf_10_replication_and_backup_impact',
        mode='pattern',
        pattern=r'(?im)replay_lag\s*\|\s*\d+:\d+:\d+',
        severity='Critical',
        title='Replication lag detected',
        recommendation='Replica is behind primary. Check network throughput and '
                       'replica I/O / replay capacity.',
        commands=(
            "-- Inspect replica state\n"
            "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn,\n"
            "       write_lag, flush_lag, replay_lag\n"
            "  FROM pg_stat_replication;\n"
            "\n"
            "-- On the replica: confirm it's catching up\n"
            "SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn(),\n"
            "       now() - pg_last_xact_replay_timestamp() AS apply_lag;"
        ),
        docs=[
            ('Streaming replication monitoring',
             'https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-REPLICATION-VIEW'),
            ('Aurora PostgreSQL replication',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Replication.Logical.html'),
        ],
    ),
    dict(
        script='perf_11_bloat_estimation',
        mode='has_data', severity='Warning',
        title='Table or index bloat exceeds threshold',
        recommendation='Run VACUUM (FULL) or pg_repack on the listed objects to '
                       'reclaim bloat.',
        extractor=_ext_bloat,
        ext_label='Top bloated objects',
        ext_columns=None,
        commands=(
            "-- Online rebuild via pg_repack (recommended -- minimal locking)\n"
            "pg_repack -h <host> -d <db> -U <user> -t app.orders\n"
            "\n"
            "-- VACUUM FULL is offline (takes ACCESS EXCLUSIVE)\n"
            "VACUUM (FULL, VERBOSE) app.orders;\n"
            "\n"
            "-- Rebuild a bloated index without blocking writes\n"
            "REINDEX INDEX CONCURRENTLY app.idx_orders_user_placed;"
        ),
        docs=[
            ('pg_repack',
             'https://reorg.github.io/pg_repack/'),
            ('REINDEX CONCURRENTLY',
             'https://www.postgresql.org/docs/current/sql-reindex.html#SQL-REINDEX-CONCURRENTLY'),
        ],
    ),
    dict(
        script='perf_14_checkpoint_bgwriter',
        mode='pattern',
        pattern=r'(?im)forced_checkpoints\s*\|\s*[1-9]\d*|checkpoints_req\s*\|\s*[1-9]\d*',
        severity='Warning',
        title='Requested (forced) checkpoints occurring',
        recommendation='Requested checkpoints indicate WAL pressure. Increase '
                       'max_wal_size or checkpoint_timeout.',
        extractor=_ext_checkpoint,
        ext_label='Checkpoint counters',
        ext_columns=None,
        commands=(
            "ALTER SYSTEM SET max_wal_size            = '4GB';\n"
            "ALTER SYSTEM SET checkpoint_timeout      = '15min';\n"
            "ALTER SYSTEM SET checkpoint_completion_target = 0.9;\n"
            "SELECT pg_reload_conf();"
        ),
        docs=[
            ('Write-Ahead Log: checkpoint tuning',
             'https://www.postgresql.org/docs/current/wal-configuration.html'),
        ],
    ),
    dict(
        script='perf_15_capacity_and_growth',
        mode='pattern',
        pattern=r'(?im)\b(5[0-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9]|100)\.\d+\s*%',
        severity='Critical',
        title='Capacity headroom under 50% (sequence / storage / connections)',
        recommendation='Plan widening (INT to BIGINT for sequences), storage '
                       'expansion, or raise max_connections before exhaustion.',
        extractor=_ext_capacity,
        ext_label='Objects near capacity',
        ext_columns=None,
        commands=(
            "-- Widen the column from INT to BIGINT\n"
            "ALTER TABLE app.orders ALTER COLUMN id TYPE BIGINT;\n"
            "ALTER SEQUENCE app.orders_id_seq AS BIGINT MAXVALUE 9223372036854775807;\n"
            "\n"
            "-- Raise max_connections (requires restart -- use pgbouncer first)\n"
            "ALTER SYSTEM SET max_connections = 500;\n"
            "\n"
            "# RDS / Aurora storage scaling\n"
            "aws rds modify-db-instance --db-instance-identifier <db> \\\n"
            "  --allocated-storage 200 --apply-immediately"
        ),
        docs=[
            ('Numeric types -- BIGINT range',
             'https://www.postgresql.org/docs/current/datatype-numeric.html'),
            ('Connection pooling with PgBouncer',
             'https://www.pgbouncer.org/usage.html'),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def find_findings(log_dir: Path) -> list:
    findings: list = []

    # 1. Failed scripts -> Critical
    for status, script in read_summary(log_dir / '_summary.txt'):
        if status != 'FAIL':
            continue
        log_base = script.replace('/', '_').replace('.sql', '.log')
        log_path = log_dir / log_base
        detail = '(no log captured)'
        if log_path.exists():
            if log_path.stat().st_size == 0:
                detail = '(empty log -- runner produced no output, likely killed mid-run)'
            else:
                errs = [l for l in read_log_text(log_path).splitlines()
                        if re.match(r'(ERROR|FATAL|psql:)', l)][:5]
                if errs:
                    detail = '\n'.join(errs)
        findings.append(dict(
            severity='Critical', script=script,
            title='Script execution failed', detail=detail,
            recommendation='Check connection privileges, psql version, and the script log file.',
            objects=[], object_columns=[], object_label='',
        ))

    # 2. Apply content rules
    for log in sorted(log_dir.glob('*.log')):
        for rule in RULES:
            if rule['script'] not in log.stem:
                continue
            text = read_log_text(log)
            if not text:
                continue
            hit = False
            detail = ''
            if rule['mode'] == 'has_data':
                if has_data_rows(text):
                    hit = True
            elif rule['mode'] == 'pattern':
                m = re.search(rule['pattern'], text)
                if m:
                    hit = True
                    snip = m.group(0)
                    detail = 'Match: ' + (snip if len(snip) <= 200 else snip[:200] + '...')
            elif rule['mode'] == 'check':
                # Custom predicate -- used when has_data is too broad
                # (e.g. perf_02 where lock/deadlock summary sets are
                # always non-empty but not actionable).
                try:
                    if rule['check'](text):
                        hit = True
                except Exception:
                    pass
            if not hit:
                continue
            objs: list = []
            ext_cols: list = []
            object_groups: list = []
            ext_label = rule.get('ext_label', '')
            extractor = rule.get('extractor')
            if extractor:
                try:
                    out = extractor(text)
                except Exception:
                    out = []
                # Detect whether the extractor returned a list of groups
                # ({label, columns, rows}, ...) or a flat list of rows.
                if (out and isinstance(out[0], dict)
                        and {'label', 'columns', 'rows'} <= set(out[0].keys())):
                    object_groups = out
                else:
                    objs = out
                    if objs and not rule.get('ext_columns'):
                        ext_cols = list(objs[0].keys())
                    elif objs:
                        ext_cols = rule['ext_columns']
            findings.append(dict(
                severity=rule['severity'], script=log.name,
                title=rule['title'], detail=detail,
                recommendation=rule['recommendation'],
                objects=objs, object_columns=ext_cols,
                object_label=ext_label,
                object_groups=object_groups,
                commands=rule.get('commands', ''),
                docs=rule.get('docs', []),
            ))
    return findings


def discover_contexts(root: Path) -> list:
    """Return [{name, log_dir}, ...]. Prefer the actual DB name (set later
    after fingerprint is read); fall back to '(single run)' here."""
    if (root / '_summary.txt').exists():
        return [dict(name='(single run)', log_dir=root)]
    contexts: list = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted(sub.glob('postgres_perf_*'), reverse=True)
        if runs:
            contexts.append(dict(name=sub.name, log_dir=runs[0]))
    return contexts


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
def render_top_issues(findings: list) -> str:
    """Top critical+warning findings with anchor links to detail rows."""
    top = [f for f in findings if f['severity'] in ('Critical', 'Warning')]
    top = sorted(top, key=lambda f: (severity_rank(f['severity']), f['script']))[:10]
    if not top:
        return "<p class='ok'>No critical or warning issues detected.</p>"
    parts = ["<p>Highest-priority findings. Click a title to jump to the detail "
             "row and the list of concrete objects flagged.</p>"
             "<ol class='issue-list'>"]
    for f in top:
        sev = f['severity'].lower()
        cls = 'warn' if sev == 'warning' else ''
        anchor = re.sub(r'[^A-Za-z0-9]', '-', f['script'] + '-' + f['title']).lower()
        parts.append(
            f"<li class='{cls}'><div class='it'>"
            f"<span class='ti'><a class='jump' href='#f-{anchor}'>{esc(f['title'])}</a></span>"
            f"<span class='sc'><span class='badge {sev}'>{f['severity']}</span> "
            f"&middot; <code>{esc(f['script'])}</code></span></div>"
            f"<div class='ac'><strong>Action:</strong> {esc(f['recommendation'])}</div>"
            f"</li>"
        )
    parts.append("</ol>")
    return ''.join(parts)


def render_findings(findings: list) -> str:
    """Card-based finding layout. Each finding is its own block with:
      - severity badge + title + script reference (header bar)
      - recommendation paragraph (the action item)
      - 0..N concrete-objects sub-tables (each with its own caption)

    Cards stack vertically, columns auto-size to their content -- so 5-
    char-per-line wrapping of identifiers is impossible by construction."""
    if not findings:
        return "<p class='ok'>No problems detected by the rule set.</p>"

    parts = []
    for f in sorted(findings, key=lambda x: (severity_rank(x['severity']), x['script'])):
        sev = f['severity'].lower()
        anchor = re.sub(r'[^A-Za-z0-9]', '-', f['script'] + '-' + f['title']).lower()
        parts.append(f"<div class='finding sev-{sev}' id='f-{anchor}'>")
        # Header
        parts.append(
            f"<div class='finding-head'>"
            f"<span class='badge {sev}'>{f['severity']}</span>"
            f"<span class='finding-title'>{esc(f['title'])}</span>"
            f"<span class='finding-script'><code>{esc(f['script'])}</code></span>"
            f"</div>"
        )
        # Recommendation
        parts.append(
            f"<div class='finding-rec'><strong>Action:</strong> "
            f"{esc(f['recommendation'])}</div>"
        )
        if f.get('detail'):
            parts.append(f"<div class='finding-detail'>{esc(f['detail'])}</div>")

        # Concrete objects
        if f.get('object_groups'):
            for g in f['object_groups']:
                link_columns = None
                if 'queryid' in g['columns']:
                    link_columns = {'queryid': '#sql-{value}'}
                parts.append(
                    f"<div class='objs-caption'><strong>{esc(g['label'])}</strong>"
                    f" &middot; {len(g['rows'])} row(s)</div>"
                    + object_table(g['rows'], g['columns'], limit=10,
                                   link_columns=link_columns)
                )
        elif f.get('objects') and f.get('object_columns'):
            parts.append(
                f"<div class='objs-caption'><strong>"
                f"{esc(f['object_label'] or 'Concrete objects')}</strong></div>"
                + object_table(f['objects'], f['object_columns'], limit=10)
            )
        if f.get('commands'):
            parts.append(
                "<div class='objs-caption'><strong>How to fix &mdash; "
                "starter commands</strong></div>"
                f"<pre class='cmd'>{esc(f['commands'])}</pre>"
            )
        if f.get('docs'):
            items = ''.join(
                f"<li><a href='{esc(url)}' target='_blank' rel='noopener'>"
                f"{esc(name)}</a></li>"
                for name, url in f['docs']
            )
            parts.append(
                "<div class='objs-caption'><strong>Further reading</strong></div>"
                f"<ul class='docs-list'>{items}</ul>"
            )
        parts.append("</div>")  # close .finding
    return ''.join(parts)


def build_html(report: list, server_label: str, report_dir: Path,
               fingerprint: dict, target: dict) -> str:
    total_pass = sum(r['passed']  for r in report)
    total_fail = sum(r['failed']  for r in report)
    total_crit = sum(r['critical'] for r in report)
    total_warn = sum(r['warning']  for r in report)
    total_info = sum(r['info']     for r in report)

    server = (server_label or fingerprint.get('cluster_name')
              or target.get('host') or '(unspecified)')

    parts = [f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<title>PostgreSQL Performance Audit Report</title>
{SHARED_CSS}
</head><body id='top'>
<header>
  <h1>PostgreSQL Performance Audit Report</h1>
  <p><strong>Server:</strong> {esc(server)}</p>
  <p><strong>Report folder:</strong> {esc(str(report_dir))}</p>
  <p><strong>Generated:</strong> {now_str()}</p>
</header>"""]

    # Quick navigation (hidden in print)
    parts.append(
        "<nav class='quick-nav'>"
        "<a href='#env-fingerprint'>Environment</a>"
        "<a href='#exec-summary'>Executive Summary</a>"
        "<a href='#findings'>Findings</a>"
        "<a href='#sql-appendix'>SQL Appendix</a>"
        "</nav>"
    )

    # Environment fingerprint
    parts.append("<a id='env-fingerprint'></a>")
    parts.append(render_fingerprint_card(fingerprint, target, report_dir))

    # Executive summary -- KPIs + Top issues
    parts.append("<a id='exec-summary'></a>")
    parts.append("<div class='card'><h2 style='margin-top:0;border:none;'>"
                 "Executive Summary<a class='back-top' href='#top'>top &uarr;</a></h2>")
    parts.append("<div class='kpi-row'>")
    parts.append(
        f"<div class='kpi'><div class='lbl'>Databases analysed</div><div class='num'>{len(report)}</div></div>"
        f"<div class='kpi'><div class='lbl'>Scripts OK</div><div class='num'>{total_pass}</div></div>"
        f"<div class='kpi {'fail' if total_fail else ''}'><div class='lbl'>Failed scripts</div><div class='num fail'>{total_fail}</div></div>"
        f"<div class='kpi {'crit' if total_crit else ''}'><div class='lbl'>Critical findings</div><div class='num crit'>{total_crit}</div></div>"
        f"<div class='kpi {'warn' if total_warn else ''}'><div class='lbl'>Warnings</div><div class='num warn'>{total_warn}</div></div>"
    )
    parts.append("</div>")
    # Aggregate findings across all contexts for the Top issues block
    all_findings = []
    for r in report:
        all_findings.extend(r['findings'])
    parts.append("<h3>Top issues -- what to fix</h3>")
    parts.append(render_top_issues(all_findings))
    # Per-context rollup table -- only shown for multi-database runs;
    # for a single context the KPI cards above already cover the same
    # numbers and the extra table is pure noise.
    if len(report) > 1:
        parts.append(
            "<h3>Context rollup</h3>"
            "<table class='exec-summary'><thead><tr>"
            "<th>Database / Context</th><th>Scripts OK</th><th>Failed</th>"
            "<th>Critical</th><th>Warning</th><th>Info</th></tr></thead><tbody>"
        )
        for r in report:
            anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
            parts.append(
                f"<tr><td><a href='#db_{anchor}'>{esc(r['name'])}</a></td>"
                f"<td class='num'>{r['passed']}</td>"
                f"<td class='num fail'>{r['failed']}</td>"
                f"<td class='num crit'>{r['critical']}</td>"
                f"<td class='num warn'>{r['warning']}</td>"
                f"<td class='num'>{r['info']}</td></tr>"
            )
        parts.append(
            f"<tr style='font-weight:bold;background:#eef3f7;'><td>TOTAL</td>"
            f"<td class='num'>{total_pass}</td>"
            f"<td class='num fail'>{total_fail}</td>"
            f"<td class='num crit'>{total_crit}</td>"
            f"<td class='num warn'>{total_warn}</td>"
            f"<td class='num'>{total_info}</td></tr>"
            f"</tbody></table>"
        )
    parts.append("</div>")  # close exec-summary card

    # Findings -- one section, with a header so the reader knows what
    # they're scrolling into.
    parts.append("<a id='findings'></a>")
    multi = len(report) > 1
    parts.append("<div class='card'><h2 style='margin-top:0;border:none;'>"
                 "Findings<a class='back-top' href='#top'>top &uarr;</a></h2>")
    for r in report:
        anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
        if multi:
            parts.append(f"<section class='db' id='db_{anchor}'>")
            parts.append(f"<h3>{esc(r['name'])}</h3>")
        parts.append(
            f"<div class='meta'>Logs: <code>{esc(str(r['log_dir']))}</code> "
            f"&middot; Scripts run: {r['passed'] + r['failed']} "
            f"(OK: {r['passed']}, Failed: {r['failed']})</div>"
        )
        parts.append(render_findings(r['findings']))
        if multi:
            parts.append("</section>")
    parts.append("</div>")  # close findings card

    # SQL appendix -- full untruncated text per queryid, anchored so the
    # queryid cells in the Top SQL tables link straight to it.
    parts.append(render_sql_appendix(report))

    parts.append("</body></html>")
    return ''.join(parts)


def render_sql_appendix(report: list) -> str:
    """Build the appendix section listing full SQL text per queryid.
    Pulls from perf_01_top_sql logs across all contexts, de-duplicating
    by queryid so each statement appears exactly once."""
    by_qid: dict = {}
    for r in report:
        log = find_log(r['log_dir'], 'perf_01_top_sql')
        if not log:
            continue
        text = read_log_text(log)
        for s in parse_result_sets(text):
            cols = s['columns']
            if 'queryid' not in cols or 'query' not in cols:
                continue
            for row in s['rows']:
                qid = (row.get('queryid') or '').strip()
                q   = (row.get('query')   or '').strip()
                if qid and q and qid not in by_qid:
                    by_qid[qid] = dict(query=q, context=r['name'])
    if not by_qid:
        return ''
    parts = ["<section class='card' id='sql-appendix'>"
             "<h2 style='margin-top:0;'>SQL Appendix -- full text by queryid"
             "<a class='back-top' href='#top'>top &uarr;</a></h2>"
             f"<div class='meta'>One entry per unique pg_stat_statements queryid surfaced in Top SQL "
             f"({len(by_qid)} statements). queryid links in the Top SQL tables jump here.</div>"]

    # Mini index at the top -- queryid -> one-line preview. Lets the
    # reader scan all SQL labels without scrolling through every <pre>.
    sorted_qids = sorted(by_qid, key=lambda k: int(k) if k.lstrip('-').isdigit() else 0)
    parts.append("<details class='sql-index'><summary>"
                 f"Jump-to index ({len(sorted_qids)} statements)</summary><ul>")
    for qid in sorted_qids:
        preview = by_qid[qid]['query'].strip().replace('\n', ' ')
        if len(preview) > 100:
            preview = preview[:100] + '...'
        parts.append(
            f"<li><a href='#sql-{esc(qid)}'><code>{esc(qid)}</code></a> "
            f"&middot; {esc(preview)}</li>"
        )
    parts.append("</ul></details>")

    for qid in sorted_qids:
        entry = by_qid[qid]
        q = entry['query']
        if len(q) > 5000:
            q = q[:5000] + '\n-- ... truncated; see raw .log file for the full text'
        parts.append(
            f"<h4 id='sql-{esc(qid)}'>queryid <code>{esc(qid)}</code> "
            f"<span style='font-weight:normal;color:#888'>({esc(entry['context'])})</span>"
            f"<a class='back-top' href='#top'>top &uarr;</a></h4>"
            f"<pre class='sql-full'>{esc(q)}</pre>"
        )
    parts.append("</section>")
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('report_dir', help='Folder produced by run_audit.sh / run_all_databases.sh')
    ap.add_argument('--server', default='', help='Server label printed on the cover')
    ap.add_argument('--out',    default='', help='Output HTML path (default: <report_dir>/perf_analysis.html)')
    args = ap.parse_args()

    report_dir = Path(args.report_dir).resolve()
    if not report_dir.is_dir():
        print(f'ERROR: report directory not found: {report_dir}', file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else (report_dir / 'perf_analysis.html')

    contexts = discover_contexts(report_dir)
    if not contexts:
        print(f'ERROR: no log folders found under {report_dir}', file=sys.stderr)
        return 3

    target = read_target(report_dir)

    report = []
    fingerprint = {}
    for ctx in contexts:
        findings = find_findings(ctx['log_dir'])
        passed = failed = 0
        for status, _ in read_summary(ctx['log_dir'] / '_summary.txt'):
            if status == 'OK':   passed += 1
            elif status == 'FAIL': failed += 1
        ctx_fp = read_fingerprint(ctx['log_dir'], ('perf_05_configuration_snapshot',))
        if not fingerprint and ctx_fp:
            fingerprint = ctx_fp
        # Replace "(single run)" with actual DB name when available.
        ctx_name = context_label(ctx_fp, target, ctx['name'])
        report.append(dict(
            name=ctx_name, log_dir=ctx['log_dir'], findings=findings,
            passed=passed, failed=failed,
            critical=sum(1 for f in findings if f['severity']=='Critical'),
            warning =sum(1 for f in findings if f['severity']=='Warning'),
            info    =sum(1 for f in findings if f['severity']=='Info'),
        ))

    out.write_text(build_html(report, args.server, report_dir, fingerprint, target),
                   encoding='utf-8')

    total_crit = sum(r['critical'] for r in report)
    total_warn = sum(r['warning']  for r in report)
    total_fail = sum(r['failed']   for r in report)
    print('=' * 80)
    print('Performance audit analysis complete.')
    print(f'  Databases analysed : {len(report)}')
    print(f'  Critical findings  : {total_crit}')
    print(f'  Warnings           : {total_warn}')
    print(f'  Failed scripts     : {total_fail}')
    print(f'  Report             : {out}')
    print('=' * 80)
    return 0


if __name__ == '__main__':
    sys.exit(main())
