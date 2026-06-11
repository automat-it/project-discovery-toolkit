#!/usr/bin/env python3
"""
analyze_report.py -- MySQL performance audit report analyzer.

Reads the report directory produced by mysql/perf/run_audit.sh and writes
an HTML report with:

  * Environment fingerprint card (host, version, role, Aurora/RDS flag, ...)
  * Executive summary (KPI counts + Top issues with what-to-do)
  * Per-finding concrete objects (table / index names, digest IDs, etc.)
    pulled from the actual mysql(1) batch-mode logs so the reader has
    actionable targets, not just "review the log".

Usage:
    ./analyze_report.py <report_dir>
    ./analyze_report.py <report_dir> --server prod-mysql-01

Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Import shared analyzer library (mysql/_analyze_lib.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _analyze_lib import (  # noqa: E402
    DOMAIN_BUCKETS_PERF, SHARED_CSS, context_label, copy_brand_assets,
    domain_counts, esc, find_log, has_data_rows, kv_grid, now_str,
    object_table, parse_result_sets, read_fingerprint, read_log_text,
    read_summary, read_target, render_at_a_glance, render_cover,
    render_fingerprint_card,
    script_matches_log, severity_rank, svg_bar, svg_donut,
)


# ---------------------------------------------------------------------------
# Rules: how to recognise a finding in a given log file.
# Each rule is processed in two stages:
#   1. trigger -- 'has_data' (any rows present) or 'pattern' (regex match)
#      or 'check' (custom predicate)
#   2. extractor (optional) -- pull a structured list of "objects of
#      concern" from the log to render under the finding row.
# ---------------------------------------------------------------------------
def _set_with(sets, *col_names):
    """Return the first non-empty result set whose columns include ANY of
    the given names (case-insensitive). Used by simple extractors that
    just need to find 'the right' table among multiple in one log."""
    wanted = {c.lower() for c in col_names}
    for s in sets:
        if not s['rows']:
            continue
        if {c.lower() for c in s['columns']} & wanted:
            return s
    return None


def _ext_top_sql(text):
    """perf_01 emits the consumer-status row plus several Top-N snapshots
    over events_statements_summary_by_digest. The actionable rows always
    have a `queryid` column. We curate to 5 columns + link queryid to
    the SQL appendix at the end of the report."""
    sets = parse_result_sets(text)
    labels = [
        'Top by total execution time',
        'Top by mean execution time',
        'Top by call count',
        'Top by rows returned',
        'Top by examined-row ratio',
        'Top by temp tables',
        'Top by lock time',
    ]

    def pick(row, *names, default=''):
        for n in names:
            if n in row and row[n] != '':
                return row[n]
        return default

    groups = []
    metric_cols = {'total_min', 'total_ms', 'mean_ms', 'avg_ms', 'calls',
                   'pct_total', 'pct_calls', 'rows', 'examined_ratio'}
    for s in sets:
        if not s['rows']:
            continue
        cols_lc = [c.lower() for c in s['columns']]
        if 'queryid' not in cols_lc:
            continue
        # Sub-tables in perf_01 that happen to expose queryid but no
        # ranking metric are not actionable "top SQL" snapshots.
        if not (metric_cols & set(cols_lc)):
            continue
        new_rows = []
        for r in s['rows'][:200]:
            new_rows.append({
                'queryid':   pick(r, 'queryid'),
                'calls':     pick(r, 'calls'),
                'total_min': pick(r, 'total_min', 'total_ms'),
                'mean_ms':   pick(r, 'mean_ms', 'avg_ms'),
                'pct_total': pick(r, 'pct_total', 'pct_calls'),
                # 'query' kept in the source row so the SQL appendix can
                # pull the digest text; it is NOT rendered inline.
                'query':     pick(r, 'query'),
            })
        groups.append(dict(
            label=labels[len(groups)] if len(groups) < len(labels)
                  else f'Top SQL set #{len(groups)+1}',
            columns=['queryid', 'calls', 'total_min', 'mean_ms', 'pct_total'],
            rows=new_rows,
        ))
    return groups


def _check_perf_02(text):
    """True only when perf_02 returned actually-blocking sessions or
    long-running transactions. The script also emits InnoDB lock
    summary / event scheduler etc. that are always non-empty -- those
    must NOT trigger the finding."""
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        # Real blocking signal: data_locks_waits or innodb_trx with locks
        if 'blocking_thread_id' in lc or 'blocked_thread_id' in lc:
            if s['rows']:
                return True
        # Long-running active queries (excluding daemon rows we already
        # see by default like 'event_scheduler')
        if 'seconds' in lc and 'state' in lc and 'query' in lc:
            for r in s['rows']:
                try:
                    # float, not int -- some PERFORMANCE_SCHEMA views emit
                    # fractional seconds (e.g. '61.500000').
                    sec = float(r.get('seconds') or '0')
                except (TypeError, ValueError):
                    continue
                if sec > 60 and (r.get('query') or '').strip() not in ('', 'NULL'):
                    return True
    return False


def _ext_blocking(text):
    """Render blocking-pair / long-running tables as separate groups so
    the reader sees them with their natural columns."""
    sets = parse_result_sets(text)
    groups = []
    for s in sets:
        lc = [c.lower() for c in s['columns']]
        if not s['rows']:
            continue
        if 'blocking_thread_id' in lc or 'blocked_thread_id' in lc:
            groups.append(dict(label='Blocking pairs (data_locks_waits)',
                               columns=s['columns'], rows=s['rows'][:200]))
        elif 'seconds' in lc and 'query' in lc:
            # Drop event_scheduler daemon noise
            kept = [r for r in s['rows']
                    if (r.get('user') or '').strip() != 'event_scheduler']
            if kept:
                groups.append(dict(label='Active sessions (>0 s)',
                                   columns=s['columns'], rows=kept[:200]))
    return groups


def _ext_index_findings(text):
    """perf_06 emits multiple sub-tables. Surface each as its own group
    with curated columns (drop raw byte counts, keep names + sizes)."""
    sets = parse_result_sets(text)

    def reshape(set_idx, label, picks):
        if not (0 <= set_idx < len(sets)) or not sets[set_idx]['rows']:
            return None
        new_rows = []
        for r in sets[set_idx]['rows'][:200]:
            row = {}
            for p in picks:
                src, disp = (p if isinstance(p, tuple) else (p, p))
                row[disp] = r.get(src, '')
            new_rows.append(row)
        return dict(label=label, rows=new_rows,
                    columns=[(p[1] if isinstance(p, tuple) else p) for p in picks])

    groups = []
    # Set 0: I/O activity per index (low reads -> candidate for unused)
    g = reshape(0, 'Index I/O activity (low reads => candidates to drop)',
                [('schema_name','schema'), 'table_name',
                 ('index_name','index_name'),
                 'reads', 'writes', 'fetches'])
    if g: groups.append(g)
    # Set 1: sys.schema_unused_indexes
    g = reshape(1, 'Indexes never read (sys.schema_unused_indexes)',
                [('object_schema','schema'), 'table_name',
                 ('index_name','index_name')])
    if g: groups.append(g)
    # Sets 2..N: duplicates / redundant / FK without index -- discover
    # remaining sets and emit each with its native columns.
    for i, s in enumerate(sets[2:], start=2):
        if not s['rows']:
            continue
        # Pick a useful label heuristically from column names.
        lc = [c.lower() for c in s['columns']]
        if 'duplicate_of' in lc:
            label = f'Duplicate / redundant indexes (set #{i+1})'
        elif 'fk_columns' in lc or any('fk' in c for c in lc):
            label = 'Foreign keys without supporting index'
        elif 'cardinality' in lc:
            label = f'Index cardinality / selectivity (set #{i+1})'
        else:
            label = f'Index sub-table #{i+1}'
        groups.append(dict(label=label, columns=s['columns'],
                           rows=s['rows'][:200]))
    return groups


def _ext_table_stats(text):
    """perf_07: tables with stale stats / never-analyzed (last_modified
    NULL means InnoDB hasn't run a write-triggered analyze)."""
    s = _set_with(parse_result_sets(text),
                  'table_name', 'TABLE_NAME', 'tablename')
    return s['rows'][:200] if s else []


def _ext_object_sizes(text):
    """perf_08: render the per-table size table (skip the per-schema
    rollup which has only one row)."""
    sets = parse_result_sets(text)
    groups = []
    for s in sets:
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        if 'table_name' in lc and 'total_mb' in lc:
            groups.append(dict(label='Top tables by total size (MB)',
                               columns=s['columns'], rows=s['rows'][:200]))
            break
    return groups


def _ext_temp_pressure(text):
    """perf_09: pull rows whose temp/disk-spill columns are > 0."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        lc = [c.lower() for c in s['columns']]
        keys = [c for c in s['columns']
                if 'tmp_disk' in c.lower() or 'sort_merge' in c.lower()
                or 'created_tmp' in c.lower() or 'temp' in c.lower()]
        if not keys:
            continue
        for r in s['rows']:
            for k in keys:
                v = (r.get(k) or '').strip()
                if v and v != '0' and v != 'NULL' and any(ch.isdigit() and ch != '0' for ch in v):
                    out.append(r)
                    break
    return out[:200]


def _ext_bloat(text):
    """perf_11: tables with non-trivial data_free fraction."""
    s = _set_with(parse_result_sets(text),
                  'free_pct', 'bloat_pct', 'free_mb')
    if not s:
        return []
    # Filter to rows where free_pct > 20% if column present
    pct_col = None
    for c in s['columns']:
        if c.lower() in ('free_pct', 'bloat_pct'):
            pct_col = c
            break
    if not pct_col:
        return s['rows'][:200]
    keep = []
    for r in s['rows']:
        try:
            if float(r.get(pct_col) or 0) > 20:
                keep.append(r)
        except ValueError:
            pass
    return keep[:200] or s['rows'][:200]


def _ext_seq_scans(text):
    """perf_12: tables without useful indexes -- the no_index_table demo
    is a classic case."""
    s = _set_with(parse_result_sets(text),
                  'table_name', 'TABLE_NAME')
    return s['rows'][:200] if s else []


def _ext_capacity(text):
    """perf_15: AUTO_INCREMENT consumption, max_connections usage etc."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        lc = [c.lower() for c in s['columns']]
        if not any('pct' in c or 'percent' in c or 'consumed' in c or 'used' in c
                   for c in lc):
            continue
        for r in s['rows']:
            for col, val in r.items():
                if 'pct' not in col.lower() and 'percent' not in col.lower():
                    continue
                try:
                    if float(str(val).rstrip('%')) >= 50:
                        out.append(r); break
                except ValueError:
                    pass
    return out[:200]


def _ext_partitions(text):
    """perf_21: per-partition row counts / sizes."""
    s = _set_with(parse_result_sets(text),
                  'partition_name', 'PARTITION_NAME')
    return s['rows'][:200] if s else []


RULES = [
    dict(
        script='perf_01_top_sql',
        mode='has_data', severity='Warning',
        title='Top SQL by execution cost',
        recommendation='Tune or rewrite the highest-cost statements. Add indexes '
                       'where appropriate. Verify performance_schema digest '
                       'instrumentation is enabled and recent.',
        extractor=_ext_top_sql,
        ext_label='Top statements (snapshot)',
        ext_columns=None,
        commands=(
            "-- Walk the live ranking yourself\n"
            "SELECT DIGEST_TEXT, COUNT_STAR, SUM_TIMER_WAIT/1e12 AS total_sec,\n"
            "       AVG_TIMER_WAIT/1e9 AS avg_ms, SUM_ROWS_EXAMINED\n"
            "  FROM performance_schema.events_statements_summary_by_digest\n"
            "  ORDER BY SUM_TIMER_WAIT DESC LIMIT 20;\n"
            "\n"
            "-- Get the EXPLAIN for a flagged digest\n"
            "EXPLAIN ANALYZE <statement-from-digest>;"
        ),
        docs=[
            ('performance_schema digest tables',
             'https://dev.mysql.com/doc/refman/8.0/en/performance-schema-statement-digests.html'),
            ('EXPLAIN ANALYZE',
             'https://dev.mysql.com/doc/refman/8.0/en/explain.html#explain-analyze'),
        ],
    ),
    dict(
        script='perf_02_blocking_and_locks',
        mode='check', check=_check_perf_02, severity='Critical',
        title='Active blocking sessions or long-running transactions',
        recommendation='Investigate blocking pairs and long-running open '
                       'transactions. They hold InnoDB undo segments and prevent '
                       'purge.',
        extractor=_ext_blocking,
        ext_label='Concrete blocking / long-running rows',
        ext_columns=None,
        commands=(
            "-- Inspect the blocker / waiter chain\n"
            "SELECT * FROM performance_schema.data_lock_waits;\n"
            "SELECT * FROM information_schema.innodb_trx WHERE trx_started < NOW() - INTERVAL 5 MINUTE;\n"
            "\n"
            "-- Kill the offending session (use with care)\n"
            "KILL <thread_id>;"
        ),
        docs=[
            ('InnoDB monitoring (data_locks / data_lock_waits)',
             'https://dev.mysql.com/doc/refman/8.0/en/performance-schema-data-locks-table.html'),
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
            "SELECT * FROM sys.schema_unused_indexes;\n"
            "\n"
            "-- Make it invisible first (8.0+), drop after a soak period\n"
            "ALTER TABLE audit_test.users ALTER INDEX idx_users_email_dup INVISIBLE;\n"
            "ALTER TABLE audit_test.users DROP INDEX idx_users_email_dup;"
        ),
        docs=[
            ('sys schema: schema_unused_indexes',
             'https://dev.mysql.com/doc/refman/8.0/en/sys-schema-unused-indexes.html'),
            ('Invisible indexes',
             'https://dev.mysql.com/doc/refman/8.0/en/invisible-indexes.html'),
        ],
    ),
    dict(
        script='perf_07_table_stats_health',
        mode='has_data', severity='Warning',
        title='Stale or never-analyzed table statistics',
        recommendation='Run ANALYZE TABLE on the listed tables or enable '
                       'innodb_stats_auto_recalc. Stale stats produce bad plans.',
        extractor=_ext_table_stats,
        ext_label='Tables flagged',
        ext_columns=None,
        commands=(
            "-- Refresh stats for a flagged table\n"
            "ANALYZE TABLE audit_test.orders;\n"
            "\n"
            "-- Enable auto-recalc cluster-wide (Aurora: via DB cluster param group)\n"
            "SET PERSIST innodb_stats_auto_recalc = ON;\n"
            "SET PERSIST innodb_stats_persistent  = ON;"
        ),
        docs=[
            ('Optimizer statistics',
             'https://dev.mysql.com/doc/refman/8.0/en/innodb-persistent-stats.html'),
        ],
    ),
    dict(
        script='perf_08_object_sizes',
        mode='has_data', severity='Info',
        title='Top tables by total size',
        recommendation='Inventory of largest tables -- review for archive / '
                       'partition / TTL opportunities.',
        extractor=_ext_object_sizes,
        ext_label='Top tables',
        ext_columns=None,
        docs=[
            ('information_schema.TABLES sizing',
             'https://dev.mysql.com/doc/refman/8.0/en/information-schema-tables-table.html'),
        ],
    ),
    dict(
        script='perf_09_temp_and_memory_pressure',
        mode='pattern',
        pattern=r'(?im)Created_tmp_disk_tables\s+[1-9]\d*|created_tmp_disk_tables\t[1-9]\d*',
        severity='Warning',
        title='Temporary tables spilling to disk',
        recommendation='Increase tmp_table_size and max_heap_table_size, or '
                       'rewrite spilling queries to avoid large in-memory '
                       'sorts / joins.',
        extractor=_ext_temp_pressure,
        ext_label='Statements / status counters with non-zero spill',
        ext_columns=None,
        commands=(
            "-- Raise the in-memory temp ceiling (RDS / Aurora: via param group)\n"
            "SET PERSIST tmp_table_size      = 268435456;  -- 256 MiB\n"
            "SET PERSIST max_heap_table_size = 268435456;\n"
            "\n"
            "-- Find which digests are spilling\n"
            "SELECT digest_text, SUM_CREATED_TMP_DISK_TABLES\n"
            "  FROM performance_schema.events_statements_summary_by_digest\n"
            "  WHERE SUM_CREATED_TMP_DISK_TABLES > 0\n"
            "  ORDER BY SUM_CREATED_TMP_DISK_TABLES DESC LIMIT 20;"
        ),
        docs=[
            ('Internal temporary tables',
             'https://dev.mysql.com/doc/refman/8.0/en/internal-temporary-tables.html'),
        ],
    ),
    dict(
        script='perf_10_replication_and_backup_impact',
        mode='pattern',
        pattern=r'(?im)Seconds_Behind_(Source|Master)\s+[1-9]\d*',
        severity='Critical',
        title='Replica lag detected',
        recommendation='Replica is behind primary. Check parallel-replication '
                       'settings (replica_parallel_workers, replica_preserve_'
                       'commit_order) and IO capacity.',
        commands=(
            "-- See per-worker apply progress\n"
            "SELECT CHANNEL_NAME, WORKER_ID, SERVICE_STATE, LAST_APPLIED_TRANSACTION\n"
            "  FROM performance_schema.replication_applier_status_by_worker;\n"
            "\n"
            "-- Raise parallel apply (requires restart; Aurora: cluster param group)\n"
            "SET PERSIST replica_parallel_workers       = 8;\n"
            "SET PERSIST replica_parallel_type          = 'LOGICAL_CLOCK';\n"
            "SET PERSIST replica_preserve_commit_order  = ON;"
        ),
        docs=[
            ('Replica lag troubleshooting',
             'https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-monitoring.html'),
            ('Aurora MySQL replication',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Replication.MySQL.html'),
        ],
    ),
    dict(
        script='perf_11_bloat_estimation',
        mode='has_data', severity='Warning',
        title='Table free-space (bloat) above threshold',
        recommendation='Run OPTIMIZE TABLE (or ALTER TABLE ... ENGINE=InnoDB) '
                       'on the listed tables to reclaim free space. Heavy '
                       'free_pct indicates UPDATE/DELETE churn.',
        extractor=_ext_bloat,
        ext_label='Top bloated tables',
        ext_columns=None,
        commands=(
            "-- Reclaim free space (rebuilds the table -- offline-ish on big tables)\n"
            "ALTER TABLE audit_test.orders ENGINE=InnoDB,\n"
            "  ALGORITHM=INPLACE, LOCK=NONE;"
        ),
        docs=[
            ('Defragmenting a table',
             'https://dev.mysql.com/doc/refman/8.0/en/innodb-file-defragmenting.html'),
        ],
    ),
    dict(
        script='perf_12_sequential_scans',
        mode='has_data', severity='Warning',
        title='Tables candidate for sequential scans (missing indexes)',
        recommendation='Add indexes covering common WHERE / JOIN columns. '
                       'no_index_table-style cases are immediate.',
        extractor=_ext_seq_scans,
        ext_label='Tables without useful indexes',
        ext_columns=None,
        commands=(
            "-- Find candidate columns from slow log / digest stats\n"
            "SELECT digest_text FROM performance_schema.events_statements_summary_by_digest\n"
            "  WHERE digest_text LIKE '%FROM audit_test.audit_log%' ORDER BY COUNT_STAR DESC;\n"
            "\n"
            "-- Add the index online\n"
            "ALTER TABLE audit_test.audit_log\n"
            "  ADD INDEX idx_audit_actor_ts (actor, ts),\n"
            "  ALGORITHM=INPLACE, LOCK=NONE;"
        ),
        docs=[
            ('Indexing strategy',
             'https://dev.mysql.com/doc/refman/8.0/en/optimization-indexes.html'),
        ],
    ),
    dict(
        script='perf_15_capacity_and_growth',
        mode='pattern',
        # Require trailing `%` so the rule fires only on capacity-percent
        # columns -- without it, ANY numeric column with a 50+ value
        # (durations, sizes, row counts) wrongly produces a Critical.
        pattern=r'(?im)\b(5[0-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9]|100)\.\d+\s*%',
        severity='Critical',
        title='Capacity headroom under 50% (AUTO_INCREMENT / storage / conns)',
        recommendation='Plan AUTO_INCREMENT widening (INT->BIGINT), storage '
                       'expansion, or raise max_connections before exhaustion.',
        extractor=_ext_capacity,
        ext_label='Objects near capacity',
        ext_columns=None,
        commands=(
            "-- Widen AUTO_INCREMENT to BIGINT (online on 8.0)\n"
            "ALTER TABLE audit_test.orders\n"
            "  MODIFY id BIGINT NOT NULL AUTO_INCREMENT,\n"
            "  ALGORITHM=INPLACE, LOCK=NONE;\n"
            "\n"
            "-- RDS / Aurora: grow storage\n"
            "aws rds modify-db-instance --db-instance-identifier <db> \\\n"
            "  --allocated-storage 200 --apply-immediately"
        ),
        docs=[
            ('Using AUTO_INCREMENT',
             'https://dev.mysql.com/doc/refman/8.0/en/example-auto-increment.html'),
            ('RDS storage scaling',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIOPS.StorageTypes.html'),
        ],
    ),
    dict(
        script='perf_21_partition_health',
        mode='has_data', severity='Info',
        title='Partition layout / size distribution',
        recommendation='Review partition skew, empty future partitions, and '
                       'oversized historical partitions.',
        extractor=_ext_partitions,
        ext_label='Partitions',
        ext_columns=None,
        commands=(
            "-- Add a future RANGE partition (typical retention pattern)\n"
            "ALTER TABLE audit_test.events\n"
            "  REORGANIZE PARTITION pmax INTO (\n"
            "    PARTITION p202607 VALUES LESS THAN (TO_DAYS('2026-08-01')),\n"
            "    PARTITION pmax    VALUES LESS THAN MAXVALUE\n"
            "  );\n"
            "\n"
            "-- Drop the oldest partition (instant -- no row scan)\n"
            "ALTER TABLE audit_test.events DROP PARTITION p202401;"
        ),
        docs=[
            ('Partitioning',
             'https://dev.mysql.com/doc/refman/8.0/en/partitioning.html'),
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

    # 2. Apply content rules. Read each .log at most once.
    log_text_cache: dict = {}
    for log in sorted(log_dir.glob('*.log')):
        for rule in RULES:
            if not script_matches_log(rule['script'], log.stem):
                continue
            if log not in log_text_cache:
                log_text_cache[log] = read_log_text(log)
            text = log_text_cache[log]
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
                except Exception as e:
                    print(f'[warn] check predicate failed on {log.name}: {e}',
                          file=sys.stderr)
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
                except Exception as e:
                    print(f'[warn] extractor {extractor.__name__} failed on '
                          f'{log.name}: {e}', file=sys.stderr)
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
        runs = sorted(sub.glob('mysql_perf_*'), reverse=True)
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
               fingerprint: dict, target: dict, customer: str = '') -> str:
    total_pass = sum(r['passed']  for r in report)
    total_fail = sum(r['failed']  for r in report)
    total_crit = sum(r['critical'] for r in report)
    total_warn = sum(r['warning']  for r in report)
    total_info = sum(r['info']     for r in report)

    server = (server_label or fingerprint.get('cluster_name')
              or target.get('host') or '(unspecified)')

    parts = [f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<title>MySQL Performance Audit Report</title>
{SHARED_CSS}
</head><body id='top'>"""]

    # Branded cover + watermark (matches MSSQL analyzer).
    parts.append(render_cover('MySQL Performance Audit Report',
                              server, customer, len(report)))

    parts.append(f"""<header>
  <h1>MySQL Performance Audit Report</h1>
  <p><strong>Server:</strong> {esc(server)}</p>
  <p><strong>Report folder:</strong> {esc(report_dir.name)}</p>
  <p><strong>Generated:</strong> {now_str()}</p>
</header>""")

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
    all_findings = []
    for r in report:
        all_findings.extend(r['findings'])
    parts.append("<a id='exec-summary'></a>")
    parts.append("<section class='section card'><h2>1. Executive Summary</h2>")
    parts.append(render_at_a_glance(len(report), total_crit, total_warn,
                                    total_info, all_findings))
    parts.append("<p class='intro'>Snapshot of this audit: how many databases "
                 "were analyzed, the severity mix of findings, and which "
                 "functional areas drove the count.</p>")
    parts.append("<div class='kpi-row'>"
                 f"<div class='kpi'><span class='lbl'>Databases analyzed</span>"
                 f"<span class='num'>{len(report)}</span></div>"
                 f"<div class='kpi'><span class='lbl'>Critical findings</span>"
                 f"<span class='num crit'>{total_crit}</span></div>"
                 f"<div class='kpi'><span class='lbl'>Warning findings</span>"
                 f"<span class='num warn'>{total_warn}</span></div>"
                 f"<div class='kpi'><span class='lbl'>Info findings</span>"
                 f"<span class='num'>{total_info}</span></div>"
                 f"<div class='kpi'><span class='lbl'>Failed scripts</span>"
                 f"<span class='num fail'>{total_fail}</span></div>"
                 "</div>")
    domain_data = domain_counts(all_findings, DOMAIN_BUCKETS_PERF)
    parts.append("<div class='charts-row'>")
    parts.append(f"<div>{svg_donut(total_crit, total_warn, total_info)}</div>")
    if domain_data:
        parts.append("<div><h3>Findings by Domain</h3>"
                     f"{svg_bar(domain_data)}</div>")
    parts.append("</div>")
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
    parts.append("</section>")  # close 1. Executive Summary

    # Findings -- one section, with a header so the reader knows what
    # they're scrolling into.
    parts.append("<a id='findings'></a>")
    multi = len(report) > 1
    parts.append("<section class='section card'><h2>2. Findings"
                 "<a class='back-top' href='#top'>top &uarr;</a></h2>")
    for r in report:
        anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
        if multi:
            parts.append(f"<section class='db' id='db_{anchor}'>")
            parts.append(f"<h3>{esc(r['name'])}</h3>")
        parts.append(
            f"<div class='meta'>Logs: <code>{esc(Path(r['log_dir']).name)}</code> "
            f"&middot; Scripts run: {r['passed'] + r['failed']} "
            f"(OK: {r['passed']}, Failed: {r['failed']})</div>"
        )
        parts.append(render_findings(r['findings']))
        if multi:
            parts.append("</section>")
    parts.append("</section>")  # close 2. Findings

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
    parts = ["<section class='section card' id='sql-appendix'>"
             "<h2>3. SQL Appendix -- full text by queryid"
             "<a class='back-top' href='#top'>top &uarr;</a></h2>"
             f"<div class='meta'>One entry per unique performance_schema digest surfaced in Top SQL "
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
    ap.add_argument('--server',   default='', help='Server label printed on the cover')
    ap.add_argument('--customer', default='', help='Customer / project name printed on the cover (optional)')
    ap.add_argument('--out',      default='', help='Output HTML path (default: <report_dir>/mysql_perf_analysis.html)')
    args = ap.parse_args()

    report_dir = Path(args.report_dir).resolve()
    if not report_dir.is_dir():
        print(f'ERROR: report directory not found: {report_dir}', file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else (report_dir / 'mysql_perf_analysis.html')

    contexts = discover_contexts(report_dir)
    if not contexts:
        print(f'ERROR: no log folders found under {report_dir}', file=sys.stderr)
        return 3

    target = read_target(report_dir)
    if not target:
        # Multi-context aggregate runs have _summary.txt per sub-folder,
        # not at the root. Use the first context's target as a header.
        for c in contexts:
            target = read_target(c['log_dir'])
            if target:
                break

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

    out.write_text(
        build_html(report, args.server, report_dir, fingerprint, target,
                   customer=args.customer),
        encoding='utf-8')
    copy_brand_assets(out.parent)

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
