#!/usr/bin/env python3
"""
merge_index_usage.py -- combine per-node captures from
perf_index_bloat_crossnode.sql into one unused / low-use index review.

Input: CSV captures (files or directories), one or more per node, possibly
taken at different times. Usage is judged per ROOT index (the parent-level
index for partitioned tables, the index itself otherwise) and summed over
every node, so an index counts as unused only if no writer or reader used it.

Stats resets and failovers: counters restart on an instance restart, a
failover or pg_stat_reset(). Captures of one node are split into epochs
whenever its counters go down or its stats window start changes; the last
capture of each epoch is summed. This never undercounts usage (it can only
overcount, which errs on the side of keeping an index).

Usage:
    python3 merge_index_usage.py CAPTURES... [--recent 3] [--min-days 14]
                                 [--low-per-day 5] [--min-size-mb 1]
                                 [--out-dir DIR]

Writes index_review.md, index_review.csv and drop_candidates.sql (every
statement commented out). Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REQUIRED_COLUMNS = {
    'node_id', 'node_role', 'captured_at', 'stats_reset', 'postmaster_start',
    'database', 'schema_name', 'table_name', 'index_name', 'root_table',
    'root_index', 'root_is_partitioned_index', 'is_partition',
    'partition_rank_newest', 'partition_bound', 'index_bytes', 'idx_scan',
    'last_idx_scan', 'is_unique', 'is_primary', 'backs_constraint',
    'is_valid', 'table_index_write_ops', 'index_def', 'root_index_def',
}

_TS_RE = re.compile(
    r'^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.(\d+))?([+-]\d\d)(?::?(\d\d))?$')


def parse_ts(value):
    """Parse a psql timestamptz (e.g. '2026-10-12 10:11:12.5+00')."""
    m = _TS_RE.match((value or '').strip())
    if not m:
        return None
    date, time, frac, tz_h, tz_m = m.groups()
    frac = (frac or '0')[:6].ljust(6, '0')
    return datetime.fromisoformat(f'{date}T{time}.{frac}{tz_h}:{tz_m or "00"}')


def to_bool(value):
    return (value or '').strip().lower() in ('t', 'true', '1', 'yes')


def to_int(value):
    value = (value or '').strip()
    if not value:
        return 0
    try:
        return int(value)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return 0


def pretty_bytes(n):
    size = float(n)
    for unit in ('B', 'kB', 'MB', 'GB', 'TB'):
        if size < 1024 or unit == 'TB':
            return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return f'{n} B'


def days(delta):
    return max(delta.total_seconds(), 0) / 86400.0


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def collect_files(inputs):
    files = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.glob('*.csv')))
        elif p.is_file():
            files.append(p)
        else:
            sys.exit(f'not a file or directory: {raw}')
    if not files:
        sys.exit('no capture files found')
    return files


def load_captures(files):
    """Return a list of captures: one per (node_id, captured_at)."""
    captures = {}
    for path in files:
        with path.open(newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
            if missing:
                sys.exit(f'{path}: not a perf_index_bloat_crossnode.sql CSV capture '
                         f'(missing columns: {", ".join(sorted(missing))}). '
                         f'Run psql with --csv.')
            for row in reader:
                captured_at = parse_ts(row['captured_at'])
                if captured_at is None:
                    sys.exit(f'{path}: cannot parse captured_at {row["captured_at"]!r}')
                key = (row['node_id'], captured_at)
                cap = captures.get(key)
                if cap is None:
                    starts = [t for t in (parse_ts(row['stats_reset']),
                                          parse_ts(row['postmaster_start'])) if t]
                    cap = captures[key] = {
                        'file': path.name,
                        'node_id': row['node_id'],
                        'node_role': row['node_role'],
                        'captured_at': captured_at,
                        # Conservative (latest) start of the counter window.
                        'window_start': max(starts) if starts else captured_at,
                        'database': row['database'],
                        'rows': {},
                    }
                index_key = f'{row["schema_name"]}.{row["index_name"]}'
                row['idx_scan'] = to_int(row['idx_scan'])
                cap['rows'][index_key] = row
    databases = {c['database'] for c in captures.values()}
    if len(databases) > 1:
        sys.exit(f'captures span several databases ({", ".join(sorted(databases))}); '
                 f'run the merge once per database')
    return list(captures.values())


# ---------------------------------------------------------------------------
# Per-node accumulation across epochs
# ---------------------------------------------------------------------------
def accumulate_nodes(captures):
    by_node = defaultdict(list)
    for cap in captures:
        by_node[cap['node_id']].append(cap)

    nodes = {}
    node_scans = defaultdict(dict)   # node_id -> index_key -> scans
    node_writes = defaultdict(dict)  # node_id -> index_key -> table write ops
    for node_id, caps in by_node.items():
        caps.sort(key=lambda c: c['captured_at'])
        epochs = [[caps[0]]]
        for prev, cur in zip(caps, caps[1:]):
            common = cur['rows'].keys() & prev['rows'].keys()
            went_down = any(cur['rows'][k]['idx_scan'] < prev['rows'][k]['idx_scan']
                            for k in common)
            if went_down or cur['window_start'] != prev['window_start']:
                epochs.append([cur])
            else:
                epochs[-1].append(cur)

        window = 0.0
        for epoch in epochs:
            last = epoch[-1]
            window += days(last['captured_at'] - epoch[0]['window_start'])
            for key, row in last['rows'].items():
                node_scans[node_id][key] = node_scans[node_id].get(key, 0) + row['idx_scan']
                # Write counters reset with the scan counters (failover,
                # restart), so stitch them across epochs the same way.
                node_writes[node_id][key] = (node_writes[node_id].get(key, 0)
                                             + to_int(row['table_index_write_ops']))

        roles = {c['node_role'] for c in caps}
        nodes[node_id] = {
            'role': caps[-1]['node_role'],
            'roles_seen': roles,
            'captures': len(caps),
            'epochs': len(epochs),
            'window_days': window,
            'first': caps[0]['captured_at'],
            'last': caps[-1]['captured_at'],
        }
    return nodes, node_scans, node_writes


def latest_metadata(captures):
    """Per index: the newest row, preferring writer captures."""
    meta = {}
    ordered = sorted(captures, key=lambda c: (c['node_role'] == 'writer', c['captured_at']))
    for cap in ordered:
        for key, row in cap['rows'].items():
            meta[key] = row
    return meta


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify(meta, nodes, node_scans, node_writes, args):
    window_days = min((n['window_days'] for n in nodes.values()), default=0.0)

    roots = defaultdict(list)
    for key, row in meta.items():
        roots[row['root_index']].append(key)

    results = []
    for root, keys in roots.items():
        rows = [meta[k] for k in keys]
        per_node = {node: sum(node_scans[node].get(k, 0) for k in keys)
                    for node in sorted(nodes)}
        total = sum(per_node.values())
        partitioned = any(to_bool(r['root_is_partitioned_index']) for r in rows)

        recent_keys = [k for k in keys
                       if to_bool(meta[k]['is_partition'])
                       and 0 < to_int(meta[k]['partition_rank_newest']) <= args.recent]
        recent_scans = sum(node_scans[n].get(k, 0) for n in nodes for k in recent_keys)
        older_used = sum(1 for k in keys if k not in recent_keys
                         and any(node_scans[n].get(k, 0) for n in nodes))
        older_unused = sum(1 for k in keys if k not in recent_keys
                           and not any(node_scans[n].get(k, 0) for n in nodes))

        size = sum(to_int(r['index_bytes']) for r in rows)
        # Writes run on whichever node was the writer at the time; readers
        # report ~0, so summing every node across epochs is safe.
        write_ops = sum(node_writes[n].get(k, 0) for n in nodes for k in keys)
        last_used = max((r['last_idx_scan'] for r in rows if r['last_idx_scan']),
                        default='')
        per_day = total / window_days if window_days > 0 else float('inf')
        constraint = any(to_bool(r['is_primary']) or to_bool(r['is_unique'])
                         or to_bool(r['backs_constraint']) for r in rows)
        invalid = any(not to_bool(r['is_valid']) for r in rows)

        if constraint:
            category = 'KEEP-CONSTRAINT'
            reason = ('backs a primary key / unique / exclusion / FK constraint'
                      + (' (unused - check whether the constraint itself is redundant)'
                         if total == 0 else ''))
        elif invalid:
            category = 'INVALID'
            reason = 'invalid index (failed CREATE INDEX CONCURRENTLY): rebuild or drop'
        elif total == 0:
            category = 'DROP-CANDIDATE'
            reason = f'0 scans on all {len(nodes)} node(s)'
        elif partitioned and recent_keys and recent_scans == 0:
            category = 'REVIEW-OLD-PARTITIONS-ONLY'
            reason = (f'used only in older partitions ({older_used} leaf index(es)); '
                      f'0 scans in the {len(recent_keys)} newest')
        elif per_day < args.low_per_day:
            category = 'REVIEW-LOW-USE'
            reason = f'{per_day:.2f} scans/day over the shortest node window'
        else:
            category = 'KEEP-IN-USE'
            reason = f'{per_day:.1f} scans/day'
            if partitioned and older_unused:
                reason += (f'; {older_unused} older partition(s) unused '
                           f'(ignored: index is managed at parent level)')

        results.append({
            'root_index': root,
            'root_table': rows[0]['root_table'],
            'category': category,
            'reason': reason,
            'total_scans': total,
            'scans_by_node': '; '.join(f'{n}={s}' for n, s in per_node.items()),
            'recent_partition_scans': recent_scans if partitioned else '',
            'scans_per_day': f'{per_day:.2f}' if per_day != float('inf') else '',
            'leaf_indexes': len(keys),
            'size_bytes': size,
            'size_pretty': pretty_bytes(size),
            'table_index_write_ops': write_ops,
            'last_idx_scan': last_used,
            'is_partitioned': partitioned,
            'root_index_def': rows[0]['root_index_def'],
        })

    order = {'DROP-CANDIDATE': 0, 'REVIEW-OLD-PARTITIONS-ONLY': 1,
             'REVIEW-LOW-USE': 2, 'INVALID': 3, 'KEEP-CONSTRAINT': 4,
             'KEEP-IN-USE': 5}
    results.sort(key=lambda r: (order[r['category']], -r['size_bytes']))
    return results, window_days


def coverage_warnings(nodes, window_days, args):
    warns = []
    roles = [n['role'] for n in nodes.values()]
    if 'writer' not in roles:
        warns.append('No writer capture found - write-load figures are missing.')
    if 'reader' not in roles:
        warns.append('No reader capture found. If the cluster has readers, capture '
                      'them too: reader-only index usage is invisible on the writer.')
    short = sorted((nid, n) for nid, n in nodes.items() if n['window_days'] < args.min_days)
    if short:
        listed = ', '.join(f'{nid} ({n["role"]}, {n["window_days"]:.1f} d)' for nid, n in short)
        warns.append(f'Stats window shorter than {args.min_days:g} days on: {listed}. '
                     f'Counters this young cannot prove an index unused - weekly or '
                     f'monthly jobs may not have run yet. Keep capturing (captures '
                     f'accumulate across resets) and re-run the merge. An autoscaled '
                     f'reader that only exists during scaling is expected to stay short.')
    for node_id, n in sorted(nodes.items()):
        if len(n['roles_seen']) > 1:
            warns.append(f'{node_id} changed role between captures (failover); '
                         f'usage from both roles is included.')
    return warns


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
CSV_FIELDS = ['category', 'root_index', 'root_table', 'reason', 'total_scans',
              'scans_by_node', 'recent_partition_scans', 'scans_per_day',
              'leaf_indexes', 'size_bytes', 'size_pretty', 'table_index_write_ops',
              'last_idx_scan', 'is_partitioned', 'root_index_def']


def md_escape(text):
    return str(text).replace('|', '\\|').replace('\n', ' ')


def write_markdown(path, results, nodes, warns, window_days, args):
    min_bytes = args.min_size_mb * 1024 * 1024
    counts = defaultdict(int)
    for r in results:
        counts[r['category']] += 1

    out = ['# Index usage review', '',
           f'Generated: {datetime.now().astimezone():%Y-%m-%d %H:%M %Z}  ',
           f'Shortest node stats window: **{window_days:.1f} days**  ',
           f'Recent partitions considered: newest **{args.recent}** per table  ',
           f'Low-use threshold: < **{args.low_per_day}** scans/day', '',
           '## Node coverage', '',
           '| Node | Role | Captures | Epochs | Window (days) | First capture | Last capture |',
           '|---|---|---:|---:|---:|---|---|']
    for node_id, n in sorted(nodes.items()):
        out.append(f'| {md_escape(node_id)} | {n["role"]} | {n["captures"]} | '
                   f'{n["epochs"]} | {n["window_days"]:.1f} | '
                   f'{n["first"]:%Y-%m-%d %H:%M} | {n["last"]:%Y-%m-%d %H:%M} |')
    out.append('')
    if warns:
        out += ['## Warnings', ''] + [f'- {w}' for w in warns] + ['']

    out += ['## Summary', '', '| Category | Indexes |', '|---|---:|']
    for cat in ('DROP-CANDIDATE', 'REVIEW-OLD-PARTITIONS-ONLY', 'REVIEW-LOW-USE',
                'INVALID', 'KEEP-CONSTRAINT', 'KEEP-IN-USE'):
        out.append(f'| {cat} | {counts.get(cat, 0)} |')
    out.append('')

    sections = [
        ('DROP-CANDIDATE', 'Drop candidates - unused on every node'),
        ('REVIEW-OLD-PARTITIONS-ONLY', 'Review - used only in older partitions'),
        ('REVIEW-LOW-USE', 'Review - low use (check for rare workloads)'),
        ('INVALID', 'Invalid indexes'),
    ]
    for cat, title in sections:
        rows = [r for r in results if r['category'] == cat]
        shown = [r for r in rows if r['size_bytes'] >= min_bytes]
        out += [f'## {title}', '']
        if not rows:
            out += ['None.', '']
            continue
        out += ['| Index | Table | Size | Index write ops | Scans by node | '
                'Recent-partition scans | Reason |',
                '|---|---|---:|---:|---|---:|---|']
        for r in shown:
            out.append(f'| {md_escape(r["root_index"])} | {md_escape(r["root_table"])} | '
                       f'{r["size_pretty"]} | {r["table_index_write_ops"]:,} | '
                       f'{md_escape(r["scans_by_node"])} | '
                       f'{r["recent_partition_scans"]} | {md_escape(r["reason"])} |')
        hidden = len(rows) - len(shown)
        if hidden:
            out.append('')
            out.append(f'_{hidden} more under {args.min_size_mb} MB - see index_review.csv._')
        out.append('')

    unused_constraint = [r for r in results
                         if r['category'] == 'KEEP-CONSTRAINT' and r['total_scans'] == 0]
    if unused_constraint:
        out += ['## FYI - unused but constraint-backed', '',
                'Cannot be dropped while the constraint exists; worth a look if '
                'the constraint duplicates another one.', '',
                '| Index | Table | Size |', '|---|---|---:|']
        for r in unused_constraint:
            out.append(f'| {md_escape(r["root_index"])} | {md_escape(r["root_table"])} | '
                       f'{r["size_pretty"]} |')
        out.append('')

    path.write_text('\n'.join(out), encoding='utf-8')


def write_drop_sql(path, results, window_days):
    lines = [
        '-- Drop candidates from merge_index_usage.py',
        f'-- Generated {datetime.now().astimezone():%Y-%m-%d %H:%M %Z}; '
        f'shortest node stats window {window_days:.1f} days.',
        '-- REVIEW BEFORE RUNNING. Every statement is commented out on purpose.',
        '-- Each DROP is preceded by its rollback (CREATE) statement.',
        '',
    ]
    for r in results:
        if r['category'] != 'DROP-CANDIDATE':
            continue
        lines.append(f'-- {r["root_index"]} on {r["root_table"]}: {r["size_pretty"]}, '
                     f'{r["table_index_write_ops"]:,} index write ops, '
                     f'scans {r["scans_by_node"]}')
        rollback = r['root_index_def']
        if r['is_partitioned']:
            # pg_get_indexdef gives "ON ONLY" for a partitioned index; the
            # rollback must recreate it on every partition.
            rollback = rollback.replace(' ON ONLY ', ' ON ', 1)
            lines.append(f'--   rollback: {rollback};')
            lines.append('--   partitioned index: DROP INDEX CONCURRENTLY is not supported; '
                         'this takes ACCESS EXCLUSIVE on the parent and all partitions.')
            lines.append(f'-- DROP INDEX {r["root_index"]};')
        else:
            lines.append(f'--   rollback: {rollback.replace("CREATE INDEX", "CREATE INDEX CONCURRENTLY", 1)};')
            lines.append(f'-- DROP INDEX CONCURRENTLY {r["root_index"]};')
        lines.append('')
    path.write_text('\n'.join(lines), encoding='utf-8')


def write_csv(path, results):
    with path.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('captures', nargs='+', help='capture CSV files or directories')
    ap.add_argument('--recent', type=int, default=3,
                    help='newest N partitions per table that decide a '
                         'parent-level index (default: 3)')
    ap.add_argument('--min-days', type=float, default=14,
                    help='warn when the shortest node stats window is shorter (default: 14)')
    ap.add_argument('--low-per-day', type=float, default=5,
                    help='scans/day below which an in-use index is flagged for review (default: 5)')
    ap.add_argument('--min-size-mb', type=float, default=1,
                    help='hide smaller indexes from the markdown tables (default: 1)')
    ap.add_argument('--out-dir', default='.', help='output directory (default: .)')
    args = ap.parse_args()

    captures = load_captures(collect_files(args.captures))
    nodes, node_scans, node_writes = accumulate_nodes(captures)
    meta = latest_metadata(captures)
    results, window_days = classify(meta, nodes, node_scans, node_writes, args)
    warns = coverage_warnings(nodes, window_days, args)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_markdown(out_dir / 'index_review.md', results, nodes, warns, window_days, args)
    write_csv(out_dir / 'index_review.csv', results)
    write_drop_sql(out_dir / 'drop_candidates.sql', results, window_days)

    counts = defaultdict(int)
    for r in results:
        counts[r['category']] += 1
    node_list = ', '.join(f'{k}={v["role"]}' for k, v in sorted(nodes.items()))
    print(f'nodes: {len(nodes)} ({node_list})')
    print(f'shortest stats window: {window_days:.1f} days')
    for w in warns:
        print(f'WARN {w}')
    print('  '.join(f'{k}={v}' for k, v in sorted(counts.items())))
    print(f'wrote {out_dir}/index_review.md, index_review.csv, drop_candidates.sql')


if __name__ == '__main__':
    main()
