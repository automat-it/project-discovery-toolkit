#!/usr/bin/env python3
"""
analyze_report.py -- PostgreSQL performance audit report analyzer.

Reads the report directory produced by run_audit.sh (single database) or
multiple sub-folders containing per-database runs, applies a rule set that
flags known performance issues, and writes one HTML file with an executive
summary plus a dedicated section per database.

Usage:
    ./analyze_report.py <report_dir>
    ./analyze_report.py <report_dir> --server prod-pg-01 --out report.html

The output HTML is written to <report_dir>/perf_analysis.html unless --out
is supplied.

Standard library only (no external dependencies).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Rules: (script_substring, mode, severity, title, recommendation, [pattern])
# mode: 'has_data' = any data rows -> finding;
#       'pattern'  = regex match  -> finding (Pattern field required)
# Severity: Critical / Warning / Info
# ---------------------------------------------------------------------------
RULES = [
    dict(script='perf_02_blocking_and_locks',     mode='has_data', severity='Critical',
         title='Active blocking sessions or long-running transactions',
         recommendation='Investigate blocking pairs. Long-running transactions block VACUUM and bloat the WAL.'),

    dict(script='perf_04_wait_events_and_io',     mode='pattern',  severity='Warning',
         pattern=r'(?i)\b(IO|LWLock|Lock|BufferPin|Client|Activity)\b',
         title='Wait events recorded',
         recommendation='Wait events were captured. Review their distribution to identify the dominant bottleneck.'),

    dict(script='perf_06_index_audit',            mode='has_data', severity='Warning',
         title='Index hygiene findings (unused / duplicate / missing)',
         recommendation='Drop unused indexes, consolidate duplicates, add suggested missing indexes after evaluating impact.'),

    dict(script='perf_07_table_stats_health',     mode='has_data', severity='Warning',
         title='Stale autovacuum / autoanalyze targets',
         recommendation='Tables need autovacuum or autoanalyze. Tune per-table thresholds or run manually.'),

    dict(script='perf_09_temp_and_memory_pressure', mode='pattern', severity='Warning',
         pattern=r'(?im)temp_files\s*\|.*\b[1-9]\d*\b|temp_bytes\s*\|.*\b[1-9]\d*\b',
         title='Temporary files spilled to disk',
         recommendation='work_mem is too low for some queries. Increase work_mem or rewrite the spilling queries.'),

    dict(script='perf_10_replication_and_backup_impact', mode='pattern', severity='Critical',
         pattern=r'(?im)replay_lag\s*\|\s*\d+:\d+:\d+',
         title='Replication lag detected',
         recommendation='Replica is behind primary. Check network throughput and replica I/O capacity.'),

    dict(script='perf_11_bloat_estimation',       mode='has_data', severity='Warning',
         title='Table or index bloat exceeds threshold',
         recommendation='Run VACUUM FULL or pg_repack on the listed objects to reclaim bloat.'),

    dict(script='perf_15_capacity_and_growth',    mode='pattern', severity='Critical',
         pattern=r'(?im)\b(8[0-9]|9[0-9]|100)\.\d+\s*%',
         title='Sequence consumption above 80%',
         recommendation='A sequence is approaching its data-type limit. Plan for type widening (int->bigint).'),

    dict(script='perf_14_checkpoint_bgwriter',    mode='pattern', severity='Warning',
         pattern=r'(?im)checkpoints_req\s*\|\s*[1-9]\d*',
         title='Requested checkpoints (vs scheduled) occurring',
         recommendation='Requested checkpoints indicate WAL pressure. Increase max_wal_size or checkpoint_timeout.'),
]

# ---------------------------------------------------------------------------
# Log parsing helpers (psql output format)
# ---------------------------------------------------------------------------
SEPARATOR_RE  = re.compile(r'^[\s\-+]*\-{3,}[\s\-+]*$')   # psql divider
ROW_COUNT_RE  = re.compile(r'^\(\s*\d+\s+rows?\s*\)\s*$')
NOTE_RE       = re.compile(r'^(NOTICE|WARNING|psql:|--|\s*$)')


def log_has_data_rows(log_path: Path) -> bool:
    """Return True if a psql log has data rows beyond headers / notices."""
    try:
        text = log_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return False
    in_data = False
    for line in text.splitlines():
        if SEPARATOR_RE.match(line):
            in_data = True
            continue
        if not in_data:
            continue
        if ROW_COUNT_RE.match(line):
            in_data = False
            continue
        if not line.strip() or NOTE_RE.match(line):
            continue
        return True
    return False


def read_log_text(log_path: Path) -> str:
    try:
        return log_path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def read_summary(summary_path: Path):
    """Yield (status, script_path) tuples from _summary.txt."""
    if not summary_path.exists():
        return
    for raw in summary_path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = re.match(r'^(OK|FAIL)\s+(\S+)', raw)
        if m:
            yield m.group(1), m.group(2)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def find_findings(log_dir: Path) -> list[dict]:
    findings: list[dict] = []

    # 1. Failed scripts
    for status, script in read_summary(log_dir / '_summary.txt'):
        if status != 'FAIL':
            continue
        log_base = script.replace('/', '_').replace('.sql', '.log')
        log_path = log_dir / log_base
        detail = '(no log captured)'
        if log_path.exists():
            errs = [l for l in read_log_text(log_path).splitlines()
                    if re.match(r'(ERROR|FATAL|psql:)', l)][:5]
            if errs:
                detail = '\n'.join(errs)
        findings.append(dict(
            severity='Critical', script=script,
            title='Script execution failed', detail=detail,
            recommendation='Check connection privileges, psql version, and the script log file.',
        ))

    # 2. Apply content rules
    for log in sorted(log_dir.glob('*.log')):
        for rule in RULES:
            if rule['script'] not in log.stem:
                continue
            hit = False
            detail = ''
            if rule['mode'] == 'has_data':
                if log_has_data_rows(log):
                    hit = True
                    detail = 'Diagnostic script returned data rows -- review the full log.'
            elif rule['mode'] == 'pattern':
                text = read_log_text(log)
                m = re.search(rule['pattern'], text) if text else None
                if m:
                    hit = True
                    snip = m.group(0)
                    detail = 'Match: ' + (snip if len(snip) <= 200 else snip[:200] + '...')
            if hit:
                findings.append(dict(
                    severity=rule['severity'], script=log.name,
                    title=rule['title'], detail=detail,
                    recommendation=rule['recommendation'],
                ))
    return findings


def discover_contexts(root: Path) -> list[dict]:
    """Find per-DB log directories. Returns [{name, log_dir}, ...]."""
    if (root / '_summary.txt').exists():
        return [dict(name='(single run)', log_dir=root)]

    contexts: list[dict] = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        # Look for the most recent postgres_perf_* sub-folder per DB
        runs = sorted(sub.glob('postgres_perf_*'), reverse=True)
        if runs:
            contexts.append(dict(name=sub.name, log_dir=runs[0]))
    return contexts


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------
def severity_rank(s: str) -> int:
    return {'Critical': 0, 'Warning': 1, 'Info': 2}.get(s, 3)


def render_findings(findings: list[dict]) -> str:
    if not findings:
        return '<p class="ok">No problems detected by the rule set.</p>'
    rows = []
    for f in sorted(findings, key=lambda x: severity_rank(x['severity'])):
        sev_class = f['severity'].lower()
        detail_html = f'<br><span class="detail">{html.escape(f.get("detail",""))}</span>' if f.get('detail') else ''
        rows.append(
            f'<tr class="sev-{sev_class}">'
            f'<td><span class="badge {sev_class}">{f["severity"]}</span></td>'
            f'<td><code>{html.escape(f["script"])}</code></td>'
            f'<td><strong>{html.escape(f["title"])}</strong>{detail_html}</td>'
            f'<td>{html.escape(f["recommendation"])}</td>'
            f'</tr>'
        )
    return (
        '<table class="findings"><thead><tr>'
        '<th>Severity</th><th>Script</th><th>Finding</th><th>Recommendation</th>'
        '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
    )


CSS = """\
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;}
h1{margin:0 0 4px 0;}h2{border-bottom:2px solid #336791;padding-bottom:4px;margin-top:32px;}
header{background:#336791;color:white;padding:24px;border-radius:6px;margin-bottom:20px;}
header p{margin:4px 0;opacity:0.9;}
.summary{background:white;padding:16px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;}
th,td{padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#eaf0f6;font-weight:600;}
.findings tr:hover{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;}
.badge.critical{background:#c0392b;}.badge.warning{background:#e67e22;}.badge.info{background:#2980b9;}
.sev-critical>td:first-child{border-left:4px solid #c0392b;}
.sev-warning >td:first-child{border-left:4px solid #e67e22;}
.sev-info    >td:first-child{border-left:4px solid #2980b9;}
.detail{color:#666;font-size:0.9em;font-family:Consolas,monospace;white-space:pre-wrap;}
.ok{color:#27ae60;font-weight:600;}
.exec-summary td.num{text-align:right;font-variant-numeric:tabular-nums;}
.exec-summary td.crit{color:#c0392b;font-weight:600;}
.exec-summary td.warn{color:#e67e22;font-weight:600;}
.exec-summary td.fail{color:#c0392b;font-weight:600;}
.toc{background:white;padding:12px 20px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
.toc ul{margin:0;padding-left:20px;columns:3;}
.toc a{text-decoration:none;color:#336791;}.toc a:hover{text-decoration:underline;}
section.db{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
section.db h3{margin-top:0;color:#336791;}
.meta{color:#666;font-size:0.9em;margin-bottom:12px;}
code{background:#f0f0f0;padding:1px 6px;border-radius:3px;font-size:0.9em;}
</style>"""


def build_html(report: list[dict], server: str, report_dir: Path) -> str:
    now = _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_pass = sum(r['passed']  for r in report)
    total_fail = sum(r['failed']  for r in report)
    total_crit = sum(r['critical'] for r in report)
    total_warn = sum(r['warning']  for r in report)
    total_info = sum(r['info']     for r in report)

    parts = [f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<title>PostgreSQL Performance Audit Report</title>
{CSS}
</head><body>
<header>
  <h1>PostgreSQL Performance Audit Report</h1>
  <p><strong>Server:</strong> {html.escape(server or '(unspecified)')}</p>
  <p><strong>Report folder:</strong> {html.escape(str(report_dir))}</p>
  <p><strong>Generated:</strong> {now}</p>
</header>
<div class='summary'>
<h2 style='margin-top:0;border:none;'>Executive Summary</h2>
<table class='exec-summary'>
<thead><tr><th>Database / Context</th><th>Scripts OK</th><th>Failed</th><th>Critical</th><th>Warning</th><th>Info</th></tr></thead>
<tbody>"""]

    for r in report:
        anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
        parts.append(
            f"<tr><td><a href='#db_{anchor}'>{html.escape(r['name'])}</a></td>"
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
        f"</tbody></table></div>"
    )

    if len(report) > 1:
        parts.append("<div class='toc'><h2 style='margin-top:0;border:none;'>Sections</h2><ul>")
        for r in report:
            anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
            parts.append(f"<li><a href='#db_{anchor}'>{html.escape(r['name'])}</a></li>")
        parts.append("</ul></div>")

    for r in report:
        anchor = re.sub(r'[^A-Za-z0-9]', '_', r['name'])
        parts.append(f"<section class='db' id='db_{anchor}'>")
        parts.append(f"<h3>{html.escape(r['name'])}</h3>")
        parts.append(f"<div class='meta'>Logs: <code>{html.escape(str(r['log_dir']))}</code></div>")
        parts.append(
            f"<div class='meta'>Scripts run: {r['passed'] + r['failed']} | "
            f"OK: {r['passed']} | Failed: {r['failed']}</div>"
        )
        parts.append(render_findings(r['findings']))
        parts.append("</section>")

    parts.append("</body></html>")
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('report_dir', help='Folder produced by run_audit.sh / run_all_databases.sh')
    ap.add_argument('--server', default='', help='Server label for the report header')
    ap.add_argument('--out', default='', help='Output HTML path (default: <report_dir>/perf_analysis.html)')
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

    report = []
    for ctx in contexts:
        findings = find_findings(ctx['log_dir'])
        passed = failed = 0
        for status, _ in read_summary(ctx['log_dir'] / '_summary.txt'):
            if status == 'OK':   passed += 1
            elif status == 'FAIL': failed += 1
        report.append(dict(
            name=ctx['name'], log_dir=ctx['log_dir'], findings=findings,
            passed=passed, failed=failed,
            critical=sum(1 for f in findings if f['severity']=='Critical'),
            warning =sum(1 for f in findings if f['severity']=='Warning'),
            info    =sum(1 for f in findings if f['severity']=='Info'),
        ))

    out.write_text(build_html(report, args.server, report_dir), encoding='utf-8')

    total_crit = sum(r['critical'] for r in report)
    total_warn = sum(r['warning']  for r in report)
    total_fail = sum(r['failed']   for r in report)
    print('=' * 80)
    print('Performance audit analysis complete.')
    print(f'  Databases analyzed : {len(report)}')
    print(f'  Critical findings  : {total_crit}')
    print(f'  Warnings           : {total_warn}')
    print(f'  Failed scripts     : {total_fail}')
    print(f'  Report             : {out}')
    print('=' * 80)
    return 0


if __name__ == '__main__':
    sys.exit(main())
