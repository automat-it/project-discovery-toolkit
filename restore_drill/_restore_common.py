"""Shared analyzer core for the restore-drill reports (PostgreSQL + MySQL).

The runner (`run_restore_drill.sh`) writes one structured .log per check plus a
`_summary.txt` footer. This module turns that folder into the same branded
HTML report the db-audit-scripts analyzers produce: it reuses their rendering
primitives (cover, CSS, brand assets, charts) from `_analyze_lib.py` so the
restore-drill report looks identical to the perf/sec reports, and only the
content - drill verdict, recovery objectives, per-check results - is new.

Standard library only (plus the shared toolkit lib). No external deps.
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path
from typing import Dict, List

# Reuse the toolkit's rendering primitives. Both engine libs resolve the brand
# assets to db-audit-scripts/assets/, so importing the postgres copy works for
# every engine. (esc, SHARED_CSS, copy_brand_assets, render_cover, kv_grid,
# svg_bar, now_str all live there.)
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / 'db-audit-scripts' / 'postgres'))
from _analyze_lib import (  # noqa: E402
    esc, kv_grid, SHARED_CSS, copy_brand_assets, svg_bar, render_cover, now_str,
)

# ---------------------------------------------------------------------------
# Per-check metadata. Check IDs are shared across engines (rd_01 means the
# same control everywhere), so this table is engine-agnostic. `rec` is the
# remediation shown when a check does not pass; `domain` buckets the bar chart.
# ---------------------------------------------------------------------------
CHECK_META: Dict[str, Dict[str, str]] = {
    'rd_01_backup_create': dict(domain='Backup', rec=(
        'Investigate why the backup could not be produced (permissions, disk '
        'space, dump tool version). A DR plan with no working backup is the '
        'single highest-priority gap.')),
    'rd_02_restore_execute': dict(domain='Restore', rec=(
        'The backup exists but cannot be restored, so it is effectively '
        'useless. Check the restore log for version incompatibilities, missing '
        'roles/owners, or absent extensions, and re-test.')),
    'rd_02_backup_verify': dict(domain='Restore', rec=(
        'The backup is incomplete or unreadable, so it cannot be relied on for '
        'recovery. Re-take the backup and check storage/transfer integrity. '
        'Note: verify-only proves the backup is readable, not that the data '
        'restores faithfully - run a full restore drill periodically.')),
    'rd_03_restore_online': dict(domain='Restore', rec=(
        'The restored database does not come online. Review the restore log '
        'for fatal errors and confirm the recovery instance is healthy.')),
    'rd_04_object_parity': dict(domain='Integrity', rec=(
        'Schema objects are missing after restore. Confirm the backup captured '
        'every object (owners, extensions, routines, large objects) and that '
        'the restore ran to completion.')),
    'rd_05_rowcount_parity': dict(domain='Integrity', rec=(
        'Rows are missing after restore - this is data loss. Re-check the dump '
        'options (excluded tables, --no-data) and look for partial restore '
        'failures.')),
    'rd_06_integrity_check': dict(domain='Integrity', rec=(
        'The restored copy has invalid indexes or unvalidated constraints. '
        'Rebuild/validate them and verify the source was consistent when the '
        'backup was taken.')),
    'rd_07_rto': dict(domain='Recovery objectives', rec=(
        'Restore is slower than the recovery-time objective. Consider parallel '
        'restore, faster storage, or physical/base backups for large '
        'databases to shrink recovery time.')),
    'rd_08_rpo_backup_age': dict(domain='Recovery objectives', rec=(
        'The backup is older than the recovery-point objective. Increase backup '
        'frequency (and WAL/binlog archival) to reduce the data you would lose '
        'in a real recovery.')),
    'rd_09_data_checksum': dict(domain='Integrity', rec=(
        'Row-content checksums differ between source and restored copy - silent '
        'corruption or an inconsistent backup. Investigate before relying on '
        'this backup.')),
}

TIER_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

EXTRA_CSS = """\
<style>
.badge.pass{background:#27ae60;}.badge.warn{background:#e67e22;}.badge.fail{background:#c0392b;}
.verdict{display:flex;align-items:baseline;gap:14px;padding:14px 20px;border-radius:8px;margin:6px 0 16px;font-weight:600;line-height:1.45;page-break-inside:avoid;}
.verdict .big{font-size:20pt;font-weight:800;letter-spacing:0.5px;}
.verdict.pass{background:#eafaf1;border-left:6px solid #27ae60;color:#1e7e45;}
.verdict.warn{background:#fff6ec;border-left:6px solid #e67e22;color:#9c5410;}
.verdict.fail{background:#fdecea;border-left:6px solid #c0392b;color:#a02b1f;}
.kpi .num.ok{color:#27ae60;}
table.results td.st{white-space:nowrap;}
table.results td.metric,table.results td.thr{font-family:Consolas,monospace;font-size:0.9em;white-space:nowrap;}
table.results td.detail{color:#444;}
table.results tr.row-fail td:first-child{border-left:4px solid #c0392b;}
table.results tr.row-warn td:first-child{border-left:4px solid #e67e22;}
table.results tr.row-pass td:first-child{border-left:4px solid #27ae60;}
</style>"""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def parse_check_log(text: str) -> Dict[str, str]:
    """Pull the structured header + raw body out of one check .log file."""
    fields: Dict[str, str] = {}
    body: List[str] = []
    in_body = False
    for ln in text.splitlines():
        if ln.startswith('--- output'):
            in_body = True
            continue
        if in_body:
            body.append(ln)
            continue
        m = re.match(r'^(Check|Tier|Title|Status|Metric|Threshold|Detail):\s*(.*)$', ln)
        if m:
            fields[m.group(1).lower()] = m.group(2).strip()
    fields['output'] = '\n'.join(body).strip()
    return fields


def parse_summary(text: str) -> Dict[str, str]:
    """Read the labeled footer block of _summary.txt into a dict."""
    out: Dict[str, str] = {}
    for ln in text.splitlines():
        m = re.match(r'^(Engine|Category|Timestamp|Source|Target|Backup|RTO|RPO|Rows|Verdict|Pass|Warn|Fail):\s*(.*)$', ln)
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


def load_checks(report_dir: Path) -> List[Dict[str, str]]:
    checks = []
    for log in sorted(report_dir.glob('*.log')):
        f = parse_check_log(_read(log))
        if not f.get('check'):
            continue
        f['logfile'] = log.name
        checks.append(f)
    checks.sort(key=lambda c: (TIER_RANK.get(c.get('tier', ''), 9), c.get('check', '')))
    return checks


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def status_donut(passed: int, warned: int, failed: int) -> str:
    """Pass/Warn/Fail donut - same geometry & palette as the toolkit donut,
    relabeled for a drill (Passed / Warning / Failed)."""
    total = passed + warned + failed
    if total <= 0:
        return "<p class='ok'>No checks recorded.</p>"
    rad, cx, cy, stroke = 80, 110, 110, 30
    vals = [('Passed', passed, '#27ae60'), ('Warning', warned, '#e67e22'), ('Failed', failed, '#c0392b')]
    nonzero = [(lbl, n, c) for lbl, n, c in vals if n > 0]
    out = []
    if len(nonzero) == 1:
        # A single 100% slice is a degenerate SVG arc (start == end point) and
        # renders as nothing - draw a full circle of that colour instead.
        out.append(f"<circle cx='{cx}' cy='{cy}' r='{rad}' fill='{nonzero[0][2]}'/>")
    else:
        offset = 0
        for _, n, c in nonzero:
            angle = 360.0 * n / total
            a1 = (offset - 90) * math.pi / 180.0
            a2 = (offset + angle - 90) * math.pi / 180.0
            x1, y1 = cx + rad * math.cos(a1), cy + rad * math.sin(a1)
            x2, y2 = cx + rad * math.cos(a2), cy + rad * math.sin(a2)
            large = 1 if angle > 180 else 0
            out.append(f"<path d='M {cx} {cy} L {x1:.2f} {y1:.2f} A {rad} {rad} 0 {large} 1 {x2:.2f} {y2:.2f} Z' fill='{c}'/>")
            offset += angle
    out.append(f"<circle cx='{cx}' cy='{cy}' r='{rad - stroke}' fill='white'/>")
    out.append(f"<text x='{cx}' y='{cy - 3}' text-anchor='middle' font-size='22' font-weight='600' fill='#222'>{total}</text>")
    out.append(f"<text x='{cx}' y='{cy + 18}' text-anchor='middle' font-size='10' fill='#777'>checks</text>")
    out.append("<g font-family='-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial' font-size='12'>")
    ly = 30
    for label, n, c in vals:
        out.append(f"<rect x='240' y='{ly}' width='14' height='14' fill='{c}'/>")
        out.append(f"<text x='262' y='{ly + 12}' fill='#222'>{label}: {n}</text>")
        ly += 22
    out.append('</g>')
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 380 220' "
            f"width='380' height='220'>{''.join(out)}</svg>")


_BADGE = {'PASS': "<span class='badge pass'>PASS</span>",
          'WARN': "<span class='badge warn'>WARN</span>",
          'FAIL': "<span class='badge fail'>FAIL</span>"}


def _finding_severity(status: str) -> str:
    return {'FAIL': 'Critical', 'WARN': 'Warning'}.get(status, 'Info')


def build_html(report_dir: Path, engine_label: str, server: str, customer: str) -> str:
    checks = load_checks(report_dir)
    summary = parse_summary(_read(report_dir / '_summary.txt'))

    n_pass = sum(1 for c in checks if c.get('status') == 'PASS')
    n_warn = sum(1 for c in checks if c.get('status') == 'WARN')
    n_fail = sum(1 for c in checks if c.get('status') == 'FAIL')
    n_other = sum(1 for c in checks if c.get('status') not in ('PASS', 'WARN', 'FAIL'))
    total = len(checks)
    n_fail += n_other  # an unrecognized status counts as a non-pass (red), never as success

    # Single canonical verdict: trust _summary.txt only if it is a known token,
    # otherwise compute from the check outcomes. Guarantees banner text, colour
    # and CSS class can never disagree.
    sv = (summary.get('verdict') or '').strip().upper()
    computed = 'FAIL' if n_fail else ('WARN' if n_warn else 'PASS')
    verdict = sv if sv in ('PASS', 'WARN', 'FAIL') else computed
    vkey = verdict.lower()
    server_label = server or (summary.get('target', '').split('/')[0] if summary.get('target') else '')

    # headline numbers (summary first, metrics as fallback)
    rto = summary.get('rto', '') or '-'
    rpo = summary.get('rpo', '') or '-'
    rto_short = re.match(r'^(\S+)', rto).group(1) if rto != '-' else '-'
    rpo_short = re.match(r'^(\S+)', rpo).group(1) if rpo != '-' else '-'
    rows = summary.get('rows', '') or '-'
    backup = summary.get('backup', '')
    m_backup = re.search(r'\(([^,]+),', backup)
    backup_size = m_backup.group(1).strip() if m_backup else 'n/a'

    title = f"{engine_label} Restore-Drill Report"

    p = [SHARED_CSS, EXTRA_CSS, render_cover(title, server_label, customer, 1)]

    # ---- Executive summary --------------------------------------------------
    p.append("<div class='section'><h2>Executive summary</h2>")

    vmsg = {
        'PASS': ('PASS', 'Restore drill passed - the backup is restorable and the restored copy '
                         'matches the source on every check.'),
        'WARN': ('WARN', 'Restore drill completed with warnings - the data is recoverable, but one '
                         'or more recovery objectives were missed.'),
        'FAIL': ('FAIL', 'Restore drill failed - this backup cannot be relied on for recovery in its '
                         'current state. Fix before an incident forces the issue.'),
    }[verdict if verdict in ('PASS', 'WARN', 'FAIL') else 'FAIL']
    p.append(f"<div class='verdict {vkey}'><span class='big'>{esc(vmsg[0])}</span>"
             f"<span>{esc(vmsg[1])}</span></div>")

    # plain-language tldr + next steps (same look as the toolkit at-a-glance)
    nonpass = [c for c in checks if c.get('status') != 'PASS']
    nonpass.sort(key=lambda c: (0 if c.get('status') == 'FAIL' else 1, TIER_RANK.get(c.get('tier', ''), 9)))
    src = (summary.get('source') or '').split('/')[-1] or 'the source database'
    if verdict == 'PASS':
        tldr = (f"<strong>Bottom line:</strong> the backup of <em>{esc(src)}</em> restored cleanly into "
                f"a throw-away scratch database and matched the source on all {total} checks - objects, "
                f"row counts ({esc(rows)} rows), integrity and row-content checksums. Recovery is proven, "
                f"and the restore finished in {esc(rto)}.")
    elif verdict == 'WARN':
        tldr = (f"<strong>Bottom line:</strong> the backup of <em>{esc(src)}</em> restored and verified "
                f"correctly ({n_pass}/{total} checks passed), but {n_warn} recovery-objective "
                f"warning{'s' if n_warn != 1 else ''} need attention. The data is recoverable.")
    else:
        tldr = (f"<strong>Bottom line:</strong> the restore drill for <em>{esc(src)}</em> failed "
                f"{n_fail} of {total} checks. This backup is not currently a reliable recovery source.")
    p.append(f"<div class='tldr'>{tldr}</div>")

    if nonpass:
        p.append("<div class='nextsteps'><h3>Next steps - what to fix first</h3><ol>")
        for c in nonpass[:3]:
            base = re.sub(r'^', '', c.get('check', ''))
            rec = CHECK_META.get(base, {}).get('rec', '')
            p.append(f"<li><strong>{esc(c.get('title', base))}</strong> - {esc(rec)}</li>")
        p.append("</ol></div>")

    # KPI cards
    pass_cls = 'ok' if n_fail == 0 and n_warn == 0 else ('crit' if n_fail else 'warn')
    verdict_cls = {'PASS': 'ok', 'WARN': 'warn', 'FAIL': 'crit'}[verdict if verdict in ('PASS', 'WARN', 'FAIL') else 'FAIL']
    kpis = [
        ('Drill result', verdict, verdict_cls),
        ('Checks passed', f"{n_pass}/{total}", pass_cls),
        ('Restore time (RTO)', rto_short, ''),
        ('Backup size', backup_size, ''),
        ('Backup age (RPO)', rpo_short, ''),
        ('Rows verified', rows, ''),
    ]
    p.append("<div class='kpi-row'>")
    for lbl, num, cls in kpis:
        ncls = f" {cls}" if cls else ''
        p.append(f"<div class='kpi'><div class='lbl'>{esc(lbl)}</div>"
                 f"<span class='num{ncls}'>{esc(num)}</span></div>")
    p.append("</div>")

    # charts
    domain_counts: Dict[str, int] = {}
    for c in checks:
        dom = CHECK_META.get(c.get('check', ''), {}).get('domain', 'Other')
        domain_counts[dom] = domain_counts.get(dom, 0) + 1
    bar = svg_bar([(k, v) for k, v in domain_counts.items()])
    p.append("<div class='charts-row'>"
             f"<div><h3>Check outcomes</h3>{status_donut(n_pass, n_warn, n_fail)}</div>"
             f"<div><h3>Checks by area</h3>{bar}</div></div>")
    p.append("</div>")  # /section

    # ---- Drill parameters ---------------------------------------------------
    params = [
        ('Engine', engine_label),
        ('Source database', summary.get('source', '(unknown)')),
        ('Scratch database', summary.get('target', '(unknown)')),
        ('Backup', summary.get('backup', '(unknown)')),
        ('Recovery time (RTO)', summary.get('rto', '(unknown)')),
        ('Recovery point (RPO)', summary.get('rpo', '(unknown)')),
        ('Rows verified', summary.get('rows', '(unknown)')),
        ('Run timestamp', summary.get('timestamp', '(unknown)')),
        ('Report folder', report_dir.name),
        ('Generated', now_str()),
    ]
    p.append(f"<div class='card'><h2 style='margin-top:0;border:none;'>Drill parameters</h2>{kv_grid(params)}</div>")

    # ---- Results table ------------------------------------------------------
    p.append("<div class='section'><h2>Drill results</h2>"
             "<p class='intro'>Every check, in priority order. The drill is read-only on the "
             "source; the scratch database is dropped on completion.</p>")
    p.append("<table class='results'><thead><tr>"
             "<th>Status</th><th>Tier</th><th>Check</th><th>Result</th><th>Threshold</th><th>Detail</th>"
             "</tr></thead><tbody>")
    for c in checks:
        st = c.get('status', 'FAIL')
        rowcls = {'PASS': 'row-pass', 'WARN': 'row-warn'}.get(st, 'row-fail')
        metric = c.get('metric', '-') or '-'
        thr = c.get('threshold', '-') or '-'
        p.append(f"<tr class='{rowcls}'>"
                 f"<td class='st'>{_BADGE.get(st, esc(st))}</td>"
                 f"<td>{esc(c.get('tier', ''))}</td>"
                 f"<td>{esc(c.get('title', c.get('check', '')))}</td>"
                 f"<td class='metric'>{esc(metric)}</td>"
                 f"<td class='thr'>{esc(thr)}</td>"
                 f"<td class='detail'>{esc(c.get('detail', ''))}</td></tr>")
    p.append("</tbody></table></div>")

    # ---- Findings (non-pass) ------------------------------------------------
    p.append("<div class='section'><h2>Findings</h2>")
    if not nonpass:
        p.append("<div class='note'><span class='ok'>No issues.</span> Every check passed - "
                 "the backup is proven restorable and faithful to the source.</div>")
    else:
        for c in nonpass:
            sev = _finding_severity(c.get('status', 'FAIL'))
            sevcls = sev.lower()
            base = c.get('check', '')
            rec = CHECK_META.get(base, {}).get('rec', '')
            out = c.get('output', '')
            p.append(f"<div class='finding sev-{sevcls}'>")
            p.append("<div class='finding-head'>"
                     f"<span class='finding-title'>{esc(c.get('title', base))}</span>"
                     f"<span class='finding-script'>{_BADGE.get(c.get('status'), '')} &middot; {esc(base)}</span></div>")
            if c.get('detail'):
                p.append(f"<div class='finding-detail'>{esc(c['detail'])}</div>")
            if rec:
                p.append(f"<div class='finding-rec'>{esc(rec)}</div>")
            if out:
                excerpt = out if len(out) < 2000 else out[:2000] + '\n... (truncated, see raw log)'
                p.append(f"<pre class='cmd'>{esc(excerpt)}</pre>")
            p.append("</div>")
    p.append("</div>")

    # ---- Raw output appendix ------------------------------------------------
    p.append("<div class='section' id='appendix'><h2>Raw check output</h2>")
    for c in checks:
        out = c.get('output', '') or '(no output)'
        p.append(f"<details class='sql-index'><summary>{_BADGE.get(c.get('status'), '')} "
                 f"{esc(c.get('logfile', c.get('check', '')))}</summary>"
                 f"<pre class='cmd'>{esc(out)}</pre></details>")
    p.append("</div>")

    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>{esc(title)}</title>{''.join(p[:2])}</head><body>"
            f"{''.join(p[2:])}</body></html>")


# ---------------------------------------------------------------------------
# CLI entry point shared by the per-engine wrappers
# ---------------------------------------------------------------------------
def cli(engine_key: str, engine_label: str, default_name: str) -> int:
    ap = argparse.ArgumentParser(
        description=f'Turn a {engine_label} restore-drill report folder into a branded HTML report.')
    ap.add_argument('report_dir', help='Folder produced by run_restore_drill.sh')
    ap.add_argument('--server',   default='', help='Server label printed on the cover')
    ap.add_argument('--customer', default='', help='Customer / project name printed on the cover')
    ap.add_argument('--out',      default='', help=f'Output HTML path (default: <report_dir>/{default_name})')
    args = ap.parse_args()

    report_dir = Path(args.report_dir)
    if not report_dir.is_dir():
        print(f'[ERROR] report dir not found: {report_dir}', file=sys.stderr)
        return 2
    if not any(report_dir.glob('*.log')):
        print(f'[ERROR] no .log files in {report_dir}', file=sys.stderr)
        return 3
    if not load_checks(report_dir):
        print(f'[ERROR] no parseable restore-drill checks in {report_dir} '
              '(the .log files are missing the structured header)', file=sys.stderr)
        return 3

    out = Path(args.out) if args.out else report_dir / default_name
    html = build_html(report_dir, engine_label, args.server, args.customer)
    out.write_text(html, encoding='utf-8')
    copy_brand_assets(out.parent)
    print(f'[OK] wrote {out}')
    return 0
