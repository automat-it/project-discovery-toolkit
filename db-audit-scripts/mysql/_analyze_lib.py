"""Shared helpers for the MySQL audit-report analyzers (perf + sec).

The two analyzers under mysql/perf and mysql/sec import this module to
share three responsibilities:

  1. Read MySQL .log files produced by the audit runner. The mysql(1)
     client in non-interactive mode emits TAB-SEPARATED columns with a
     header line per result set. `parse_result_sets()` turns each block
     into a list of dicts so the rules can pull concrete object names
     (table, index, user, digest, ...) instead of only saying "review
     the log".

  2. Extract a one-row fingerprint snapshot of the target server.
     perf_05 and sec_21 both emit a fingerprint header (added for the
     analyzer specifically) with @@version, current database, hostname,
     buffer pool, Aurora/RDS flag and a handful of headline settings.
     The analyzer surfaces this card at the top of the report.

  3. Provide tiny HTML helpers (`esc`, `kv_grid`, `object_table`) used
     by both analyzers so the styling stays consistent across perf / sec.

Standard library only. No external dependencies.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# File encoding detection + reading
# ---------------------------------------------------------------------------
_BOM_UTF16_LE = b'\xff\xfe'
_BOM_UTF16_BE = b'\xfe\xff'
_BOM_UTF8     = b'\xef\xbb\xbf'


def detect_encoding(path: Path) -> str:
    """Best-effort encoding sniff. PowerShell 5.1 writes UTF-16 LE with a
    BOM; macOS / Linux runners write UTF-8 (often with no BOM).  We sniff
    the first four bytes; if there's no BOM we fall back to UTF-8."""
    try:
        with path.open('rb') as fh:
            head = fh.read(4)
    except OSError:
        return 'utf-8'
    if head[:2] == _BOM_UTF16_LE: return 'utf-16'
    if head[:2] == _BOM_UTF16_BE: return 'utf-16'
    if head[:3] == _BOM_UTF8:     return 'utf-8-sig'
    if len(head) >= 2 and 0 < head[0] < 128 and head[1] == 0:
        return 'utf-16-le'
    return 'utf-8'


def read_log_text(path: Path) -> str:
    enc = detect_encoding(path)
    try:
        return path.read_text(encoding=enc, errors='replace')
    except OSError as e:
        # A silent empty string would make the analyzer behave as if the
        # script had no findings. Make the failure visible so the user can
        # distinguish "clean" from "couldn't read".
        print(f'[warn] cannot read {path}: {e}', file=sys.stderr)
        return ''


# ---------------------------------------------------------------------------
# MySQL TAB-separated output parser (mysql client in non-interactive mode)
# ---------------------------------------------------------------------------
# The mysql(1) batch-mode output for each SELECT is:
#   COL1<TAB>COL2<TAB>COL3       <- header line
#   v1<TAB>v2<TAB>v3             <- data row
#   v1<TAB>v2<TAB>v3
# Multiple SELECTs in one script are concatenated WITHOUT a blank-line
# separator -- the next result set just starts with its own header line.
#
# Header detection: see parse_result_sets() docstring. We use tab-count
# change as the boundary heuristic; an identifier-pattern check on the
# header would drop data rows like ``shop_demo\tcustomers\temail``.
_ERROR_RE = re.compile(r'^(ERROR|mysql:|\[note\]|\[ERROR\])')


def parse_result_sets(text: str) -> List[Dict]:
    """Parse mysql(1) tab-separated batch-mode output into a list of
    result sets. Each set is {'columns': [...], 'rows': [{col: v, ...}, ...]}.

    Heuristic: a new result set begins whenever the tab count of the
    current line differs from the previous one. The first non-empty line
    is always the first header. Same-tab-count consecutive queries will
    merge into one set -- that is acceptable for the report.

    Why not detect headers by identifier-pattern? Because real data
    rows like ``shop_demo\\tcustomers\\temail`` look identical to a
    header ``schema\\ttable\\tcolumn`` and false positives drop data."""
    sets: List[Dict] = []
    lines = text.splitlines()
    current: Dict = {'columns': [], 'rows': []}

    def flush():
        if current['columns']:
            sets.append({'columns': current['columns'],
                         'rows': current['rows']})

    started = False
    for raw in lines:
        if not raw.strip():
            continue
        if _ERROR_RE.match(raw):
            continue
        cells = raw.split('\t')
        if not started:
            current['columns'] = cells
            current['rows'] = []
            started = True
            continue
        if len(cells) != len(current['columns']):
            # Tab count changed -- this is the header of a new result set.
            flush()
            current = {'columns': cells, 'rows': []}
            continue
        # Same tab count: treat as data row of the current set.
        cols = current['columns']
        current['rows'].append({cols[k]: cells[k] for k in range(len(cols))})
    flush()
    return sets


def first_row(text: str, set_index: int = 0) -> Optional[Dict[str, str]]:
    """Return the first row of the N-th result set, or None."""
    sets = parse_result_sets(text)
    if set_index < 0 or set_index >= len(sets):
        return None
    rows = sets[set_index]['rows']
    return rows[0] if rows else None


def has_data_rows(text: str) -> bool:
    return any(s['rows'] for s in parse_result_sets(text))


# ---------------------------------------------------------------------------
# Log discovery
# ---------------------------------------------------------------------------
def find_log(log_dir: Path, name_substring: str) -> Optional[Path]:
    """Return the .log file whose name matches <substring> best.

    Preference order:
      1. exact stem match
      2. stem starts with the substring (after the priority prefix)
      3. substring appears anywhere in the name
    The runner prefixes logs with ``<priority>_`` (e.g. ``critical_``),
    so we strip that before the prefix check."""
    candidates = sorted(log_dir.glob('*.log'))
    exact = [p for p in candidates if p.stem == name_substring]
    if exact:
        return exact[0]
    prefix = [p for p in candidates
              if re.sub(r'^(critical|high|medium|low)_', '', p.stem)
                  .startswith(name_substring)]
    if prefix:
        return prefix[0]
    for p in candidates:
        if name_substring in p.name:
            return p
    return None


def script_matches_log(rule_script: str, log_stem: str) -> bool:
    """Return True iff ``log_stem`` corresponds to ``rule_script``.

    ``log_stem`` has the form ``<priority>_<script>`` (e.g.
    ``critical_sec_05_authentication_and_passwords``). We strip the
    priority prefix and require an exact match, so a rule for
    ``perf_02_blocking_and_locks`` will NOT also fire on a future
    ``perf_02_blocking_and_locks_extended`` log."""
    stem = re.sub(r'^(critical|high|medium|low)_', '', log_stem)
    return stem == rule_script


def read_summary(summary_path: Path) -> Iterable:
    """Yield (status, script_path) tuples from a runner _summary.txt."""
    if not summary_path.exists():
        return
    for raw in read_log_text(summary_path).splitlines():
        m = re.match(r'^(OK|FAIL)\s+(\S+)', raw)
        if m:
            yield m.group(1), m.group(2)


def read_target(report_dir: Path) -> Dict[str, str]:
    """Parse the `Target: user@host:port/db` line from _summary.txt."""
    out: Dict[str, str] = {}
    sp = report_dir / '_summary.txt'
    if not sp.exists():
        return out
    for raw in read_log_text(sp).splitlines():
        m = re.match(r'^Target:\s+([^@]+)@([^:]+):(\d+)/(\S+)', raw.strip())
        if m:
            out.update(
                user=m.group(1).strip(),
                host=m.group(2).strip(),
                port=m.group(3).strip(),
                database=m.group(4).strip(),
            )
            break
    return out


# ---------------------------------------------------------------------------
# Fingerprint extraction (works for both perf_05 and sec_21 headers)
# ---------------------------------------------------------------------------
_FINGERPRINT_KEYS = (
    'database_name', 'connection_user', 'server_version',
    'server_version_comment', 'server_hostname',
    'max_connections', 'innodb_buffer_pool_size',
    'performance_schema', 'log_bin', 'gtid_mode',
    'read_only', 'super_read_only', 'is_aws_rds',
    'time_zone', 'character_set_server', 'server_time',
)


def read_fingerprint(log_dir: Path, source_substrings: Iterable[str]) -> Dict[str, str]:
    """Pull the single-row fingerprint header from the first matching log.

    perf analyzer passes ('perf_05_configuration_snapshot',), sec analyzer
    passes ('sec_21_patch_and_cve_level',). When neither is found (the
    audit didn't include the file) we return {} and the caller renders
    a fallback card from _summary.txt only.
    """
    for sub in source_substrings:
        log = find_log(log_dir, sub)
        if not log:
            continue
        row = first_row(read_log_text(log), set_index=0)
        if row and any(k in row for k in _FINGERPRINT_KEYS):
            return row
    return {}


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
def esc(value) -> str:
    return _html.escape('' if value is None else str(value))


def kv_grid(items: List[tuple], css_class: str = 'fp') -> str:
    """Render a <dl> grid of (label, value) tuples. Mirrors mssql analyzer."""
    if not items:
        return ''
    parts = [f"<dl class='{css_class}'>"]
    for label, value in items:
        if value in (None, '', '(unknown)'):
            value = '(unknown)'
        parts.append(f"<dt>{esc(label)}</dt><dd>{esc(value)}</dd>")
    parts.append("</dl>")
    return ''.join(parts)


def object_table(rows: List[Dict[str, str]], columns: List[str],
                 limit: int = 25, css_class: str = 'objs',
                 link_columns: Optional[Dict[str, str]] = None) -> str:
    """Render a small <table> of concrete objects (e.g. unused indexes).

    rows: a list of dicts produced by parse_result_sets.
    columns: which columns (and in which order) to render; missing
             columns are emitted as blank cells.
    limit:   cap the rendered rows; appends "... +N more" when truncated.
    link_columns: optional {column_name: href_template} where the
             template is a format string with {value} placeholder.
             When set, the cell content is wrapped in
             <a href="...">value</a>. Used to link queryid -> the
             full-SQL appendix entry.
    """
    if not rows:
        return ''
    link_columns = link_columns or {}
    visible = rows[:limit]
    overflow = max(0, len(rows) - limit)
    parts = [f"<table class='{css_class}'><thead><tr>"]
    for c in columns:
        parts.append(f"<th>{esc(c)}</th>")
    parts.append("</tr></thead><tbody>")
    # Long-text columns: allow line wrapping; identifiers stay intact.
    wrap_cols = set()
    for c in columns:
        cl = c.lower()
        if (cl == 'query' or cl == 'last_query' or cl == 'blocked_query'
                or 'definition' in cl or 'fk_columns' in cl
                or 'detail' in cl or cl == 'options' or cl == 'settings'):
            wrap_cols.add(c)
    for r in visible:
        parts.append("<tr>")
        for c in columns:
            val = r.get(c, '')
            if val and isinstance(val, str) and len(val) > 200:
                val = val[:200].rstrip() + ' ...'
            cls = " class='wrap'" if c in wrap_cols else ''
            if c in link_columns and val:
                # urllib.quote both protects against odd queryid contents
                # AND keeps the anchor target consistent with the appendix
                # (which also URL-encodes the id).
                qv = urllib.parse.quote(str(r.get(c, '')), safe='')
                href = link_columns[c].replace('{value}', qv)
                parts.append(f"<td{cls}><a class='qid-link' href='{esc(href)}'>{esc(val)}</a></td>")
            else:
                parts.append(f"<td{cls}>{esc(val)}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    if overflow:
        parts.append(f"<div class='overflow'>... +{overflow} more rows -- consult the raw .log file for the full list</div>")
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Brand assets: cover image + watermark. Shared by all engine analyzers
# (PostgreSQL / MySQL Python; MSSQL PowerShell). Files live at
# db-audit-scripts/assets/ -- we copy them next to the rendered HTML so
# Chromium picks them up via relative URLs.
# ---------------------------------------------------------------------------
def copy_brand_assets(out_dir: Path) -> None:
    import shutil
    # Walk up from this file (db-audit-scripts/<engine>/_analyze_lib.py)
    # to db-audit-scripts/, then assets/.
    src_dir = Path(__file__).resolve().parent.parent / 'assets'
    if not src_dir.is_dir():
        return
    for name in ('ait_bg_cover.png', 'ait_bg_page.png'):
        src = src_dir / name
        if src.exists():
            try:
                shutil.copy2(src, out_dir / name)
            except OSError as e:
                print(f'[warn] could not copy {name}: {e}', file=sys.stderr)


def svg_donut(critical: int, warning: int, info: int) -> str:
    """Severity-mix donut chart matching the MSSQL analyzer."""
    import math
    total = critical + warning + info
    if total <= 0:
        return "<p class='ok'>No findings recorded.</p>"
    rad, cx, cy, stroke = 80, 110, 110, 30
    vals = [
        ('Critical', critical, '#c0392b'),
        ('Warning',  warning,  '#e67e22'),
        ('Info',     info,     '#2980b9'),
    ]
    out, offset = [], 0
    for _, n, c in vals:
        if n <= 0:
            continue
        angle = 360.0 * n / total
        a1 = (offset - 90) * math.pi / 180.0
        a2 = (offset + angle - 90) * math.pi / 180.0
        x1, y1 = cx + rad * math.cos(a1), cy + rad * math.sin(a1)
        x2, y2 = cx + rad * math.cos(a2), cy + rad * math.sin(a2)
        large = 1 if angle > 180 else 0
        out.append(
            f"<path d='M {cx} {cy} L {x1:.2f} {y1:.2f} "
            f"A {rad} {rad} 0 {large} 1 {x2:.2f} {y2:.2f} Z' fill='{c}'/>"
        )
        offset += angle
    out.append(f"<circle cx='{cx}' cy='{cy}' r='{rad - stroke}' fill='white'/>")
    out.append(f"<text x='{cx}' y='{cy - 3}' text-anchor='middle' "
               f"font-size='22' font-weight='600' fill='#222'>{total}</text>")
    out.append(f"<text x='{cx}' y='{cy + 18}' text-anchor='middle' "
               f"font-size='10' fill='#777'>findings</text>")
    out.append("<g font-family='Segoe UI,Arial' font-size='12'>")
    ly = 30
    for label, n, c in vals:
        out.append(f"<rect x='240' y='{ly}' width='14' height='14' fill='{c}'/>")
        out.append(f"<text x='262' y='{ly + 12}' fill='#222'>{label}: {n}</text>")
        ly += 22
    out.append('</g>')
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 380 220' "
            f"width='380' height='220'>{''.join(out)}</svg>")


def svg_bar(items: list, color: str = '#1F497D') -> str:
    """Horizontal bar chart. ``items`` is [(label, value), ...]."""
    items = [(l, v) for l, v in items if v > 0]
    if not items:
        return ''
    max_n = max(v for _, v in items) or 1
    row_h, pad_top, pad_left, width = 22, 10, 200, 600
    h = pad_top + row_h * len(items) + 10
    out = [f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {h}' "
           f"width='{width}' height='{h}' font-family='Segoe UI,Arial' font-size='12'>"]
    y = pad_top
    for label, n in items:
        w = int((width - pad_left - 50) * n / max_n)
        out.append(f"<text x='{pad_left - 8}' y='{y + 14}' text-anchor='end' "
                   f"fill='#333'>{esc(label)}</text>")
        out.append(f"<rect x='{pad_left}' y='{y}' width='{w}' height='16' fill='{color}'/>")
        out.append(f"<text x='{pad_left + w + 6}' y='{y + 14}' fill='#333'>{n}</text>")
        y += row_h
    out.append('</svg>')
    return ''.join(out)


# Per-category domain buckets used for "Findings by Domain". Match the
# MSSQL analyzer's bucket map so the same finding number rolls up under
# the same domain across all three engines.
DOMAIN_BUCKETS_SEC: dict = {
    'Identity & access':         ('sec_01', 'sec_02', 'sec_03', 'sec_11', 'sec_12'),
    'Public / excessive grants': ('sec_04',),
    'Authentication':            ('sec_05',),
    'Audit & logging':           ('sec_06', 'sec_18', 'sec_19', 'sec_20'),
    'Encryption':                ('sec_07', 'sec_22'),
    'Network exposure':          ('sec_08',),
    'Sensitive data (PII)':      ('sec_09', 'sec_16'),
    'Dangerous objects':         ('sec_10', 'sec_15'),
    'Backup security':           ('sec_14', 'sec_17'),
    'Patch / CVE level':         ('sec_21',),
}

DOMAIN_BUCKETS_PERF: dict = {
    'Top SQL & queries':         ('perf_01', 'perf_16', 'perf_23'),
    'Blocking & locking':        ('perf_02', 'perf_13'),
    'Sessions & connections':    ('perf_03',),
    'Waits & I/O':               ('perf_04', 'perf_14'),
    'Indexes':                   ('perf_06', 'perf_12'),
    'Statistics & bloat':        ('perf_07', 'perf_11', 'perf_17'),
    'Storage & sizing':          ('perf_08', 'perf_15', 'perf_19'),
    'Memory & temp':             ('perf_09',),
    'Backup / replication':      ('perf_10', 'perf_22'),
    'HA / cluster':              ('perf_24',),
    'Workload & partitions':     ('perf_18', 'perf_20', 'perf_21'),
}


def domain_counts(findings: list, buckets: dict) -> list:
    """Aggregate findings into [(domain, count), ...] preserving bucket
    order. A finding lands in the first bucket whose prefix matches its
    ``script`` field."""
    counts = {k: 0 for k in buckets}
    for f in findings:
        script = f.get('script', '')
        for domain, prefixes in buckets.items():
            if any(p in script for p in prefixes):
                counts[domain] += 1
                break
    return [(d, c) for d, c in counts.items() if c > 0]


def render_cover(title: str, server: str, customer: str,
                 databases_analysed: int) -> str:
    """Branded cover page matching the MSSQL analyzer.

    Renders as the first <section> of the HTML; the @page CSS + the
    .cover background fill the first A4 sheet. The watermark on every
    other page is produced by .page-bg (rendered separately, fixed
    position)."""
    cust = (esc(customer) if customer else '&nbsp;')
    return (
        "<section class='cover'><div class='cover-content'>"
        f"<h1>{esc(title)}</h1>"
        f"<div class='sub'>{cust}</div>"
        f"<div class='meta'><strong>Server:</strong> {esc(server or '(unspecified)')} "
        f"&nbsp;&middot;&nbsp; <strong>{databases_analysed}</strong> "
        f"{'database' if databases_analysed == 1 else 'databases'} analyzed</div>"
        f"<div class='date'>{now_str()}</div>"
        "</div></section>"
        "<div class='page-bg'></div>"
    )


# ---------------------------------------------------------------------------
# Severity ranking + common CSS shared by both analyzers
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {'Critical': 0, 'Warning': 1, 'Info': 2}
_UNKNOWN_SEVERITY_SEEN: set = set()


def severity_rank(s: str) -> int:
    if s in _SEVERITY_RANK:
        return _SEVERITY_RANK[s]
    # Warn ONCE per unknown severity so a typo in a rule doesn't silently
    # disappear from KPI counters.
    if s not in _UNKNOWN_SEVERITY_SEEN:
        _UNKNOWN_SEVERITY_SEEN.add(s)
        print(f'[warn] unknown severity {s!r} -- treating as Warning',
              file=sys.stderr)
    return _SEVERITY_RANK['Warning']


SHARED_CSS = """\
<style>
@page{size:A4 portrait;margin:18mm 14mm;@bottom-center{content:counter(page) ' / ' counter(pages);font-size:8pt;color:#777;}}
@media print{body{background:white !important;padding:0;}.card,section.db{box-shadow:none !important;background:white !important;}}
/* Branded cover page + watermark on inner pages (Chromium --print-to-pdf). */
.page-bg{position:fixed;top:0;left:0;right:0;bottom:0;z-index:-1;background-image:url('ait_bg_page.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;opacity:0.5;}
.cover{position:relative;width:100%;height:calc(297mm - 36mm);page-break-after:always;break-after:page;background-image:url('ait_bg_cover.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;color:#000;text-align:center;}
.cover-content{position:absolute;left:0;right:0;top:55%;padding:0 16mm;}
.cover h1{font-size:24pt;font-weight:800;color:#000;margin:0 0 10px;}
.cover .sub{font-size:13pt;color:#333;margin:0 0 4px;font-weight:500;}
.cover .meta{font-size:11pt;color:#444;margin:0 0 6px;}
.cover .date{font-size:11pt;color:#666;margin-top:8px;}
@media screen{.cover{background-color:#f5f5f5;}}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;line-height:1.4;font-size:9.5pt;}
h1{margin:0 0 4px 0;}
h2{border-bottom:2px solid #336791;padding-bottom:4px;margin-top:28px;color:#336791;}
h3{margin:14px 0 6px;color:#1F497D;}
header{background:#336791;color:white;padding:24px;border-radius:6px;margin-bottom:20px;}
header p{margin:4px 0;opacity:0.9;}
.card{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;font-size:0.95em;}
th,td{padding:6px 10px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#eaf0f6;font-weight:600;color:#1F497D;}
.findings tr:hover{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;}
.badge.critical{background:#c0392b;}.badge.warning{background:#e67e22;}.badge.info{background:#2980b9;}
.sev-critical>td:first-child{border-left:4px solid #c0392b;}
.sev-warning >td:first-child{border-left:4px solid #e67e22;}
.sev-info    >td:first-child{border-left:4px solid #2980b9;}
.detail{color:#555;font-size:0.9em;font-family:Consolas,monospace;white-space:pre-wrap;}
.ok{color:#27ae60;font-weight:600;}
.exec-summary td.num{text-align:right;font-variant-numeric:tabular-nums;}
.exec-summary td.crit{color:#c0392b;font-weight:600;}
.exec-summary td.warn{color:#e67e22;font-weight:600;}
.exec-summary td.fail{color:#c0392b;font-weight:600;}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 16px;}
.kpi{flex:1;min-width:160px;background:rgba(255,255,255,0.92);border:1px solid #d6e6b9;border-radius:6px;padding:14px 16px;}
.kpi .num{font-size:22pt;font-weight:700;color:#1F497D;line-height:1.1;display:block;margin-top:4px;}
.kpi .num.crit{color:#c0392b;}.kpi .num.warn{color:#e67e22;}.kpi .num.fail{color:#c0392b;}
.kpi .lbl{font-size:9pt;color:#666;text-transform:uppercase;letter-spacing:0.5px;}
.section{margin:18px 0 10px;}
.section h2{margin:0 0 6px;font-size:17pt;color:#1F497D;border-bottom:1px solid #d6e6f0;padding-bottom:4px;}
.section .intro{color:#444;font-size:10pt;margin:0 0 12px;}
.charts-row{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start;margin:14px 0 8px;}
.charts-row > div{flex:1;min-width:320px;}
.charts-row h3{margin-top:0;color:#1F497D;font-size:11pt;}
.quick-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px;padding:8px 12px;background:white;border-radius:6px;border:1px solid #e3e8ed;}
.quick-nav a{color:#1F497D;text-decoration:none;font-size:0.88em;padding:4px 10px;border-radius:3px;border:1px solid #d6e6f0;background:#f6f8fb;}
.quick-nav a:hover{background:#eaf0f6;}
.back-top{font-size:0.8em;color:#888;text-decoration:none;float:right;padding:2px 8px;border-radius:3px;}
.back-top:hover{background:#eef3f7;color:#1F497D;}
@media print{
    .quick-nav, .back-top{display:none;}
    section#sql-appendix{page-break-before:always;}
    /* Do NOT avoid breaking inside a whole finding card: a tall card (big
       result table) would otherwise jump entirely to the next page and
       leave a large blank gap under the section header. Instead let the
       card flow across pages and only keep small atomic pieces together. */
    .section{page-break-inside:avoid;break-inside:avoid;}
    .section h2{page-break-after:avoid;break-after:avoid;}
    .finding-head{page-break-inside:avoid;break-inside:avoid;page-break-after:avoid;break-after:avoid;}
    .finding-rec{page-break-inside:avoid;break-inside:avoid;}
    .objs-caption{page-break-after:avoid;break-after:avoid;}
    table.objs thead{display:table-header-group;}
    table.objs tr{page-break-inside:avoid;break-inside:avoid;}
}
dl.fp{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:0.95em;margin:0;}
dl.fp dt{font-weight:600;color:#444;}
dl.fp dd{margin:0;font-family:Consolas,monospace;}
section.db{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
section.db h3{margin-top:0;color:#336791;}
.meta{color:#666;font-size:0.9em;margin-bottom:12px;}
code{background:#f0f0f0;padding:1px 6px;border-radius:3px;font-size:0.9em;}
/* ===== Object table (concrete-objects sub-table inside a finding card) */
table.objs{margin:8px 0 14px;font-size:0.86em;border-collapse:collapse;
    /* width:auto lets columns size to actual content -- prevents the
       "queryid one digit per line" disaster we hit with table-layout:fixed
       inside a narrow finding cell. */
    width:auto;max-width:100%;}
table.objs th, table.objs td{
    overflow-wrap:normal;word-break:normal;white-space:normal;
    padding:5px 10px;vertical-align:top;border-bottom:1px solid #eee;
}
table.objs th{background:#f6f8fb;color:#1F497D;font-weight:600;
    text-align:left;white-space:nowrap;border-bottom:2px solid #d0dbe6;}
/* Identifier-like columns stay on one line; long text wraps only when
   the column is explicitly marked .wrap (query/definition/options ...). */
table.objs td.wrap{overflow-wrap:anywhere;word-break:break-word;
    max-width:520px;}

/* ===== Finding card (replaces the old 4-column findings table) ====== */
.finding{background:white;border-radius:6px;padding:14px 18px;
    margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,0.07);
    border-left:5px solid #999;}
.finding.sev-critical{border-left-color:#c0392b;}
.finding.sev-warning {border-left-color:#e67e22;}
.finding.sev-info    {border-left-color:#2980b9;}
.finding-head{display:flex;align-items:center;flex-wrap:wrap;gap:10px;
    margin-bottom:6px;}
.finding-title{font-weight:700;color:#1F497D;font-size:1.05em;flex:1;}
.finding-script{font-size:0.82em;color:#666;}
.finding-rec{background:#f6f8fb;border-radius:4px;padding:6px 10px;
    margin:4px 0 8px;font-size:0.95em;}
.finding-detail{color:#666;font-size:0.85em;font-family:Consolas,monospace;
    margin:0 0 4px;white-space:pre-wrap;}
.objs-caption{margin:8px 0 2px;font-size:0.92em;color:#444;}
.overflow{color:#888;font-size:0.85em;font-style:italic;margin-top:4px;}
.issue-list{list-style:none;padding:0;margin:6px 0 0;}
.issue-list li{background:white;border-left:4px solid #c0392b;border-radius:4px;padding:8px 12px;margin:6px 0;}
.issue-list li.warn{border-left-color:#e67e22;}
.issue-list .it{display:flex;justify-content:space-between;gap:12px;align-items:baseline;}
.issue-list .ti{font-weight:700;color:#1F497D;}
.issue-list .sc{font-size:0.85em;color:#666;}
.issue-list .ac{margin:4px 0 0;color:#333;font-size:0.92em;}
.issue-list a.jump{font-size:0.85em;color:#1F497D;text-decoration:none;border-bottom:1px dotted #1F497D;}
.note{background:#fff8e1;border-left:4px solid #e67e22;padding:8px 12px;border-radius:4px;margin:8px 0;}
.alert{background:#fdecea;border-left:4px solid #c0392b;padding:8px 12px;border-radius:4px;margin:8px 0;}
a.qid-link{color:#1F497D;text-decoration:none;border-bottom:1px dotted #1F497D;font-family:Consolas,monospace;}
a.qid-link:hover{background:#eef5fc;}
pre.sql-full{background:#1e1e1e;color:#d4d4d4;padding:10px 14px;border-radius:4px;font-family:Consolas,monospace;font-size:0.85em;white-space:pre-wrap;word-break:break-word;page-break-inside:avoid;margin:6px 0 16px;}
details.sql-index{margin:8px 0 16px;background:#f6f8fb;border:1px solid #d6e6f0;border-radius:4px;padding:8px 12px;}
details.sql-index summary{font-weight:600;color:#1F497D;cursor:pointer;}
details.sql-index ul{margin:8px 0 0;padding-left:16px;font-size:0.85em;column-count:1;}
details.sql-index li{margin:2px 0;}
details.sql-index a{color:#1F497D;text-decoration:none;}
details.sql-index a:hover{text-decoration:underline;}
@media print{details.sql-index[open]{display:block;}details.sql-index{padding:6px 10px;}}
section#sql-appendix h4{font-family:Consolas,monospace;font-size:0.95em;margin:14px 0 4px;color:#1F497D;border-top:1px solid #e0e0e0;padding-top:10px;}
pre.cmd{background:#1e1e1e;color:#d4d4d4;padding:10px 14px;border-radius:4px;font-family:Consolas,monospace;font-size:0.85em;white-space:pre-wrap;word-break:break-word;page-break-inside:avoid;margin:4px 0 10px;}
ul.docs-list{margin:4px 0 8px;padding-left:18px;font-size:0.9em;}
ul.docs-list li{margin:2px 0;}
ul.docs-list a{color:#1F497D;text-decoration:none;border-bottom:1px dotted #1F497D;}
ul.docs-list a:hover{text-decoration:underline;}
</style>"""


def now_str() -> str:
    return _dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# ---------------------------------------------------------------------------
# Fingerprint rendering (used by both analyzers)
# ---------------------------------------------------------------------------
def _humanize_bytes(s) -> str:
    """Pretty-print a byte count expressed as a string."""
    try:
        n = int(s)
    except (TypeError, ValueError):
        return str(s) if s is not None else ''
    units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f'{f:.1f} {units[i]}' if i else f'{n} B'


def render_fingerprint_card(fp: Dict[str, str],
                            target: Dict[str, str],
                            report_dir: Path) -> str:
    """Render the Environment Fingerprint card with sensible fallbacks
    (MySQL flavour)."""
    if not fp and not target:
        return "<div class='card'><div class='note'>Environment fingerprint unavailable -- perf_05 / sec_21 produced no parseable header.</div></div>"

    host = target.get('host') or '(unknown)'
    port = target.get('port') or '3306'
    user = target.get('user') or '(unknown)'
    conn_user = fp.get('connection_user') or user
    database = fp.get('database_name') or target.get('database') or '(unknown)'

    version_comment = fp.get('server_version_comment') or ''
    version = fp.get('server_version') or '(unknown)'
    full_version = (f"{version}  ({version_comment})"
                    if version_comment else version)

    # AWS detection. `is_aws_rds` is set whenever the 'rdsadmin' user
    # exists -- that covers both RDS MySQL AND Aurora MySQL. We refine
    # the label by sniffing version_comment ("Source distribution" on
    # Aurora ALSO; Aurora actually shows "Source distribution" in
    # @@version_comment too). The most reliable signal for true Aurora
    # is the `aurora_*` variables, but they don't show up in our
    # fingerprint header. For now we report "AWS RDS / Aurora" honestly.
    aws = (fp.get('is_aws_rds') or '').strip()
    if aws and aws not in ('0', 'NULL'):
        aws_label = 'Yes (AWS RDS or Aurora)'
    elif aws == '0':
        aws_label = 'No (self-managed)'
    else:
        aws_label = '(unknown)'

    def _onoff(v, on='ON', off='OFF'):
        if v in (None, '', 'NULL'):
            return '(unknown)'
        s = str(v).strip().upper()
        if s in ('1', 'ON', 'YES', 'TRUE', 'Y'):
            return on
        if s in ('0', 'OFF', 'NO', 'FALSE', 'N'):
            return off
        return s

    read_only = (fp.get('read_only') or '').strip()
    super_ro  = (fp.get('super_read_only') or '').strip()
    if super_ro == '1':
        role = 'replica (super_read_only)'
    elif read_only == '1':
        role = 'replica (read_only)'
    elif read_only == '0':
        role = 'primary (writeable)'
    else:
        role = '(unknown)'

    bp_bytes = fp.get('innodb_buffer_pool_size')
    bp_human = _humanize_bytes(bp_bytes) if bp_bytes else '(unknown)'

    rows = [
        ('Host',                  f"{host}:{port}"),
        ('Database',              database),
        ('Connection user',       conn_user),
        ('MySQL version',         full_version),
        ('Server hostname',       fp.get('server_hostname') or '(unknown)'),
        ('Server role',           role),
        ('AWS managed (RDS / Aurora)', aws_label),
        ('Server time',           fp.get('server_time') or '(unknown)'),
        ('Time zone',             fp.get('time_zone') or '(unknown)'),
        ('Character set',         fp.get('character_set_server') or '(unknown)'),
        ('max_connections',       fp.get('max_connections') or '(unknown)'),
        ('innodb_buffer_pool',    bp_human),
        ('performance_schema',    _onoff(fp.get('performance_schema'))),
        ('log_bin',               _onoff(fp.get('log_bin'))),
        ('gtid_mode',             fp.get('gtid_mode') or '(unknown)'),
        ('Report folder',         str(report_dir)),
    ]
    rows = [(k, v) for k, v in rows if v not in (None, '', '(unknown)')] or rows
    return f"<div class='card'><h2 style='margin-top:0;border:none;'>Environment Fingerprint</h2>{kv_grid(rows)}</div>"


# ---------------------------------------------------------------------------
# Context naming
# ---------------------------------------------------------------------------
def context_label(fingerprint: Dict[str, str], target: Dict[str, str], fallback: str) -> str:
    """Choose the human-friendly context name shown in the Executive Summary.

    Prefers the actual database name from the fingerprint, then the target
    user-supplied database, and only falls back to "(single run)" when
    neither is available.
    """
    db = fingerprint.get('database_name') or target.get('database')
    return db or fallback
