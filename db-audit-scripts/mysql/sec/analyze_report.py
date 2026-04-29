#!/usr/bin/env python3
"""
analyze_report.py -- MySQL security audit report analyzer.

Reads the report directory produced by run_audit.sh, applies a security
rule set, and writes one HTML file with an executive summary plus a
dedicated section per database.

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import re
import sys
from pathlib import Path

RULES = [
    dict(script='sec_01_users_and_roles_inventory', mode='has_data', severity='Info',
         title='User / role inventory captured',
         recommendation='Review the user list. Remove unused accounts. Rotate dormant role grants.'),

    dict(script='sec_03_admin_and_superusers',       mode='has_data', severity='Info',
         title='Privileged accounts (SUPER / GRANT OPTION / ALL)',
         recommendation='Reduce SUPER, GRANT OPTION, and ALL PRIVILEGES grants to the minimum required.'),

    dict(script='sec_04_public_and_excessive_grants',  mode='pattern', severity='Warning',
         pattern=r"(?im)'%'\s*\|.*ALL PRIVILEGES|host\s*=\s*'%'",
         title='Account allowed to connect from any host (host = %)',
         recommendation="Restrict 'host' for privileged accounts. % allows connections from anywhere."),

    dict(script='sec_05_authentication_and_passwords',  mode='pattern', severity='Critical',
         pattern=r"(?im)mysql_native_password|password_lifetime\s*\|\s*0|authentication_string\s*\|\s*\W*$",
         title='Weak authentication plugin or no password policy',
         recommendation='Use caching_sha2_password. Set default_password_lifetime > 0. Force complex passwords.'),

    dict(script='sec_05_authentication_and_passwords',  mode='pattern', severity='Warning',
         pattern=r'(?im)password\s*=\s*user|account_locked\s*\|\s*N',
         title='Trivial passwords or no account lockout',
         recommendation='Force password change. Configure password_lock_time / failed-login policy.'),

    dict(script='sec_06_audit_logging',               mode='pattern', severity='Warning',
         pattern=r'(?im)general_log\s*\|\s*OFF.*audit_log',
         title='No audit logging plugin active',
         recommendation='Enable audit_log (Enterprise) or MariaDB Audit Plugin. general_log alone is insufficient.'),

    dict(script='sec_07_encryption_status',           mode='pattern', severity='Warning',
         pattern=r'(?im)require_secure_transport\s*\|\s*OFF|have_ssl\s*\|\s*DISABLED',
         title='SSL/TLS not enforced',
         recommendation='Set require_secure_transport=ON and configure SSL certs.'),

    dict(script='sec_08_network_exposure',            mode='pattern', severity='Warning',
         pattern=r"(?im)bind_address\s*\|\s*0\.0\.0\.0|bind_address\s*\|\s*\*",
         title='bind-address binds all interfaces',
         recommendation='Bind to specific interfaces or restrict via firewall. Use TLS for any non-localhost.'),

    dict(script='sec_09_sensitive_data_discovery',    mode='has_data', severity='Warning',
         title='Columns with PII / sensitive name patterns',
         recommendation='Verify whether these columns hold sensitive data. Apply at-rest encryption or tokenization.'),

    dict(script='sec_10_dangerous_objects',           mode='pattern', severity='Critical',
         pattern=r'(?im)local_infile\s*\|\s*ON',
         title='LOCAL INFILE is enabled',
         recommendation='Disable local_infile to prevent client-side file disclosure attacks.'),

    dict(script='sec_10_dangerous_objects',           mode='has_data', severity='Warning',
         title='Server-defined UDFs / functions',
         recommendation='Audit each function. Untrusted code in UDFs is a privilege escalation surface.'),

    dict(script='sec_17_recovery_and_backup_security', mode='pattern', severity='Warning',
         pattern=r'(?im)log_bin\s*\|\s*OFF',
         title='Binary logging disabled',
         recommendation='Without binlog there is no point-in-time recovery. Enable log_bin and configure retention.'),

    dict(script='sec_20_failed_login_patterns',       mode='has_data', severity='Warning',
         title='Failed-login activity',
         recommendation='Review the failed-login source. Tune brute-force defenses (FAILED_LOGIN_ATTEMPTS).'),
]

SEPARATOR_RE = re.compile(r'^[\s+\-]+\-{3,}[\s+\-]*$')
ROW_COUNT_RE = re.compile(r'^\(?\s*\d+\s+rows?(\s+in\s+set)?.*\)?\s*$', re.IGNORECASE)
NOTE_RE      = re.compile(r'^(\+|\-\-|Empty set|Query OK|Database changed|\s*$)')


_BOM_UTF16_LE = b'\xff\xfe'
_BOM_UTF16_BE = b'\xfe\xff'
_BOM_UTF8     = b'\xef\xbb\xbf'


def _detect_encoding(path: Path) -> str:
    try:
        with path.open('rb') as f:
            head = f.read(4)
    except OSError:
        return 'utf-8'
    if head[:2] == _BOM_UTF16_LE: return 'utf-16'
    if head[:2] == _BOM_UTF16_BE: return 'utf-16'
    if head[:3] == _BOM_UTF8:     return 'utf-8-sig'
    if len(head) >= 2 and 0 < head[0] < 128 and head[1] == 0:
        return 'utf-16-le'        # BOM-less UTF-16 LE
    return 'utf-8'


def _read_log(path: Path) -> str:
    enc = _detect_encoding(path)
    try:
        return path.read_text(encoding=enc, errors='replace')
    except OSError:
        return ''


def log_has_data_rows(log_path: Path) -> bool:
    """Return True if a psql log has data rows beyond headers / notices."""
    text = _read_log(log_path)
    if not text:
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
    return _read_log(log_path)



def read_summary(summary_path: Path):
    if not summary_path.exists():
        return
    for raw in _read_log(summary_path).splitlines():
        m = re.match(r'^(OK|FAIL)\s+(\S+)', raw)
        if m:
            yield m.group(1), m.group(2)


def find_findings(log_dir: Path) -> list[dict]:
    findings: list[dict] = []
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
                        if re.match(r'^ERROR\s+\d+', l)][:5]
                if errs:
                    detail = '\n'.join(errs)
        findings.append(dict(severity='Critical', script=script,
                             title='Script execution failed', detail=detail,
                             recommendation='Check connection privileges and the script log.'))

    for log in sorted(log_dir.glob('*.log')):
        for rule in RULES:
            if rule['script'] not in log.stem:
                continue
            hit, detail = False, ''
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
                findings.append(dict(severity=rule['severity'], script=log.name,
                                     title=rule['title'], detail=detail,
                                     recommendation=rule['recommendation']))
    return findings


def discover_contexts(root: Path) -> list[dict]:
    if (root / '_summary.txt').exists():
        return [dict(name='(single run)', log_dir=root)]
    contexts: list[dict] = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted(sub.glob('mysql_sec_*'), reverse=True)
        if runs:
            contexts.append(dict(name=sub.name, log_dir=runs[0]))
    return contexts


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
    return ('<table class="findings"><thead><tr>'
            '<th>Severity</th><th>Script</th><th>Finding</th><th>Recommendation</th>'
            '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')


CSS = """\
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;}
h1{margin:0 0 4px 0;}h2{border-bottom:2px solid #00758f;padding-bottom:4px;margin-top:32px;}
header{background:#00758f;color:white;padding:24px;border-radius:6px;margin-bottom:20px;}
header p{margin:4px 0;opacity:0.9;}
.summary{background:white;padding:16px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;}
th,td{padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#e6f0f3;font-weight:600;}
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
.toc a{text-decoration:none;color:#00758f;}.toc a:hover{text-decoration:underline;}
section.db{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
section.db h3{margin-top:0;color:#00758f;}
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
<title>MySQL Security Audit Report</title>
{CSS}
</head><body>
<header>
  <h1>MySQL Security Audit Report</h1>
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
        f"<tr style='font-weight:bold;background:#e9f0f3;'><td>TOTAL</td>"
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('report_dir')
    ap.add_argument('--server', default='')
    ap.add_argument('--out', default='')
    args = ap.parse_args()

    report_dir = Path(args.report_dir).resolve()
    if not report_dir.is_dir():
        print(f'ERROR: report directory not found: {report_dir}', file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else (report_dir / 'sec_analysis.html')

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

    print('=' * 80)
    print('Security audit analysis complete.')
    print(f'  Databases analyzed : {len(report)}')
    print(f'  Critical findings  : {sum(r["critical"] for r in report)}')
    print(f'  Warnings           : {sum(r["warning"]  for r in report)}')
    print(f'  Failed scripts     : {sum(r["failed"]   for r in report)}')
    print(f'  Report             : {out}')
    print('=' * 80)
    return 0


if __name__ == '__main__':
    sys.exit(main())
