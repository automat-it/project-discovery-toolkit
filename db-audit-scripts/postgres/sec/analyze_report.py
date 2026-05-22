#!/usr/bin/env python3
"""
analyze_report.py -- PostgreSQL security audit report analyzer.

Reads the report directory produced by run_audit.sh, applies a security
rule set, and writes one HTML file with:

  * Environment fingerprint card (server, version, auth/SSL state, ...)
  * Executive summary (KPI counts + Top issues with what-to-do)
  * Per-finding concrete objects (privileged roles, public grants, PII
    columns, SECURITY DEFINER functions, expiring credentials, ...) so
    the reader has actionable targets, not "review the log".

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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _analyze_lib import (  # noqa: E402
    SHARED_CSS, context_label, esc, has_data_rows, kv_grid, now_str,
    object_table, parse_result_sets, read_fingerprint, read_log_text,
    read_summary, read_target, render_fingerprint_card, severity_rank,
)


# ---------------------------------------------------------------------------
# Sec-specific extractors -- pull concrete objects from logs
# ---------------------------------------------------------------------------
def _ext_superusers(text):
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if 'rolname' in lc or 'rolsuper' in lc:
            return s['rows'][:200]
    return []


def _ext_public_grants(text):
    """sec_04 emits multiple sub-tables (default privileges, schema-level
    grants, object-level grants, public connect ...). Render each as a
    separate small table so column names match their content."""
    sets = parse_result_sets(text)
    groups = []
    for i, s in enumerate(sets):
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        if any(c in lc for c in ('grantee', 'object', 'schema', 'role',
                                 'privilege_type', 'object_type')):
            groups.append(dict(
                label=f"Excessive grants -- subset #{len(groups)+1}",
                columns=s['columns'],
                rows=s['rows'][:200],
            ))
    return groups


def _ext_pii_columns(text):
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if 'column_name' in lc or 'column' in lc:
            return s["rows"][:200]
    return []


def _ext_dangerous(text):
    """sec_10 emits SECURITY DEFINER funcs + dangerous languages + event
    triggers + foreign servers, etc. Render each as a separate small
    table; the SQL script's ORDER OF OUTPUT defines our labels."""
    sets = parse_result_sets(text)
    labels = [
        'SECURITY DEFINER functions',
        'SECURITY DEFINER functions owned by superusers',
        'Functions in untrusted languages',
        'User-defined functions in language "internal"',
        'Installed procedural languages',
        'Event triggers (DDL interceptors)',
        'Superuser-owned triggers on user tables',
        'Foreign Data Wrappers',
        'Foreign servers',
        'User mappings (masked)',
        'Public-executable SECURITY DEFINER functions',
    ]
    groups = []
    for i, s in enumerate(sets):
        if not s['rows']:
            continue
        groups.append(dict(
            label=labels[i] if i < len(labels) else f'Result set #{i+1}',
            columns=s['columns'],
            rows=s['rows'][:200],
        ))
    return groups


def _ext_dormant(text):
    for s in parse_result_sets(text):
        if 'rolname' in s['columns']:
            return s['rows'][:200]
    return []


def _ext_failed_logins(text):
    for s in parse_result_sets(text):
        lc = [c.lower() for c in s['columns']]
        if any(c in lc for c in ('login_name', 'client_addr', 'event_type', 'reason')):
            return s['rows'][:200]
    return []


def _ext_cert_expiry(text):
    for s in parse_result_sets(text):
        if 'expiry_state' in s['columns'] or 'days_until_expiry' in s['columns']:
            # keep only rows where expiry_state != 'no expiry'
            keep = []
            for r in s['rows']:
                state = (r.get('expiry_state') or '').lower()
                if state and 'no expiry' not in state and 'ok' not in state:
                    keep.append(r)
            return keep[:200]
    return []


def _ext_audit_gaps(text):
    out = []
    for s in parse_result_sets(text):
        out.extend(s['rows'][:200])
    return out[:200]


RULES = [
    dict(
        script='sec_03_admin_and_superusers',
        mode='has_data', severity='Info',
        title='Superuser / privileged role membership',
        recommendation='Reduce SUPERUSER, pg_signal_backend, pg_read_all_data '
                       'memberships to the minimum required.',
        extractor=_ext_superusers,
        ext_label='Privileged accounts (sample)',
    ),
    dict(
        script='sec_04_public_and_excessive_grants',
        mode='has_data', severity='Warning',
        title='Permissions granted to PUBLIC or excessive scope',
        recommendation='PUBLIC grants apply to every role. Move them to specific '
                       'roles or REVOKE.',
        extractor=_ext_public_grants,
        ext_label='Excessive grants (sample)',
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Critical',
        pattern=r'(?im)^\s*trust\s|method\s*\|\s*trust',
        title='pg_hba.conf uses "trust" authentication',
        recommendation='Trust auth allows password-less access. Replace with '
                       'scram-sha-256 or cert.',
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Warning',
        pattern=r'(?im)password_encryption\s*\|\s*md5',
        title='password_encryption is md5',
        recommendation='md5 password hashing is deprecated. Switch to scram-sha-256 '
                       'and re-set all passwords.',
    ),
    dict(
        script='sec_06_audit_logging',
        mode='pattern', severity='Warning',
        pattern=r'(?im)log_statement\s*\|\s*none',
        title='log_statement is "none"',
        recommendation='No SQL is logged. Set log_statement to ddl or all for audit.',
    ),
    dict(
        script='sec_07_encryption_status',
        mode='pattern', severity='Warning',
        pattern=r'(?im)\bssl\s*\|\s*off\b',
        title='SSL is disabled on the server',
        recommendation='Enable SSL and require it via pg_hba (hostssl) for all clients.',
    ),
    dict(
        script='sec_08_network_exposure',
        mode='pattern', severity='Warning',
        pattern=r'(?im)listen_addresses\s*\|\s*\*',
        title='listen_addresses is "*" (all interfaces)',
        recommendation='Bind only to required interfaces. Restrict via firewall '
                       'or pg_hba host rules.',
    ),
    dict(
        script='sec_09_sensitive_data_discovery',
        mode='has_data', severity='Warning',
        title='Columns with PII / sensitive name patterns',
        recommendation='Verify whether these columns hold sensitive data. Apply '
                       'pgcrypto column encryption or column-level access controls.',
        extractor=_ext_pii_columns,
        ext_label='Candidate PII columns (sample)',
    ),
    dict(
        script='sec_10_dangerous_objects',
        mode='has_data', severity='Warning',
        title='Privileged extensions / SECURITY DEFINER functions',
        recommendation='Audit each finding. SECURITY DEFINER functions should '
                       'set search_path explicitly; untrusted languages need review.',
        extractor=_ext_dangerous,
        ext_label='Dangerous objects (sample)',
    ),
    dict(
        script='sec_12_dormant_users',
        mode='has_data', severity='Info',
        title='Dormant or expired users',
        recommendation='Review dormant accounts. Disable or remove unused logins.',
        extractor=_ext_dormant,
        ext_label='Dormant accounts (sample)',
    ),
    dict(
        script='sec_17_recovery_and_backup_security',
        mode='pattern', severity='Warning',
        pattern=r'(?im)\barchive_mode\s*\|\s*off\b',
        title='archive_mode is off',
        recommendation='Without WAL archiving, point-in-time recovery is impossible.',
    ),
    dict(
        script='sec_18_audit_gaps',
        mode='has_data', severity='Info',
        title='Audit configuration gaps',
        recommendation='Cross-check pgaudit / log_* settings against your audit '
                       'baseline.',
        extractor=_ext_audit_gaps,
        ext_label='Audit settings of interest',
    ),
    dict(
        script='sec_20_failed_login_patterns',
        mode='has_data', severity='Warning',
        title='Failed login activity recorded',
        recommendation='Review failed login source IPs and roles. Tune brute-force defenses.',
        extractor=_ext_failed_logins,
        ext_label='Failed-login events (sample)',
    ),
    dict(
        script='sec_22_cert_and_key_expiry',
        mode='has_data', severity='Warning',
        title='Credentials / certificates approaching expiry',
        recommendation='Plan rotation. Expired role passwords trigger silent auth '
                       'failures; expired certs take TLS offline.',
        extractor=_ext_cert_expiry,
        ext_label='Roles with non-trivial expiry state',
    ),
]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def find_findings(log_dir: Path) -> list:
    findings: list = []

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
            recommendation='Check connection privileges and the script log.',
            objects=[], object_columns=[], object_label='',
        ))

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
            if not hit:
                continue
            objs: list = []
            ext_cols: list = []
            object_groups: list = []
            extractor = rule.get('extractor')
            if extractor:
                try:
                    out = extractor(text)
                except Exception:
                    out = []
                if (out and isinstance(out[0], dict)
                        and {'label', 'columns', 'rows'} <= set(out[0].keys())):
                    object_groups = out
                else:
                    objs = out
                    if objs:
                        ext_cols = list(objs[0].keys())
            findings.append(dict(
                severity=rule['severity'], script=log.name,
                title=rule['title'], detail=detail,
                recommendation=rule['recommendation'],
                objects=objs, object_columns=ext_cols,
                object_label=rule.get('ext_label', ''),
                object_groups=object_groups,
            ))
    return findings


def discover_contexts(root: Path) -> list:
    if (root / '_summary.txt').exists():
        return [dict(name='(single run)', log_dir=root)]
    contexts: list = []
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted(sub.glob('postgres_sec_*'), reverse=True)
        if runs:
            contexts.append(dict(name=sub.name, log_dir=runs[0]))
    return contexts


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
def render_top_issues(findings: list) -> str:
    top = [f for f in findings if f['severity'] in ('Critical', 'Warning')]
    top = sorted(top, key=lambda f: (severity_rank(f['severity']), f['script']))[:10]
    if not top:
        return "<p class='ok'>No critical or warning issues detected.</p>"
    parts = ["<p>Highest-priority findings. Click a title to jump to the detail "
             "row and the list of concrete objects.</p>"
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
    """Card-based finding layout (see perf analyzer for rationale)."""
    if not findings:
        return "<p class='ok'>No problems detected by the rule set.</p>"
    parts = []
    for f in sorted(findings, key=lambda x: (severity_rank(x['severity']), x['script'])):
        sev = f['severity'].lower()
        anchor = re.sub(r'[^A-Za-z0-9]', '-', f['script'] + '-' + f['title']).lower()
        parts.append(f"<div class='finding sev-{sev}' id='f-{anchor}'>")
        parts.append(
            f"<div class='finding-head'>"
            f"<span class='badge {sev}'>{f['severity']}</span>"
            f"<span class='finding-title'>{esc(f['title'])}</span>"
            f"<span class='finding-script'><code>{esc(f['script'])}</code></span>"
            f"</div>"
            f"<div class='finding-rec'><strong>Action:</strong> "
            f"{esc(f['recommendation'])}</div>"
        )
        if f.get('detail'):
            parts.append(f"<div class='finding-detail'>{esc(f['detail'])}</div>")
        if f.get('object_groups'):
            for g in f['object_groups']:
                parts.append(
                    f"<div class='objs-caption'><strong>{esc(g['label'])}</strong>"
                    f" &middot; {len(g['rows'])} row(s)</div>"
                    + object_table(g['rows'], g['columns'], limit=10)
                )
        elif f.get('objects') and f.get('object_columns'):
            parts.append(
                f"<div class='objs-caption'><strong>"
                f"{esc(f['object_label'] or 'Concrete objects')}</strong></div>"
                + object_table(f['objects'], f['object_columns'], limit=10)
            )
        parts.append("</div>")
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
<title>PostgreSQL Security Audit Report</title>
{SHARED_CSS}
</head><body id='top'>
<header>
  <h1>PostgreSQL Security Audit Report</h1>
  <p><strong>Server:</strong> {esc(server)}</p>
  <p><strong>Report folder:</strong> {esc(str(report_dir))}</p>
  <p><strong>Generated:</strong> {now_str()}</p>
</header>"""]

    parts.append(
        "<nav class='quick-nav'>"
        "<a href='#env-fingerprint'>Environment</a>"
        "<a href='#exec-summary'>Executive Summary</a>"
        "<a href='#findings'>Findings</a>"
        "</nav>"
    )

    parts.append("<a id='env-fingerprint'></a>")
    parts.append(render_fingerprint_card(fingerprint, target, report_dir))

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
    all_findings = []
    for r in report:
        all_findings.extend(r['findings'])
    parts.append("<h3>Top issues -- what to fix</h3>")
    parts.append(render_top_issues(all_findings))
    # Context rollup only when multi-context (single-DB run duplicates KPI cards)
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
    parts.append("</div>")

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
    parts.append("</body></html>")
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
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

    target = read_target(report_dir)

    report = []
    fingerprint = {}
    for ctx in contexts:
        findings = find_findings(ctx['log_dir'])
        passed = failed = 0
        for status, _ in read_summary(ctx['log_dir'] / '_summary.txt'):
            if status == 'OK':   passed += 1
            elif status == 'FAIL': failed += 1
        ctx_fp = read_fingerprint(ctx['log_dir'], ('sec_21_patch_and_cve_level',))
        if not fingerprint and ctx_fp:
            fingerprint = ctx_fp
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

    print('=' * 80)
    print('Security audit analysis complete.')
    print(f'  Databases analysed : {len(report)}')
    print(f'  Critical findings  : {sum(r["critical"] for r in report)}')
    print(f'  Warnings           : {sum(r["warning"]  for r in report)}')
    print(f'  Failed scripts     : {sum(r["failed"]   for r in report)}')
    print(f'  Report             : {out}')
    print('=' * 80)
    return 0


if __name__ == '__main__':
    sys.exit(main())
