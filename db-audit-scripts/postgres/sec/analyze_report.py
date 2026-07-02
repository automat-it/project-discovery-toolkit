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
    DOMAIN_BUCKETS_SEC, SHARED_CSS, context_label, copy_brand_assets,
    domain_counts, esc, finding_anchor, has_data_rows, kv_grid, now_str,
    object_table, parse_result_sets, read_fingerprint, read_log_text,
    read_summary, read_target, render_at_a_glance, render_cover,
    render_fingerprint_card,
    script_matches_log, severity_rank, svg_bar, svg_donut,
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


# ---------------------------------------------------------------------------
# Extractors for pattern-mode rules. They look up the actual psql result-
# set (pg_settings / pg_hba_file_rules) and pull the rows that triggered
# the regex match -- so the report shows e.g. the trust-auth pg_hba lines
# rather than just "pattern matched".
# ---------------------------------------------------------------------------
def _filter_rows(text, required_cols, predicate):
    req = {c.lower() for c in required_cols}
    for s in parse_result_sets(text):
        cols_lc = {c.lower() for c in s['columns']}
        if not req <= cols_lc:
            continue
        rows = [r for r in s['rows'] if predicate(r)]
        if rows:
            return s['columns'], rows
    return None, []


def _ext_settings_named(text, names, label):
    target = {n.lower() for n in names}
    cols, rows = _filter_rows(
        text, ('name',),
        lambda r: any(v.strip().lower() in target
                      for k, v in r.items() if k.lower() == 'name'))
    if not rows:
        return []
    return [dict(label=label, columns=cols, rows=rows)]


def _ext_trust_auth(text):
    """sec_05: rows in pg_hba_file_rules where auth_method='trust'."""
    cols, rows = _filter_rows(
        text, ('auth_method',),
        lambda r: any(v.strip().lower() == 'trust'
                      for k, v in r.items() if k.lower() == 'auth_method'))
    if not rows:
        return []
    return [dict(label='pg_hba.conf rules using "trust"',
                 columns=cols, rows=rows)]


def _ext_md5_password(text):
    return _ext_settings_named(text, ['password_encryption'],
                               'password_encryption setting')


def _ext_log_statement(text):
    return _ext_settings_named(text, ['log_statement', 'log_min_duration_statement',
                                      'log_connections', 'log_disconnections'],
                               'Logging-related settings')


def _ext_ssl_setting(text):
    return _ext_settings_named(text, ['ssl', 'ssl_cert_file', 'ssl_key_file',
                                      'ssl_ca_file'],
                               'SSL settings')


def _ext_listen_addresses(text):
    return _ext_settings_named(text, ['listen_addresses', 'port'],
                               'Network-exposure settings')


def _ext_archive_mode(text):
    return _ext_settings_named(text, ['archive_mode', 'archive_command',
                                      'archive_timeout', 'wal_level'],
                               'WAL archiving settings')


RULES = [
    dict(
        script='sec_03_admin_and_superusers',
        mode='has_data', severity='Info',
        title='Superuser / privileged role membership',
        recommendation='Reduce SUPERUSER, pg_signal_backend, pg_read_all_data '
                       'memberships to the minimum required.',
        extractor=_ext_superusers,
        ext_label='Privileged accounts (sample)',
        commands=(
            "-- Inspect what a flagged role inherits\n"
            "\\du+ app_admin\n"
            "SELECT rolname FROM pg_auth_members m\n"
            "  JOIN pg_roles r ON r.oid = m.roleid\n"
            " WHERE m.member = 'app_admin'::regrole;\n"
            "\n"
            "-- Drop SUPERUSER / unneeded membership\n"
            "ALTER ROLE app_admin NOSUPERUSER NOCREATEROLE NOREPLICATION;\n"
            "REVOKE pg_read_all_data, pg_write_all_data FROM app_admin;"
        ),
        docs=[
            ('PostgreSQL: Predefined roles',
             'https://www.postgresql.org/docs/current/predefined-roles.html'),
            ('Aurora PostgreSQL: rds_superuser',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Appendix.PostgreSQL.CommonDBATasks.Roles.html'),
        ],
    ),
    dict(
        script='sec_04_public_and_excessive_grants',
        mode='has_data', severity='Warning',
        title='Permissions granted to PUBLIC or excessive scope',
        recommendation='PUBLIC grants apply to every role. Move them to specific '
                       'roles or REVOKE.',
        extractor=_ext_public_grants,
        ext_label='Excessive grants (sample)',
        commands=(
            "-- Revoke wildcard PUBLIC grant\n"
            "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
            "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;\n"
            "\n"
            "-- Re-grant only to the role(s) that actually need it\n"
            "GRANT  USAGE  ON SCHEMA public TO app_read;\n"
            "GRANT  SELECT ON ALL TABLES IN SCHEMA public TO app_read;\n"
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public\n"
            "  GRANT SELECT ON TABLES TO app_read;"
        ),
        docs=[
            ('GRANT',
             'https://www.postgresql.org/docs/current/sql-grant.html'),
            ('ALTER DEFAULT PRIVILEGES',
             'https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html'),
        ],
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Critical',
        # sec_05 renders pg_hba_file_rules with the auth_method value
        # mid-row: ``... | trust         | options | ...``. Match a data
        # cell whose value is exactly ``trust`` (pipe-delimited on both
        # sides). This never matches the header (``auth_method | options``)
        # nor scram-sha-256 rows.
        pattern=r'(?im)\|\s*trust\s*\|',
        title='pg_hba.conf uses "trust" authentication',
        recommendation='Trust auth allows password-less access. Replace with '
                       'scram-sha-256 or cert.',
        extractor=_ext_trust_auth,
        commands=(
            "-- Inspect the rules in effect\n"
            "SELECT line_number, type, database, user_name, address, auth_method\n"
            "  FROM pg_hba_file_rules ORDER BY line_number;\n"
            "\n"
            "-- Edit pg_hba.conf -- replace trust rows with scram-sha-256\n"
            "#   host all all 0.0.0.0/0 scram-sha-256\n"
            "\n"
            "-- Apply without restart\n"
            "SELECT pg_reload_conf();\n"
            "\n"
            "-- RDS / Aurora: the equivalent is the parameter\n"
            "--   rds.restrict_password_commands and per-role REQUIRES\n"
        ),
        docs=[
            ('PostgreSQL: pg_hba.conf',
             'https://www.postgresql.org/docs/current/auth-pg-hba-conf.html'),
            ('Authentication methods',
             'https://www.postgresql.org/docs/current/auth-methods.html'),
        ],
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Warning',
        pattern=r'(?im)password_encryption\s*\|\s*md5',
        title='password_encryption is md5',
        recommendation='md5 password hashing is deprecated. Switch to scram-sha-256 '
                       'and re-set all passwords.',
        extractor=_ext_md5_password,
        commands=(
            "-- Server-wide: switch hashing\n"
            "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\n"
            "SELECT pg_reload_conf();\n"
            "\n"
            "-- Re-set each role (their md5 hash stays until they change it)\n"
            "ALTER ROLE app_read WITH PASSWORD '<new-strong-password>';"
        ),
        docs=[
            ('Password authentication',
             'https://www.postgresql.org/docs/current/auth-password.html'),
        ],
    ),
    dict(
        script='sec_06_audit_logging',
        mode='pattern', severity='Warning',
        pattern=r'(?im)log_statement\s*\|\s*none',
        title='log_statement is "none"',
        recommendation='No SQL is logged. Set log_statement to ddl or all for audit.',
        extractor=_ext_log_statement,
        commands=(
            "ALTER SYSTEM SET log_statement              = 'ddl';\n"
            "ALTER SYSTEM SET log_min_duration_statement = 1000;  -- ms\n"
            "ALTER SYSTEM SET log_connections            = on;\n"
            "ALTER SYSTEM SET log_disconnections         = on;\n"
            "SELECT pg_reload_conf();\n"
            "\n"
            "-- Stronger: install pgaudit and route to CloudWatch / journald\n"
            "CREATE EXTENSION IF NOT EXISTS pgaudit;\n"
            "ALTER SYSTEM SET pgaudit.log = 'write, ddl, role';"
        ),
        docs=[
            ('Error reporting and logging',
             'https://www.postgresql.org/docs/current/runtime-config-logging.html'),
            ('pgaudit',
             'https://github.com/pgaudit/pgaudit'),
            ('Aurora PostgreSQL: enabling pgaudit',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Reference.html#AuroraPostgreSQL.Reference.pgaudit'),
        ],
    ),
    dict(
        script='sec_07_encryption_status',
        mode='pattern', severity='Warning',
        pattern=r'(?im)\bssl\s*\|\s*off\b',
        title='SSL is disabled on the server',
        recommendation='Enable SSL and require it via pg_hba (hostssl) for all clients.',
        extractor=_ext_ssl_setting,
        commands=(
            "ALTER SYSTEM SET ssl = on;\n"
            "-- Point ALTER SYSTEM SET ssl_cert_file / ssl_key_file at the cert pair,\n"
            "-- then reload\n"
            "SELECT pg_reload_conf();\n"
            "\n"
            "-- Require TLS for every client: edit pg_hba.conf\n"
            "#   hostssl all all 0.0.0.0/0 scram-sha-256\n"
            "\n"
            "-- RDS / Aurora: set rds.force_ssl = 1 in the parameter group"
        ),
        docs=[
            ('Secure TCP/IP connections with SSL',
             'https://www.postgresql.org/docs/current/ssl-tcp.html'),
            ('RDS PostgreSQL SSL',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html'),
        ],
    ),
    dict(
        script='sec_08_network_exposure',
        mode='pattern', severity='Warning',
        pattern=r'(?im)listen_addresses\s*\|\s*\*',
        title='listen_addresses is "*" (all interfaces)',
        recommendation='Bind only to required interfaces. Restrict via firewall '
                       'or pg_hba host rules.',
        extractor=_ext_listen_addresses,
        commands=(
            "-- Self-managed: pin to a private interface\n"
            "ALTER SYSTEM SET listen_addresses = '10.0.1.50';\n"
            "-- requires a server restart (NOT just pg_reload_conf())\n"
            "\n"
            "# RDS / Aurora: tighten via the security group\n"
            "aws ec2 revoke-security-group-ingress    --group-id sg-... \\\n"
            "  --protocol tcp --port 5432 --cidr 0.0.0.0/0\n"
            "aws ec2 authorize-security-group-ingress --group-id sg-... \\\n"
            "  --protocol tcp --port 5432 --cidr 10.0.0.0/8"
        ),
        docs=[
            ('Connection settings: listen_addresses',
             'https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-LISTEN-ADDRESSES'),
        ],
    ),
    dict(
        script='sec_09_sensitive_data_discovery',
        mode='has_data', severity='Warning',
        title='Columns with PII / sensitive name patterns',
        recommendation='Verify whether these columns hold sensitive data. Apply '
                       'pgcrypto column encryption or column-level access controls.',
        extractor=_ext_pii_columns,
        ext_label='Candidate PII columns (sample)',
        commands=(
            "-- Encrypt the column on write (server-side)\n"
            "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
            "UPDATE app.users\n"
            "   SET ssn = pgp_sym_encrypt(ssn, current_setting('app.kms_key'));\n"
            "\n"
            "-- Column-level grants -- give the reporter only non-sensitive columns\n"
            "REVOKE SELECT ON app.users FROM reporter;\n"
            "GRANT  SELECT (id, full_name) ON app.users TO reporter;\n"
            "\n"
            "-- Row-level security policy\n"
            "ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;\n"
            "CREATE POLICY u_self ON app.users USING (id = current_setting('app.uid')::int);"
        ),
        docs=[
            ('pgcrypto',
             'https://www.postgresql.org/docs/current/pgcrypto.html'),
            ('Row Security Policies',
             'https://www.postgresql.org/docs/current/ddl-rowsecurity.html'),
        ],
    ),
    dict(
        script='sec_10_dangerous_objects',
        mode='has_data', severity='Warning',
        title='Privileged extensions / SECURITY DEFINER functions',
        recommendation='Audit each finding. SECURITY DEFINER functions should '
                       'set search_path explicitly; untrusted languages need review.',
        extractor=_ext_dangerous,
        ext_label='Dangerous objects (sample)',
        commands=(
            "-- Inspect a flagged function\n"
            "\\sf+ schema.func_name\n"
            "\n"
            "-- Pin search_path so it cannot be hijacked by a malicious schema\n"
            "ALTER FUNCTION schema.func_name() SET search_path = pg_catalog, public;\n"
            "\n"
            "-- Convert SECURITY DEFINER -> INVOKER where the elevated privilege\n"
            "-- is not actually needed\n"
            "ALTER FUNCTION schema.func_name() SECURITY INVOKER;"
        ),
        docs=[
            ('Writing SECURITY DEFINER functions safely',
             'https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY'),
        ],
    ),
    dict(
        script='sec_12_dormant_users',
        mode='has_data', severity='Info',
        title='Dormant or expired users',
        recommendation='Review dormant accounts. Disable or remove unused logins.',
        extractor=_ext_dormant,
        ext_label='Dormant accounts (sample)',
        commands=(
            "-- Disable login for a dormant role (recommended before drop)\n"
            "ALTER ROLE dormant_user NOLOGIN;\n"
            "ALTER ROLE dormant_user VALID UNTIL 'now';\n"
            "\n"
            "-- Drop after a grace period (must reassign or drop owned objects first)\n"
            "REASSIGN OWNED BY dormant_user TO admin;\n"
            "DROP    OWNED BY dormant_user;\n"
            "DROP    ROLE     dormant_user;"
        ),
        docs=[
            ('ALTER ROLE',
             'https://www.postgresql.org/docs/current/sql-alterrole.html'),
        ],
    ),
    dict(
        # archive_mode is emitted by sec_14_backup_security.sql (a
        # pg_settings name|setting block). The old script stem
        # 'sec_17_recovery_and_backup_security' does not exist -- the
        # actual sec_17 file is sec_17_deprecated_features.sql and emits
        # no archive settings -- so this rule never fired. Point it at the
        # script that really outputs archive_mode.
        script='sec_14_backup_security',
        mode='pattern', severity='Warning',
        pattern=r'(?im)\barchive_mode\s*\|\s*off\b',
        title='archive_mode is off',
        recommendation='Without WAL archiving, point-in-time recovery is impossible.',
        extractor=_ext_archive_mode,
        commands=(
            "-- Self-managed: turn on WAL archiving (requires restart)\n"
            "ALTER SYSTEM SET wal_level      = replica;\n"
            "ALTER SYSTEM SET archive_mode   = on;\n"
            "ALTER SYSTEM SET archive_command = 'aws s3 cp %p s3://my-wal-bucket/%f';\n"
            "\n"
            "# RDS / Aurora: enable automated backups\n"
            "aws rds modify-db-instance --db-instance-identifier <db> \\\n"
            "  --backup-retention-period 7 --apply-immediately"
        ),
        docs=[
            ('Continuous archiving and PITR',
             'https://www.postgresql.org/docs/current/continuous-archiving.html'),
            ('RDS backups and PITR',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html'),
        ],
    ),
    dict(
        script='sec_18_audit_gaps',
        mode='has_data', severity='Info',
        title='Audit configuration gaps',
        recommendation='Cross-check pgaudit / log_* settings against your audit '
                       'baseline.',
        extractor=_ext_audit_gaps,
        ext_label='Audit settings of interest',
        docs=[
            ('Logging parameters reference',
             'https://www.postgresql.org/docs/current/runtime-config-logging.html'),
        ],
    ),
    dict(
        script='sec_20_failed_login_patterns',
        mode='has_data', severity='Warning',
        title='Failed login activity recorded',
        recommendation='Review failed login source IPs and roles. Tune brute-force defenses.',
        extractor=_ext_failed_logins,
        ext_label='Failed-login events (sample)',
        commands=(
            "-- Lock the targeted role until the IP is blocked at the network layer\n"
            "ALTER ROLE \"<role>\" VALID UNTIL 'now';\n"
            "\n"
            "-- Self-managed: install auth_delay to slow down brute force\n"
            "ALTER SYSTEM SET shared_preload_libraries = 'auth_delay';\n"
            "ALTER SYSTEM SET auth_delay.milliseconds  = 500;\n"
            "-- requires a restart"
        ),
        docs=[
            ('auth_delay',
             'https://www.postgresql.org/docs/current/auth-delay.html'),
        ],
    ),
    dict(
        script='sec_22_cert_and_key_expiry',
        mode='has_data', severity='Warning',
        title='Credentials / certificates approaching expiry',
        recommendation='Plan rotation. Expired role passwords trigger silent auth '
                       'failures; expired certs take TLS offline.',
        extractor=_ext_cert_expiry,
        ext_label='Roles with non-trivial expiry state',
        commands=(
            "-- Rotate a role's password and extend its validity window\n"
            "ALTER ROLE app_read WITH PASSWORD '<new-strong-password>'\n"
            "                    VALID UNTIL  '2027-12-31';\n"
            "\n"
            "# RDS / Aurora: rotate the cluster CA cert\n"
            "aws rds modify-db-instance --db-instance-identifier <db> \\\n"
            "  --ca-certificate-identifier rds-ca-rsa2048-g1 \\\n"
            "  --apply-immediately"
        ),
        docs=[
            ('Updating SSL/TLS certificates on RDS',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html'),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def find_findings(log_dir: Path) -> list:
    findings: list = []

    failed_stems: set = set()
    for status, script in read_summary(log_dir / '_summary.txt'):
        if status != 'FAIL':
            continue
        log_base = script.replace('/', '_').replace('.sql', '.log')
        failed_stems.add(Path(log_base).stem)
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

    # Read each .log at most once.
    log_text_cache: dict = {}
    for log in sorted(log_dir.glob('*.log')):
        # Skip content-rule evaluation for scripts already marked FAIL:
        # their partial output is error-contaminated and would produce a
        # second bogus finding on top of the "Script execution failed" one.
        if log.stem in failed_stems:
            continue
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
            if not hit:
                continue
            objs: list = []
            ext_cols: list = []
            object_groups: list = []
            extractor = rule.get('extractor')
            if extractor:
                try:
                    out = extractor(text)
                except Exception as e:
                    print(f'[warn] extractor {extractor.__name__} failed on '
                          f'{log.name}: {e}', file=sys.stderr)
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
                commands=rule.get('commands', ''),
                docs=rule.get('docs', []),
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
        anchor = finding_anchor(f)
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
        anchor = finding_anchor(f)
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
        parts.append("</div>")
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
<title>PostgreSQL Security Audit Report</title>
{SHARED_CSS}
</head><body id='top'>"""]

    parts.append(render_cover('PostgreSQL Security Audit Report',
                              server, customer, len(report)))

    parts.append(f"""<header>
  <h1>PostgreSQL Security Audit Report</h1>
  <p><strong>Server:</strong> {esc(server)}</p>
  <p><strong>Report folder:</strong> {esc(report_dir.name)}</p>
  <p><strong>Generated:</strong> {now_str()}</p>
</header>""")

    parts.append(
        "<nav class='quick-nav'>"
        "<a href='#env-fingerprint'>Environment</a>"
        "<a href='#exec-summary'>Executive Summary</a>"
        "<a href='#findings'>Findings</a>"
        "</nav>"
    )

    parts.append("<a id='env-fingerprint'></a>")
    parts.append(render_fingerprint_card(fingerprint, target, report_dir))

    all_findings = []
    for r in report:
        all_findings.extend(r['findings'])
    parts.append("<a id='exec-summary'></a>")
    parts.append("<section class='section card'><h2>1. Executive Summary</h2>")
    parts.append(render_at_a_glance(len(report), total_crit, total_warn,
                                    total_info, all_findings))
    parts.append("<p class='intro'>Snapshot of this audit: how many databases "
                 "were analyzed, the severity mix of findings, and which "
                 "security domains drove the count.</p>")
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
    domain_data = domain_counts(all_findings, DOMAIN_BUCKETS_SEC)
    parts.append("<div class='charts-row'>")
    parts.append(f"<div>{svg_donut(total_crit, total_warn, total_info)}</div>")
    if domain_data:
        parts.append("<div><h3>Findings by Domain</h3>"
                     f"{svg_bar(domain_data)}</div>")
    parts.append("</div>")
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
    parts.append("</section>")  # close 1. Executive Summary

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
    parts.append("</body></html>")
    return ''.join(parts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('report_dir')
    ap.add_argument('--server',   default='')
    ap.add_argument('--customer', default='', help='Customer / project name on the cover')
    ap.add_argument('--out',      default='')
    args = ap.parse_args()

    report_dir = Path(args.report_dir).resolve()
    if not report_dir.is_dir():
        print(f'ERROR: report directory not found: {report_dir}', file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else (report_dir / 'postgres_sec_analysis.html')

    contexts = discover_contexts(report_dir)
    if not contexts:
        print(f'ERROR: no log folders found under {report_dir}', file=sys.stderr)
        return 3

    target = read_target(report_dir)
    if not target:
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
        ctx_fp = read_fingerprint(ctx['log_dir'], ('sec_21_patch_and_cve_level',))
        if not fingerprint and ctx_fp:
            fingerprint = ctx_fp
        ctx_name = context_label(ctx_fp, target, ctx['name'])
        # Stamp the context onto every finding so per-(context, finding)
        # HTML anchors are unique across databases in a multi-DB report.
        for f in findings:
            f['context'] = ctx_name
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
