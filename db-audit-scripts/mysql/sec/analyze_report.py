#!/usr/bin/env python3
"""
analyze_report.py -- MySQL security audit report analyzer.

Reads the report directory produced by mysql/sec/run_audit.sh and writes
an HTML report with:

  * Environment fingerprint card (host, version, auth/SSL state, ...)
  * Executive summary (KPI counts + Top issues with what-to-do)
  * Per-finding concrete objects (privileged users, PUBLIC grants, PII
    columns, SECURITY DEFINER routines, expiring credentials, ...) so
    the reader has actionable targets, not "review the log".

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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _analyze_lib import (  # noqa: E402
    SHARED_CSS, context_label, esc, has_data_rows, kv_grid, now_str,
    object_table, parse_result_sets, read_fingerprint, read_log_text,
    read_summary, read_target, render_fingerprint_card, script_matches_log,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Sec-specific extractors -- pull concrete objects from logs
# ---------------------------------------------------------------------------
def _set_with(sets, *col_names):
    """First non-empty set whose columns include ANY of the names (case-
    insensitive). For sub-table picking when one log emits many."""
    wanted = {c.lower() for c in col_names}
    for s in sets:
        if not s['rows']:
            continue
        if {c.lower() for c in s['columns']} & wanted:
            return s
    return None


def _ext_privileged_users(text):
    """sec_03 emits the user inventory ~4 times (with different filters:
    has_super, dynamic_privilege, role chains, etc.) plus a per-grantee
    grants table. We DEDUPLICATE by label: keep the LARGEST set per
    label so the reader sees a single row count, not the same caption
    repeated six times.

    The script's repeating structure made sense when output was meant
    for grep, but in a customer-facing report it is pure noise."""
    sets = parse_result_sets(text)
    best: dict = {}  # label -> set with most rows
    for s in sets:
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        label = None
        if 'user' in lc and ('host' in lc or 'account_locked' in lc):
            label = 'Users with administrative-grade attributes'
        elif 'grantee' in lc or 'privilege_type' in lc:
            label = 'Grants flagged as administrative'
        elif 'dynamic_privilege' in lc:
            label = 'Dynamic privileges granted'
        elif 'privileged_role' in lc or 'with_admin_option' in lc:
            label = 'Privileged role chain (role -> member)'
        if not label:
            continue
        prev = best.get(label)
        if not prev or len(s['rows']) > len(prev['rows']):
            best[label] = dict(label=label, columns=s['columns'],
                               rows=s['rows'][:200])
    return list(best.values())


def _ext_public_grants(text):
    """sec_04 emits multiple sub-tables -- render each separately."""
    sets = parse_result_sets(text)
    groups = []
    for i, s in enumerate(sets):
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        if any(c in lc for c in ('grantee', 'privilege_type', 'object_schema',
                                 'object_type', 'user', 'host')):
            label = f"Excessive grants -- subset #{len(groups)+1}"
            groups.append(dict(label=label, columns=s['columns'],
                               rows=s['rows'][:200]))
    return groups


def _ext_pii_columns(text):
    """sec_09 / sec_16: column-name heuristic PII discovery."""
    s = _set_with(parse_result_sets(text),
                  'column_name', 'COLUMN_NAME')
    return s['rows'][:200] if s else []


def _ext_dangerous(text):
    """sec_10: SECURITY DEFINER routines + UDFs + triggers + events."""
    sets = parse_result_sets(text)
    # Sub-table labels in the order the SQL script emits them.
    labels = [
        'SECURITY DEFINER routines',
        'SECURITY DEFINER routines owned by admin-grade users',
        'User-defined functions loaded from shared libraries',
        'Triggers',
        'Scheduled events (EVENT_SCHEDULER)',
        'Non-standard storage engines per schema',
        'Plugins with elevated risk',
    ]
    groups = []
    for i, s in enumerate(sets):
        if not s['rows']:
            continue
        groups.append(dict(
            label=labels[i] if i < len(labels) else f'Sub-table #{i+1}',
            columns=s['columns'],
            rows=s['rows'][:200],
        ))
    return groups


def _ext_dormant(text):
    """sec_12: dormant accounts -- users with old last-login or never-
    used credentials."""
    s = _set_with(parse_result_sets(text), 'user', 'User')
    return s['rows'][:200] if s else []


def _ext_failed_logins(text):
    """sec_20: failed login activity via Connection_Errors_* status
    variables + connection_control_failed_login_attempts if available."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        if s['rows']:
            out.extend(s['rows'][:200])
    return out[:200]


def _ext_cert_expiry(text):
    """sec_22: TLS cert + per-user password_lifetime. Dedupe by label
    keeping the most-populated set."""
    sets = parse_result_sets(text)
    best: dict = {}
    for s in sets:
        if not s['rows']:
            continue
        lc = [c.lower() for c in s['columns']]
        label = None
        if 'expiry_state' in lc or 'password_lifetime' in lc or 'days_until_expiry' in lc:
            label = 'Credentials with non-trivial expiry state'
        elif 'tls_version' in lc or 'ssl_protocol' in lc:
            label = 'TLS / SSL connection state'
        elif 'variable_name' in lc:
            label = 'TLS / SSL configuration variables'
        if not label:
            continue
        prev = best.get(label)
        if not prev or len(s['rows']) > len(prev['rows']):
            best[label] = dict(label=label, columns=s['columns'],
                               rows=s['rows'][:200])
    return list(best.values())


def _ext_audit_gaps(text):
    """sec_18: GLOBAL variables + plugins related to audit logging."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        if s['rows']:
            out.extend(s['rows'][:200])
    return out[:200]


def _ext_external_integrations(text):
    """sec_15: federated tables, FEDERATED servers, UDFs, non-standard SEs."""
    sets = parse_result_sets(text)
    out = []
    for s in sets:
        if s['rows']:
            out.extend(s['rows'][:200])
    return out[:200]


# ---------------------------------------------------------------------------
# Extractors for pattern-mode rules. Pattern rules just say "this regex hit
# in the log" -- without an extractor the reader sees a category but not
# which user / which row triggered it. These return [dict(label,columns,rows)]
# so the renderer treats them as object_groups.
# ---------------------------------------------------------------------------
def _filter_rows(text, required_cols, predicate):
    """Find the first result set whose columns include ALL required_cols
    (case-insensitive) and return rows that match `predicate(row)`.
    Returns (columns, rows) or (None, [])."""
    req = {c.lower() for c in required_cols}
    for s in parse_result_sets(text):
        cols_lc = {c.lower() for c in s['columns']}
        if not req <= cols_lc:
            continue
        rows = [r for r in s['rows'] if predicate(r)]
        if rows:
            return s['columns'], rows
    return None, []


def _ext_native_password_users(text):
    cols, rows = _filter_rows(
        text, ('user', 'plugin'),
        lambda r: any(v.strip().lower().startswith('mysql_native_password')
                      for k, v in r.items() if k.lower() == 'plugin'))
    if not rows:
        return []
    return [dict(label='Accounts still on mysql_native_password',
                 columns=cols, rows=rows[:200])]


def _ext_expired_password_users(text):
    cols, rows = _filter_rows(
        text, ('user', 'password_expired'),
        lambda r: any(v.strip().upper() == 'Y'
                      for k, v in r.items() if k.lower() == 'password_expired'))
    if not rows:
        return []
    return [dict(label='Accounts with expired passwords',
                 columns=cols, rows=rows[:200])]


def _ext_audit_log_settings(text):
    """sec_06: surface the audit-related variable rows so the reader sees
    exactly which logs are OFF."""
    targets = {'general_log', 'log_output', 'slow_query_log',
               'audit_log_policy', 'audit_log_format', 'log_error_verbosity',
               'binlog_format', 'log_bin'}
    cols, rows = _filter_rows(
        text, ('variable_name',),
        lambda r: any(v.lower() in targets
                      for k, v in r.items() if k.lower() == 'variable_name'))
    if not rows:
        return []
    return [dict(label='Audit / logging variables', columns=cols, rows=rows)]


def _ext_ssl_settings(text):
    """sec_07: pull SSL-related variables and non-SSL accounts."""
    out = []
    targets = {'have_ssl', 'have_openssl', 'require_secure_transport',
               'ssl_cipher', 'tls_version', 'ssl_ca', 'ssl_cert', 'ssl_key'}
    cols, rows = _filter_rows(
        text, ('variable_name',),
        lambda r: any(v.lower() in targets
                      for k, v in r.items() if k.lower() == 'variable_name'))
    if rows:
        out.append(dict(label='SSL/TLS server settings', columns=cols, rows=rows))
    cols, rows = _filter_rows(
        text, ('user', 'ssl_type'),
        lambda r: any((v or '').strip() == ''
                      for k, v in r.items() if k.lower() == 'ssl_type'))
    if rows:
        out.append(dict(label='Accounts without REQUIRE SSL', columns=cols, rows=rows[:200]))
    return out


def _ext_bind_address(text):
    targets = {'bind_address', 'mysqlx_bind_address', 'skip_networking', 'port'}
    cols, rows = _filter_rows(
        text, ('variable_name',),
        lambda r: any(v.lower() in targets
                      for k, v in r.items() if k.lower() == 'variable_name'))
    if not rows:
        return []
    return [dict(label='Network exposure variables', columns=cols, rows=rows)]


RULES = [
    dict(
        script='sec_03_admin_and_superusers',
        mode='has_data', severity='Info',
        title='Administrative / privileged users',
        recommendation='Reduce SUPER, GRANT OPTION and admin-tier privilege '
                       'memberships to the minimum required.',
        extractor=_ext_privileged_users,
        ext_label='Privileged accounts (sample)',
        commands=(
            "-- Inspect what each flagged account actually has\n"
            "SHOW GRANTS FOR 'app_admin'@'%';\n"
            "\n"
            "-- Revoke unneeded global privileges\n"
            "REVOKE SUPER, GRANT OPTION ON *.* FROM 'app_admin'@'%';\n"
            "REVOKE 'rds_superuser_role' FROM 'app_admin'@'%';\n"
            "FLUSH PRIVILEGES;"
        ),
        docs=[
            ('MySQL: Privileges Provided by MySQL',
             'https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html'),
            ('RDS / Aurora: master user account',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.MasterAccounts.html'),
        ],
    ),
    dict(
        script='sec_04_public_and_excessive_grants',
        mode='has_data', severity='Warning',
        title='Permissions granted to wildcards / excessive scope',
        recommendation='Grants on `*.*` apply to every schema. Move them to '
                       'specific schemas, or restrict host patterns.',
        extractor=_ext_public_grants,
        ext_label='Excessive grants (sample)',
        commands=(
            "-- Replace a wildcard grant with a schema-scoped one\n"
            "REVOKE SELECT, INSERT, UPDATE, DELETE ON *.* FROM 'app_user'@'%';\n"
            "GRANT  SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'%';\n"
            "\n"
            "-- Tighten the host pattern (e.g. only the app subnet)\n"
            "RENAME USER 'app_user'@'%' TO 'app_user'@'10.20.%';"
        ),
        docs=[
            ('GRANT statement',
             'https://dev.mysql.com/doc/refman/8.0/en/grant.html'),
        ],
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Critical',
        pattern=r'(?im)\bmysql_native_password\b',
        title='Accounts on the legacy mysql_native_password plugin',
        recommendation='Migrate accounts to caching_sha2_password (or '
                       'authentication_oci / IAM). mysql_native_password is '
                       'removed in MySQL 9.x.',
        extractor=_ext_native_password_users,
        commands=(
            "-- List affected accounts\n"
            "SELECT user, host, plugin FROM mysql.user\n"
            " WHERE plugin = 'mysql_native_password';\n"
            "\n"
            "-- Migrate each account (issue a new strong password)\n"
            "ALTER USER 'app_read'@'%' IDENTIFIED WITH caching_sha2_password\n"
            "  BY '<new-strong-password>';\n"
            "\n"
            "-- Force migration on next login (8.0.18+)\n"
            "ALTER USER 'app_read'@'%' PASSWORD EXPIRE;"
        ),
        docs=[
            ('MySQL: Pluggable Authentication',
             'https://dev.mysql.com/doc/refman/8.0/en/pluggable-authentication.html'),
            ('caching_sha2_password plugin',
             'https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html'),
            ('Deprecation & removal of mysql_native_password',
             'https://dev.mysql.com/doc/refman/8.4/en/native-pluggable-authentication.html'),
        ],
    ),
    dict(
        script='sec_05_authentication_and_passwords',
        mode='pattern', severity='Warning',
        pattern=r'(?im)password_expired\t[Y]',
        title='Accounts with expired passwords',
        recommendation='Force password reset for expired accounts. Configure '
                       'default_password_lifetime to limit silent-expiry risk.',
        extractor=_ext_expired_password_users,
        commands=(
            "-- Reset password for an expired account\n"
            "ALTER USER 'old_dev'@'%' IDENTIFIED BY '<new-strong-password>';\n"
            "\n"
            "-- Set a global rotation policy (days)\n"
            "SET PERSIST default_password_lifetime = 180;\n"
            "SET PERSIST password_history          = 5;\n"
            "SET PERSIST password_reuse_interval   = 365;"
        ),
        docs=[
            ('MySQL: Password Management',
             'https://dev.mysql.com/doc/refman/8.0/en/password-management.html'),
        ],
    ),
    dict(
        script='sec_06_audit_logging',
        mode='pattern', severity='Warning',
        pattern=r'(?im)general_log\t(OFF|0)',
        title='general_log / audit logging not active',
        recommendation='Enable audit logging (MySQL Enterprise Audit, '
                       'server_audit for MariaDB/Percona, or RDS / Aurora Audit).',
        extractor=_ext_audit_log_settings,
        commands=(
            "-- Aurora / RDS: enable advanced audit via DB cluster parameter group\n"
            "--   server_audit_logging          = 1\n"
            "--   server_audit_events           = CONNECT,QUERY_DDL,QUERY_DCL\n"
            "--   server_audit_incl_users / excl_users -- scope\n"
            "\n"
            "aws rds modify-db-cluster-parameter-group \\\n"
            "  --db-cluster-parameter-group-name <pg-name> \\\n"
            "  --parameters \"ParameterName=server_audit_logging,ParameterValue=1,ApplyMethod=immediate\"\n"
            "\n"
            "-- Self-managed MySQL: enable General Log + Audit Plugin\n"
            "SET PERSIST general_log      = 'ON';\n"
            "SET PERSIST log_output       = 'FILE';"
        ),
        docs=[
            ('MySQL Enterprise Audit',
             'https://dev.mysql.com/doc/refman/8.0/en/audit-log.html'),
            ('Aurora MySQL advanced auditing',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html'),
            ('MariaDB / Percona server_audit',
             'https://mariadb.com/kb/en/mariadb-audit-plugin/'),
        ],
    ),
    dict(
        script='sec_07_encryption_status',
        mode='pattern', severity='Warning',
        pattern=r'(?im)\bhave_ssl\t(DISABLED|NO)\b',
        title='SSL is disabled on the server',
        recommendation='Enable SSL/TLS and require it for client connections '
                       '(REQUIRE SSL on user accounts).',
        extractor=_ext_ssl_settings,
        commands=(
            "-- Require encrypted transport for every connection\n"
            "SET PERSIST require_secure_transport = ON;\n"
            "\n"
            "-- Force a specific account to use TLS (or X.509)\n"
            "ALTER USER 'app_read'@'%' REQUIRE SSL;\n"
            "-- ALTER USER 'app_read'@'%' REQUIRE X509;"
        ),
        docs=[
            ('Using Encrypted Connections',
             'https://dev.mysql.com/doc/refman/8.0/en/encrypted-connections.html'),
            ('RDS / Aurora: SSL/TLS to a MySQL DB',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html'),
        ],
    ),
    dict(
        script='sec_08_network_exposure',
        mode='pattern', severity='Warning',
        pattern=r'(?im)bind_address\t(\*|0\.0\.0\.0)',
        title='bind_address is wildcard (all interfaces)',
        recommendation='Bind to specific interfaces. Restrict access via '
                       'firewall or security group + user host patterns.',
        extractor=_ext_bind_address,
        commands=(
            "# RDS / Aurora -- restrict via security group\n"
            "aws ec2 revoke-security-group-ingress \\\n"
            "  --group-id sg-xxxxxxxx --protocol tcp --port 3306 --cidr 0.0.0.0/0\n"
            "aws ec2 authorize-security-group-ingress \\\n"
            "  --group-id sg-xxxxxxxx --protocol tcp --port 3306 --cidr 10.0.0.0/8\n"
            "\n"
            "-- Self-managed: bind to a private interface in my.cnf\n"
            "[mysqld]\n"
            "bind-address = 10.0.1.50"
        ),
        docs=[
            ('Server System Variable: bind_address',
             'https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_bind_address'),
        ],
    ),
    dict(
        script='sec_09_sensitive_data_discovery',
        mode='has_data', severity='Warning',
        title='Columns with PII / sensitive name patterns',
        recommendation='Verify whether these columns actually hold sensitive '
                       'data. Apply column-level encryption (AES_ENCRYPT, KMS) '
                       'or row-level access controls.',
        extractor=_ext_pii_columns,
        ext_label='Candidate PII columns (sample)',
        commands=(
            "-- Encrypt at write time using a KMS-managed key\n"
            "UPDATE audit_test.users\n"
            "   SET ssn = TO_BASE64(AES_ENCRYPT(ssn, @kms_key));\n"
            "\n"
            "-- Or restrict access to a dedicated role / view\n"
            "CREATE ROLE pii_reader;\n"
            "GRANT SELECT (id, full_name) ON audit_test.users TO 'reporter'@'%';"
        ),
        docs=[
            ('MySQL Encryption Functions',
             'https://dev.mysql.com/doc/refman/8.0/en/encryption-functions.html'),
            ('Column-level GRANTs',
             'https://dev.mysql.com/doc/refman/8.0/en/grant.html#grant-column-privileges'),
        ],
    ),
    dict(
        script='sec_10_dangerous_objects',
        mode='has_data', severity='Warning',
        title='SECURITY DEFINER routines / UDFs / triggers / events',
        recommendation='Audit each routine. SECURITY DEFINER inherits the '
                       'definer\'s privileges -- a poorly-scoped function can '
                       'become a privilege escalation path.',
        extractor=_ext_dangerous,
        ext_label='Dangerous objects (sample)',
        commands=(
            "-- Inspect the body of a flagged routine\n"
            "SHOW CREATE FUNCTION audit_test.get_user_email;\n"
            "\n"
            "-- Convert SQL SECURITY DEFINER to INVOKER where possible\n"
            "ALTER FUNCTION audit_test.get_user_email SQL SECURITY INVOKER;\n"
            "\n"
            "-- Or recreate the routine under a least-privileged definer\n"
            "DROP   FUNCTION audit_test.get_user_email;\n"
            "CREATE DEFINER='svc_routine'@'%' FUNCTION ... SQL SECURITY DEFINER ...;"
        ),
        docs=[
            ('Stored object access control (DEFINER vs INVOKER)',
             'https://dev.mysql.com/doc/refman/8.0/en/stored-objects-security.html'),
        ],
    ),
    dict(
        script='sec_12_dormant_users',
        mode='has_data', severity='Info',
        title='Dormant or never-used user accounts',
        recommendation='Review dormant accounts. Disable or remove unused logins.',
        extractor=_ext_dormant,
        ext_label='Dormant accounts (sample)',
        commands=(
            "-- Lock a dormant account (recommended before drop)\n"
            "ALTER USER 'dormant_user'@'%' ACCOUNT LOCK;\n"
            "\n"
            "-- Drop after a grace period\n"
            "DROP USER 'dormant_user'@'%';"
        ),
        docs=[
            ('ALTER USER ... ACCOUNT LOCK',
             'https://dev.mysql.com/doc/refman/8.0/en/alter-user.html#alter-user-account-lock'),
        ],
    ),
    dict(
        script='sec_14_backup_security',
        mode='has_data', severity='Info',
        title='Backup configuration / replication accounts',
        recommendation='Review who can read backup channels. RDS/Aurora users '
                       'with REPLICATION CLIENT can read binlog.',
        commands=(
            "-- See who has replication privileges\n"
            "SELECT user, host\n"
            "  FROM mysql.user\n"
            " WHERE Repl_slave_priv = 'Y' OR Repl_client_priv = 'Y';\n"
            "\n"
            "-- Revoke if not needed\n"
            "REVOKE REPLICATION SLAVE, REPLICATION CLIENT ON *.* FROM 'legacy_admin'@'%';"
        ),
        docs=[
            ('Replication privileges',
             'https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_replication-slave'),
            ('Aurora MySQL: binlog access',
             'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Replication.MySQL.html'),
        ],
    ),
    dict(
        script='sec_15_external_integrations',
        mode='has_data', severity='Info',
        title='External integrations (FEDERATED, UDF, non-standard SEs)',
        recommendation='Inventory of code paths reaching outside MySQL. Audit '
                       'credentials for FEDERATED servers and review UDFs.',
        extractor=_ext_external_integrations,
        ext_label='External integration objects',
        commands=(
            "-- List FEDERATED servers and any non-InnoDB engines\n"
            "SELECT * FROM mysql.servers;\n"
            "SELECT table_schema, table_name, engine\n"
            "  FROM information_schema.tables\n"
            " WHERE engine NOT IN ('InnoDB','MEMORY','PERFORMANCE_SCHEMA','SYS');"
        ),
        docs=[
            ('FEDERATED storage engine',
             'https://dev.mysql.com/doc/refman/8.0/en/federated-storage-engine.html'),
            ('User-Defined Functions',
             'https://dev.mysql.com/doc/refman/8.0/en/adding-loadable-function.html'),
        ],
    ),
    dict(
        script='sec_18_audit_gaps',
        mode='has_data', severity='Info',
        title='Audit configuration gaps',
        recommendation='Cross-check audit / log_* settings against the desired '
                       'baseline.',
        extractor=_ext_audit_gaps,
        ext_label='Audit settings of interest',
        docs=[
            ('Server logs',
             'https://dev.mysql.com/doc/refman/8.0/en/server-logs.html'),
        ],
    ),
    dict(
        script='sec_20_failed_login_patterns',
        mode='has_data', severity='Warning',
        title='Failed login / brute-force indicators',
        recommendation='Review failed-login counters and Connection_Errors_* '
                       'status variables. Enable connection_control plugin.',
        extractor=_ext_failed_logins,
        ext_label='Failed-login signals',
        commands=(
            "-- Install + enable connection_control (self-managed)\n"
            "INSTALL PLUGIN connection_control\n"
            "  SONAME 'connection_control.so';\n"
            "INSTALL PLUGIN connection_control_failed_login_attempts\n"
            "  SONAME 'connection_control.so';\n"
            "\n"
            "SET PERSIST connection_control_failed_connections_threshold = 5;\n"
            "SET PERSIST connection_control_min_connection_delay         = 1000;  -- ms"
        ),
        docs=[
            ('The Connection-Control Plugins',
             'https://dev.mysql.com/doc/refman/8.0/en/connection-control.html'),
        ],
    ),
    dict(
        script='sec_22_cert_and_key_expiry',
        mode='has_data', severity='Warning',
        title='Credentials / certificates approaching expiry',
        recommendation='Plan rotation. Expired user passwords cause silent auth '
                       'failures; expired TLS certs take SSL connections offline.',
        extractor=_ext_cert_expiry,
        ext_label='Expiry-related findings',
        commands=(
            "-- Rotate a user password (sets password_last_changed to NOW)\n"
            "ALTER USER 'app_read'@'%' IDENTIFIED BY '<new-strong-password>';\n"
            "\n"
            "-- RDS / Aurora: rotate the cluster CA before 2024 cert expires\n"
            "aws rds modify-db-cluster \\\n"
            "  --db-cluster-identifier <cluster> --ca-certificate-identifier rds-ca-rsa2048-g1\n"
            "aws rds modify-db-instance \\\n"
            "  --db-instance-identifier <writer> --ca-certificate-identifier rds-ca-rsa2048-g1"
        ),
        docs=[
            ('RDS: rotating the SSL/TLS certificate',
             'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html'),
            ('MySQL password lifetime',
             'https://dev.mysql.com/doc/refman/8.0/en/password-management.html#password-management-lifetime'),
        ],
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

    # Read each .log at most once -- before the optimisation a single log
    # with N matching rules was parsed 2N+ times (has_data_rows + extractor
    # both call parse_result_sets internally).
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
                    # Don't crash the whole report on one bad extractor;
                    # but DO surface the error so it gets fixed.
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
        runs = sorted(sub.glob('mysql_sec_*'), reverse=True)
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
<title>MySQL Security Audit Report</title>
{SHARED_CSS}
</head><body id='top'>
<header>
  <h1>MySQL Security Audit Report</h1>
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
