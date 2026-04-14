# db-audit-scripts

Read-only diagnostic SQL scripts for database health, performance, and
security audits. Intended for ad-hoc investigations, discovery runs
before migrations, and baseline assessments on existing deployments.

## Layout

```
db-audit-scripts/
├── postgres/        # 36 scripts — verified on PostgreSQL 13–15
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
├── mysql/           # 36 scripts — verified on MySQL 8.0–8.3
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
└── mssql/           # directory structure reserved; scripts not yet implemented
    ├── perf/{critical,high,medium,low}/
    └── sec/{critical,high,medium,low}/
```

## Conventions

- Every script is **read-only** — `SELECT` and `SHOW` only. No
  `CREATE / ALTER / DROP / INSERT / UPDATE / DELETE / GRANT / REVOKE`.
- No temporary tables, no functions, no objects of any kind are created.
- Filenames are prefixed with category and audit number for ordering,
  e.g. `perf_01_top_sql.sql`, `sec_03_admin_and_superusers.sql`.
- Privileged blocks (e.g. reading `pg_authid`, `pg_hba_file_rules`) are
  guarded with runtime privilege checks and skip cleanly when the
  current role lacks access — they never abort the whole script.

## Categories

| Category | Purpose                                                       |
|----------|---------------------------------------------------------------|
| `perf/`  | Performance audit — top SQL, locks, indexes, vacuum, sizing   |
| `sec/`   | Security audit — roles, privileges, auth, encryption, PII     |

## Priorities

| Level      | When to run                                                   |
|------------|---------------------------------------------------------------|
| `critical` | First — ~80% of the insight; run on every audit               |
| `high`     | After critical findings are triaged — main optimization value |
| `medium`   | Long-term stability and tuning                                |
| `low`      | Nice-to-have, deeper investigation                            |

## Running

### PostgreSQL

```bash
psql -h <host> -U <user> -d <database> -f postgres/perf/critical/perf_01_top_sql.sql
```

### MySQL

```bash
mysql -h <host> -u <user> -p <database> < mysql/perf/critical/perf_01_top_sql.sql
```

Scripts use client meta-commands (`\if`, `\gset` in psql; `DELIMITER`
not used in MySQL). Running from IDEs that strip meta-commands
(DBeaver, DataGrip) may skip guarded blocks — prefer `psql -f` and
`mysql <`.

See per-engine and per-category READMEs for the full script catalog,
required privileges, and engine version notes.
