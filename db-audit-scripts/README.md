# db-audit-scripts

Read-only diagnostic SQL scripts for database health, performance, and
security audits.

## Layout

```
db-audit-scripts/
├── postgres/
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
├── mysql/
│   ├── perf/{critical,high,medium,low}/
│   └── sec/{critical,high,medium,low}/
└── mssql/
    ├── perf/{critical,high,medium,low}/
    └── sec/{critical,high,medium,low}/
```

## Conventions

* Every script is **read-only** — `SELECT` and `SHOW` only.
  No `CREATE / ALTER / DROP / INSERT / UPDATE / DELETE / GRANT / REVOKE`.
* No temporary tables, no functions, no objects of any kind are created.
* Filenames are prefixed with their audit number for ordering,
  e.g. `perf_01_top_sql.sql`, `sec_03_admin_and_superusers.sql`.

## Categories

| Category | Purpose                                                       |
|----------|---------------------------------------------------------------|
| `perf/`  | Performance audit — top SQL, locks, indexes, vacuum, sizing   |
| `sec/`   | Security audit — roles, privileges, auth, encryption, PII     |

## Priorities

| Level      | When to run                                                   |
|------------|---------------------------------------------------------------|
| `critical` | First — gives ~80% of insight, run on every audit             |
| `high`     | After stabilization — main optimization potential             |
| `medium`   | Long-term stability and tuning                                |
| `low`      | Nice-to-have, deeper investigation                            |

See per-engine and per-category READMEs for the script catalog.
