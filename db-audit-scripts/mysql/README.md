# mysql audit scripts

Read-only diagnostic scripts for MySQL. 36 scripts total —
18 performance + 18 security — organized by priority tier.

## Target version

MySQL 8.0 and newer. Verified against 8.0 and 8.3 community builds.
Some blocks (`SHOW REPLICAS`, `performance_schema.variables_info`,
`replication_applier_status_by_worker`) require specific minor
versions — see `perf/README.md` and `sec/README.md` for per-script
notes. Scripts will produce errors in those blocks on MySQL 5.7.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance audit (top SQL, locks, indexes, temp, growth) |
| `sec/`    | Security audit (roles, privileges, auth, encryption, PII) |

## Priority order

Run in this order for the most efficient audit:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/` — after critical findings are triaged
3. `medium/` — tuning and stability
4. `low/` — deeper investigation

## Running

```bash
mysql -h <host> -u <user> -p <database> --batch --table \
  < perf/critical/perf_01_top_sql.sql
```

All scripts are read-only and do not create temporary tables. See
`perf/README.md` and `sec/README.md` for the full script catalog,
required privileges, and `performance_schema` prerequisites.
