# postgres audit scripts

Read-only diagnostic scripts for PostgreSQL. 36 scripts total —
18 performance + 18 security — organized by priority tier.

## Target version

PostgreSQL 13 and newer. Verified against 13, 14, and 15. Some
queries reference catalogs added in newer versions (`pg_stat_wal` in
14+). Those blocks are guarded with a `server_version_num` check and
degrade to a `note` row instead of erroring out. A few columns were
renamed or moved in PG17 (e.g. `blk_read_time` → `shared_blk_read_time`
in `pg_stat_statements`, checkpoint counters moved to
`pg_stat_checkpointer`); individual scripts document the adjustment
needed for PG17.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance audit (top SQL, locks, indexes, bloat, WAL)   |
| `sec/`    | Security audit (roles, privileges, auth, encryption, PII) |

## Priority order

Run in this order for the most efficient audit:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/` — after critical findings are triaged
3. `medium/` — tuning and stability
4. `low/` — deeper investigation

## Running

```bash
psql -h <host> -U <user> -d <database> \
  -v ON_ERROR_STOP=0 --pset=pager=off \
  -f perf/critical/perf_01_top_sql.sql
```

Several scripts use `psql` meta-commands (`\gset` + `\if`) to guard
privileged or version-specific blocks. These work in `psql -f` but
are ignored by IDE SQL editors (DBeaver, DataGrip, pgAdmin) — run
from `psql` for full coverage.

See `perf/README.md` and `sec/README.md` for the full script catalog,
required privileges, and engine-version caveats.
