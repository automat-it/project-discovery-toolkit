# mysql audit scripts

Read-only diagnostic scripts for mysql.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/` | Performance audit (top SQL, locks, indexes, vacuum, etc.) |
| `sec/`  | Security audit (roles, privileges, auth, encryption, etc.)|

## Priority order

Run in this order for the most efficient audit:

1. `critical/` — first, highest signal-to-noise
2. `high/` — after critical issues are resolved
3. `medium/` — tuning and stability
4. `low/` — deeper investigation

See `perf/README.md` and `sec/README.md` for the full script catalog.
