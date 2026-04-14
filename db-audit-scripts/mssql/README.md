# mssql audit scripts

**Status: not yet implemented.** The `perf/` and `sec/` subdirectories
exist to keep layout symmetrical with `postgres/` and `mysql/`, but no
audit scripts have been committed for SQL Server yet.

The categories and priorities follow the same convention as the
PostgreSQL and MySQL trees:

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance audit — top SQL, locks, indexes, statistics   |
| `sec/`    | Security audit — logins, permissions, auth, encryption    |

| Priority   | Intent                                                    |
|------------|-----------------------------------------------------------|
| `critical` | First — highest signal-to-noise                           |
| `high`     | After critical issues are resolved                        |
| `medium`   | Tuning and stability                                      |
| `low`      | Deeper investigation                                      |

Contributions welcome. Target engine: Microsoft SQL Server 2019 and
newer (including Azure SQL Database / Managed Instance). Use the
existing PostgreSQL and MySQL scripts as a structural reference.
