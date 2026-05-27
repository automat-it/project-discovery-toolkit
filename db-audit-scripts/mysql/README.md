# MySQL audit scripts

Read-only diagnostic scripts for MySQL. **47 scripts** total —
24 performance + 23 security — plus a Bash runner per category and a
Python report analyzer that produces an HTML report (with optional PDF).

Works on **self-managed MySQL 8.0+**, **Amazon RDS MySQL**, and
**Amazon Aurora MySQL Serverless v2**. Verified end-to-end on
RDS MySQL 8.0.46 (db.t4g.micro) and Aurora MySQL 3.10.0 (db.serverless),
and on the script catalogue against MySQL 8.0 and 8.3 community builds.

## Quick start (5 minutes)

```bash
cd db-audit-scripts/mysql

# 1. Performance audit -- runs every perf script in priority order
MYSQL_PWD=secret ./perf/run_audit.sh \
    -h db.internal -P 3306 -u auditor -d prod

# 2. Security audit
MYSQL_PWD=secret ./sec/run_audit.sh \
    -h db.internal -P 3306 -u auditor -d prod

# 3. Build the HTML report (always produced; PDF if headless Chrome / Edge present)
python3 ./perf/analyze_report.py ./reports/mysql_perf_<TIMESTAMP> \
        --server db.internal
python3 ./sec/analyze_report.py  ./reports/mysql_sec_<TIMESTAMP> \
        --server db.internal

# 4. (Optional) render to PDF
google-chrome --headless --disable-gpu --no-pdf-header-footer \
    --print-to-pdf=perf_analysis.pdf \
    "file://$(pwd)/reports/mysql_perf_<TIMESTAMP>/perf_analysis.html"
```

`<TIMESTAMP>` is the folder created by the runner — look in `./reports/`.

## What the analyzer produces

The HTML report contains, top-to-bottom:

* **Environment Fingerprint** — host, database, MySQL version,
  AWS-managed flag (RDS / Aurora), server role (primary writeable vs
  read-only replica), max_connections, innodb_buffer_pool, time zone,
  character set, `performance_schema` / `log_bin` / `gtid_mode` state.
  Populated from a single-row header that `perf_05` / `sec_21` emit
  specifically for the analyzer.
* **Executive Summary** — KPI cards (databases analysed, scripts
  OK/Failed, Critical / Warning counts) colour-tinted by severity, plus
  a **Top issues — what to fix** block listing the highest-priority
  findings as anchor links straight to their detail cards.
* **Findings** — one card per finding with severity colour bar,
  recommendation, a curated table of **concrete objects** flagged
  (table / index / digest queryid / user / column / routine), a
  **"How to fix — starter commands"** code block with copy-pastable SQL
  / `aws rds` snippets, and a **"Further reading"** list of links to
  dev.mysql.com and AWS docs for that specific control. Long lists are
  capped at 10 rows with `... +N more rows -- consult the raw .log
  file` so the reader gets the actionable set without being drowned in
  noise.
* **SQL Appendix** (perf only) — full `performance_schema` digest text
  per unique queryid, indexed by a collapsible jump-to list. Top SQL
  queryid cells link straight to the corresponding appendix entry.

The analyzer is **standard library only** — no Python packages required.
PDF rendering uses headless Chrome / Edge if available; HTML remains
the primary, always-emitted output.

## Authentication notes

The runners build a **temporary `--defaults-file`** from the
`MYSQL_PWD` env var and hand it to `mysql(1)` as the first argument.
This is the portable way to pass credentials and handles two real-
world traps:

1. **MySQL client 9.x** (Homebrew default on macOS) silently ignores
   `MYSQL_PWD` on some builds.
2. **`~/.my.cnf` overrides** — the mysql client reads `~/.my.cnf`
   *after* any `--defaults-extra-file`, so a stale local
   `[client] user=root password=...` block would override the audit
   credentials. `--defaults-file` (singular) replaces the entire
   option-file search, so isolation is guaranteed.

## Target version

MySQL **8.0 and newer**. Verified against 8.0.x and 8.3 community
builds plus RDS MySQL 8.0.46. Some blocks (`SHOW REPLICAS`,
`performance_schema.variables_info`,
`replication_applier_status_by_worker`) require specific 8.x minor
versions — see `perf/README.md` and `sec/README.md` for per-script
notes. Scripts will produce errors in those blocks on MySQL 5.7.

## Categories

| Category  | Purpose                                                   |
|-----------|-----------------------------------------------------------|
| `perf/`   | Performance — top SQL, locks, indexes, temp, growth, I/O  |
| `sec/`    | Security — accounts, privileges, auth, encryption, PII    |

## Priority order

Run priorities top-to-bottom — `critical` first gives roughly 80% of
the insight needed:

1. `critical/` — highest signal-to-noise, run on every audit
2. `high/`     — main optimization / hardening value
3. `medium/`   — long-term tuning and stability
4. `low/`      — deeper investigation, edge cases

## Prerequisites

- **`mysql` client** (8.0+ recommended; works with 9.x too).
- **`performance_schema = ON`** on the target server. Verified at the
  top of the HTML report's Environment Fingerprint card. RDS / Aurora
  default parameter groups have it OFF on the smallest instance
  classes — enable it via a custom DB parameter group + reboot if you
  see most perf scripts producing single-line `consumer` output only.
- **Bash** (Linux / macOS / WSL) for the runner scripts.
- **Python 3.9+** for the analyzer (standard library only).
- **Headless Chrome / Edge** (optional) for PDF output.

## Required privileges

A minimum-privilege audit account:

```sql
CREATE USER 'auditor'@'%' IDENTIFIED BY '<strong-password>';
GRANT SELECT, PROCESS, REPLICATION CLIENT, SHOW DATABASES,
      SHOW VIEW ON *.* TO 'auditor'@'%';
GRANT SELECT ON mysql.* TO 'auditor'@'%';   -- mysql.user / mysql.role_edges
```

Some `sec/` queries read `mysql.user.authentication_string` and
`mysql.role_edges` — they need `SELECT` on the `mysql` schema and
emit a degraded result if the grant is missing.

## AWS RDS / Aurora MySQL

The toolkit runs unchanged on RDS and Aurora. The fingerprint card
reports an `AWS managed (RDS / Aurora)` flag based on the presence of
the `rdsadmin` reserved user. Practical caveats:

* **`performance_schema` is often OFF by default** on the smallest
  RDS instance classes (1–2 GB RAM). Enable via a custom DB parameter
  group + reboot. Without it, the perf-side scripts produce only
  consumer-status rows.
* **`log_bin_trust_function_creators=1`** is needed if you want to
  create test triggers/events as a non-SUPER master user. Set in the
  parameter group for sandbox testing.
* **The RDS master user is not a true superuser.** `GRANT ALL
  PRIVILEGES` will fail because RDS reserves SUPER / SHUTDOWN / FILE /
  CREATE TABLESPACE. Grant the exact set of dynamic privileges the
  master holds via `rds_superuser_role` if you need to mirror admin.
* **Aurora reader-lag** is not in `pg_stat_replication`-style views;
  use CloudWatch (`AuroraReplicaLag`). Aurora replicates at the
  storage layer, not via binlog streaming.

## Running a single script

```bash
mysql -h <host> -u <user> -p <database> --batch \
      < perf/critical/perf_01_top_sql.sql
```

All scripts are read-only and do not create temporary tables.

## Folder layout

```
mysql/
  _analyze_lib.py            ← shared parser / fingerprint / HTML helpers
  perf/
    run_audit.sh             ← Bash runner for the perf category
    analyze_report.py        ← builds perf_analysis.html (+ PDF if Chrome)
    {critical,high,medium,low}/   ← the .sql scripts
  sec/
    run_audit.sh
    analyze_report.py
    {critical,high,medium,low}/
```

## Multi-database / multi-server reports

The runner connects to **one MySQL endpoint** at a time and queries
through `information_schema` / `mysql.user` / `performance_schema`,
which already span every schema on that instance — so a single audit
run covers **every schema** on that server.

For multiple servers, run the audit once per endpoint into per-server
subfolders, then point the analyzer at the parent directory:

```bash
bash sec/run_audit.sh -u admin -h srv-a.example.com -o ./reports/srv-a ...
bash sec/run_audit.sh -u admin -h srv-b.example.com -o ./reports/srv-b ...
python3 sec/analyze_report.py ./reports          # one combined report
```

The analyzer's `discover_contexts()` will pick up each subfolder and
produce a single HTML report with a **Context rollup** table (one KPI
row per server) plus per-server findings sections.

See `perf/README.md` and `sec/README.md` for the full per-script
catalog, runner flags, analyzer options, and `performance_schema`
prerequisites.
