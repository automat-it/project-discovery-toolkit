# Cross-node unused index review (PostgreSQL / Aurora PostgreSQL)

Finds indexes that can be dropped to cut write load, judged across **every
node** of a cluster and at the **parent level** for partitioned tables.

| File | Role |
|---|---|
| `perf_index_bloat_crossnode.sql` | Read-only per-node capture: one CSV row per leaf index, with node identity, stats window, partition mapping, size, scans and table write counters |
| `collect_index_usage.sh` | Runs the capture on every instance (from a host list or an Aurora cluster id) and saves one CSV per node |
| `merge_index_usage.py` | Combines all captures into `index_review.md`, `index_review.csv` and `drop_candidates.sql` |

This is deliberately separate from the tiered `perf/` scripts: those audit
one connection, which is not enough for this question (see below).

## Why every node must be captured

`pg_stat_user_indexes` counters live in each instance's own memory and are
**not replicated**. On Aurora the readers share storage with the writer but
keep their own statistics. An index that serves only reader queries shows
`idx_scan = 0` on the writer and looks unused if only the writer is checked.
The merge treats an index as unused only when it is unused on **all** nodes.

Counters also restart on an instance restart, a failover or
`pg_stat_reset()`. On Aurora a failover restarts **every** instance in the
cluster, so counters go back to zero on the writer and all readers at once
(verified on Aurora PostgreSQL 17). A single capture taken after a failover
or a maintenance reboot therefore says nothing about usage. The merge splits
each node's captures into epochs at every reset and sums them, so usage seen
before a failover is not lost - which only works if captures were taken
before it. Hence the daily schedule below. When in doubt the merge
overcounts, which errs on the side of keeping an index.

## How partitioned tables are judged

Each leaf index is mapped to its root (parent-level) index, and each
partition gets a newest-first rank. The decision is made per **root index**:

- used in any of the newest `--recent` partitions (default 3) -> **keep**,
  even if older partitions never use it (reported as a note, not a finding)
- used only in older partitions -> **review** (may be historic / reporting
  queries)
- used nowhere on any node -> **drop candidate**

Partition age is taken from creation order (OID). The capture includes each
partition's bound expression so the order can be checked; it can be off if
old partitions were detached and re-attached or rebuilt.

## Prerequisites

- psql client 12+ (for `--csv`), PostgreSQL / Aurora PostgreSQL 13+
- Network access to **each instance endpoint** (VPN, bastion, or an SSM
  port-forward per instance). The cluster (`.cluster-`) and reader
  (`.cluster-ro-`) DNS endpoints do not pin an instance - do not use them.
- A login that can connect to the database. Any role can read the stats
  views; a read-only monitoring role is enough.
- For `-c` (cluster discovery): AWS CLI with `rds:DescribeDBClusters` and
  `rds:DescribeDBInstances`. It uses the default credential chain, so set
  `AWS_PROFILE` when the account is not your default profile.

The collector forces `default_transaction_read_only=on` and a 10-minute
`statement_timeout` on its sessions. The password is read from
`PGPASSWORD` or `~/.pgpass`, never passed on the command line.

## Run it once

```bash
cd db-audit-scripts/postgres/index_review
export PGPASSWORD='<password>'

# 1. Capture every instance of the cluster (writer + all readers)
bash collect_index_usage.sh -U <user> -d <db> -c <aurora-cluster-id> -r <region> -o ./captures

#    ...or list the instance endpoints yourself
bash collect_index_usage.sh -U <user> -d <db> -o ./captures <writer-instance-endpoint> <reader-1-endpoint> <reader-2-endpoint>

# 2. Merge
python3 merge_index_usage.py ./captures --out-dir ./review
```

With SSM / SSH port-forwarding every instance sits on its own local port.
Run the collector once per port into the same directory:

```bash
bash collect_index_usage.sh -U <user> -d <db> -P 15432 -o ./captures 127.0.0.1   # writer
bash collect_index_usage.sh -U <user> -d <db> -P 15433 -o ./captures 127.0.0.1   # reader 1
```

Nodes are told apart by the instance identifier inside each capture, not by
the host name, so this is safe. Capture every node within a short time of
each other.

Before acting on any finding, check the **Node coverage** table at the top
of `index_review.md`:

- Every writer and reader must be listed. A missing reader means its usage
  is invisible.
- **Window (days)** is how long that node's counters have been collecting.
  Under ~2-4 weeks (or less than your longest regular job cycle, e.g. a
  month-end report) is too short to call anything unused. If the cluster
  failed over or restarted recently, keep capturing daily and merge later -
  see below.

## Reading the result

`index_review.md` groups root indexes into:

| Category | Meaning | Action |
|---|---|---|
| `DROP-CANDIDATE` | 0 scans on every node over the whole window | Drop after review, largest first |
| `REVIEW-OLD-PARTITIONS-ONLY` | Used, but only in partitions older than the newest N | Check which workload reads old data |
| `REVIEW-LOW-USE` | Used, but less than `--low-per-day` scans/day | Assess individually - rare jobs may depend on it |
| `INVALID` | Failed `CREATE INDEX CONCURRENTLY` | Rebuild or drop |
| `KEEP-CONSTRAINT` | Backs a PK / unique / exclusion / FK constraint | Cannot drop; unused ones are listed as FYI |
| `KEEP-IN-USE` | Regularly used | Keep |

Every row shows scans per node, size, and **index write ops** (inserts plus
non-HOT updates on the table since the writer's last stats reset: every one
of them also writes this index). Size together with write ops ranks the
indexes whose removal saves the most write work.

`index_review.csv` has all indexes with the same columns for spreadsheets or
tickets. `drop_candidates.sql` lists a `DROP INDEX` for every drop candidate
with its rollback `CREATE INDEX` above it. **Every line is commented out.**

Tunables: `--recent N` (partitions that decide a parent index), `--low-per-day`
(review threshold), `--min-days` (window warning), `--min-size-mb` (hide small
indexes from the markdown tables).

## Dropping safely

- Non-partitioned index: `DROP INDEX CONCURRENTLY` - no blocking lock.
- Parent-level index on a partitioned table: PostgreSQL does **not** support
  `CONCURRENTLY` here. The drop takes `ACCESS EXCLUSIVE` on the parent and all
  partitions; schedule it in a quiet window with a short `lock_timeout`.
- Drop a few at a time, watch latency and the slow-query log on the writer
  **and** the readers for a few days, and keep the rollback statements handy.

## Doing it regularly

Captures accumulate, and the merge stitches them across resets and
failovers. To turn the once-off into a routine:

1. Schedule `collect_index_usage.sh -c <cluster-id> -o <captures-dir>` once a
   day (cron on a bastion, or a scheduled task with network access to the
   instances). Autoscaled readers are picked up whenever they exist.
2. Run `merge_index_usage.py <captures-dir>` monthly or before index work and
   review the new drop candidates.
3. Prune captures older than the window you care about (for example keep 90
   days) so dropped or rebuilt indexes age out.
