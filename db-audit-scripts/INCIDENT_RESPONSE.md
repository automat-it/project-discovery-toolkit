# Incident-response playbook

When one of the audit scripts surfaces an active incident — brute-force
logins, head blockers, runaway queries, replication stall, impending
wraparound — the operator needs a short, deterministic sequence of
commands to run. This document is that sequence, grouped by signal.

Everything in the audit scripts themselves is **read-only**. The
commands below include *remediation* steps that write state. They are
marked **[WRITE]** and must be executed deliberately, by a human, with
the customer and change-management process informed.

---

## Signal → Playbook

### 1. `sec_20` shows a spike in failed logins

**Symptom:** `host_cache.COUNT_AUTHENTICATION_ERRORS` (MySQL) /
failed-login rows in ERRORLOG (MSSQL) / many client IPs in
`pg_stat_activity` climbing fast.

1. Identify the attacker IP(s) from the script output.
2. If a single host — null-route or firewall at the network layer
   *first*, before touching the database.
3. Lock the targeted account at the database layer if the IP cannot be
   blocked quickly:
   * PG **[WRITE]**:  `ALTER ROLE "<login>" VALID UNTIL 'now';`
   * MySQL **[WRITE]**: `ALTER USER '<u>'@'<h>' ACCOUNT LOCK;`
   * MSSQL **[WRITE]**: `ALTER LOGIN [<login>] DISABLE;`
4. Preserve evidence: copy the ERRORLOG segment / host_cache snapshot to
   a ticket **before** flushing any state.
5. Re-run `sec_20` 10 minutes later to confirm the attack has stopped.

### 2. `perf_02` shows a long-standing head blocker

**Symptom:** blocking chain with depth > 2 and wait times > 60 s; head
blocker's session is idle in transaction or in a long statement.

1. Read the head blocker's *current statement* and *application_name*
   from the `perf_02` output. Identify the application owner.
2. Contact the application owner — there is often a deploy, cron job,
   or stuck worker on their side. Prefer fixing the client.
3. Only if the application cannot act in a reasonable window:
   * PG **[WRITE]**: `SELECT pg_cancel_backend(<pid>);` first;
     `pg_terminate_backend(<pid>)` only if cancel is ignored.
   * MySQL **[WRITE]**: `KILL <thread_id>;` (soft) or
     `KILL CONNECTION <thread_id>;` (hard).
   * MSSQL **[WRITE]**: `KILL <spid>;` — note the rollback may take as
     long as the work already done.
4. Re-run `perf_02` to confirm the chain dissolved; check for a new
   head blocker (often another client was waiting).

### 3. `perf_01` shows a runaway query

**Symptom:** one query dominating CPU / I/O / mean_time, especially if
it is new since the last run.

1. Capture the full query text + plan from the script output.
2. Check for a recent deployment that changed the query or the schema
   it hits (`sec_19` shows recent DDL).
3. Options in order of preference:
   a. Fix the query or add the missing index (`perf_06` /
      `dm_db_missing_index_details` for MSSQL, `pg_stat_statements`
      + `EXPLAIN` for PG).
   b. Rewrite the query in the application.
   c. **[WRITE]** Force a plan (MSSQL Query Store: `sp_query_store_
      force_plan`; PG: `pg_hint_plan` or `auto_explain` + rewrite; MySQL:
      query-level hints).
4. If the query is from an ad-hoc user, cancel per playbook §2 and
   escalate to the user's manager — a new pattern of ad-hoc queries on
   prod usually indicates missing read-replica access.

### 4. `perf_08` shows replication lag climbing

**Symptom:** standby behind primary by minutes and not catching up;
replay LSN stuck or WAL-apply worker idle.

1. First check the *network* — replication stall is most often a
   network issue, not a database issue.
2. On PG: is there a long query on the replica holding replay back?
   `SELECT * FROM pg_stat_activity WHERE state = 'active';` on the
   replica. **[WRITE]** cancel the query if so.
3. On MySQL: is SQL_THREAD running? `SHOW REPLICA STATUS\G`. If
   stopped with a specific `Last_SQL_Errno`, the playbook is
   error-specific (do **not** use `SET GLOBAL SQL_SLAVE_SKIP_COUNTER`
   without understanding the divergence risk).
4. On MSSQL AG: check `sys.dm_hadr_database_replica_states` for
   `redo_queue_size` vs `redo_rate`.
5. If lag continues to grow and reads must not drift: **[WRITE]** fail
   over (PG promote / MySQL `CHANGE REPLICATION SOURCE` / MSSQL AG
   manual failover).

### 5. `perf_15` / `perf_19` shows disk > 85 %

**Symptom:** any database file at > 85 % of its max_size, or a
tablespace / filegroup at > 85 % of its mount.

1. Identify the table / file consuming the most space (`perf_15` +
   `perf_19`).
2. Quick win: can any table be truncated / archived? (check retention
   policies via `sec_23` once it exists).
3. **[WRITE]** Grow the file / add a file to the filegroup. Do **not**
   shrink a data file under pressure — shrink is I/O-intensive and
   causes massive index fragmentation.
4. If WAL / binlog is the culprit:
   * PG: check `pg_replication_slots` (`perf_19` shows retention) —
     an inactive logical slot holds WAL indefinitely.
     **[WRITE]** `SELECT pg_drop_replication_slot('<name>')` only
     after confirming the consumer is truly gone.
   * MySQL: `PURGE BINARY LOGS TO '<file>'` **[WRITE]** after
     confirming all replicas are past that position.
   * MSSQL: full + log backup chain; check `log_reuse_wait_desc`
     before issuing `BACKUP LOG`.

### 6. PG only: `age(datfrozenxid)` > 1.5B

**Symptom:** `perf_15` / `perf_18` flagging wraparound.

1. **[WRITE]** `VACUUM (FREEZE, VERBOSE) <table>` on the largest
   offenders first.
2. Raise `autovacuum_freeze_max_age` only as a temporary brake, not a
   fix.
3. If under 100M xids remain: stop writes and issue
   `VACUUM FREEZE` cluster-wide **[WRITE]**. Missing this window
   requires single-user-mode recovery.

### 7. `sec_19` shows unexpected DDL from an unknown account

**Symptom:** `modify_date` < 24 h on production objects from a login
that is not on the deployment service account list.

1. Freeze the account **[WRITE]** (same as playbook §1).
2. Preserve the default trace / Server Audit / binlog position *now*
   — these rotate.
3. Compare the affected object against the last known-good schema
   (your migration repo). Any unexpected indexes, triggers,
   `SECURITY DEFINER` / `EXECUTE AS OWNER` functions are
   high-priority escalation signals (see `sec_10`).
4. Treat as a suspected compromise: bring in the security team before
   dropping the suspicious object — keep it as evidence.

---

## Rules that apply to all playbooks

- **Preserve first, remediate second.** A `KILL` / `ACCOUNT LOCK` /
  `pg_terminate_backend` is destructive. Copy the audit output to the
  ticket first.
- **Communicate before you kill.** A cancelled query that was doing
  legitimate work will come back ten minutes later. Fix the client if
  at all possible.
- **Never use `--force` / `--no-verify` / `NOCHECK CONSTRAINT` as
  first-line remediation.** Those turn a database bug into a data
  integrity bug.
- **Prefer read-only escalation.** If you can re-route reads to a
  replica to buy time, do it before any write on the primary.
- **Document.** Every [WRITE] step goes in the ticket with the exact
  command executed and the operator who ran it.
