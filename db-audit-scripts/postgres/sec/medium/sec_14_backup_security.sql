-- =============================================================================
-- sec_14_backup_security.sql
-- Priority: MEDIUM
-- Purpose: Verify backup-related access and ongoing backup activity.
-- Note: Most backup security (encryption, access to S3 / disk, retention)
--       lives outside PostgreSQL — at the cloud provider or filesystem
--       layer. This script covers only what is visible from inside the DB.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Roles with REPLICATION privilege (can run pg_basebackup, read all WAL)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin,
    rolsuper,
    rolvaliduntil
FROM pg_roles
WHERE rolreplication
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Roles with pg_read_all_data (can dump all data — backup-equivalent)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS member,
    am.admin_option
FROM pg_auth_members am
JOIN pg_roles g ON g.oid = am.roleid
JOIN pg_roles r ON r.oid = am.member
WHERE g.rolname = 'pg_read_all_data'
ORDER BY r.rolname;

-- ---------------------------------------------------------------------------
-- Currently running base backups and WAL senders (true backup activity)
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    backend_start,
    state,
    backend_type,
    left(query, 200)                                     AS query
FROM pg_stat_activity
WHERE backend_type IN ('walsender', 'walreceiver')
   OR query ILIKE '%pg_basebackup%'
   OR query ILIKE '%pg_start_backup%'
   OR query ILIKE '%pg_backup_start%';

-- ---------------------------------------------------------------------------
-- Possible data export channels (NOT necessarily backups).
-- COPY TO is a generic data export — it may be used for backup, ETL,
-- ad-hoc analytics, or data exfiltration. Investigate each session
-- individually before drawing conclusions.
-- ---------------------------------------------------------------------------
SELECT
    pid,
    usename,
    application_name,
    client_addr,
    backend_start,
    state,
    now() - query_start                                  AS duration,
    left(query, 300)                                     AS query
FROM pg_stat_activity
WHERE state <> 'idle'
  AND query ~* '\mCOPY\M.*\mTO\M'
  AND backend_type = 'client backend';

-- ---------------------------------------------------------------------------
-- Replication slots (logical / physical) — each is a backup-adjacent channel
-- ---------------------------------------------------------------------------
SELECT
    slot_name,
    plugin,
    slot_type,
    database,
    temporary,
    active,
    active_pid,
    confirmed_flush_lsn
FROM pg_replication_slots
ORDER BY slot_type, slot_name;

-- ---------------------------------------------------------------------------
-- Archive / WAL settings relevant to backup integrity
-- ---------------------------------------------------------------------------
SELECT name, setting
FROM pg_settings
WHERE name IN (
    'archive_mode',
    'archive_command',
    'archive_library',
    'archive_timeout',
    'wal_level',
    'wal_compression',
    'full_page_writes',
    'wal_log_hints'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Last successful WAL archive time (PG 9.4+)
-- ---------------------------------------------------------------------------
SELECT
    archived_count,
    last_archived_wal,
    last_archived_time,
    failed_count,
    last_failed_wal,
    last_failed_time,
    stats_reset
FROM pg_stat_archiver;

-- ---------------------------------------------------------------------------
-- Historic backup connection sources (sessions long enough to be backups)
-- ---------------------------------------------------------------------------
SELECT
    usename                                              AS user,
    application_name,
    client_addr,
    backend_start,
    now() - backend_start                                AS connection_age,
    backend_type
FROM pg_stat_activity
WHERE backend_type IN ('walsender', 'walreceiver')
   OR application_name ILIKE '%backup%'
   OR application_name ILIKE '%dump%';
