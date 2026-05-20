-- =============================================================================
-- perf_19_storage_topology.sql
-- Priority: MEDIUM
-- Purpose: Map where data actually lives on disk — tablespaces, per-
--          tablespace size, data/WAL/log directories, and any cluster
--          objects placed off the default tablespace.
-- Read-only.
--
-- Portability: pg_current_wal_lsn() is blocked on AWS Aurora regardless of
-- wal_level. The replication-slot block below uses a $wal_lsn variable that
-- is NULL on Aurora and pg_current_wal_lsn() elsewhere so the rest of the
-- script still runs.
-- =============================================================================

SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdsadmin') AS is_aws_rds \gset

-- ---------------------------------------------------------------------------
-- Tablespace inventory + physical location (requires pg_read_server_files
-- privileges for pg_tablespace_location to return a real path on PG12+).
-- ---------------------------------------------------------------------------
SELECT
    t.oid,
    t.spcname                                            AS tablespace,
    pg_get_userbyid(t.spcowner)                          AS owner,
    pg_tablespace_location(t.oid)                        AS location_on_disk,
    pg_size_pretty(pg_tablespace_size(t.oid))            AS size,
    pg_tablespace_size(t.oid)                            AS bytes,
    t.spcoptions                                         AS options
FROM pg_tablespace t
ORDER BY pg_tablespace_size(t.oid) DESC;

-- ---------------------------------------------------------------------------
-- Server-level storage directories
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'data_directory',
    'config_file',
    'hba_file',
    'ident_file',
    'external_pid_file',
    'log_directory',
    'stats_temp_directory',
    'temp_tablespaces',
    'default_tablespace',
    'wal_level',
    'wal_segment_size',
    'max_wal_size',
    'min_wal_size',
    'archive_mode',
    'archive_command'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Objects NOT on the default tablespace (important for DR / restore
-- planning — these depend on a specific mount point existing on the
-- target host).
-- reltablespace = 0 means "default" in pg_class; expand to the real name.
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS relation,
    c.relkind                                            AS kind,
    t.spcname                                            AS tablespace,
    pg_size_pretty(pg_relation_size(c.oid))              AS size
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_tablespace t ON t.oid = c.reltablespace
WHERE c.reltablespace <> 0
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
ORDER BY pg_relation_size(c.oid) DESC
LIMIT 50;

-- ---------------------------------------------------------------------------
-- Size distribution per schema (where is the data concentrated?)
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    count(*) FILTER (WHERE c.relkind = 'r')              AS tables,
    count(*) FILTER (WHERE c.relkind = 'i')              AS indexes,
    count(*) FILTER (WHERE c.relkind IN ('m','v'))       AS views,
    pg_size_pretty(sum(pg_total_relation_size(c.oid)))   AS total_size,
    sum(pg_total_relation_size(c.oid))                   AS total_bytes
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','i','m','v','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
GROUP BY n.nspname
ORDER BY total_bytes DESC NULLS LAST;

-- ---------------------------------------------------------------------------
-- WAL / replication slot usage — disk pressure on pg_wal
-- pg_current_wal_lsn() is blocked on Aurora; skip the size computation
-- there but still surface slot inventory.
-- ---------------------------------------------------------------------------
\if :is_aws_rds
SELECT
    slot_name, slot_type, database, active, restart_lsn, confirmed_flush_lsn,
    '(blocked on Aurora)' AS retained_bytes
FROM pg_replication_slots
ORDER BY slot_name;
\else
SELECT
    slot_name, slot_type, database, active, restart_lsn, confirmed_flush_lsn,
    pg_wal_lsn_diff(
        pg_current_wal_lsn(),
        COALESCE(restart_lsn, pg_current_wal_lsn())
    )                                                    AS retained_bytes
FROM pg_replication_slots
ORDER BY retained_bytes DESC NULLS LAST;
\endif

-- ---------------------------------------------------------------------------
-- Temporary-file activity (spills to disk in tempdir / temp_tablespaces)
-- ---------------------------------------------------------------------------
SELECT
    datname                                              AS database,
    temp_files,
    pg_size_pretty(temp_bytes)                           AS temp_size,
    temp_bytes,
    stats_reset
FROM pg_stat_database
WHERE datname IS NOT NULL
ORDER BY temp_bytes DESC;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT count(*) FROM pg_tablespace)                                      AS tablespaces,
    (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')) AS custom_tablespaces,
    (SELECT setting FROM pg_settings WHERE name = 'data_directory')           AS data_directory,
    (SELECT pg_size_pretty(sum(pg_tablespace_size(oid))) FROM pg_tablespace)  AS total_tablespace_size;
