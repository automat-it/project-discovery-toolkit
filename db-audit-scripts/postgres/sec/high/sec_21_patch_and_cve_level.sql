-- =============================================================================
-- sec_21_patch_and_cve_level.sql
-- Priority: HIGH
-- Purpose: Identify the exact PostgreSQL build, the EOL status of the
--          major branch, and whether the patch level is behind the
--          latest CPU (critical patch update). The output is a fixed
--          set of facts the operator cross-references against the
--          PostgreSQL security page.
-- Read-only.
-- Reference: https://www.postgresql.org/support/security/
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Version string — human-readable, platform, compile-time options.
-- ---------------------------------------------------------------------------
SELECT version()                                          AS full_version;

-- ---------------------------------------------------------------------------
-- Numeric major.minor — used to compare against the latest point
-- release of each supported branch.
-- ---------------------------------------------------------------------------
SELECT
    current_setting('server_version')                     AS server_version,
    current_setting('server_version_num')::int            AS server_version_num,
    -- Derive major from server_version_num: XX00YY (pre-10) / XXYYYY (10+)
    CASE
        WHEN current_setting('server_version_num')::int >= 100000
            THEN (current_setting('server_version_num')::int / 10000)::text
        ELSE (current_setting('server_version_num')::int / 10000)::text || '.' ||
             ((current_setting('server_version_num')::int / 100) % 100)::text
    END                                                   AS major_branch,
    -- EOL reference table (update yearly — values as of Nov 2024):
    --   17  EOL 2029-11
    --   16  EOL 2028-11
    --   15  EOL 2027-11
    --   14  EOL 2026-11
    --   13  EOL 2025-11
    --   12  EOL 2024-11 (end of life)
    --   11  EOL 2023-11
    --   10  EOL 2022-11
    CASE current_setting('server_version_num')::int / 10000
        WHEN 17 THEN '2029-11'
        WHEN 16 THEN '2028-11'
        WHEN 15 THEN '2027-11'
        WHEN 14 THEN '2026-11'
        WHEN 13 THEN '2025-11'
        WHEN 12 THEN '2024-11 (EOL)'
        WHEN 11 THEN '2023-11 (EOL)'
        WHEN 10 THEN '2022-11 (EOL)'
        ELSE 'EOL / unsupported'
    END                                                   AS branch_eol;

-- ---------------------------------------------------------------------------
-- Extension versions installed vs. latest available on this server.
-- Extension CVEs (pgbouncer, pljava, PostGIS, pgaudit) hit independent of
-- core PostgreSQL patches — compare installed vs default_version.
-- ---------------------------------------------------------------------------
SELECT
    e.extname,
    e.extversion                                          AS installed_version,
    av.default_version                                    AS latest_available,
    CASE WHEN e.extversion = av.default_version
         THEN 'current'
         ELSE 'outdated — ALTER EXTENSION ' || e.extname
              || ' UPDATE TO ''' || av.default_version || ''''
    END                                                   AS status
FROM pg_extension e
LEFT JOIN pg_available_extensions av ON av.name = e.extname
ORDER BY status, e.extname;

-- ---------------------------------------------------------------------------
-- Key procedural language versions (plperl / plpython / pljava) — CVEs
-- in the embedded runtime drag PG along.
-- ---------------------------------------------------------------------------
SELECT
    lanname                                               AS language,
    lanispl                                               AS is_procedural,
    lanpltrusted                                          AS is_trusted,
    lanplcallfoid::regproc::text                          AS handler_function
FROM pg_language
WHERE lanispl = true
ORDER BY lanname;

-- ---------------------------------------------------------------------------
-- Operator guidance: output includes the two facts needed to check the
-- current CPU against https://www.postgresql.org/support/security/ :
--   1. server_version (e.g. 15.4)
--   2. the list of minor releases of that branch after the installed one
-- There is no SQL view of CVE IDs — cross-reference manually.
-- ---------------------------------------------------------------------------
SELECT
    'Cross-reference ' || current_setting('server_version')
    || ' against https://www.postgresql.org/support/security/ — any row '
    || 'for this major branch above the installed minor is a missed CPU.'
                                                          AS operator_action;
