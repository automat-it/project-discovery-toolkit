-- =============================================================================
-- sec_21_patch_and_cve_level.sql
-- Priority: HIGH
-- Purpose: Identify the exact MySQL / MariaDB build, the branch EOL
--          status, and the plugin / component versions that carry
--          independent CVE risk.
-- Read-only.
-- References:
--   https://www.oracle.com/security-alerts/
--   https://mariadb.com/kb/en/security/
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Fingerprint header -- single-row context the report analyzer reads to
-- populate the Environment Fingerprint card. Keep as the FIRST query so
-- the analyzer can find it deterministically.
-- ---------------------------------------------------------------------------
SELECT
    @@version                                            AS server_version,
    @@version_comment                                    AS server_version_comment,
    DATABASE()                                           AS database_name,
    USER()                                               AS connection_user,
    @@hostname                                           AS server_hostname,
    @@max_connections                                    AS max_connections,
    @@innodb_buffer_pool_size                            AS innodb_buffer_pool_size,
    @@performance_schema                                 AS performance_schema,
    @@log_bin                                            AS log_bin,
    @@gtid_mode                                          AS gtid_mode,
    @@read_only                                          AS read_only,
    @@super_read_only                                    AS super_read_only,
    (SELECT COUNT(*) FROM mysql.user WHERE user='rdsadmin') AS is_aws_rds,
    @@time_zone                                          AS time_zone,
    @@character_set_server                               AS character_set_server,
    NOW()                                                AS server_time;

-- ---------------------------------------------------------------------------
-- Version / build / compile platform
-- ---------------------------------------------------------------------------
SELECT
    VERSION()                                             AS full_version,
    @@version_compile_machine                             AS arch,
    @@version_compile_os                                  AS compile_os,
    @@version_comment                                     AS edition;

-- ---------------------------------------------------------------------------
-- Major.minor/branch EOL lookup (update yearly — values as of Nov 2024):
--   MySQL 8.4 LTS    — Premier through 2029-04
--   MySQL 8.0        — Premier through 2026-04, Extended through 2032-04
--   MySQL 5.7        — EOL 2023-10
--   MySQL 5.6        — EOL 2021-02
--   MariaDB 11.4 LTS — EOL 2029-05
--   MariaDB 11.x STS — 1-year support
--   MariaDB 10.11 LTS— EOL 2028-02
--   MariaDB 10.6 LTS — EOL 2026-07
--   MariaDB 10.5 LTS — EOL 2025-06
--   MariaDB 10.4     — EOL 2024-06 (EOL)
-- ---------------------------------------------------------------------------
SELECT
    SUBSTRING_INDEX(VERSION(), '.', 2)                    AS major_branch,
    CASE
        WHEN VERSION() LIKE '8.4%'     THEN '2029-04 (LTS)'
        WHEN VERSION() LIKE '8.0%'     THEN '2026-04 Premier / 2032-04 Extended'
        WHEN VERSION() LIKE '5.7%'     THEN '2023-10 (EOL)'
        WHEN VERSION() LIKE '5.6%'     THEN '2021-02 (EOL)'
        WHEN VERSION() LIKE '11.4%-MariaDB'  THEN '2029-05 (LTS)'
        WHEN VERSION() LIKE '10.11%-MariaDB' THEN '2028-02 (LTS)'
        WHEN VERSION() LIKE '10.6%-MariaDB'  THEN '2026-07 (LTS)'
        WHEN VERSION() LIKE '10.5%-MariaDB'  THEN '2025-06 (LTS)'
        WHEN VERSION() LIKE '10.4%-MariaDB'  THEN '2024-06 (EOL)'
        ELSE 'check vendor matrix'
    END                                                   AS branch_eol;

-- ---------------------------------------------------------------------------
-- Installed plugins + versions — plugins (auth, audit, keyring,
-- replication, FEDERATED) ship with independent CPU cadence.
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLUGIN_STATUS,
    PLUGIN_LIBRARY,
    PLUGIN_LIBRARY_VERSION,
    LOAD_OPTION
FROM information_schema.PLUGINS
WHERE PLUGIN_STATUS = 'ACTIVE'
ORDER BY PLUGIN_TYPE, PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- Installed components (MySQL 8.0+ — mysql_component framework)
-- Guarded with a prepared statement so the query does not error on 5.7.
-- ---------------------------------------------------------------------------
SET @cmp_has := (SELECT COUNT(*) FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'component');
SET @cmp_sql := IF(@cmp_has = 1,
    'SELECT component_id, component_group_id, component_urn FROM mysql.component ORDER BY component_id',
    'SELECT ''mysql.component table not present — pre-8.0 server or missing grant'' AS note');
PREPARE cmp_stmt FROM @cmp_sql;
EXECUTE cmp_stmt;
DEALLOCATE PREPARE cmp_stmt;

-- ---------------------------------------------------------------------------
-- SSL / OpenSSL library version (MySQL statically links OpenSSL on many
-- builds — library CVEs follow the server)
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_status
WHERE VARIABLE_NAME IN ('Ssl_version','Ssl_cipher','Ssl_cipher_list')
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Operator guidance
-- ---------------------------------------------------------------------------
SELECT CONCAT(
    'Cross-reference ',
    VERSION(),
    ' against the vendor Critical Patch Update matrix. ',
    'Oracle MySQL: https://www.oracle.com/security-alerts/ ; ',
    'MariaDB: https://mariadb.com/kb/en/security/'
) AS operator_action;
