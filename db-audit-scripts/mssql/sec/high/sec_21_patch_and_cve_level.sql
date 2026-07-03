-- =============================================================================
-- sec_21_patch_and_cve_level.sql
-- Priority: HIGH
-- Purpose: Identify the exact SQL Server build, branch EOL status, and
--          indicate whether the build is behind the latest Cumulative
--          Update / Security Update.
-- Sources: SERVERPROPERTY, @@VERSION, sys.dm_os_host_info,
--          sys.dm_server_services (non-Azure).
-- Read-only.
-- References:
--   https://learn.microsoft.com/en-us/troubleshoot/sql/releases/download-and-install-latest-updates
--   https://msrc.microsoft.com/update-guide/
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Version facts
-- ---------------------------------------------------------------------------
SELECT
    SERVERPROPERTY('ProductVersion')                      AS product_version,
    SERVERPROPERTY('ProductLevel')                        AS product_level,   -- RTM / SP1 / CU13 / etc
    SERVERPROPERTY('ProductMajorVersion')                 AS product_major,
    SERVERPROPERTY('ProductMinorVersion')                 AS product_minor,
    SERVERPROPERTY('ProductBuild')                        AS product_build,
    SERVERPROPERTY('ProductUpdateLevel')                  AS update_level,
    SERVERPROPERTY('ProductUpdateReference')              AS update_kb,
    SERVERPROPERTY('Edition')                             AS edition,
    SERVERPROPERTY('EngineEdition')                       AS engine_edition, -- 5 = Azure SQL DB, 8 = Managed Instance
    SERVERPROPERTY('IsClustered')                         AS is_clustered,
    SERVERPROPERTY('IsHadrEnabled')                       AS hadr_enabled;

-- ---------------------------------------------------------------------------
-- Free-form @@VERSION (platform, build date, compile flags)
-- ---------------------------------------------------------------------------
SELECT @@VERSION AS version_banner;

-- ---------------------------------------------------------------------------
-- Branch EOL matrix — Mainstream / Extended support per major version.
-- Values as of Nov 2024; update annually.
--
--   SQL Server 2022 — Mainstream 2028-01, Extended 2033-01
--   SQL Server 2019 — Mainstream 2025-01, Extended 2030-01
--   SQL Server 2017 — Mainstream 2022-10 (EOL), Extended 2027-10
--   SQL Server 2016 — Mainstream 2021-07 (EOL), Extended 2026-07
--   SQL Server 2014 — EOL 2024-07
--   SQL Server 2012 — EOL 2022-07
-- ---------------------------------------------------------------------------
SELECT
    CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)    AS major,
    CASE CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)
        WHEN 16 THEN 'SQL 2022 — Mainstream 2028-01 / Extended 2033-01'
        WHEN 15 THEN 'SQL 2019 — Mainstream 2025-01 / Extended 2030-01'
        WHEN 14 THEN 'SQL 2017 — Mainstream EOL 2022-10, Extended 2027-10'
        WHEN 13 THEN 'SQL 2016 — Mainstream EOL 2021-07, Extended 2026-07'
        WHEN 12 THEN 'SQL 2014 — EOL 2024-07'
        WHEN 11 THEN 'SQL 2012 — EOL 2022-07'
        ELSE 'Check lifecycle matrix'
    END                                                   AS support_state;

-- ---------------------------------------------------------------------------
-- Host info (OS version carries independent CVE risk)
-- ---------------------------------------------------------------------------
SELECT host_platform, host_distribution, host_release, host_service_pack_level,
       host_sku, os_language_version
FROM sys.dm_os_host_info;

-- ---------------------------------------------------------------------------
-- Service accounts + last start-up (patch requires a service restart —
-- a long uptime is a strong signal of a skipped CU).
-- sys.dm_server_services is not available on Azure SQL DB.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        servicename,
        startup_type_desc,
        status_desc,
        process_id,
        last_startup_time,
        DATEDIFF(day, last_startup_time, SYSDATETIME()) AS days_since_restart,
        service_account,
        is_clustered,
        instant_file_initialization_enabled
    FROM sys.dm_server_services;
END TRY
BEGIN CATCH
    PRINT '[note] sys.dm_server_services not available (Azure SQL DB?): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Operator guidance
-- ---------------------------------------------------------------------------
SELECT CONCAT(
    'Cross-reference build ',
    CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(40)),
    ' (',
    CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(40)),
    ') against the Microsoft updates page. Any CU released after this ',
    'build number is a missed patch. Security-only updates are published ',
    'monthly via https://msrc.microsoft.com/update-guide/'
) AS operator_action;
