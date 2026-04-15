-- =============================================================================
-- sec_16_pii_naming_heuristics.sql
-- Priority: LOW
-- Purpose: Extended PII patterns — international identifiers, biometric
--          data, auth tokens, crypto wallets, device / tracking. Broader
--          than sec_09; many false positives; manual review required.
-- Sources: sys.columns, sys.objects, sys.extended_properties.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Extended PII pattern match (international and specialised categories)
-- ---------------------------------------------------------------------------
;WITH classified AS (
    SELECT
        OBJECT_SCHEMA_NAME(c.object_id)               AS schema_name,
        OBJECT_NAME(c.object_id)                      AS object_name,
        c.name                                        AS column_name,
        TYPE_NAME(c.user_type_id)                     AS data_type,
        c.max_length,
        CASE
            -- US identifiers
            WHEN c.name LIKE '%ssn%' OR c.name LIKE '%us_tin%' OR c.name LIKE '%ein%'
                                                                          THEN 'us_id'
            -- EU identifiers
            WHEN c.name LIKE '%nin%' OR c.name LIKE '%nino%' OR c.name LIKE '%insee%'
              OR c.name LIKE '%codice_fiscale%' OR c.name LIKE '%dni%' OR c.name LIKE '%nif%'
                                                                          THEN 'eu_id'
            -- CIS identifiers
            WHEN c.name LIKE '%inn%' OR c.name LIKE '%ipn%' OR c.name LIKE '%edrpou%'
              OR c.name LIKE '%okpo%' OR c.name LIKE '%snils%'            THEN 'cis_id'
            -- Canada / UK
            WHEN c.name LIKE '%sin%' OR c.name LIKE '%nhs%' OR c.name LIKE '%ni_number%'
                                                                          THEN 'ca_uk_id'
            -- Health codes
            WHEN c.name LIKE '%icd%' OR c.name LIKE '%snomed%' OR c.name LIKE '%loinc%'
              OR c.name LIKE '%hipaa%' OR c.name LIKE '%ehr%' OR c.name LIKE '%emr%'
                                                                          THEN 'health_code'
            -- Biometric
            WHEN c.name LIKE '%biometric%' OR c.name LIKE '%fingerprint%'
              OR c.name LIKE '%retina%' OR c.name LIKE '%face_id%'
              OR c.name LIKE '%voice_print%' OR c.name LIKE '%dna%'       THEN 'biometric'
            -- Auth tokens
            WHEN c.name LIKE '%jwt%' OR c.name LIKE '%bearer%' OR c.name LIKE '%refresh_token%'
              OR c.name LIKE '%access_token%' OR c.name LIKE '%session_id%'
              OR c.name LIKE '%cookie%'                                   THEN 'auth_token'
            -- Crypto / wallet
            WHEN c.name LIKE '%wallet%' OR c.name LIKE '%btc%' OR c.name LIKE '%eth%'
              OR c.name LIKE '%crypto%' OR c.name LIKE '%seed_phrase%'
              OR c.name LIKE '%mnemonic%' OR c.name LIKE '%private_key%'
              OR c.name LIKE '%public_key%'                               THEN 'crypto'
            -- Device / tracking
            WHEN c.name LIKE '%imei%' OR c.name LIKE '%imsi%' OR c.name LIKE '%mac_address%'
              OR c.name LIKE '%device_id%' OR c.name LIKE '%udid%'
              OR c.name LIKE '%advertising_id%' OR c.name LIKE '%idfa%'
              OR c.name LIKE '%gaid%'                                     THEN 'device_id'
            -- Immigration docs
            WHEN c.name LIKE '%visa%' OR c.name LIKE '%residence_permit%'
              OR c.name LIKE '%work_permit%' OR c.name LIKE '%green_card%' THEN 'immigration'
            ELSE NULL
        END                                            AS extended_category
    FROM sys.columns c
    JOIN sys.objects o ON o.object_id = c.object_id
    WHERE o.type IN ('U','V')
      AND o.is_ms_shipped = 0
)
SELECT *
FROM classified
WHERE extended_category IS NOT NULL
ORDER BY extended_category, schema_name, object_name, column_name;

-- ---------------------------------------------------------------------------
-- Tables whose name contains "log", "audit", "history", "trail", "event",
-- "track" — likely to accumulate sensitive data without retention controls
-- ---------------------------------------------------------------------------
SELECT
    SCHEMA_NAME(o.schema_id)                          AS schema_name,
    o.name                                            AS table_name,
    p.rows                                            AS row_count,
    CAST(SUM(ps.reserved_page_count) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.objects o
JOIN sys.partitions p             ON p.object_id = o.object_id AND p.index_id IN (0,1)
JOIN sys.dm_db_partition_stats ps ON ps.object_id = o.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND (o.name LIKE '%log%' OR o.name LIKE '%audit%' OR o.name LIKE '%history%'
    OR o.name LIKE '%trail%' OR o.name LIKE '%event%' OR o.name LIKE '%track%')
GROUP BY o.schema_id, o.name, p.rows
ORDER BY size_mb DESC;

-- ---------------------------------------------------------------------------
-- Extended properties / comments that mention "personal", "sensitive",
-- "GDPR", "HIPAA", etc.
-- ---------------------------------------------------------------------------
SELECT
    ep.class_desc,
    OBJECT_SCHEMA_NAME(ep.major_id)                   AS schema_name,
    OBJECT_NAME(ep.major_id)                          AS object_name,
    ep.name                                           AS property_name,
    CAST(ep.value AS NVARCHAR(MAX))                   AS property_value
FROM sys.extended_properties ep
WHERE CAST(ep.value AS NVARCHAR(MAX)) LIKE '%personal%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%sensitive%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%pii%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%gdpr%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%hipaa%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%secret%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%confidential%'
   OR CAST(ep.value AS NVARCHAR(MAX)) LIKE '%encrypted%'
ORDER BY schema_name, object_name;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
;WITH classified AS (
    SELECT
        CASE
            WHEN c.name LIKE '%biometric%' OR c.name LIKE '%fingerprint%' THEN 'biometric'
            WHEN c.name LIKE '%jwt%' OR c.name LIKE '%access_token%'      THEN 'auth_token'
            WHEN c.name LIKE '%wallet%' OR c.name LIKE '%private_key%'    THEN 'crypto'
            WHEN c.name LIKE '%imei%' OR c.name LIKE '%device_id%'        THEN 'device_id'
            ELSE NULL
        END AS category
    FROM sys.columns c
    JOIN sys.objects o ON o.object_id = c.object_id
    WHERE o.type IN ('U','V')
      AND o.is_ms_shipped = 0
)
SELECT category, COUNT(*) AS column_count
FROM classified
WHERE category IS NOT NULL
GROUP BY category
ORDER BY column_count DESC;
