-- =============================================================================
-- sec_09_sensitive_data_discovery.sql
-- Purpose: Heuristic discovery of columns that may contain PII / sensitive
--          data, based on column names. Manual review required.
-- Priority: HIGH
--
-- LIMITATIONS:
--   * Column-name analysis only; does not read row content.
--   * Does not evaluate whether columns are encrypted / masked / hashed.
--   * Expect false positives (e.g. "password_hint") and false negatives
--     (sensitive data in opaque columns like "data","payload", JSON).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Columns whose name suggests PII / sensitive data
-- ---------------------------------------------------------------------------
;WITH classified AS (
    SELECT
        OBJECT_SCHEMA_NAME(c.object_id)               AS schema_name,
        OBJECT_NAME(c.object_id)                      AS object_name,
        c.name                                        AS column_name,
        TYPE_NAME(c.user_type_id)                     AS data_type,
        c.max_length,
        c.is_nullable,
        CASE
            WHEN c.name LIKE '%ssn%' OR c.name LIKE '%social_security%'
              OR c.name LIKE '%tax_id%' OR c.name LIKE '%tin%'
              OR c.name LIKE '%nin%'                                  THEN 'national_id'
            WHEN c.name LIKE '%passport%' OR c.name LIKE '%driver%licen%'
              OR c.name LIKE '%id_card%'                              THEN 'government_id'
            WHEN c.name LIKE '%credit_card%' OR c.name LIKE '%card_num%'
              OR c.name LIKE '%cc_num%'   OR c.name LIKE '%pan%'
              OR c.name LIKE '%cvv%' OR c.name LIKE '%cvc%'           THEN 'payment_card'
            WHEN c.name LIKE '%iban%' OR c.name LIKE '%swift%'
              OR c.name LIKE '%bic%'  OR c.name LIKE '%account_num%'
              OR c.name LIKE '%routing%'                              THEN 'bank_account'
            WHEN c.name LIKE '%password%' OR c.name LIKE '%passwd%'
              OR c.name LIKE '%pwd%'  OR c.name LIKE '%secret%'
              OR c.name LIKE '%api_key%' OR c.name LIKE '%token%'
              OR c.name LIKE '%auth%'                                 THEN 'credential'
            WHEN c.name LIKE '%email%' OR c.name LIKE '%e_mail%'      THEN 'email'
            WHEN c.name LIKE '%phone%' OR c.name LIKE '%mobile%'
              OR c.name LIKE '%fax%'  OR c.name LIKE '%msisdn%'       THEN 'phone'
            WHEN c.name LIKE '%first_name%' OR c.name LIKE '%last_name%'
              OR c.name LIKE '%full_name%'  OR c.name LIKE '%surname%'
              OR c.name LIKE '%given_name%' OR c.name LIKE '%family_name%' THEN 'name'
            WHEN c.name LIKE '%birth%' OR c.name LIKE '%dob%'
              OR c.name LIKE '%date_of_birth%'                        THEN 'date_of_birth'
            WHEN c.name LIKE '%address%' OR c.name LIKE '%street%'
              OR c.name LIKE '%city%'   OR c.name LIKE '%zip%'
              OR c.name LIKE '%postal%'                               THEN 'address'
            WHEN c.name LIKE '%gender%' OR c.name LIKE '%sex%'
              OR c.name LIKE '%race%'   OR c.name LIKE '%ethnic%'
              OR c.name LIKE '%nationality%' OR c.name LIKE '%religion%' THEN 'demographic'
            WHEN c.name LIKE '%salary%' OR c.name LIKE '%wage%'
              OR c.name LIKE '%income%' OR c.name LIKE '%compensation%' THEN 'financial'
            WHEN c.name LIKE '%health%' OR c.name LIKE '%medical%'
              OR c.name LIKE '%diagnosis%' OR c.name LIKE '%prescription%' THEN 'health'
            WHEN c.name LIKE '%ip_address%' OR c.name LIKE '%client_ip%'
                                                                      THEN 'ip_address'
            WHEN c.name LIKE '%geo%' OR c.name LIKE '%gps%'
              OR c.name LIKE '%lat%' OR c.name LIKE '%lon%'
              OR c.name LIKE '%coords%'                               THEN 'geolocation'
            WHEN c.name LIKE '%biometric%' OR c.name LIKE '%fingerprint%'
              OR c.name LIKE '%face%' OR c.name LIKE '%voice_print%'
              OR c.name LIKE '%retina%'                               THEN 'biometric'
            ELSE NULL
        END                                            AS pii_category
    FROM sys.columns c
    JOIN sys.objects o ON o.object_id = c.object_id
    WHERE o.type IN ('U','V')
      AND o.is_ms_shipped = 0
)
SELECT *
FROM classified
WHERE pii_category IS NOT NULL
ORDER BY pii_category, schema_name, object_name, column_name;

-- ---------------------------------------------------------------------------
-- Summary by PII category
-- ---------------------------------------------------------------------------
;WITH classified AS (
    SELECT
        CASE
            WHEN c.name LIKE '%ssn%' OR c.name LIKE '%social_security%'
              OR c.name LIKE '%tax_id%' OR c.name LIKE '%tin%'
              OR c.name LIKE '%nin%'                                  THEN 'national_id'
            WHEN c.name LIKE '%passport%' OR c.name LIKE '%driver%licen%'
              OR c.name LIKE '%id_card%'                              THEN 'government_id'
            WHEN c.name LIKE '%credit_card%' OR c.name LIKE '%card_num%'
              OR c.name LIKE '%cc_num%'   OR c.name LIKE '%pan%'
              OR c.name LIKE '%cvv%' OR c.name LIKE '%cvc%'           THEN 'payment_card'
            WHEN c.name LIKE '%iban%' OR c.name LIKE '%swift%'
              OR c.name LIKE '%bic%'  OR c.name LIKE '%account_num%'
              OR c.name LIKE '%routing%'                              THEN 'bank_account'
            WHEN c.name LIKE '%password%' OR c.name LIKE '%passwd%'
              OR c.name LIKE '%pwd%'  OR c.name LIKE '%secret%'
              OR c.name LIKE '%api_key%' OR c.name LIKE '%token%'
              OR c.name LIKE '%auth%'                                 THEN 'credential'
            WHEN c.name LIKE '%email%' OR c.name LIKE '%e_mail%'      THEN 'email'
            WHEN c.name LIKE '%phone%' OR c.name LIKE '%mobile%'      THEN 'phone'
            ELSE NULL
        END                                            AS category
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

-- ---------------------------------------------------------------------------
-- Tables containing a credential-like column (highest review priority)
-- ---------------------------------------------------------------------------
SELECT DISTINCT
    OBJECT_SCHEMA_NAME(c.object_id)                   AS schema_name,
    OBJECT_NAME(c.object_id)                          AS table_name,
    c.name                                            AS column_name,
    TYPE_NAME(c.user_type_id)                         AS data_type
FROM sys.columns c
JOIN sys.objects o ON o.object_id = c.object_id
WHERE o.type = 'U'
  AND o.is_ms_shipped = 0
  AND (c.name LIKE '%password%' OR c.name LIKE '%pwd%'
    OR c.name LIKE '%secret%'   OR c.name LIKE '%api_key%'
    OR c.name LIKE '%token%')
ORDER BY schema_name, table_name, column_name;

-- ---------------------------------------------------------------------------
-- Columns already protected by Dynamic Data Masking
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(object_id)                     AS schema_name,
    OBJECT_NAME(object_id)                            AS table_name,
    name                                              AS column_name,
    masking_function
FROM sys.masked_columns
ORDER BY schema_name, table_name, name;

-- ---------------------------------------------------------------------------
-- Row-Level Security policies (row-level access control on tables)
-- ---------------------------------------------------------------------------
SELECT
    sp.name                                           AS policy_name,
    sp.is_enabled,
    sp.is_schema_bound,
    OBJECT_SCHEMA_NAME(sp.object_id)                  AS policy_schema,
    OBJECT_NAME(sp.object_id)                         AS policy_object,
    sp.create_date,
    sp.modify_date
FROM sys.security_policies sp
ORDER BY sp.name;

-- RLS predicates on tables
SELECT
    sp.name                                           AS policy_name,
    OBJECT_SCHEMA_NAME(spp.target_object_id)          AS target_schema,
    OBJECT_NAME(spp.target_object_id)                 AS target_table,
    spp.predicate_definition,
    spp.predicate_type_desc                           AS predicate_type
FROM sys.security_predicates spp
JOIN sys.security_policies sp ON sp.object_id = spp.object_id
ORDER BY sp.name, target_table;
