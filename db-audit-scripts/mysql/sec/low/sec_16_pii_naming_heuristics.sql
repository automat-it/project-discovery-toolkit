-- =============================================================================
-- sec_16_pii_naming_heuristics.sql
-- Priority: LOW
-- Purpose: Extended naming-based PII heuristics — broader patterns than
--          sec_09 (which focuses on common categories). Manual review
--          required; many matches will be false positives.
--
-- LIMITATIONS — same as sec_09:
--   * Column-name analysis only. Does not read row content, does not
--     assess encryption / masking / hashing, does not detect PII in
--     opaque columns (data, value, payload, JSON blobs).
--   * Expect false positives and false negatives.
--   * Use as a complement to sec_09 and a broader data classification
--     process — not as primary compliance evidence.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have pg_stats or pg_description (column comments
--       are stored in COLUMNS.COLUMN_COMMENT in information_schema).
--       Column comments mentioning sensitive concepts can be queried via
--       information_schema.COLUMNS.COLUMN_COMMENT.

-- ---------------------------------------------------------------------------
-- Extended PII pattern match including international identifiers
-- ---------------------------------------------------------------------------
SELECT
    c.TABLE_SCHEMA                                          AS schema_name,
    c.TABLE_NAME,
    c.COLUMN_NAME,
    c.COLUMN_TYPE                                           AS data_type,
    CASE
        -- US identifiers
        WHEN c.COLUMN_NAME REGEXP '(ssn|social_security|us_tin|ein)'           THEN 'us_id'
        -- EU identifiers
        WHEN c.COLUMN_NAME REGEXP '(nin|nino|insee|codice_fiscale|dni|nif)'    THEN 'eu_id'
        -- Ukrainian / Russian / CIS
        WHEN c.COLUMN_NAME REGEXP '(inn|ipn|edrpou|okpo|snils)'                THEN 'cis_id'
        -- Canada / UK
        WHEN c.COLUMN_NAME REGEXP '(sin|nhs|nhs_number|niNumber)'              THEN 'ca_uk_id'
        -- Health
        WHEN c.COLUMN_NAME REGEXP '(icd|snomed|loinc|hipaa|phr|ehr|emr)'       THEN 'health_code'
        -- Biometric
        WHEN c.COLUMN_NAME REGEXP '(biometric|fingerprint|retina|face_id|voice_print|dna)' THEN 'biometric'
        -- Auth tokens
        WHEN c.COLUMN_NAME REGEXP '(jwt|bearer|refresh_token|access_token|session_id|cookie)' THEN 'auth_token'
        -- Crypto / wallets
        WHEN c.COLUMN_NAME REGEXP '(wallet|btc|eth|crypto|seed_phrase|mnemonic|private_key|public_key)' THEN 'crypto'
        -- Device / tracking
        WHEN c.COLUMN_NAME REGEXP '(imei|imsi|mac_address|device_id|udid|advertising_id|idfa|gaid)' THEN 'device_id'
        -- Personal docs
        WHEN c.COLUMN_NAME REGEXP '(visa|residence_permit|work_permit|green_card)' THEN 'immigration'
        ELSE NULL
    END                                                     AS extended_category
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES t
  ON  t.TABLE_SCHEMA = c.TABLE_SCHEMA
  AND t.TABLE_NAME   = c.TABLE_NAME
WHERE c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND t.TABLE_TYPE IN ('BASE TABLE', 'VIEW')
  AND c.COLUMN_NAME REGEXP
    '(ssn|social_security|us_tin|ein|nin|nino|insee|codice_fiscale|dni|nif|inn|ipn|edrpou|okpo|snils|sin|nhs|nhs_number|niNumber|icd|snomed|loinc|hipaa|phr|ehr|emr|biometric|fingerprint|retina|face_id|voice_print|dna|jwt|bearer|refresh_token|access_token|session_id|cookie|wallet|btc|eth|crypto|seed_phrase|mnemonic|private_key|public_key|imei|imsi|mac_address|device_id|udid|advertising_id|idfa|gaid|visa|residence_permit|work_permit|green_card)'
ORDER BY extended_category, c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME;

-- ---------------------------------------------------------------------------
-- Tables containing the word "log", "audit", or "history" — likely to
-- accumulate sensitive data over time without retention controls
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_ROWS                                              AS approx_rows,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2)   AS total_mb,
    UPDATE_TIME                                             AS last_modified
FROM information_schema.TABLES
WHERE TABLE_TYPE = 'BASE TABLE'
  AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND TABLE_NAME REGEXP '(^|_)(log|audit|history|trail|event|track)s?($|_)'
ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC;

-- ---------------------------------------------------------------------------
-- Columns with comments mentioning sensitive concepts
-- NOTE: MySQL stores column comments in information_schema.COLUMNS.COLUMN_COMMENT.
--       This is the equivalent of pg_description for columns.
-- ---------------------------------------------------------------------------
SELECT
    c.TABLE_SCHEMA,
    c.TABLE_NAME,
    c.COLUMN_NAME,
    c.COLUMN_COMMENT                                        AS comment
FROM information_schema.COLUMNS c
WHERE c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND c.COLUMN_COMMENT REGEXP
    '(personal|sensitive|pii|gdpr|hipaa|secret|password|encrypted|confidential)'
ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME;

-- ---------------------------------------------------------------------------
-- Table comments mentioning sensitive concepts
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_COMMENT
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND TABLE_COMMENT REGEXP
    '(personal|sensitive|pii|gdpr|hipaa|secret|password|encrypted|confidential)'
ORDER BY TABLE_SCHEMA, TABLE_NAME;

-- ---------------------------------------------------------------------------
-- JSON / BLOB / TEXT columns (may store PII in unstructured form)
-- These are the "payload, data, value" columns that bypass naming heuristics.
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME,
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_COMMENT
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND COLUMN_TYPE IN ('json', 'blob', 'mediumblob', 'longblob',
                      'text', 'mediumtext', 'longtext')
  AND COLUMN_NAME REGEXP '(data|value|payload|content|body|raw|extra|metadata|info|details)'
ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
LIMIT 50;
