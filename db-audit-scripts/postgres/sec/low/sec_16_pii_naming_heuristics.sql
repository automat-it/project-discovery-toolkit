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
--     opaque columns (data, value, payload, JSONB blobs).
--   * Expect false positives and false negatives.
--   * Use as a complement to sec_09 and a broader data classification
--     process — not as primary compliance evidence.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extended PII pattern match including international identifiers
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    a.attname                                            AS column,
    format_type(a.atttypid, a.atttypmod)                 AS type,
    CASE
        -- US identifiers
        WHEN a.attname ~* '(ssn|social_security|us_tin|ein)'           THEN 'us_id'
        -- EU identifiers
        WHEN a.attname ~* '(nin|nino|insee|codice_fiscale|dni|nif)'    THEN 'eu_id'
        -- Ukrainian / Russian / CIS
        WHEN a.attname ~* '(inn|ipn|edrpou|okpo|snils)'                THEN 'cis_id'
        -- Canada / UK
        WHEN a.attname ~* '(sin|nhs|nhs_number|niNumber)'              THEN 'ca_uk_id'
        -- Health
        WHEN a.attname ~* '(icd|snomed|loinc|hipaa|phr|ehr|emr)'       THEN 'health_code'
        -- Biometric
        WHEN a.attname ~* '(biometric|fingerprint|retina|face_id|voice_print|dna)' THEN 'biometric'
        -- Auth tokens
        WHEN a.attname ~* '(jwt|bearer|refresh_token|access_token|session_id|cookie)' THEN 'auth_token'
        -- Crypto / wallets
        WHEN a.attname ~* '(wallet|btc|eth|crypto|seed_phrase|mnemonic|private_key|public_key)' THEN 'crypto'
        -- Device / tracking
        WHEN a.attname ~* '(imei|imsi|mac_address|device_id|udid|advertising_id|idfa|gaid)' THEN 'device_id'
        -- Personal docs
        WHEN a.attname ~* '(visa|residence_permit|work_permit|green_card)' THEN 'immigration'
        ELSE NULL
    END                                                  AS extended_category
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'm', 'v')
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND a.attname ~* '(ssn|social_security|us_tin|ein|nin|nino|insee|codice_fiscale|dni|nif|inn|ipn|edrpou|okpo|snils|sin|nhs|nhs_number|niNumber|icd|snomed|loinc|hipaa|phr|ehr|emr|biometric|fingerprint|retina|face_id|voice_print|dna|jwt|bearer|refresh_token|access_token|session_id|cookie|wallet|btc|eth|crypto|seed_phrase|mnemonic|private_key|public_key|imei|imsi|mac_address|device_id|udid|advertising_id|idfa|gaid|visa|residence_permit|work_permit|green_card)'
ORDER BY extended_category, n.nspname, c.relname, a.attname;

-- ---------------------------------------------------------------------------
-- Tables containing the word "log", "audit", or "history" — likely to
-- accumulate sensitive data over time without retention controls
-- ---------------------------------------------------------------------------
SELECT
    schemaname,
    relname                                              AS table,
    n_live_tup                                           AS rows,
    pg_size_pretty(pg_total_relation_size(relid))        AS size
FROM pg_stat_user_tables
WHERE relname ~* '(^|_)(log|audit|history|trail|event|track)s?($|_)'
ORDER BY pg_total_relation_size(relid) DESC;

-- ---------------------------------------------------------------------------
-- Comments on columns that mention sensitive concepts
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    a.attname                                            AS column,
    d.description                                        AS comment
FROM pg_description d
JOIN pg_class c     ON c.oid = d.objoid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.objsubid
WHERE d.objsubid > 0
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND d.description ~* '(personal|sensitive|pii|gdpr|hipaa|secret|password|encrypted|confidential)'
ORDER BY n.nspname, c.relname, a.attname;
