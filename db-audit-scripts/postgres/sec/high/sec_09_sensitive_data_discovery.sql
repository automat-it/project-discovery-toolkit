-- =============================================================================
-- sec_09_sensitive_data_discovery.sql
-- Purpose: Heuristic discovery of columns that may contain PII / sensitive
--          data based on column name patterns. Manual review required.
-- Priority: HIGH
--
-- LIMITATIONS — read before relying on results:
--   * This script analyzes COLUMN NAMES ONLY. It does not read row content,
--     does not assess actual data sensitivity, and does not detect PII
--     stored in columns with non-obvious names (e.g. "data", "value",
--     "field_07", JSONB blobs).
--   * It does not evaluate whether sensitive columns are encrypted, masked,
--     hashed, or otherwise protected at rest or in transit.
--   * Expect both false positives (e.g. "password_hint" matched as
--     credential, "client_email_template" matched as email) and false
--     negatives (sensitive data in oddly-named columns).
--   * Use as ONE INPUT into a broader data classification process — not as
--     primary evidence of PII coverage or compliance.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Columns whose name suggests PII / sensitive content
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    a.attname                                            AS column,
    format_type(a.atttypid, a.atttypmod)                 AS data_type,
    CASE
        WHEN a.attname ~* '(^|_)(ssn|social_security|nin|inn|tax_id|tin)' THEN 'national_id'
        WHEN a.attname ~* '(^|_)(passport|driver_?licen[sc]e|id_?card)'   THEN 'government_id'
        WHEN a.attname ~* '(^|_)(credit_?card|cc_?num|card_?num|cvv|cvc|pan)' THEN 'payment_card'
        WHEN a.attname ~* '(^|_)(iban|swift|bic|account_?num|routing)'    THEN 'bank_account'
        WHEN a.attname ~* '(^|_)(password|passwd|pwd|secret|api_?key|token|auth)' THEN 'credential'
        WHEN a.attname ~* '(^|_)(email|e_?mail)'                          THEN 'email'
        WHEN a.attname ~* '(^|_)(phone|mobile|tel|fax|msisdn)'            THEN 'phone'
        WHEN a.attname ~* '(^|_)(first_?name|last_?name|full_?name|surname|given_?name|family_?name)' THEN 'name'
        WHEN a.attname ~* '(^|_)(birth|dob|date_?of_?birth)'              THEN 'date_of_birth'
        WHEN a.attname ~* '(^|_)(addr|street|city|zip|postcode|postal)'   THEN 'address'
        WHEN a.attname ~* '(^|_)(gender|sex|race|ethnic|nationality|religion)' THEN 'demographic'
        WHEN a.attname ~* '(^|_)(salary|wage|income|compensation)'        THEN 'financial'
        WHEN a.attname ~* '(^|_)(health|medical|diagnosis|condition|prescription)' THEN 'health'
        WHEN a.attname ~* '(^|_)(geo|gps|lat|lon|longitude|latitude|coords)' THEN 'geolocation'
        ELSE NULL
    END                                                  AS pii_category
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'm', 'v')
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND a.attname ~* '(ssn|social_security|nin|inn|tax_id|tin|passport|driver_?licen[sc]e|id_?card|credit_?card|cc_?num|card_?num|cvv|cvc|pan|iban|swift|bic|account_?num|routing|password|passwd|pwd|secret|api_?key|token|auth|email|e_?mail|phone|mobile|tel|fax|msisdn|first_?name|last_?name|full_?name|surname|given_?name|family_?name|birth|dob|date_?of_?birth|addr|street|city|zip|postcode|postal|gender|sex|race|ethnic|nationality|religion|salary|wage|income|compensation|health|medical|diagnosis|condition|prescription|geo|gps|lat|lon|longitude|latitude|coords)'
ORDER BY pii_category, n.nspname, c.relname, a.attname;

-- ---------------------------------------------------------------------------
-- Summary by category
-- ---------------------------------------------------------------------------
WITH classified AS (
    SELECT
        CASE
            WHEN a.attname ~* '(^|_)(ssn|social_security|nin|inn|tax_id|tin)' THEN 'national_id'
            WHEN a.attname ~* '(^|_)(passport|driver_?licen[sc]e|id_?card)'   THEN 'government_id'
            WHEN a.attname ~* '(^|_)(credit_?card|cc_?num|card_?num|cvv|cvc|pan)' THEN 'payment_card'
            WHEN a.attname ~* '(^|_)(iban|swift|bic|account_?num|routing)'    THEN 'bank_account'
            WHEN a.attname ~* '(^|_)(password|passwd|pwd|secret|api_?key|token|auth)' THEN 'credential'
            WHEN a.attname ~* '(^|_)(email|e_?mail)'                          THEN 'email'
            WHEN a.attname ~* '(^|_)(phone|mobile|tel|fax|msisdn)'            THEN 'phone'
            WHEN a.attname ~* '(^|_)(first_?name|last_?name|full_?name|surname|given_?name|family_?name)' THEN 'name'
            WHEN a.attname ~* '(^|_)(birth|dob|date_?of_?birth)'              THEN 'date_of_birth'
            WHEN a.attname ~* '(^|_)(addr|street|city|zip|postcode|postal)'   THEN 'address'
            WHEN a.attname ~* '(^|_)(gender|sex|race|ethnic|nationality|religion)' THEN 'demographic'
            WHEN a.attname ~* '(^|_)(salary|wage|income|compensation)'        THEN 'financial'
            WHEN a.attname ~* '(^|_)(health|medical|diagnosis|condition|prescription)' THEN 'health'
            WHEN a.attname ~* '(^|_)(geo|gps|lat|lon|longitude|latitude|coords)' THEN 'geolocation'
        END AS category
    FROM pg_attribute a
    JOIN pg_class c     ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'm', 'v')
      AND a.attnum > 0
      AND NOT a.attisdropped
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
)
SELECT
    category,
    count(*)                                             AS column_count
FROM classified
WHERE category IS NOT NULL
GROUP BY category
ORDER BY column_count DESC;

-- ---------------------------------------------------------------------------
-- Tables containing potential credential columns
-- (highest priority for review — should be hashed, encrypted, or removed)
-- ---------------------------------------------------------------------------
SELECT DISTINCT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    a.attname                                            AS column
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0
  AND NOT a.attisdropped
  AND c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND a.attname ~* '(^|_)(password|passwd|pwd|secret|api_?key|token)'
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- Row Level Security status — tables with RLS enabled
-- ---------------------------------------------------------------------------
SELECT
    n.nspname                                            AS schema,
    c.relname                                            AS table,
    c.relrowsecurity                                     AS rls_enabled,
    c.relforcerowsecurity                                AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (c.relrowsecurity OR c.relforcerowsecurity)
ORDER BY n.nspname, c.relname;

-- ---------------------------------------------------------------------------
-- RLS policies in detail
-- ---------------------------------------------------------------------------
SELECT
    schemaname                                           AS schema,
    tablename                                            AS table,
    policyname                                           AS policy,
    permissive,
    roles,
    cmd                                                  AS command,
    qual                                                 AS using_expression,
    with_check                                           AS check_expression
FROM pg_policies
ORDER BY schemaname, tablename, policyname;
