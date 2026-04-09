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
--     "field_07", JSON blobs).
--   * It does not evaluate whether sensitive columns are encrypted, masked,
--     hashed, or otherwise protected at rest or in transit.
--   * Expect both false positives and false negatives.
--   * Use as ONE INPUT into a broader data classification process — not as
--     primary evidence of PII coverage or compliance.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL does not have pg_stats (column-level statistics with null_frac,
--       n_distinct, etc.) accessible for this type of analysis.
--       MySQL also has no native Row Level Security (RLS); the equivalent
--       is implemented via views with SECURITY DEFINER or stored procedures.
--       The pg_policies query has no direct MySQL equivalent.

-- ---------------------------------------------------------------------------
-- Columns whose name suggests PII / sensitive content
-- ---------------------------------------------------------------------------
SELECT
    c.TABLE_SCHEMA                                          AS schema_name,
    c.TABLE_NAME,
    c.COLUMN_NAME,
    c.COLUMN_TYPE                                           AS data_type,
    c.IS_NULLABLE,
    CASE
        WHEN c.COLUMN_NAME REGEXP '(^|_)(ssn|social_security|nin|inn|tax_id|tin)' THEN 'national_id'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(passport|driver_?licen[sc]e|id_?card)'   THEN 'government_id'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(credit_?card|cc_?num|card_?num|cvv|cvc|pan)' THEN 'payment_card'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(iban|swift|bic|account_?num|routing)'    THEN 'bank_account'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(password|passwd|pwd|secret|api_?key|token|auth)' THEN 'credential'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(email|e_?mail)'                          THEN 'email'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(phone|mobile|tel|fax|msisdn)'            THEN 'phone'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(first_?name|last_?name|full_?name|surname|given_?name|family_?name)' THEN 'name'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(birth|dob|date_?of_?birth)'              THEN 'date_of_birth'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(addr|street|city|zip|postcode|postal)'   THEN 'address'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(gender|sex|race|ethnic|nationality|religion)' THEN 'demographic'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(salary|wage|income|compensation)'        THEN 'financial'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(health|medical|diagnosis|condition|prescription)' THEN 'health'
        WHEN c.COLUMN_NAME REGEXP '(^|_)(geo|gps|lat|lon|longitude|latitude|coords)' THEN 'geolocation'
        ELSE NULL
    END                                                     AS pii_category
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES t
  ON  t.TABLE_SCHEMA = c.TABLE_SCHEMA
  AND t.TABLE_NAME   = c.TABLE_NAME
WHERE c.TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND t.TABLE_TYPE IN ('BASE TABLE', 'VIEW')
  AND c.COLUMN_NAME REGEXP
    '(ssn|social_security|nin|inn|tax_id|tin|passport|driver.?licen.e|id.?card|credit.?card|cc.?num|card.?num|cvv|cvc|pan|iban|swift|bic|account.?num|routing|password|passwd|pwd|secret|api.?key|token|auth|email|e.?mail|phone|mobile|tel|fax|msisdn|first.?name|last.?name|full.?name|surname|given.?name|family.?name|birth|dob|date.?of.?birth|addr|street|city|zip|postcode|postal|gender|sex|race|ethnic|nationality|religion|salary|wage|income|compensation|health|medical|diagnosis|condition|prescription|geo|gps|lat|lon|longitude|latitude|coords)'
ORDER BY pii_category, c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME;

-- ---------------------------------------------------------------------------
-- Summary by PII category
-- ---------------------------------------------------------------------------
SELECT
    CASE
        WHEN COLUMN_NAME REGEXP '(^|_)(ssn|social_security|nin|inn|tax_id|tin)' THEN 'national_id'
        WHEN COLUMN_NAME REGEXP '(^|_)(passport|driver_?licen[sc]e|id_?card)'   THEN 'government_id'
        WHEN COLUMN_NAME REGEXP '(^|_)(credit_?card|cc_?num|card_?num|cvv|cvc|pan)' THEN 'payment_card'
        WHEN COLUMN_NAME REGEXP '(^|_)(iban|swift|bic|account_?num|routing)'    THEN 'bank_account'
        WHEN COLUMN_NAME REGEXP '(^|_)(password|passwd|pwd|secret|api_?key|token|auth)' THEN 'credential'
        WHEN COLUMN_NAME REGEXP '(^|_)(email|e_?mail)'                          THEN 'email'
        WHEN COLUMN_NAME REGEXP '(^|_)(phone|mobile|tel|fax|msisdn)'            THEN 'phone'
        WHEN COLUMN_NAME REGEXP '(^|_)(first_?name|last_?name|full_?name|surname|given_?name|family_?name)' THEN 'name'
        WHEN COLUMN_NAME REGEXP '(^|_)(birth|dob|date_?of_?birth)'              THEN 'date_of_birth'
        WHEN COLUMN_NAME REGEXP '(^|_)(addr|street|city|zip|postcode|postal)'   THEN 'address'
        WHEN COLUMN_NAME REGEXP '(^|_)(gender|sex|race|ethnic|nationality|religion)' THEN 'demographic'
        WHEN COLUMN_NAME REGEXP '(^|_)(salary|wage|income|compensation)'        THEN 'financial'
        WHEN COLUMN_NAME REGEXP '(^|_)(health|medical|diagnosis|condition|prescription)' THEN 'health'
        WHEN COLUMN_NAME REGEXP '(^|_)(geo|gps|lat|lon|longitude|latitude|coords)' THEN 'geolocation'
        ELSE NULL
    END                                                     AS category,
    COUNT(*)                                                AS column_count
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND COLUMN_NAME REGEXP
    '(ssn|social_security|nin|inn|tax_id|tin|passport|driver.?licen.e|id.?card|credit.?card|cc.?num|card.?num|cvv|cvc|pan|iban|swift|bic|account.?num|routing|password|passwd|pwd|secret|api.?key|token|auth|email|e.?mail|phone|mobile|tel|fax|msisdn|first.?name|last.?name|full.?name|surname|given.?name|family.?name|birth|dob|date.?of.?birth|addr|street|city|zip|postcode|postal|gender|sex|race|ethnic|nationality|religion|salary|wage|income|compensation|health|medical|diagnosis|condition|prescription|geo|gps|lat|lon|longitude|latitude|coords)'
GROUP BY category
HAVING category IS NOT NULL
ORDER BY column_count DESC;

-- ---------------------------------------------------------------------------
-- Tables containing potential credential columns
-- (highest priority for review — should be hashed, encrypted, or removed)
-- ---------------------------------------------------------------------------
SELECT DISTINCT
    TABLE_SCHEMA,
    TABLE_NAME,
    COLUMN_NAME
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
  AND COLUMN_NAME REGEXP '(^|_)(password|passwd|pwd|secret|api_?key|token)'
ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME;

-- ---------------------------------------------------------------------------
-- Row Level Security status
-- NOTE: MySQL does not have built-in RLS (Row Level Security).
--       The closest equivalents are:
--         1. Views with WHERE clauses and SECURITY DEFINER
--         2. Stored procedures that enforce row filtering
--         3. Application-layer filtering
--       This query lists views that might serve as RLS proxies:
-- ---------------------------------------------------------------------------
SELECT
    TABLE_SCHEMA,
    TABLE_NAME                                              AS view_name,
    DEFINER,
    SECURITY_TYPE,
    IS_UPDATABLE,
    -- NOTE: Views with SECURITY DEFINER run as the DEFINER's privileges,
    --       similar to PostgreSQL SECURITY DEFINER functions used for RLS.
    CASE SECURITY_TYPE
        WHEN 'DEFINER'  THEN 'runs as definer (like SECURITY DEFINER in PG)'
        WHEN 'INVOKER'  THEN 'runs as caller (like normal view in PG)'
        ELSE SECURITY_TYPE
    END                                                     AS rls_analog
FROM information_schema.VIEWS
WHERE TABLE_SCHEMA NOT IN ('mysql', 'information_schema',
                            'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME;
