/*
Purpose:
  Generate an AWS DMS compatibility report for a PostgreSQL database by inspecting schemas, tables, and column data types.
  Prints an aggregated summary (OK / REVIEW / RISK / UNKNOWN) to the console and exports a detailed CSV report to the
  current working directory with a timestamped filename.

Safety:
  Read-only analysis. No changes to application data.
  The script creates a TEMP VIEW (session-scoped) to deduplicate logic; it is dropped automatically at session end.

Required permissions (minimum practical):
  - CONNECT on the database
  - USAGE on schemas being inspected
  - Metadata visibility for table columns:
      Recommended: role membership in pg_read_all_data (PostgreSQL 14+) OR SELECT on all tables to be assessed
  - Read access to system catalogs (default for regular users)

Recommended execution:
  psql -d <db_name> -f dms_postgres_compatibility_report.sql

Output:
  - Console: aggregated summary by status
  - CSV file: dms_report_YYYYMMDD_HHMMSS.csv in the current working directory

Notes:
  - Status mapping is conservative. REVIEW indicates types that may require validation/transformations depending on target
    engine and DMS settings.
  - If using a restricted user, ensure it can see all schemas/tables intended for assessment.
*/

\set ON_ERROR_STOP on
\pset pager off
\pset format aligned
\pset border 1

\set ts `date +%Y%m%d_%H%M%S | tr -d '\n'`
\set outfile dms_report_:ts.csv

\set QUIET 1
CREATE TEMP VIEW dms_report AS
WITH
pk_tables AS (
  SELECT ns.nspname AS table_schema, c.relname AS table_name, true AS has_pk
  FROM pg_constraint con
  JOIN pg_class c ON c.oid = con.conrelid
  JOIN pg_namespace ns ON ns.oid = c.relnamespace
  WHERE con.contype = 'p'
),
col_base AS (
  SELECT
    n.nspname AS table_schema,
    c.relname AS table_name,
    a.attname AS column_name,
    a.atttypid AS type_oid,
    t.typname AS type_name,
    tn.nspname AS type_namespace,
    t.typcategory AS typcategory,
    t.typtype AS typtype,
    t.typbasetype AS domain_base_oid,
    t.typelem AS array_elem_oid,
    format_type(a.atttypid, a.atttypmod) AS formatted_type,
    (t.typelem <> 0 AND t.typcategory = 'A') AS is_array,
    (t.typtype = 'd') AS is_domain,
    (t.typtype = 'e') AS is_enum,
    (t.typtype = 'r') AS is_range,
    (t.typtype = 'c') AS is_composite
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_type t ON t.oid = a.atttypid
  JOIN pg_namespace tn ON tn.oid = t.typnamespace
  WHERE a.attnum > 0
    AND NOT a.attisdropped
    AND c.relkind IN ('r','p')
    AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
),
resolved AS (
  SELECT
    cb.*,
    LOWER(
      CASE
        WHEN cb.is_domain THEN (SELECT typname FROM pg_type WHERE oid = cb.domain_base_oid)
        WHEN cb.is_array  THEN (SELECT typname FROM pg_type WHERE oid = cb.array_elem_oid)
        ELSE cb.type_name
      END
    ) AS base_type
  FROM col_base cb
),
ext_types AS (
  SELECT t.oid AS type_oid, e.extname AS extension_name
  FROM pg_type t
  JOIN pg_depend d ON d.objid = t.oid AND d.classid = 'pg_type'::regclass
  JOIN pg_extension e ON e.oid = d.refobjid
  WHERE d.refclassid = 'pg_extension'::regclass
),
isc AS (
  SELECT table_schema, table_name, column_name, numeric_precision, numeric_scale
  FROM information_schema.columns
)
SELECT
  now()::timestamptz AS run_ts,
  r.table_schema,
  r.table_name,
  r.column_name,
  r.formatted_type,
  r.base_type,
  r.type_namespace,
  r.is_array,
  r.is_domain,
  r.is_enum,
  r.is_range,
  r.is_composite,
  et.extension_name,
  COALESCE(pk.has_pk, false) AS has_pk,
  i.numeric_precision,
  i.numeric_scale,
  CASE
    WHEN r.is_array AND COALESCE(pk.has_pk, false) = false THEN 'RISK'
    WHEN et.extension_name IS NOT NULL THEN 'RISK'
    WHEN r.type_namespace <> 'pg_catalog' AND NOT r.is_domain AND NOT r.is_enum THEN 'RISK'
    WHEN r.base_type IN ('numeric','decimal') AND (i.numeric_precision IS NULL OR i.numeric_precision = 0) THEN 'RISK'
    WHEN r.base_type IN ('numeric','decimal') AND i.numeric_precision >= 39 THEN 'RISK'
    WHEN r.base_type IN (
      'money','interval','xml','json','jsonb','tsvector','tsquery',
      'point','line','lseg','box','path','polygon','circle',
      'int4range','int8range','numrange','tsrange','tstzrange','daterange'
    ) THEN 'REVIEW'
    WHEN r.is_array OR r.is_composite OR r.is_range THEN 'REVIEW'
    WHEN r.is_domain OR r.is_enum THEN 'REVIEW'
    WHEN r.formatted_type ILIKE 'timestamp%' THEN 'REVIEW'
    WHEN r.base_type IN (
      'int2','int4','int8','smallint','integer','bigint',
      'float4','float8','real','double precision',
      'numeric','decimal',
      'bool','boolean',
      'date',
      'time','timetz','time without time zone','time with time zone',
      'text','varchar','bpchar','char','character','character varying',
      'bytea','uuid','cidr','inet','macaddr','bit','varbit'
    ) THEN 'OK'
    ELSE 'UNKNOWN'
  END AS status,
  CASE
    WHEN r.is_array AND COALESCE(pk.has_pk, false) = false THEN 'ARRAY column but no primary key'
    WHEN et.extension_name IS NOT NULL THEN 'Extension-owned type'
    WHEN r.type_namespace <> 'pg_catalog' AND NOT r.is_domain AND NOT r.is_enum THEN 'User-defined type'
    WHEN r.base_type IN ('numeric','decimal') AND (i.numeric_precision IS NULL OR i.numeric_precision = 0) THEN 'Unbounded numeric'
    WHEN r.base_type IN ('numeric','decimal') AND i.numeric_precision >= 39 THEN 'Numeric precision >=39'
    WHEN r.base_type IN ('json','jsonb','xml') THEN 'LOB-like behavior'
    WHEN r.base_type = 'interval' THEN 'Interval mapped to string'
    WHEN r.base_type = 'money' THEN 'Money type (locale-sensitive)'
    WHEN r.base_type IN ('tsvector','tsquery') THEN 'Full-text search type'
    WHEN r.base_type IN ('point','line','lseg','box','path','polygon','circle') THEN 'Geometric type'
    WHEN r.base_type IN ('int4range','int8range','numrange','tsrange','tstzrange','daterange') THEN 'Range type'
    WHEN r.is_array THEN 'Array type'
    WHEN r.is_composite THEN 'Composite type'
    WHEN r.is_range THEN 'Range type'
    WHEN r.is_domain THEN 'Domain type'
    WHEN r.is_enum THEN 'Enum type'
    WHEN r.formatted_type ILIKE 'timestamp%' THEN 'Timestamp infinity truncation risk'
    ELSE 'General'
  END AS reason
FROM resolved r
LEFT JOIN pk_tables pk
  ON pk.table_schema = r.table_schema AND pk.table_name = r.table_name
LEFT JOIN ext_types et
  ON et.type_oid = r.type_oid
LEFT JOIN isc i
  ON i.table_schema = r.table_schema AND i.table_name = r.table_name AND i.column_name = r.column_name
;
\set QUIET 0

\echo =====================================================================
\echo Generating DMS compatibility report...
\echo =====================================================================
\echo
\echo Summary by Status:
\echo ---------------------------------------------------------------------

SELECT
  status,
  count(*) AS column_count,
  round(100.0 * count(*) / sum(count(*)) OVER (), 2) AS percentage
FROM dms_report
GROUP BY status
ORDER BY CASE status WHEN 'RISK' THEN 1 WHEN 'UNKNOWN' THEN 2 WHEN 'REVIEW' THEN 3 ELSE 4 END;

\echo
\echo Exporting detailed report to CSV...

\pset format csv
\pset footer off
\o :outfile
SELECT
  run_ts,
  table_schema,
  table_name,
  column_name,
  formatted_type,
  base_type,
  type_namespace,
  is_array,
  is_domain,
  is_enum,
  is_range,
  is_composite,
  extension_name,
  has_pk,
  numeric_precision,
  numeric_scale,
  status,
  reason
FROM dms_report
ORDER BY CASE status WHEN 'RISK' THEN 1 WHEN 'UNKNOWN' THEN 2 WHEN 'REVIEW' THEN 3 ELSE 4 END, table_schema, table_name, column_name;
\o
\pset footer on
\pset format aligned
\pset border 1

\echo
\echo =====================================================================
\echo Report generation complete!
\echo File: :outfile
\echo Location: current working directory
\echo =====================================================================
