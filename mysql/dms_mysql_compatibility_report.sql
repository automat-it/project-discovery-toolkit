WITH
tables_base AS (
  SELECT
    t.TABLE_SCHEMA AS table_schema,
    t.TABLE_NAME   AS table_name
  FROM information_schema.TABLES t
  WHERE t.TABLE_TYPE = 'BASE TABLE'
    AND t.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
pk_tables AS (
  SELECT
    tc.TABLE_SCHEMA AS table_schema,
    tc.TABLE_NAME   AS table_name,
    1               AS has_pk
  FROM information_schema.TABLE_CONSTRAINTS tc
  WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
    AND tc.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
col_base AS (
  SELECT
    c.TABLE_SCHEMA     AS table_schema,
    c.TABLE_NAME       AS table_name,
    c.COLUMN_NAME      AS column_name,
    LOWER(c.DATA_TYPE) AS data_type,
    c.COLUMN_TYPE      AS column_type,
    c.IS_NULLABLE      AS is_nullable,
    c.COLUMN_DEFAULT   AS column_default,
    c.EXTRA            AS extra,
    c.COLUMN_KEY       AS column_key,
    c.CHARACTER_SET_NAME AS character_set_name,
    c.COLLATION_NAME     AS collation_name,
    c.NUMERIC_PRECISION  AS numeric_precision,
    c.NUMERIC_SCALE      AS numeric_scale
  FROM information_schema.COLUMNS c
  WHERE c.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
report AS (
  SELECT
    NOW() AS run_ts,
    cb.table_schema,
    cb.table_name,
    cb.column_name,
    cb.data_type,
    cb.column_type,
    cb.is_nullable,
    cb.column_default,
    cb.extra,
    COALESCE(pt.has_pk, 0) AS has_pk,
    cb.numeric_precision,
    cb.numeric_scale,
    cb.character_set_name,
    cb.collation_name,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'RISK'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'RISK'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'REVIEW'
      WHEN cb.data_type = 'json' THEN 'REVIEW'
      WHEN cb.data_type IN ('enum','set') THEN 'REVIEW'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'RISK'
      WHEN cb.data_type IN (
        'tinyint','smallint','mediumint','int','integer','bigint',
        'float','double','real','bit','boolean','bool',
        'date','datetime','timestamp','time','year',
        'char','varchar','binary','varbinary',
        'tinytext','text','mediumtext','longtext',
        'tinyblob','blob','mediumblob','longblob',
        'json','uuid'
      ) THEN 'OK'
      ELSE 'UNKNOWN'
    END AS status,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'Table without primary key'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'Generated column'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'Spatial type'
      WHEN cb.data_type = 'json' THEN 'JSON type'
      WHEN cb.data_type IN ('enum','set') THEN 'ENUM/SET type'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'LOB-like type'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'Unbounded DECIMAL/NUMERIC'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'DECIMAL/NUMERIC precision >= 39'
      ELSE 'General'
    END AS reason
  FROM col_base cb
  LEFT JOIN pk_tables pt
    ON pt.table_schema = cb.table_schema AND pt.table_name = cb.table_name
)

SELECT
  status,
  COUNT(*) AS column_count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM report
GROUP BY status
ORDER BY
  CASE status
    WHEN 'RISK' THEN 1
    WHEN 'UNKNOWN' THEN 2
    WHEN 'REVIEW' THEN 3
    ELSE 4
  END;

SELECT '__CSV_BEGIN__' AS marker;

WITH
tables_base AS (
  SELECT
    t.TABLE_SCHEMA AS table_schema,
    t.TABLE_NAME   AS table_name
  FROM information_schema.TABLES t
  WHERE t.TABLE_TYPE = 'BASE TABLE'
    AND t.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
pk_tables AS (
  SELECT
    tc.TABLE_SCHEMA AS table_schema,
    tc.TABLE_NAME   AS table_name,
    1               AS has_pk
  FROM information_schema.TABLE_CONSTRAINTS tc
  WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
    AND tc.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
col_base AS (
  SELECT
    c.TABLE_SCHEMA     AS table_schema,
    c.TABLE_NAME       AS table_name,
    c.COLUMN_NAME      AS column_name,
    LOWER(c.DATA_TYPE) AS data_type,
    c.COLUMN_TYPE      AS column_type,
    c.IS_NULLABLE      AS is_nullable,
    c.COLUMN_DEFAULT   AS column_default,
    c.EXTRA            AS extra,
    c.CHARACTER_SET_NAME AS character_set_name,
    c.COLLATION_NAME     AS collation_name,
    c.NUMERIC_PRECISION  AS numeric_precision,
    c.NUMERIC_SCALE      AS numeric_scale
  FROM information_schema.COLUMNS c
  WHERE c.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')
),
report AS (
  SELECT
    NOW() AS run_ts,
    cb.table_schema,
    cb.table_name,
    cb.column_name,
    cb.data_type,
    cb.column_type,
    cb.is_nullable,
    cb.column_default,
    cb.extra,
    COALESCE(pt.has_pk, 0) AS has_pk,
    cb.numeric_precision,
    cb.numeric_scale,
    cb.character_set_name,
    cb.collation_name,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'RISK'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'RISK'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'REVIEW'
      WHEN cb.data_type = 'json' THEN 'REVIEW'
      WHEN cb.data_type IN ('enum','set') THEN 'REVIEW'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'REVIEW'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'RISK'
      WHEN cb.data_type IN (
        'tinyint','smallint','mediumint','int','integer','bigint',
        'float','double','real','bit','boolean','bool',
        'date','datetime','timestamp','time','year',
        'char','varchar','binary','varbinary'
      ) THEN 'OK'
      ELSE 'UNKNOWN'
    END AS status,
    CASE
      WHEN COALESCE(pt.has_pk, 0) = 0 THEN 'Table without primary key'
      WHEN cb.extra LIKE '%GENERATED%' THEN 'Generated column'
      WHEN cb.data_type IN ('geometry','point','linestring','polygon','multipoint','multilinestring','multipolygon','geometrycollection') THEN 'Spatial type'
      WHEN cb.data_type = 'json' THEN 'JSON type'
      WHEN cb.data_type IN ('enum','set') THEN 'ENUM/SET type'
      WHEN cb.data_type IN ('blob','tinyblob','mediumblob','longblob','text','tinytext','mediumtext','longtext') THEN 'LOB-like type'
      WHEN cb.data_type IN ('decimal','numeric') AND (cb.numeric_precision IS NULL OR cb.numeric_precision = 0) THEN 'Unbounded DECIMAL/NUMERIC'
      WHEN cb.data_type IN ('decimal','numeric') AND cb.numeric_precision >= 39 THEN 'DECIMAL/NUMERIC precision >= 39'
      ELSE 'General'
    END AS reason
  FROM col_base cb
  LEFT JOIN pk_tables pt
    ON pt.table_schema = cb.table_schema AND pt.table_name = cb.table_name
)

SELECT
  CONCAT_WS(',',
    '"run_ts"',
    '"table_schema"',
    '"table_name"',
    '"column_name"',
    '"data_type"',
    '"column_type"',
    '"is_nullable"',
    '"column_default"',
    '"extra"',
    '"has_pk"',
    '"numeric_precision"',
    '"numeric_scale"',
    '"character_set_name"',
    '"collation_name"',
    '"status"',
    '"reason"'
  ) AS csv_line

UNION ALL

SELECT
  CONCAT_WS(',',
    CONCAT('"', REPLACE(IFNULL(CAST(run_ts AS CHAR), ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(table_schema, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(table_name, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(column_name, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(data_type, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(column_type, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(is_nullable, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(CAST(column_default AS CHAR), ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(extra, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(CAST(has_pk AS CHAR), ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(CAST(numeric_precision AS CHAR), ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(CAST(numeric_scale AS CHAR), ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(character_set_name, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(collation_name, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(status, ''), '"', '""'), '"'),
    CONCAT('"', REPLACE(IFNULL(reason, ''), '"', '""'), '"')
  ) AS csv_line
FROM report
ORDER BY
  CASE status WHEN 'RISK' THEN 1 WHEN 'UNKNOWN' THEN 2 WHEN 'REVIEW' THEN 3 ELSE 4 END,
  table_schema, table_name, column_name;
