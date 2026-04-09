-- =============================================================================
-- sec_15_external_integrations.sql
-- Priority: MEDIUM
-- Purpose: Audit external connectivity points — FEDERATED tables, UDFs,
--          linked server plugins, and dblink-equivalent patterns.
--          These are network egress points and may carry credentials.
-- Read-only.
--
-- Usage:
--   Default (safe, credentials not visible):
--     mysql -u admin < sec_15_external_integrations.sql
--
-- Notes:
--   * MySQL has no pg_foreign_data_wrapper or pg_foreign_server equivalent.
--   * External connections are handled via:
--       - FEDERATED storage engine (connects to remote MySQL)
--       - UDFs loaded from shared libraries (can do anything)
--       - X Plugin / MySQL Router (connection multiplexing)
--       - Application-layer connections (not visible from SQL)
-- =============================================================================

-- NOTE: MySQL does not have a Foreign Data Wrapper (FDW) concept like
--       PostgreSQL. The closest equivalents are:
--         1. FEDERATED engine: maps a local table to a remote MySQL table
--         2. Spider storage engine: distributed queries across MySQL servers
--         3. CONNECT engine (MariaDB-specific): connects to external sources
--         4. UDFs calling external services (curl/libcurl based)
--       There is no user mapping table or credential store visible via SQL
--       for FEDERATED connections; credentials are embedded in the table
--       definition (CONNECTION string) or server definition.

-- ---------------------------------------------------------------------------
-- Installed plugins relevant to external integrations
-- ---------------------------------------------------------------------------
SELECT
    PLUGIN_NAME,
    PLUGIN_VERSION,
    PLUGIN_STATUS,
    PLUGIN_TYPE,
    PLUGIN_DESCRIPTION
FROM information_schema.PLUGINS
WHERE PLUGIN_NAME IN (
    'FEDERATED',
    'federated',
    'Spider',
    'spider',
    'CONNECT',
    'connect',
    'ha_federated',
    'mysqlx',
    'X',
    'daemon_keyring_proxy'
)
  OR PLUGIN_TYPE IN ('STORAGE ENGINE')
  AND PLUGIN_NAME NOT IN ('InnoDB', 'MyISAM', 'MEMORY', 'CSV',
                           'MRG_MYISAM', 'ARCHIVE', 'BLACKHOLE',
                           'PERFORMANCE_SCHEMA', 'InnoDB tmpdir')
ORDER BY PLUGIN_TYPE, PLUGIN_NAME;

-- ---------------------------------------------------------------------------
-- FEDERATED engine tables (each is a connection to a remote MySQL server)
-- CONNECTION string may contain host, port, user, password
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.ENGINE,
    -- NOTE: TABLE_COMMENT contains the CONNECTION string for FEDERATED tables
    --       which may include plaintext credentials. Shown masked here.
    CASE WHEN t.TABLE_COMMENT LIKE '%password%'
              OR t.TABLE_COMMENT LIKE '%passwd%'
         THEN REGEXP_REPLACE(t.TABLE_COMMENT,
                             '(password|passwd)=[^,)&]+',
                             '\\1=***MASKED***')
         ELSE t.TABLE_COMMENT
    END                                                     AS connection_masked,
    t.CREATE_TIME,
    t.UPDATE_TIME
FROM information_schema.TABLES t
WHERE t.ENGINE = 'FEDERATED'
ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;

-- ---------------------------------------------------------------------------
-- FEDERATED server definitions (CREATE SERVER ... syntax)
-- These store connection details centrally; used by FEDERATED tables
-- ---------------------------------------------------------------------------
SELECT
    Server_name,
    Host,
    Db,
    Username,
    -- NOTE: Password is stored here; showing only whether it's set.
    CASE WHEN Password != '' THEN '***MASKED***' ELSE '(empty)' END AS password_state,
    Port,
    Socket,
    Wrapper,
    Owner
FROM mysql.servers
ORDER BY Server_name;

-- ---------------------------------------------------------------------------
-- User-defined functions (UDFs) — can call external libraries/services
-- ---------------------------------------------------------------------------
SELECT
    Name                                                    AS udf_name,
    dl                                                      AS library,
    Type                                                    AS udf_type,
    Aggregate
FROM mysql.func
ORDER BY Name;

-- ---------------------------------------------------------------------------
-- Spider engine tables (distributed MySQL — connects to shards)
-- Spider tables have ENGINE=Spider and connection details in the comment.
-- ---------------------------------------------------------------------------
SELECT
    t.TABLE_SCHEMA,
    t.TABLE_NAME,
    t.ENGINE,
    t.TABLE_COMMENT                                         AS spider_connection
FROM information_schema.TABLES t
WHERE t.ENGINE LIKE '%Spider%'
   OR t.ENGINE LIKE '%spider%'
ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;

-- ---------------------------------------------------------------------------
-- Routines that might establish external connections
-- Look for routines referencing connection-related keywords.
-- NOTE: MySQL does not expose routine body text in information_schema
--       without SELECT on the mysql schema. ROUTINE_DEFINITION in
--       information_schema.ROUTINES is only populated for the current user's
--       own routines (or with SHOW ROUTINE privilege in MySQL 8.0.22+).
-- ---------------------------------------------------------------------------
SELECT
    ROUTINE_SCHEMA,
    ROUTINE_NAME,
    ROUTINE_TYPE,
    DEFINER,
    SECURITY_TYPE,
    SQL_MODE
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA NOT IN ('mysql', 'information_schema',
                              'performance_schema', 'sys')
  AND (
    ROUTINE_DEFINITION LIKE '%FEDERATED%'
    OR ROUTINE_DEFINITION LIKE '%mysql.servers%'
    OR ROUTINE_DEFINITION LIKE '%CONNECTION%'
  )
ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME;

-- ---------------------------------------------------------------------------
-- X Plugin status (MySQL Document Store / JSON over X Protocol)
-- X Plugin provides an alternative protocol that could be an attack surface.
-- ---------------------------------------------------------------------------
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME IN (
    'mysqlx',
    'mysqlx_port',
    'mysqlx_bind_address',
    'mysqlx_socket',
    'mysqlx_ssl_ca',
    'mysqlx_ssl_cert',
    'mysqlx_ssl_key',
    'mysqlx_require_secure_transport'
)
ORDER BY VARIABLE_NAME;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM information_schema.TABLES
     WHERE ENGINE = 'FEDERATED')                           AS federated_tables,
    (SELECT COUNT(*) FROM mysql.servers)                   AS federated_servers,
    (SELECT COUNT(*) FROM mysql.func)                      AS udfs,
    (SELECT COUNT(*) FROM information_schema.PLUGINS
     WHERE PLUGIN_STATUS = 'ACTIVE'
       AND PLUGIN_TYPE = 'STORAGE ENGINE'
       AND PLUGIN_NAME NOT IN ('InnoDB','MyISAM','MEMORY','CSV',
                                'MRG_MYISAM','ARCHIVE','BLACKHOLE',
                                'PERFORMANCE_SCHEMA'))     AS non_standard_storage_engines;
