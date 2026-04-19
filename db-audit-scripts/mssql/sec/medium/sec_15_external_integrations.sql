-- =============================================================================
-- sec_15_external_integrations.sql
-- Priority: MEDIUM
-- Purpose: Audit outbound integration points — linked servers, Service
--          Broker, external data sources (PolyBase / OPENROWSET), and
--          credentials used by them.
-- Sources: sys.servers, sys.linked_logins, sys.credentials,
--          sys.external_data_sources, sys.services, sys.service_queues,
--          sys.service_contracts, sys.remote_service_bindings.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Linked servers (outbound connections to other SQL Server / OLE DB / ODBC)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS linked_server,
    product,
    provider,
    data_source,
    location,
    provider_string,
    catalog,
    is_linked,
    is_remote_login_enabled,
    is_rpc_out_enabled,
    is_data_access_enabled,
    modify_date
FROM sys.servers
WHERE is_linked = 1
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Linked server logins (MASKED — do NOT print the remote_password value,
-- which SQL Server stores in the clear in older editions)
-- ---------------------------------------------------------------------------
SELECT
    s.name                                            AS linked_server,
    CASE rl.local_principal_id
        WHEN 0 THEN 'any local login'
        ELSE SUSER_NAME(rl.local_principal_id)
    END                                               AS local_principal,
    rl.remote_name                                    AS remote_login,
    rl.uses_self_credential,
    rl.modify_date
FROM sys.linked_logins rl
JOIN sys.servers s ON s.server_id = rl.server_id
ORDER BY s.name;

-- ---------------------------------------------------------------------------
-- Credentials (used by linked servers, CLR assemblies, Agent proxies)
-- ---------------------------------------------------------------------------
SELECT
    c.name                                            AS credential_name,
    c.credential_identity,
    c.create_date,
    c.modify_date,
    c.target_type,
    c.target_id
FROM sys.credentials c
ORDER BY c.name;

-- ---------------------------------------------------------------------------
-- SQL Server Agent proxies (wrappers around credentials that jobs can
-- impersonate)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        p.proxy_id,
        p.name                                        AS proxy_name,
        p.enabled,
        p.description,
        c.name                                        AS credential_name,
        c.credential_identity                         AS credential_identity
    FROM msdb.dbo.sysproxies p
    LEFT JOIN sys.credentials c ON c.credential_id = p.credential_id;
END TRY
BEGIN CATCH
    PRINT '[note] msdb.dbo.sysproxies requires SQLAgentOperatorRole or sysadmin: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Service Broker — services, queues, contracts, message types
-- ---------------------------------------------------------------------------
SELECT
    s.name                                            AS service_name,
    q.name                                            AS queue_name,
    q.is_activation_enabled,
    q.activation_procedure                            AS activation_procedure_id,
    OBJECT_SCHEMA_NAME(q.activation_procedure)        AS activation_schema,
    OBJECT_NAME(q.activation_procedure)               AS activation_proc,
    q.is_receive_enabled,
    q.max_readers
-- NOTE: sys.services / sys.service_contracts / sys.service_message_types /
-- sys.routes do NOT expose an is_ms_shipped column. Instead we filter out
-- the built-in names that ship with every database.
FROM sys.services s
LEFT JOIN sys.service_queues q ON q.object_id = s.service_queue_id
WHERE s.name NOT LIKE 'http://%'
  AND s.name NOT IN (N'ServiceBrokerLaunchService');

SELECT
    name                                              AS contract_name,
    service_contract_id
FROM sys.service_contracts
WHERE name NOT LIKE 'http://%'
  AND name NOT LIKE '%DEFAULT%';

SELECT
    name                                              AS message_type_name,
    validation_desc
FROM sys.service_message_types
WHERE name NOT LIKE 'http://%'
  AND name NOT LIKE '%DEFAULT%'
  AND name NOT LIKE '%DialogTimer%'
  AND name NOT LIKE '%Error%'
  AND name NOT LIKE '%EndDialog%';

-- ---------------------------------------------------------------------------
-- Service Broker routes (endpoints to other instances)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS route_name,
    broker_instance,
    lifetime,
    -- sys.routes exposes remote_service_name (the target service), not
    -- service_name.
    remote_service_name,
    address,
    mirror_address
FROM sys.routes
WHERE name <> 'AutoCreatedLocal';

-- ---------------------------------------------------------------------------
-- External data sources (PolyBase / BULK INSERT DATA_SOURCE)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS external_data_source,
    location,
    type_desc,
    resource_manager_location,
    credential_id,
    (SELECT name FROM sys.database_scoped_credentials c WHERE c.credential_id = eds.credential_id) AS credential_name
FROM sys.external_data_sources eds
WHERE 1 = 1;

-- External tables (live queries against external data sources)
SELECT
    name                                              AS external_table,
    OBJECT_SCHEMA_NAME(object_id)                     AS schema_name,
    (SELECT name FROM sys.external_data_sources eds
      WHERE eds.data_source_id = et.data_source_id)   AS data_source,
    (SELECT name FROM sys.external_file_formats eff
      WHERE eff.file_format_id = et.file_format_id)   AS file_format,
    location
FROM sys.external_tables et;

-- ---------------------------------------------------------------------------
-- Replication publications (outbound transactional / snapshot replication)
-- ---------------------------------------------------------------------------
BEGIN TRY
    IF DB_ID('distribution') IS NOT NULL
        SELECT
            publication,
            publisher_id,
            publisher_db,
            publication_type_desc = CASE publication_type
                                       WHEN 0 THEN 'Transactional'
                                       WHEN 1 THEN 'Snapshot'
                                       WHEN 2 THEN 'Merge'
                                       ELSE 'Other' END
        FROM distribution.dbo.MSpublications;
END TRY
BEGIN CATCH
    PRINT '[note] distribution.dbo.MSpublications unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.servers WHERE is_linked = 1) AS linked_servers,
    (SELECT COUNT(*) FROM sys.linked_logins
      WHERE uses_self_credential = 0)                      AS linked_logins_with_stored_credential,
    (SELECT COUNT(*) FROM sys.credentials)                AS server_credentials,
    (SELECT COUNT(*) FROM sys.services
      WHERE name NOT LIKE 'http://%')                           AS broker_services,
    (SELECT COUNT(*) FROM sys.external_data_sources)     AS external_data_sources,
    (SELECT COUNT(*) FROM sys.external_tables)           AS external_tables;
