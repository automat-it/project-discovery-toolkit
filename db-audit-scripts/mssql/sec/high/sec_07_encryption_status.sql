-- =============================================================================
-- sec_07_encryption_status.sql
-- Priority: HIGH
-- Purpose: Verify encryption in transit (TLS) and encryption at rest (TDE,
--          column-level, Always Encrypted, backup encryption).
-- Sources: sys.dm_exec_connections, sys.certificates,
--          sys.symmetric_keys, sys.dm_database_encryption_keys,
--          sys.column_encryption_keys, sys.columns, msdb.dbo.backupset.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Connection-level encryption state (TLS per active session)
-- ---------------------------------------------------------------------------
SELECT
    c.session_id,
    s.login_name,
    s.host_name,
    c.encrypt_option,
    c.protocol_type,
    c.net_transport,
    c.auth_scheme,
    c.client_net_address
FROM sys.dm_exec_connections c
JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id
WHERE s.is_user_process = 1
ORDER BY c.encrypt_option, c.session_id;

-- ---------------------------------------------------------------------------
-- Encryption summary: encrypted vs plaintext sessions
-- ---------------------------------------------------------------------------
SELECT
    c.encrypt_option,
    COUNT(*)                                          AS session_count
FROM sys.dm_exec_connections c
JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id
WHERE s.is_user_process = 1
GROUP BY c.encrypt_option;

-- ---------------------------------------------------------------------------
-- Force Encryption / TLS server configuration (registry read — may need
-- sysadmin). On Linux the setting is in mssql-conf.
-- ---------------------------------------------------------------------------
BEGIN TRY
    EXEC xp_instance_regread
        N'HKEY_LOCAL_MACHINE',
        N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
        N'ForceEncryption';
END TRY
BEGIN CATCH
    PRINT '[note] xp_instance_regread unavailable on this platform: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- TDE (Transparent Data Encryption) — which databases are encrypted at rest
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME(dek.database_id)                          AS database_name,
    dek.encryption_state,
    CASE dek.encryption_state
        WHEN 0 THEN 'No key present'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key change in progress'
        WHEN 5 THEN 'Decryption in progress'
        ELSE 'Unknown'
    END                                               AS encryption_state_desc,
    dek.key_algorithm,
    dek.key_length,
    dek.encryptor_type,
    dek.percent_complete,
    dek.create_date,
    dek.regenerate_date,
    dek.set_date
FROM sys.dm_database_encryption_keys dek;

-- ---------------------------------------------------------------------------
-- Database master key presence (is_master_key_encrypted_by_server lives on
-- sys.databases; symmetric_keys itself does not expose that flag).
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                         AS database_name,
    sk.name                                           AS master_key_name,
    d.is_master_key_encrypted_by_server,
    sk.create_date,
    sk.modify_date
FROM sys.symmetric_keys sk
CROSS APPLY (SELECT is_master_key_encrypted_by_server
               FROM sys.databases
              WHERE database_id = DB_ID()) d
WHERE sk.symmetric_key_id = 101;

-- ---------------------------------------------------------------------------
-- Certificates (current database)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS certificate_name,
    subject,
    issuer_name,
    start_date,
    expiry_date,
    thumbprint,
    pvt_key_encryption_type_desc                      AS private_key_encryption
FROM sys.certificates
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Symmetric keys (current database)
-- ---------------------------------------------------------------------------
SELECT
    name                                              AS key_name,
    algorithm_desc,
    create_date,
    key_length
FROM sys.symmetric_keys
WHERE symmetric_key_id > 101
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Always Encrypted columns (client-side encryption)
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(c.object_id)                   AS schema_name,
    OBJECT_NAME(c.object_id)                          AS table_name,
    c.name                                            AS column_name,
    cek.name                                          AS column_encryption_key,
    c.encryption_type_desc,
    c.encryption_algorithm_name
FROM sys.columns c
JOIN sys.column_encryption_keys cek
      ON cek.column_encryption_key_id = c.column_encryption_key_id
WHERE c.encryption_type IS NOT NULL
ORDER BY schema_name, table_name, column_name;

-- ---------------------------------------------------------------------------
-- Dynamic Data Masking columns
-- ---------------------------------------------------------------------------
SELECT
    OBJECT_SCHEMA_NAME(object_id)                     AS schema_name,
    OBJECT_NAME(object_id)                            AS table_name,
    name                                              AS column_name,
    masking_function
FROM sys.masked_columns
ORDER BY schema_name, table_name, name;

-- ---------------------------------------------------------------------------
-- Last N backups — whether they were encrypted
-- ---------------------------------------------------------------------------
-- msdb is not present on Azure SQL Database; guard so the audit keeps
-- going with a [note] line on that platform.
BEGIN TRY
    SELECT TOP 50
        bs.database_name,
        bs.type                                       AS backup_type,
        bs.backup_finish_date,
        bs.encryptor_type,
        bs.encryptor_thumbprint,
        bs.key_algorithm                              AS key_alg,
        bs.is_password_protected
    FROM msdb.dbo.backupset bs
    ORDER BY bs.backup_finish_date DESC;
END TRY
BEGIN CATCH
    PRINT '[note] msdb.dbo.backupset unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.dm_database_encryption_keys
      WHERE encryption_state = 3)                     AS databases_encrypted_at_rest,
    (SELECT COUNT(*) FROM sys.certificates
      WHERE expiry_date < SYSUTCDATETIME())           AS expired_certificates,
    (SELECT COUNT(*) FROM sys.masked_columns)         AS ddm_masked_columns,
    (SELECT COUNT(*) FROM sys.columns
      WHERE encryption_type IS NOT NULL)              AS always_encrypted_columns;
